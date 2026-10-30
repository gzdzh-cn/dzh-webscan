package nodepki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type liveFixture struct {
	root, caFile, file string
	now                time.Time
	a                  *Authority
	b                  Bundle
	record             IdentityRecord
}

func newLiveFixture(t *testing.T, role, id string) liveFixture {
	t.Helper()
	f := liveFixture{root: commandRoot(t), now: time.Now().UTC().Truncate(time.Second)}
	var err error
	f.a, err = NewAuthority(f.now.Add(-24*time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	if role == Node {
		names = []string{"agent.test", "127.0.0.1"}
	}
	f.b, err = f.a.Issue(role, id, names, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.caFile = filepath.Join(f.root, "ca.crt")
	f.file = filepath.Join(f.root, "identity.pem")
	if err := os.WriteFile(f.caFile, f.b.CA, 0600); err != nil {
		t.Fatal(err)
	}
	f.record, err = PublishIdentity(context.Background(), f.caFile, f.file, role, id, "", f.b, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestIdentityAtomicCASAndPrivateHistory(t *testing.T) {
	f := newLiveFixture(t, Node, "node-a")
	ctx := context.Background()
	b1, _ := f.a.Issue(Node, "node-a", []string{"agent.test"}, f.now, 2*time.Hour)
	b2, _ := f.a.Issue(Node, "node-a", []string{"agent.test"}, f.now, 3*time.Hour)
	var won atomic.Int32
	var wg sync.WaitGroup
	for _, b := range []Bundle{b1, b2} {
		wg.Add(1)
		go func(b Bundle) {
			defer wg.Done()
			if _, err := PublishIdentity(ctx, f.caFile, f.file, Node, "node-a", f.record.CertificateSHA256, b, f.now); err == nil {
				won.Add(1)
			}
		}(b)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatal("CAS winners", won.Load())
	}
	active, record, err := ReadIdentity(f.caFile, f.file, Node, "node-a", f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(active.Key)
	retry, err := PublishIdentity(ctx, f.caFile, f.file, Node, "node-a", f.record.CertificateSHA256, active, f.now)
	if err != nil || retry.Changed || retry.CertificateSHA256 != record.CertificateSHA256 {
		t.Fatal("lost-response retry", retry, err)
	}
	old, err := os.ReadFile(filepath.Join(f.file+".history", f.record.CertificateSHA256+".pem"))
	if err != nil || !bytes.Equal(old, append(append([]byte{}, f.b.Certificate...), f.b.Key...)) {
		t.Fatal("prior identity not preserved", err)
	}
	if err := filepath.WalkDir(f.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		want := os.FileMode(0600)
		if d.IsDir() {
			want = 0700
		}
		if st.Mode().Perm() != want {
			t.Errorf("unsafe permissions %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(record)
	if strings.Contains(string(raw), "PRIVATE") || bytes.Contains(raw, active.Key) {
		t.Fatal("private response")
	}
}

func TestIdentityRejectsUnsafePublicationWithoutChangingActive(t *testing.T) {
	f := newLiveFixture(t, Node, "node-a")
	ctx := context.Background()
	other, _ := NewAuthority(f.now, 365*24*time.Hour)
	wrongCA, _ := other.Issue(Node, "node-a", []string{"agent.test"}, f.now, 2*time.Hour)
	wrongID, _ := f.a.Issue(Node, "node-b", []string{"agent.test"}, f.now, 2*time.Hour)
	wrongRole, _ := f.a.Issue(Collector, "node-a", nil, f.now, 2*time.Hour)
	expired, _ := f.a.Issue(Node, "node-a", []string{"agent.test"}, f.now.Add(-2*time.Hour), time.Hour)
	valid, _ := f.a.Issue(Node, "node-a", []string{"agent.test"}, f.now, 2*time.Hour)
	broken := valid
	broken.Key = f.b.Key
	trailing := valid
	trailing.Key = append(append([]byte{}, valid.Key...), []byte("junk")...)
	prefix := valid
	prefix.Certificate = append([]byte("ignored text\n"), valid.Certificate...)
	before, _ := os.ReadFile(f.file)
	for name, b := range map[string]Bundle{"ca": wrongCA, "id": wrongID, "role": wrongRole, "expired": expired, "key": broken, "trailing": trailing, "prefix": prefix} {
		t.Run(name, func(t *testing.T) {
			if _, err := PublishIdentity(ctx, f.caFile, f.file, Node, "node-a", f.record.CertificateSHA256, b, f.now); err == nil {
				t.Fatal("accepted invalid identity")
			}
			after, _ := os.ReadFile(f.file)
			if !bytes.Equal(before, after) {
				t.Fatal("active changed")
			}
		})
	}
	if _, err := PublishIdentity(ctx, f.caFile, f.file, Node, "node-a", "stale", valid, f.now); err == nil {
		t.Fatal("stale CAS")
	}
	if err := os.Symlink(f.root, f.file+".history"); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishIdentity(ctx, f.caFile, f.file, Node, "node-a", f.record.CertificateSHA256, valid, f.now); err == nil {
		t.Fatal("history link accepted")
	}
	after, _ := os.ReadFile(f.file)
	if !bytes.Equal(before, after) {
		t.Fatal("history failure changed active")
	}
	os.Remove(f.file + ".history")
	for _, kind := range []string{"permissions", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(f.root, "unsafe.pem")
			switch kind {
			case "permissions":
				os.WriteFile(path, before, 0644)
			case "symlink":
				os.Symlink(f.file, path)
			case "hardlink":
				os.Link(f.file, path)
			}
			defer os.Remove(path)
			if _, _, err := ReadIdentity(f.caFile, path, Node, "node-a", f.now); err == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
}

func TestLiveIdentityFailsClosedAndRecoversWithoutCAOrIDDrift(t *testing.T) {
	f := newLiveFixture(t, Collector, "collector-a")
	live, err := NewLiveIdentity(f.caFile, f.file, Collector, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := f.a.Issue(Collector, "collector-a", nil, f.now, 2*time.Hour)
	record, err := PublishIdentity(context.Background(), f.caFile, f.file, Collector, "collector-a", f.record.CertificateSHA256, next, f.now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := live.Record(f.now.Add(2 * time.Second))
	if err != nil || got.CertificateSHA256 != record.CertificateSHA256 {
		t.Fatal("reload", err)
	}
	good, _ := os.ReadFile(f.file)
	for name, raw := range map[string][]byte{"missing-content": []byte("broken"), "regression": append(append([]byte{}, f.b.Certificate...), f.b.Key...)} {
		t.Run(name, func(t *testing.T) {
			os.WriteFile(f.file, raw, 0600)
			if _, err := live.Record(f.now.Add(4 * time.Second)); err == nil {
				t.Fatal("bad source fell back to old key")
			}
			os.WriteFile(f.file, good, 0600)
			if _, err := live.Record(f.now.Add(6 * time.Second)); err != nil {
				t.Fatal("repair failed", err)
			}
		})
	}
	wrongID, _ := f.a.Issue(Collector, "collector-b", nil, f.now, 3*time.Hour)
	os.WriteFile(f.file, append(wrongID.Certificate, wrongID.Key...), 0600)
	if _, err := live.Record(f.now.Add(8 * time.Second)); err == nil {
		t.Fatal("unpinned identity")
	}
	os.WriteFile(f.file, good, 0600)
	if _, err := live.Record(f.now.Add(9 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Record(f.now.Add(2 * time.Hour)); err == nil {
		t.Fatal("expired key accepted")
	}
}

// Use actual TLS handshakes on an unchanged listener. Each connection sees
// one coherent pair, and both sides present the renewed signed identities.
func TestLiveIdentityTLSLeafAndClientReloadOnSameListener(t *testing.T) {
	f := newLiveFixture(t, Node, "node-a")
	client, _ := f.a.Issue(Collector, "collector-a", nil, f.now, time.Hour)
	clientFile := filepath.Join(f.root, "client.pem")
	firstClient, err := PublishIdentity(context.Background(), f.caFile, clientFile, Collector, "collector-a", "", client, f.now)
	if err != nil {
		t.Fatal(err)
	}
	slive, err := NewLiveIdentity(f.caFile, f.file, Node, "node-a", f.now)
	if err != nil {
		t.Fatal(err)
	}
	clive, err := NewLiveIdentity(f.caFile, clientFile, Collector, "collector-a", f.now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(f.b.CA)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	serverConfig := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, GetCertificate: slive.GetCertificate}
	clientConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "agent.test", GetClientCertificate: clive.GetClientCertificate}
	call := func() (string, string) {
		t.Helper()
		type result struct {
			serial string
			err    error
		}
		done := make(chan result, 1)
		go func() {
			raw, e := l.Accept()
			if e != nil {
				done <- result{err: e}
				return
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(5 * time.Second))
			conn := tls.Server(raw, serverConfig)
			e = conn.Handshake()
			r := result{err: e}
			if e == nil {
				r.serial = conn.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
			}
			done <- r
		}()
		raw, e := net.DialTimeout("tcp", l.Addr().String(), 5*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Client(raw, clientConfig)
		if e := conn.Handshake(); e != nil {
			t.Fatal(e)
		}
		peer := conn.ConnectionState().PeerCertificates[0].SerialNumber.Text(16)
		r := <-done
		if r.err != nil {
			t.Fatal(r.err)
		}
		return peer, r.serial
	}
	s, c := call()
	if s != f.record.Serial || c != firstClient.Serial {
		t.Fatal("initial TLS identities")
	}
	nextServer, _ := f.a.Issue(Node, "node-a", []string{"agent.test", "127.0.0.1"}, f.now, 2*time.Hour)
	nextClient, _ := f.a.Issue(Collector, "collector-a", nil, f.now, 2*time.Hour)
	sr, err := PublishIdentity(context.Background(), f.caFile, f.file, Node, "node-a", f.record.CertificateSHA256, nextServer, f.now)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := PublishIdentity(context.Background(), f.caFile, clientFile, Collector, "collector-a", firstClient.CertificateSHA256, nextClient, f.now)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	s, c = call()
	if s != sr.Serial || c != cr.Serial {
		t.Fatal("same listener used stale identities")
	}
}

func TestOfflinePublishRenewPreservesNamesAndRejectsRevoked(t *testing.T) {
	root := commandRoot(t)
	ctx := context.Background()
	authority := filepath.Join(root, "authority")
	source := filepath.Join(root, "source")
	var out bytes.Buffer
	run := func(o Options) error {
		out.Reset()
		err := Command(ctx, o, &out)
		if strings.Contains(out.String(), "BEGIN") || strings.Contains(out.String(), "PRIVATE") {
			t.Fatal("key output")
		}
		return err
	}
	if err := run(Options{Action: "init", Authority: authority}); err != nil {
		t.Fatal(err)
	}
	if err := run(Options{Action: "issue", Authority: authority, Output: source, Role: Node, ID: "node-a", Names: "agent.test,127.0.0.1", LifetimeHours: 1}); err != nil {
		t.Fatal(err)
	}
	o := Options{Action: "publish-identity", Source: source, CAFile: filepath.Join(authority, "ca.crt"), IdentityFile: filepath.Join(root, "active.pem"), Role: Node, ID: "node-a"}
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	var prior IdentityRecord
	if err := json.Unmarshal(out.Bytes(), &prior); err != nil {
		t.Fatal(err)
	}
	o.Action = "renew-identity"
	o.Source = ""
	o.Authority = authority
	o.ExpectedSHA256 = prior.CertificateSHA256
	o.LifetimeHours = 2
	if err := run(o); err != nil {
		t.Fatal(err)
	}
	var next IdentityRecord
	json.Unmarshal(out.Bytes(), &next)
	if next.CertificateSHA256 == prior.CertificateSHA256 || !next.Changed {
		t.Fatal("renewal didn't rotate")
	}
	b, _, err := ReadIdentity(o.CAFile, o.IdentityFile, Node, "node-a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	cert, _ := parseCertificate(b.Certificate)
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "agent.test" || len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatal("renewal changed SANs")
	}
	if err := run(o); err == nil {
		t.Fatal("stale renewal replaced active")
	}
	leaf := filepath.Join(root, "current.crt")
	os.WriteFile(leaf, b.Certificate, 0600)
	if err := run(Options{Action: "revoke", Authority: authority, Certificate: leaf}); err != nil {
		t.Fatal(err)
	}
	o.ExpectedSHA256 = next.CertificateSHA256
	o.LifetimeHours = 3
	if err := run(o); err == nil {
		t.Fatal("revoked identity renewed")
	}
	o.Action = "init"
	if err := run(o); err == nil {
		t.Fatal("unrelated action ignored activation arguments")
	}
}

func TestExpiredIdentityOnlyAllowsExplicitOfflineRenewal(t *testing.T) {
	root := commandRoot(t)
	ctx := context.Background()
	authority := filepath.Join(root, "authority")
	source := filepath.Join(root, "source")
	var out bytes.Buffer
	for _, o := range []Options{{Action: "init", Authority: authority}, {Action: "issue", Authority: authority, Output: source, Role: Collector, ID: "collector-expired", LifetimeHours: 1}} {
		if err := Command(ctx, o, &out); err != nil {
			t.Fatal(err)
		}
	}
	o := Options{Action: "publish-identity", CAFile: filepath.Join(authority, "ca.crt"), IdentityFile: filepath.Join(root, "active.pem"), Source: source, Role: Collector, ID: "collector-expired"}
	out.Reset()
	if err := Command(ctx, o, &out); err != nil {
		t.Fatal(err)
	}
	var record IdentityRecord
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Truncate(time.Second).Add(2 * time.Hour)
	if _, _, err := ReadIdentity(o.CAFile, o.IdentityFile, o.Role, o.ID, future); err == nil {
		t.Fatal("online expired identity accepted")
	}
	if _, err := NewLiveIdentity(o.CAFile, o.IdentityFile, o.Role, o.ID, future); err == nil {
		t.Fatal("expired TLS identity accepted")
	}
	o.Action = "renew-identity"
	o.Authority = authority
	o.Source = ""
	o.ExpectedSHA256 = record.CertificateSHA256
	o.LifetimeHours = 2
	out.Reset()
	if err := identityCommand(ctx, o, &out, future); err != nil {
		t.Fatal("explicit expired renewal failed", err)
	}
	if _, _, err := ReadIdentity(o.CAFile, o.IdentityFile, o.Role, o.ID, future); err != nil {
		t.Fatal("renewed leaf unusable", err)
	}
}
