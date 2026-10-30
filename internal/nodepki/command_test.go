package nodepki

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func commandRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestOfflineCertificateLifecyclePersistsPrivatelyWithoutKeyOutput(t *testing.T) {
	ctx := context.Background()
	root := commandRoot(t)
	authority := filepath.Join(root, "authority")
	var out bytes.Buffer
	run := func(o Options) error { out.Reset(); return Command(ctx, o, &out) }
	if err := run(Options{Action: "init", Authority: authority}); err != nil {
		t.Fatal(err)
	}
	if err := run(Options{Action: "init", Authority: authority}); err == nil {
		t.Fatal("existing authority overwritten")
	}
	collector := filepath.Join(root, "collector")
	if err := run(Options{Action: "issue", Authority: authority, Output: collector, Role: Collector, ID: "collector-a"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "PRIVATE") || strings.Contains(out.String(), "BEGIN") {
		t.Fatal("private material in output")
	}
	node := filepath.Join(root, "node")
	if err := run(Options{Action: "issue", Authority: authority, Output: node, Role: Node, ID: "node-a", Names: "agent.test,127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := run(Options{Action: "issue", Authority: authority, Output: node, Role: Node, ID: "node-a", Names: "agent.test"}); err == nil {
		t.Fatal("existing identity overwritten")
	}
	ca, err := os.ReadFile(filepath.Join(authority, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	leafRaw, err := os.ReadFile(filepath.Join(node, "identity.crt"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := parseCertificate(leafRaw)
	initial, _ := os.ReadFile(filepath.Join(authority, "ca.crl"))
	trust, err := NewTrust(ca, initial, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Verify(leaf, Node, "node-a", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := run(Options{Action: "revoke", Authority: authority, Certificate: filepath.Join(node, "identity.crt")}); err != nil {
		t.Fatal(err)
	}
	if err := run(Options{Action: "renew-crl", Authority: authority}); err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(filepath.Join(authority, "ca.crl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.UpdateCRL(active, time.Now()); err != nil {
		t.Fatal(err)
	}
	if trust.Verify(leaf, Node, "node-a", time.Now()) == nil {
		t.Fatal("revoked node accepted after renewal")
	}
	if _, err := os.Stat(filepath.Join(authority, "crls", "3.pem")); err != nil {
		t.Fatal("missing immutable CRL history", err)
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
			t.Fatalf("unsafe %s: %o", path, st.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A deployment leaf bundle contains neither the CA key nor another identity.
	if _, err := os.Stat(filepath.Join(node, "ca.key")); !os.IsNotExist(err) {
		t.Fatal("authority key distributed to node")
	}
}
func TestCRLPublicationReconcilesAndConcurrentRevokesDoNotLoseEntries(t *testing.T) {
	ctx := context.Background()
	root := commandRoot(t)
	authority := filepath.Join(root, "authority")
	if err := Command(ctx, Options{Action: "init", Authority: authority}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var certs []string
	for _, id := range []string{"a", "b"} {
		output := filepath.Join(root, id)
		if err := Command(ctx, Options{Action: "issue", Authority: authority, Output: output, Role: Collector, ID: id}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		certs = append(certs, filepath.Join(output, "identity.crt"))
	}
	initial, _ := os.ReadFile(filepath.Join(authority, "ca.crl"))
	var wg sync.WaitGroup
	for _, cert := range certs {
		wg.Add(1)
		go func(cert string) {
			defer wg.Done()
			if err := Command(ctx, Options{Action: "revoke", Authority: authority, Certificate: cert}, &bytes.Buffer{}); err != nil {
				t.Error(err)
			}
		}(cert)
	}
	wg.Wait()
	// Simulate interrupted publication: immutable revision 3 exists, active copy
	// still points to revision 1. Renewal must recover 3 before producing 4.
	if err := os.WriteFile(filepath.Join(authority, "ca.crl"), initial, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Command(ctx, Options{Action: "renew-crl", Authority: authority}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(filepath.Join(authority, "ca.crt"))
	active, _ := os.ReadFile(filepath.Join(authority, "ca.crl"))
	trust, err := NewTrust(ca, active, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range certs {
		raw, _ := os.ReadFile(path)
		cert, _ := parseCertificate(raw)
		id, _ := PeerID(cert, Collector)
		if trust.Verify(cert, Collector, id, time.Now()) == nil {
			t.Fatal("concurrent revocation lost", id)
		}
	}
	if _, err := os.Stat(filepath.Join(authority, "crls", "4.pem")); err != nil {
		t.Fatal("publication did not advance from durable latest", err)
	}
	lock, err := authorityLock(ctx, authority)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := Command(short, Options{Action: "renew-crl", Authority: authority}, &bytes.Buffer{}); err == nil {
		t.Fatal("concurrent issuer ignored lock timeout")
	}
	lock.Close()
}
func TestOfflineToolRejectsSymlinksPermissionsAndDamagedAuthority(t *testing.T) {
	root := commandRoot(t)
	authority := filepath.Join(root, "authority")
	ctx := context.Background()
	if err := Command(ctx, Options{Action: "init", Authority: authority}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(authority, "ca.key"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Command(ctx, Options{Action: "renew-crl", Authority: authority}, &bytes.Buffer{}); err == nil {
		t.Fatal("public CA key accepted")
	}
	os.Chmod(filepath.Join(authority, "ca.key"), 0600)
	link := filepath.Join(root, "link")
	if err := os.Symlink(authority, link); err != nil {
		t.Fatal(err)
	}
	if err := Command(ctx, Options{Action: "renew-crl", Authority: link}, &bytes.Buffer{}); err == nil {
		t.Fatal("authority symlink accepted")
	}
	if err := os.WriteFile(filepath.Join(authority, "crls", "2.pem"), []byte("interrupted write"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Command(ctx, Options{Action: "renew-crl", Authority: authority}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown newer revision ignored")
	}
}
