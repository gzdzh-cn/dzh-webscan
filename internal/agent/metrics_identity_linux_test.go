//go:build linux

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"webscan/internal/common"
	"webscan/internal/nodepki"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

func TestPullListenerReloadsManagedLeafWithoutRestart(t *testing.T) {
	testManagedNodeListener(t, false, false)
}
func TestSeededPullListenerRotatesAndRestartsWithoutRevertingIdentity(t *testing.T) {
	testManagedNodeListener(t, true, false)
}
func TestSeededPullListenerAppliesCSRLeafWithNodeLocalKey(t *testing.T) {
	testManagedNodeListener(t, true, true)
}
func testManagedNodeListener(t *testing.T, seeded, csrRenewal bool) {
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := authority.Export()
	server, _ := authority.Issue(nodepki.Node, "node-a", []string{"127.0.0.1"}, now, time.Hour)
	client, _ := authority.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	crl, _ := authority.Revoke(nil, nil, now, time.Hour)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	caFile := filepath.Join(dir, "ca.crt")
	crlFile := filepath.Join(dir, "ca.crl")
	identity := filepath.Join(dir, "node.pem")
	clientIdentity := filepath.Join(dir, "client.pem")
	for path, raw := range map[string][]byte{caFile: ca.CA, crlFile: crl} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := testAgent(t)
	var initial nodepki.IdentityRecord
	if seeded {
		identity = filepath.Join(a.Data, "pki-identity", "active.pem")
		for name, raw := range map[string][]byte{"identity.crt": server.Certificate, "identity.key": server.Key} {
			if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		initial, err = nodepki.PublishIdentity(context.Background(), caFile, identity, nodepki.Node, "node-a", "", server, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	initialClient, err := nodepki.PublishIdentity(context.Background(), caFile, clientIdentity, nodepki.Collector, "collector-a", "", client, now)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a.C["metrics"] = common.Map{"port": port, "tls_enabled": true, "ca_file": caFile, "identity_file": identity, "allowed_source_ip": "127.0.0.1"}
	if seeded {
		common.M(a.C["metrics"])["identity_seed_directory"] = dir
	}
	a.C["pull"] = common.Map{"collector_identities": []any{"spiffe://webscan/collector/collector-a"}, "revocation_file": crlFile, "revocation_state_directory": filepath.Join(a.Data, "pki-trust")}
	if csrRenewal {
		common.M(a.C["pull"])["identity_renewal"] = true
		if _, err := a.DB.Exec(`INSERT INTO events(id,payload,created) VALUES('pending-before-renewal','{"event_id":"pending-before-renewal","node_id":"node-a","operation":"modify"}',1)`); err != nil {
			t.Fatal(err)
		}
	}
	a.Pull, err = pull.New(a.DB, "node-a", "v3-test", &a.writeMu)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); a.worker.Wait() }()
	if err := a.startMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	if seeded {
		b, record, err := nodepki.ReadIdentity(caFile, identity, nodepki.Node, "node-a", time.Now())
		clear(b.Key)
		if err != nil {
			t.Fatal("seed was not activated", err)
		}
		initial = record
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CA)
	live, err := nodepki.NewLiveIdentity(caFile, clientIdentity, nodepki.Collector, "collector-a", now)
	if err != nil {
		t.Fatal(err)
	}
	connect := func() *grpc.ClientConn {
		t.Helper()
		conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1", GetClientCertificate: live.GetClientCertificate})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	call := func(conn *grpc.ClientConn) (string, error) {
		op, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		var p peer.Peer
		_, err := agentv1.NewAgentServiceClient(conn).Capabilities(op, &agentv1.CapabilitiesRequest{}, grpc.Peer(&p))
		if err != nil {
			return "", err
		}
		auth, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			t.Fatal("missing actual TLS peer")
		}
		return auth.State.PeerCertificates[0].SerialNumber.Text(16), nil
	}
	old := connect()
	serial, err := call(old)
	if err != nil || serial != initial.Serial {
		t.Fatal("initial leaf", serial, err)
	}
	nextClient, _ := authority.Issue(nodepki.Collector, "collector-a", nil, now, 2*time.Hour)
	var next nodepki.IdentityRecord
	if csrRenewal {
		issuer := filepath.Join(dir, "issuer")
		privateRoot, err := authority.Export()
		if err != nil {
			t.Fatal(err)
		}
		if err := nodepki.SeedAuthority(ctx, issuer, privateRoot, crl, now); err != nil {
			t.Fatal(err)
		}
		clear(privateRoot.Key)
		rpc := agentv1.NewAgentServiceClient(old)
		capability, err := rpc.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
		if err != nil || !capability.IdentityRenewal || capability.CertificateSha256 != initial.CertificateSHA256 {
			t.Fatal("renewal capability missing from actual Agent", err)
		}
		preparation := &agentv1.PrepareIdentityRenewalRequest{NodeId: "node-a", CertificateSha256: initial.CertificateSHA256}
		prepared, err := rpc.PrepareIdentityRenewal(ctx, preparation)
		if err != nil {
			t.Fatal("real Agent did not prepare a local key", err)
		}
		request, err := nodepki.ParseNodeRenewalRequest(prepared.PublicRequestJson)
		if err != nil || request.SHA256() != prepared.RequestSha256 || request.CertificateSHA256 != initial.CertificateSHA256 || request.Node != "node-a" || bytes.Contains(prepared.PublicRequestJson, []byte("PRIVATE KEY")) {
			t.Fatal("renewal request binding or privacy invalid", err)
		}
		retry, err := rpc.PrepareIdentityRenewal(ctx, preparation)
		if err != nil || !bytes.Equal(retry.PublicRequestJson, prepared.PublicRequestJson) {
			t.Fatal("network retry regenerated pending private key", err)
		}
		batch, err := rpc.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100})
		if err != nil || len(batch.Events) != 1 || batch.Events[0].Id != "pending-before-renewal" {
			t.Fatal("pre-renewal event unavailable", batch, err)
		}
		if _, err := rpc.PrepareIdentityRenewal(ctx, &agentv1.PrepareIdentityRenewalRequest{NodeId: "other", CertificateSha256: initial.CertificateSHA256}); status.Code(err) != codes.InvalidArgument {
			t.Fatal("wrong node prepared a private key", err)
		}
		if _, err := rpc.ActivateIdentityRenewal(ctx, &agentv1.ActivateIdentityRenewalRequest{NodeId: "node-a", PreviousCertificateSha256: initial.CertificateSHA256, RequestSha256: request.SHA256(), Certificate: []byte("broken")}); status.Code(err) != codes.FailedPrecondition {
			t.Fatal("invalid leaf activated", err)
		}
		unchanged, err := rpc.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
		if err != nil || unchanged.CertificateSha256 != initial.CertificateSHA256 {
			t.Fatal("failed activation changed active identity", err)
		}
		var publicLeaf []byte
		if err := nodepki.SignNodeRenewalRegistered(ctx, issuer, request, now, 2*time.Hour, func(b nodepki.Bundle, _ []byte) error {
			if len(b.Key) != 0 {
				t.Fatal("signer exported private key")
			}
			publicLeaf = append([]byte{}, b.Certificate...)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		activation := &agentv1.ActivateIdentityRenewalRequest{NodeId: "node-a", PreviousCertificateSha256: request.CertificateSHA256, RequestSha256: request.SHA256(), Certificate: publicLeaf}
		applied, err := rpc.ActivateIdentityRenewal(ctx, activation)
		if err != nil {
			t.Fatal(err)
		}
		lostResponse, err := rpc.ActivateIdentityRenewal(ctx, activation)
		if err != nil || applied.CertificateSha256 != lostResponse.CertificateSha256 || applied.RequestSha256 != request.SHA256() {
			t.Fatal("activation lost-response retry failed", err)
		}
		b, record, err := nodepki.ReadIdentity(caFile, identity, nodepki.Node, "node-a", now)
		clear(b.Key)
		if err != nil || record.CertificateSHA256 != applied.CertificateSha256 || record.ExpiresAt.Unix() != applied.CertificateNotAfterUnix {
			t.Fatal("RPC receipt differs from actual persisted identity", err)
		}
		next = record
	} else {
		nextServer, err := authority.Issue(nodepki.Node, "node-a", []string{"127.0.0.1"}, now, 2*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		next, err = nodepki.PublishIdentity(ctx, caFile, identity, nodepki.Node, "node-a", initial.CertificateSHA256, nextServer, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := nodepki.PublishIdentity(ctx, caFile, clientIdentity, nodepki.Collector, "collector-a", initialClient.CertificateSHA256, nextClient, now); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	fresh := connect()
	serial, err = call(fresh)
	if err != nil || serial != next.Serial {
		t.Fatal("same listener failed rotation", serial, err)
	}
	// The old established connection remains valid during overlap, until its
	// old collector leaf is explicitly revoked. New identity remains accepted.
	if _, err := call(old); err != nil {
		t.Fatal("overlap rejected", err)
	}
	revoked, err := authority.Revoke(crl, [][]byte{client.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "next.crl")
	os.WriteFile(tmp, revoked, 0600)
	if err := os.Rename(tmp, crlFile); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := call(old); status.Code(err) != codes.PermissionDenied {
		t.Fatal("revoked old connection accepted", err)
	}
	if _, err := call(fresh); err != nil {
		t.Fatal("renewed connection rejected", err)
	}
	if seeded {
		// Start from unchanged immutable seed after renewing the active leaf.
		cancel()
		a.worker.Wait()
		ctx, cancel = context.WithCancel(context.Background())
		if err := a.startMetrics(ctx); err != nil {
			t.Fatal("seeded listener restart", err)
		}
		serial, err := call(connect())
		if err != nil || serial != next.Serial {
			t.Fatal("restart returned original seed", serial, err)
		}
		if csrRenewal {
			rpc := agentv1.NewAgentServiceClient(connect())
			batch, err := rpc.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100})
			if err != nil || len(batch.Events) != 1 || batch.Events[0].Id != "pending-before-renewal" {
				t.Fatal("renewal/restart lost pending event", batch, err)
			}
			if result, err := rpc.AckEvents(ctx, &agentv1.AckEventsRequest{Epoch: 1, Receipt: batch.Receipt, Accepted: []string{"pending-before-renewal"}}); err != nil || result.Confirmed != 1 {
				t.Fatal("pending event could not be confirmed after renewal", result, err)
			}
		}
		// A missing initialized file must not be reconstructed from that seed.
		cancel()
		a.worker.Wait()
		if err := os.Remove(identity); err != nil {
			t.Fatal(err)
		}
		if err := a.startMetrics(ctx); err == nil {
			t.Fatal("missing active identity reinitialized")
		}
	}

}

func TestPullListenerRejectsRevokedExistingCollector(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := authority.Export()
	server, err := authority.Issue(nodepki.Node, "node-a", []string{"127.0.0.1"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client, err := authority.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := authority.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, raw := range map[string][]byte{"ca.crt": ca.CA, "ca.crl": crl, "node.crt": server.Certificate, "node.key": server.Key} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a, _ := testAgent(t)
	a.C["metrics"] = common.Map{"port": port, "allowed_source_ip": "127.0.0.1", "tls_enabled": true, "ca_file": filepath.Join(dir, "ca.crt"), "cert_file": filepath.Join(dir, "node.crt"), "key_file": filepath.Join(dir, "node.key")}
	a.C["pull"] = common.Map{"collector_identities": []any{"spiffe://webscan/collector/collector-a"}, "revocation_file": filepath.Join(dir, "ca.crl"), "revocation_state_directory": filepath.Join(a.Data, "pki-trust")}
	a.Pull, err = pull.New(a.DB, "node-a", "v3-test", &a.writeMu)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); a.worker.Wait() }()
	if err := a.startMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CA)
	pair, err := tls.X509KeyPair(client.Certificate, client.Key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "127.0.0.1", Certificates: []tls.Certificate{pair}})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rpc := agentv1.NewAgentServiceClient(conn)
	call := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := rpc.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
		return err
	}
	if err := call(); err != nil {
		t.Fatal("real listener rejected valid identity", err)
	}
	revoked, err := authority.Revoke(crl, [][]byte{client.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(dir, "next.crl")
	if err := os.WriteFile(temporary, revoked, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, filepath.Join(dir, "ca.crl")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		err := call()
		if status.Code(err) == codes.PermissionDenied {
			break
		}
		if err != nil {
			t.Fatal("unexpected revocation result", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("existing listener did not reload CRL")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// A new listener/cache must reject an authentic older source snapshot before
	// attempting to bind, even though the original listener remains established.
	if err := os.WriteFile(filepath.Join(dir, "ca.crl"), crl, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.startMetrics(ctx); err == nil || !strings.Contains(err.Error(), "revocation policy") {
		t.Fatal("listener restart did not enforce durable revocation floor", err)
	}
	// An invalid snapshot must stop startup, not silently disable revocation.
	if err := os.WriteFile(filepath.Join(dir, "ca.crl"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.startMetrics(ctx); err == nil {
		t.Fatal("invalid revocation policy accepted")
	}
}
