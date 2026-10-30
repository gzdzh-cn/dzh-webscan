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
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"webscan/internal/common"
	"webscan/internal/nodepki"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

func TestPullListenerReceivesCRLAfterExpiryAndRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-2 * time.Hour)
	authority, err := nodepki.NewAuthority(past, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := authority.Export()
	defer clear(ca.Key)
	server, _ := authority.Issue(nodepki.Node, "node-a", []string{"127.0.0.1"}, past, 24*time.Hour)
	defer clear(server.Key)
	client, _ := authority.Issue(nodepki.Collector, "collector-a", nil, past, 24*time.Hour)
	defer clear(client.Key)
	seed, _ := authority.Revoke(nil, nil, past, time.Hour)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	for name, raw := range map[string][]byte{"ca.crt": ca.CA, "ca.crl": seed, "node.crt": server.Certificate, "node.key": server.Key} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := testAgent(t)
	state := filepath.Join(a.Data, "pki-trust")
	if _, err := nodepki.NewReceiverTrust(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.crl"), state, past); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a.C["metrics"] = common.Map{"port": port, "tls_enabled": true, "ca_file": filepath.Join(dir, "ca.crt"), "cert_file": filepath.Join(dir, "node.crt"), "key_file": filepath.Join(dir, "node.key"), "allowed_source_ip": "127.0.0.1"}
	a.C["pull"] = common.Map{"collector_identities": []any{"spiffe://webscan/collector/collector-a"}, "revocation_file": filepath.Join(dir, "ca.crl"), "revocation_state_directory": state, "revocation_updates": true}
	a.Pull, err = pull.New(a.DB, "node-a", "v3-test", &a.writeMu)
	if err != nil {
		t.Fatal(err)
	}
	start := func() context.CancelFunc {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		if err := a.startMetrics(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		return func() { cancel(); a.worker.Wait() }
	}
	stop := start()
	defer func() { stop() }()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CA)
	pair, err := tls.X509KeyPair(client.Certificate, client.Key)
	if err != nil {
		t.Fatal(err)
	}
	connect := func() (*grpc.ClientConn, agentv1.AgentServiceClient) {
		t.Helper()
		conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{pair}})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn, agentv1.NewAgentServiceClient(conn)
	}
	conn, rpc := connect()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := rpc.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("expired policy allowed collection", err)
	}
	updated, _ := authority.Revoke(seed, nil, now, time.Hour)
	r, err := rpc.UpdateTrust(ctx, &agentv1.UpdateTrustRequest{NodeId: "node-a", Crl: updated})
	if err != nil || r.CrlNumber != "2" {
		t.Fatal("real listener failed recovery", r, err)
	}
	if _, err := rpc.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); err != nil {
		t.Fatal("same connection did not resume", err)
	}
	stored, _ := os.ReadFile(filepath.Join(state, "ca.crl"))
	original, _ := os.ReadFile(filepath.Join(dir, "ca.crl"))
	if !bytes.Equal(stored, updated) || !bytes.Equal(original, seed) {
		t.Fatal("CRL update changed immutable package or missed durable state")
	}
	conn.Close()
	stop()
	stop = func() {}
	// The immutable seed is still expired. Restart must use the received floor.
	stop = start()
	_, rpc = connect()
	if _, err := rpc.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); err != nil {
		t.Fatal("restart discarded received CRL", err)
	}
	if _, err := rpc.UpdateTrust(ctx, &agentv1.UpdateTrustRequest{NodeId: "node-a", Crl: seed}); err == nil {
		t.Fatal("restart permitted trust rollback")
	}
}

func TestTrustReceiverRequiresPullTLSAndPersistentState(t *testing.T) {
	for _, kind := range []string{"no-pull", "no-tls", "no-state", "no-seed"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := testAgent(t)
			a.C["metrics"] = common.Map{"port": 19100, "tls_enabled": true}
			a.C["pull"] = common.Map{"revocation_updates": true, "revocation_file": "/not-read.crl", "revocation_state_directory": "/not-read-state"}
			if kind != "no-pull" {
				var err error
				a.Pull, err = pull.New(a.DB, "node-a", "v3-test", &a.writeMu)
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "no-tls":
				common.M(a.C["metrics"])["tls_enabled"] = false
			case "no-state":
				delete(common.M(a.C["pull"]), "revocation_state_directory")
			case "no-seed":
				delete(common.M(a.C["pull"]), "revocation_file")
			}
			if err := a.startMetrics(context.Background()); err == nil {
				t.Fatal("incomplete trust receiver configuration accepted")
			}
		})
	}
}
