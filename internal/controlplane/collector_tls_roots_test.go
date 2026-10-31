package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"webscan/internal/nodepki"
)

func TestCollectorRootCredentialsUseFreshRootsAndBuiltinMutualTLSVerification(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	next, err := nodepki.NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := old.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(anchor.Key)
	oldCRL, err := old.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCRL, err := next.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := privateTestDir(t)
	caFile, crlFile, state := filepath.Join(root, "ca.crt"), filepath.Join(root, "ca.crl"), filepath.Join(root, "trust")
	localWrite(t, caFile, anchor.CA)
	localWrite(t, crlFile, oldCRL)
	trust, err := nodepki.NewPersistentFileTrust(caFile, crlFile, state, now)
	if err != nil {
		t.Fatal(err)
	}
	pair := func(a *nodepki.Authority, role, id string) *tls.Certificate {
		t.Helper()
		names := []string(nil)
		if role == nodepki.Node {
			names = []string{"node.example.test"}
		}
		b, err := a.Issue(role, id, names, now, 30*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(b.Key)
		p, err := tls.X509KeyPair(b.Certificate, b.Key)
		if err != nil {
			t.Fatal(err)
		}
		return &p
	}
	oldNode, newNode := pair(old, nodepki.Node, "node-a"), pair(next, nodepki.Node, "node-a")
	oldCollector, newCollector := pair(old, nodepki.Collector, "collector-a"), pair(next, nodepki.Collector, "collector-a")
	var serverPair, clientPair atomic.Pointer[tls.Certificate]
	serverPair.Store(oldNode)
	clientPair.Store(oldCollector)
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "node.example.test", GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return clientPair.Load(), nil }}
	policy := &nodeCertificatePolicy{trust: trust, node: "node-a"}
	policy.wrapTLS(config)
	transport := &collectorRootCredentials{config: config, roots: trust.RootPool}
	handshake := func(credential credentials.TransportCredentials) error {
		clientRaw, serverRaw := net.Pipe()
		deadline := time.Now().Add(3 * time.Second)
		clientRaw.SetDeadline(deadline)
		serverRaw.SetDeadline(deadline)
		serverConfig := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}, ClientAuth: tls.RequireAndVerifyClientCert, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return serverPair.Load(), nil }, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return nodepki.ErrIdentity
			}
			return trust.Verify(state.PeerCertificates[0], nodepki.Collector, "collector-a", time.Now())
		}}
		serverConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			clone := serverConfig.Clone()
			clone.GetConfigForClient = nil
			pool, err := trust.RootPool(time.Now())
			if err != nil {
				return nil, err
			}
			clone.ClientCAs = pool
			return clone, nil
		}
		done := make(chan error, 1)
		go func() { defer serverRaw.Close(); done <- tls.Server(serverRaw, serverConfig).Handshake() }()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// grpc derives the handshake authority from TransportCredentials.Info.
		// tlsCreds deliberately verifies that authority, overriding ServerName.
		connection, auth, err := credential.ClientHandshake(ctx, credential.Info().ServerName, clientRaw)
		if connection != nil {
			connection.Close()
		} else {
			clientRaw.Close()
		}
		serverErr := <-done
		if err != nil {
			return err
		}
		if serverErr != nil {
			return serverErr
		}
		info, ok := auth.(credentials.TLSInfo)
		if !ok || len(info.State.VerifiedChains) == 0 || config.InsecureSkipVerify {
			return nodepki.ErrIdentity
		}
		return nil
	}
	if err := handshake(transport); err != nil {
		t.Fatal("initial mutual TLS failed", err)
	}
	serverPair.Store(newNode)
	if handshake(transport) == nil {
		t.Fatal("new root accepted before explicit dual-root authorization")
	}
	dual, err := old.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := nodepki.RootSetSnapshot{Format: 1, Dual: dual, OldCRL: oldCRL, NewCRL: newCRL}
	publish := func() {
		t.Helper()
		raw, _ := json.Marshal(snapshot)
		r, err := nodepki.PublishRootSet(context.Background(), state, anchor.CA, raw, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		until := time.Now().Add(2 * time.Second)
		for {
			_, got, err := trust.RootSnapshot(time.Now(), "")
			if err == nil && got.SHA256 == r.SHA256 {
				break
			}
			if time.Now().After(until) {
				t.Fatal("live trust did not refresh", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	publish()
	clientPair.Store(newCollector)
	if err := handshake(transport); err != nil {
		t.Fatal("new leaf handshake failed after live dual-root update", err)
	}
	clone := transport.Clone()
	if err := clone.OverrideServerName("wrong.example.test"); err != nil {
		t.Fatal(err)
	}
	if handshake(clone) == nil {
		t.Fatal("hostname verification was bypassed by dynamic root loading")
	}
	if err := handshake(transport); err != nil {
		t.Fatal("cloned credentials mutated original server name", err)
	}
	final, err := old.AuthorizeRootRotation(next, dual.Rotation, dual.MembersSHA256, &dual, strings.Repeat("c", 64), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Final = &final
	publish()
	if err := handshake(transport); err != nil {
		t.Fatal("new identities failed after final root removal", err)
	}
	serverPair.Store(oldNode)
	if handshake(transport) == nil {
		t.Fatal("retired server issuer still accepted by builtin verification")
	}
	serverPair.Store(newNode)
	clientPair.Store(oldCollector)
	if handshake(transport) == nil {
		t.Fatal("retired collector issuer still accepted")
	}
	if info := transport.Info(); info.SecurityProtocol != "tls" {
		t.Fatal(info)
	}
}
