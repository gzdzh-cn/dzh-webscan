package pull

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

func TestRootTrustRefreshRealMutualTLSAndExpiredPolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	before := now.Add(-2 * time.Hour)
	old, err := nodepki.NewAuthority(before, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	next, err := nodepki.NewAuthority(before, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := old.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(anchor.Key)
	dual, err := old.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", before)
	if err != nil {
		t.Fatal(err)
	}
	oldCRL, err := old.Revoke(nil, nil, before, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCRL, err := next.Revoke(nil, nil, before, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := nodepki.RootSetSnapshot{Format: 1, Dual: dual, OldCRL: oldCRL, NewCRL: newCRL}
	raw, _ := json.Marshal(snapshot)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	caFile, crlFile, state := filepath.Join(parent, "ca.crt"), filepath.Join(parent, "seed.crl"), filepath.Join(parent, "trust")
	for path, content := range map[string][]byte{caFile: anchor.CA, crlFile: oldCRL} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := nodepki.NewReceiverTrust(caFile, crlFile, state, before); err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.PublishRootSet(context.Background(), state, anchor.CA, raw, before); err != nil {
		t.Fatal(err)
	}
	receiver, err := nodepki.NewReceiverTrust(caFile, crlFile, state, now)
	if err != nil {
		t.Fatal(err)
	}
	node, err := old.Issue(nodepki.Node, "test-node", []string{"agent.test"}, before, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(node.Key)
	collector, err := next.Issue(nodepki.Collector, "one", nil, before, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(collector.Key)
	outsider, err := next.Issue(nodepki.Collector, "outsider", nil, before, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(outsider.Key)
	source := testSource(t)
	var updates atomic.Int64
	g := NewServerWithRootTrust(source, []string{"spiffe://webscan/collector/one"}, nil, func(ctx context.Context, peer *x509.Certificate, raw []byte) (*agentv1.RefreshRootTrustResponse, error) {
		updates.Add(1)
		r, err := receiver.RefreshRoots(ctx, peer, raw, time.Now())
		if err != nil {
			return nil, err
		}
		return &agentv1.RefreshRootTrustResponse{NodeId: source.NodeID, SnapshotSha256: r.SHA256, Rotation: r.Rotation, Phase: r.Phase}, nil
	}, nil, func(cert *x509.Certificate) error {
		id, err := nodepki.PeerID(cert, nodepki.Collector)
		if err != nil {
			return err
		}
		return receiver.Verify(cert, nodepki.Collector, id, time.Now())
	})
	pair, err := tls.X509KeyPair(node.Certificate, node.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := receiver.HandshakeRootPool(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}}
	server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		clone := server.TLS.Clone()
		clone.GetConfigForClient = nil
		pool, err := receiver.HandshakeRootPool(time.Now())
		if err != nil {
			return nil, err
		}
		clone.ClientCAs = pool
		return clone, nil
	}
	server.StartTLS()
	defer func() { server.CloseClientConnections(); g.Stop(); server.Close() }()
	connect := func(b nodepki.Bundle) agentv1.AgentServiceClient {
		t.Helper()
		pair, err := tls.X509KeyPair(b.Certificate, b.Key)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.NewClient(server.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "agent.test", Certificates: []tls.Certificate{pair}})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return agentv1.NewAgentServiceClient(conn)
	}
	client, other := connect(collector), connect(outsider)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("expired policy allowed collection", err)
	}
	snapshot.OldCRL, err = old.Revoke(oldCRL, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.NewCRL, err = next.Revoke(newCRL, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := json.Marshal(snapshot)
	request := &agentv1.RefreshRootTrustRequest{NodeId: source.NodeID, SnapshotJson: fresh}
	if _, err := other.RefreshRootTrust(ctx, request); status.Code(err) != codes.PermissionDenied || updates.Load() != 0 {
		t.Fatal("unlisted collector called refresh", err)
	}
	if _, err := client.RefreshRootTrust(ctx, &agentv1.RefreshRootTrustRequest{NodeId: "other", SnapshotJson: fresh}); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	if _, err := client.RefreshRootTrust(ctx, &agentv1.RefreshRootTrustRequest{NodeId: source.NodeID, SnapshotJson: make([]byte, MaxRootTrustBytes+1)}); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	if _, err := client.RefreshRootTrust(ctx, request); err != nil {
		t.Fatal("restricted recovery failed", err)
	}
	caps, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{})
	if err != nil || !caps.RootTrustRefresh {
		t.Fatal("fresh policy not live", caps, err)
	}
	if _, err := client.RefreshRootTrust(ctx, request); err != nil {
		t.Fatal("lost-response replay failed", err)
	}
	final, err := old.AuthorizeRootRotation(next, dual.Rotation, dual.MembersSHA256, &dual, strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Final = &final
	finalRaw, _ := json.Marshal(snapshot)
	if _, err := client.RefreshRootTrust(ctx, &agentv1.RefreshRootTrustRequest{NodeId: source.NodeID, SnapshotJson: finalRaw}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("network refresh retired root", err)
	}
	if _, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); err != nil {
		t.Fatal("rejected update disturbed collection", err)
	}
}

func TestRootTrustRefreshDisabledAndUnauthenticated(t *testing.T) {
	s := &Server{Source: testSource(t)}
	if _, err := s.RefreshRootTrust(context.Background(), nil); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
	s.RootTrustRefresher = func(context.Context, *x509.Certificate, []byte) (*agentv1.RefreshRootTrustResponse, error) {
		t.Fatal("unauthenticated invocation")
		return nil, nil
	}
	if _, err := s.RefreshRootTrust(context.Background(), &agentv1.RefreshRootTrustRequest{NodeId: s.Source.NodeID, SnapshotJson: []byte("x")}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
}
