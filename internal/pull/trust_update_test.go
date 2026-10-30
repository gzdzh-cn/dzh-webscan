package pull

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestTrustUpdateRecoversExpiredPolicyAndRevokesInFlightLongPoll(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-2 * time.Hour)
	a, err := nodepki.NewAuthority(past, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := a.Export()
	defer clear(ca.Key)
	leaf, _ := a.Issue(nodepki.Node, "node-a", []string{"agent.test"}, past, 24*time.Hour)
	defer clear(leaf.Key)
	one, _ := a.Issue(nodepki.Collector, "one", nil, past, 24*time.Hour)
	defer clear(one.Key)
	two, _ := a.Issue(nodepki.Collector, "two", nil, past, 24*time.Hour)
	defer clear(two.Key)
	stranger, _ := a.Issue(nodepki.Collector, "stranger", nil, past, 24*time.Hour)
	defer clear(stranger.Key)
	seed, _ := a.Revoke(nil, nil, past, time.Hour)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0700)
	caFile, seedFile, state := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "seed.crl"), filepath.Join(dir, "state")
	for p, raw := range map[string][]byte{caFile: ca.CA, seedFile: seed} {
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := nodepki.NewReceiverTrust(caFile, seedFile, state, past); err != nil {
		t.Fatal(err)
	}
	receiver, err := nodepki.NewReceiverTrust(caFile, seedFile, state, now)
	if err != nil {
		t.Fatal(err)
	}
	source := testSource(t)
	var armed atomic.Bool
	entered := make(chan struct{}, 1)
	var updates atomic.Int64
	updater := func(ctx context.Context, cert *x509.Certificate, raw []byte) (*agentv1.UpdateTrustResponse, error) {
		updates.Add(1)
		r, err := receiver.Publish(ctx, cert, raw, time.Now())
		if err != nil {
			return nil, err
		}
		return &agentv1.UpdateTrustResponse{NodeId: source.NodeID, CrlSha256: r.SHA256, CrlNumber: r.Number, NextUpdateUnix: r.NextUpdate.Unix()}, nil
	}
	g := NewServerWithTrustUpdater(source, []string{"spiffe://webscan/collector/one", "spiffe://webscan/collector/two"}, updater, func(cert *x509.Certificate) error {
		if armed.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
		}
		id, err := nodepki.PeerID(cert, nodepki.Collector)
		if err != nil {
			return err
		}
		return receiver.Verify(cert, nodepki.Collector, id, time.Now())
	})
	pair, err := tls.X509KeyPair(leaf.Certificate, leaf.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CA)
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer func() { server.CloseClientConnections(); g.Stop(); server.Close() }()
	connect := func(b nodepki.Bundle) agentv1.AgentServiceClient {
		t.Helper()
		pair, err := tls.X509KeyPair(b.Certificate, b.Key)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.NewClient(server.Listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "agent.test", Certificates: []tls.Certificate{pair}})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return agentv1.NewAgentServiceClient(conn)
	}
	first, second, outsider := connect(one), connect(two), connect(stranger)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := first.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("expired policy allowed ordinary RPC", err)
	}
	current, _ := a.Revoke(seed, nil, now, time.Hour)
	request := &agentv1.UpdateTrustRequest{NodeId: source.NodeID, Crl: current}
	if _, err := outsider.UpdateTrust(ctx, request); status.Code(err) != codes.PermissionDenied || updates.Load() != 0 {
		t.Fatal("unlisted collector invoked updater", err)
	}
	if _, err := first.UpdateTrust(ctx, &agentv1.UpdateTrustRequest{NodeId: "other", Crl: current}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("wrong target accepted", err)
	}
	if _, err := first.UpdateTrust(ctx, &agentv1.UpdateTrustRequest{NodeId: source.NodeID, Crl: make([]byte, agentv1.MaxTrustBytes+1)}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("oversized snapshot accepted", err)
	}
	r, err := first.UpdateTrust(ctx, request)
	if err != nil || r.NodeId != source.NodeID || r.CrlNumber != "2" {
		t.Fatal("expiry recovery", r, err)
	}
	if _, err := first.Capabilities(ctx, &agentv1.CapabilitiesRequest{}); err != nil {
		t.Fatal("fresh snapshot not active", err)
	}
	armed.Store(true)
	done := make(chan error, 1)
	go func() {
		_, err := first.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100, WaitSeconds: 10})
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("long poll did not start")
	}
	armed.Store(false)
	revoked, _ := a.Revoke(current, [][]byte{one.Certificate}, now, time.Hour)
	if _, err := second.UpdateTrust(ctx, &agentv1.UpdateTrustRequest{NodeId: source.NodeID, Crl: revoked}); err != nil {
		t.Fatal(err)
	}
	addEvent(t, source, "after-revocation")
	select {
	case err := <-done:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatal("in-flight long poll leaked to revoked peer", err)
		}
	case <-ctx.Done():
		t.Fatal("revoked long poll did not finish")
	}
	if _, err := first.UpdateTrust(ctx, request); err == nil {
		t.Fatal("revoked caller replayed old trust")
	}
	if _, err := second.UpdateTrust(ctx, request); err == nil {
		t.Fatal("allowed caller lowered trust")
	}
	if _, err := second.UpdateTrust(ctx, &agentv1.UpdateTrustRequest{NodeId: source.NodeID, Crl: []byte("broken")}); err == nil {
		t.Fatal("invalid list accepted")
	}
	batch, err := second.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100})
	if err != nil || len(batch.Events) != 1 {
		t.Fatal("new identity lost unconfirmed event", batch, err)
	}
	stored, _ := os.ReadFile(filepath.Join(state, "ca.crl"))
	original, _ := os.ReadFile(seedFile)
	if !bytes.Equal(stored, revoked) || !bytes.Equal(original, seed) {
		t.Fatal("durable or immutable state changed incorrectly")
	}
}

func TestTrustUpdateDisabledReturnsUnimplemented(t *testing.T) {
	s := &Server{Source: testSource(t)}
	if _, err := s.UpdateTrust(context.Background(), &agentv1.UpdateTrustRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatal(err)
	}
}
