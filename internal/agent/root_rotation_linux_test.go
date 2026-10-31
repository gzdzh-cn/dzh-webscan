//go:build linux

package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/common"
	"webscan/internal/nodepki"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

// Actual Agent HTTP/2 listener and node-local key activation. Root publication
// is explicitly privileged/local here; the durable controller/SSH rollout is
// a separate acceptance gate and is not simulated by this test.
func TestRootRotationActualAgentRenewsAndRestartsWithPendingEvents(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ctx := context.Background()
	old, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	next, err := nodepki.NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
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
	caFile, crlFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "seed.crl")
	for file, raw := range map[string][]byte{caFile: anchor.CA, crlFile: oldCRL} {
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	serverLeaf, err := old.Issue(nodepki.Node, "node-a", []string{"127.0.0.1"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(serverLeaf.Key)
	for file, raw := range map[string][]byte{"identity.crt": serverLeaf.Certificate, "identity.key": serverLeaf.Key} {
		if err := os.WriteFile(filepath.Join(dir, file), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	clientLeaf, err := old.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(clientLeaf.Key)
	clientFile, collectorFloor := filepath.Join(dir, "collector.pem"), filepath.Join(dir, "collector-trust")
	clientRecord, err := nodepki.PublishIdentity(ctx, caFile, clientFile, nodepki.Collector, "collector-a", "", clientLeaf, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.NewPersistentFileTrust(caFile, crlFile, collectorFloor, now); err != nil {
		t.Fatal(err)
	}
	clientLive, err := nodepki.NewLiveIdentityWithRootState(caFile, clientFile, collectorFloor, nodepki.Collector, "collector-a", now)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := testAgent(t)
	identity, nodeFloor := filepath.Join(a.Data, "pki-identity", "active.pem"), filepath.Join(a.Data, "pki-trust")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	a.C["metrics"] = common.Map{"port": port, "tls_enabled": true, "ca_file": caFile, "identity_file": identity, "identity_seed_directory": dir, "allowed_source_ip": "127.0.0.1"}
	a.C["pull"] = common.Map{"collector_identities": []any{"spiffe://webscan/collector/collector-a"}, "revocation_file": crlFile, "revocation_state_directory": nodeFloor, "revocation_updates": true, "identity_renewal": true}
	a.Pull, err = pull.New(a.DB, "node-a", "v3-root-test", &a.writeMu)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(`INSERT INTO events(id,payload,created) VALUES('pending-root-rollover','{"event_id":"pending-root-rollover","node_id":"node-a","operation":"modify"}',1)`); err != nil {
		t.Fatal(err)
	}
	var stop context.CancelFunc
	start := func() {
		t.Helper()
		var child context.Context
		child, stop = context.WithCancel(ctx)
		if err := a.startMetrics(child); err != nil {
			t.Fatal(err)
		}
	}
	start()
	defer func() { stop(); a.worker.Wait() }()
	connect := func() *grpc.ClientConn {
		t.Helper()
		pool, err := nodepki.RootPoolFromState(caFile, collectorFloor, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1", RootCAs: pool, GetClientCertificate: clientLive.GetClientCertificate})))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	call := func(conn *grpc.ClientConn) (*agentv1.CapabilitiesResponse, error) {
		op, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return agentv1.NewAgentServiceClient(conn).Capabilities(op, &agentv1.CapabilitiesRequest{})
	}
	before := connect()
	initial, err := call(before)
	if err != nil || !initial.IdentityRenewal || !initial.RootTrustRefresh {
		t.Fatal("initial Agent capabilities unavailable", err)
	}
	dual, err := old.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := nodepki.RootSetSnapshot{Format: 1, Dual: dual, OldCRL: oldCRL, NewCRL: newCRL}
	publish := func() {
		t.Helper()
		raw, _ := json.Marshal(snapshot)
		for _, floor := range []string{nodeFloor, collectorFloor} {
			if _, err := nodepki.PublishRootSet(ctx, floor, anchor.CA, raw, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	publish()
	issuer := filepath.Join(dir, "successor")
	private, err := next.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private.Key)
	if err := nodepki.SeedAuthority(ctx, issuer, private, newCRL, now); err != nil {
		t.Fatal(err)
	}
	rotate := func(file, floor, role, id, expected string) nodepki.IdentityRecord {
		t.Helper()
		request, err := nodepki.PrepareRootIdentity(ctx, caFile, file, floor, role, id, nodepki.RootAuthorizationSHA256(dual), expected, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var certificate []byte
		if err := nodepki.SignRootIdentityRegistered(ctx, issuer, anchor.CA, snapshot, request, time.Now(), 2*time.Hour, func(b nodepki.Bundle) error { certificate = append([]byte{}, b.Certificate...); return nil }); err != nil {
			t.Fatal(err)
		}
		record, err := nodepki.ActivateRootIdentity(ctx, caFile, file, floor, role, id, nodepki.RootAuthorizationSHA256(dual), expected, request.SHA256(), certificate, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	rotated := rotate(identity, nodeFloor, nodepki.Node, "node-a", initial.CertificateSha256)
	_ = rotate(clientFile, collectorFloor, nodepki.Collector, "collector-a", clientRecord.CertificateSHA256)
	// Live readers intentionally check at most once/second.
	time.Sleep(1100 * time.Millisecond)
	after := connect()
	if got, err := call(after); err != nil || got.CertificateSha256 != rotated.CertificateSHA256 {
		t.Fatal("fresh mTLS did not observe successor leaf", err)
	}
	final, err := old.AuthorizeRootRotation(next, dual.Rotation, dual.MembersSHA256, &dual, strings.Repeat("c", 64), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Final = &final
	publish()
	time.Sleep(1100 * time.Millisecond)
	if _, err := call(before); err == nil {
		t.Fatal("old-root collector retained ordinary RPC access on existing connection")
	}
	rpc := agentv1.NewAgentServiceClient(after)
	prepared, err := rpc.PrepareIdentityRenewal(ctx, &agentv1.PrepareIdentityRenewalRequest{NodeId: "node-a", CertificateSha256: rotated.CertificateSHA256})
	if err != nil {
		t.Fatal("actual Agent could not prepare renewal after finalization", err)
	}
	request, err := nodepki.ParseNodeRenewalRequest(prepared.PublicRequestJson)
	if err != nil {
		t.Fatal(err)
	}
	var renewed []byte
	if err := nodepki.SignNodeRenewalRegistered(ctx, issuer, request, time.Now(), 3*time.Hour, func(b nodepki.Bundle, _ []byte) error { renewed = append([]byte{}, b.Certificate...); return nil }); err != nil {
		t.Fatal(err)
	}
	activated, err := rpc.ActivateIdentityRenewal(ctx, &agentv1.ActivateIdentityRenewalRequest{NodeId: "node-a", PreviousCertificateSha256: rotated.CertificateSHA256, RequestSha256: request.SHA256(), Certificate: renewed})
	if err != nil || activated.CertificateSha256 == rotated.CertificateSHA256 {
		t.Fatal("actual Agent could not activate successor renewal", err)
	}
	stop()
	a.worker.Wait()
	start()
	restarted := connect()
	if got, err := call(restarted); err != nil || got.CertificateSha256 != activated.CertificateSha256 {
		t.Fatal("restart reseeded old-root identity or lost current renewal", err)
	}
	batch, err := agentv1.NewAgentServiceClient(restarted).FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100})
	if err != nil || len(batch.Events) != 1 || batch.Events[0].Id != "pending-root-rollover" {
		t.Fatal("unconfirmed event lost across root rollout/renewal/restart", err)
	}
}
