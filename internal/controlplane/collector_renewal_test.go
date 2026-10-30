package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

// Uses actual private on-node identity/CSR persistence; only transport faults
// are injected. Real TLS/RPC verification is exercised separately below.
type renewalRelayClient struct {
	agentv1.AgentServiceClient
	f                                   renewalRegistryFixture
	dropActivation, unsupported, forged bool
	prepared, activated                 int
}

func (r *renewalRelayClient) Capabilities(context.Context, *agentv1.CapabilitiesRequest, ...grpc.CallOption) (*agentv1.CapabilitiesResponse, error) {
	b, record, err := nodepki.ReadIdentity(r.f.c.Collector.CAFile, r.f.identity, nodepki.Node, r.f.in.Request.Node, time.Now())
	clear(b.Key)
	if err != nil {
		return nil, err
	}
	return &agentv1.CapabilitiesResponse{NodeId: record.ID, Protocol: agentv1.ProtocolVersion, MaxEvents: agentv1.MaxEvents, MaxBytes: agentv1.MaxBytes, IdentityRenewal: !r.unsupported, CertificateSha256: record.CertificateSHA256, CertificateNotAfterUnix: record.ExpiresAt.Unix()}, nil
}

func (r *renewalRelayClient) PrepareIdentityRenewal(ctx context.Context, in *agentv1.PrepareIdentityRenewalRequest, _ ...grpc.CallOption) (*agentv1.PreparedIdentityRenewal, error) {
	r.prepared++
	request, err := nodepki.PrepareNodeRenewal(ctx, r.f.c.Collector.CAFile, r.f.identity, in.NodeId, in.CertificateSha256, time.Now())
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(request)
	out := &agentv1.PreparedIdentityRenewal{NodeId: in.NodeId, CertificateSha256: in.CertificateSha256, RequestSha256: request.SHA256(), PublicRequestJson: raw}
	if r.forged {
		out.RequestSha256 = digest([]byte("wrong"))
	}
	return out, nil
}

func (r *renewalRelayClient) ActivateIdentityRenewal(ctx context.Context, in *agentv1.ActivateIdentityRenewalRequest, _ ...grpc.CallOption) (*agentv1.ActivatedIdentityRenewal, error) {
	r.activated++
	trust, err := nodepki.NewTrust(r.f.node.CA, r.f.crl, time.Now())
	if err != nil {
		return nil, err
	}
	record, err := nodepki.ActivateNodeRenewal(ctx, r.f.c.Collector.CAFile, r.f.identity, in.NodeId, in.PreviousCertificateSha256, in.RequestSha256, in.Certificate, time.Now(), func(cert *x509.Certificate) error { return trust.Verify(cert, nodepki.Node, in.NodeId, time.Now()) })
	if err != nil {
		return nil, err
	}
	if r.dropActivation {
		return nil, status.Error(codes.Unavailable, "synthetic response loss")
	}
	return &agentv1.ActivatedIdentityRenewal{NodeId: in.NodeId, RequestSha256: in.RequestSha256, CertificateSha256: record.CertificateSHA256, CertificateNotAfterUnix: record.ExpiresAt.Unix()}, nil
}

func TestNodeRenewalCollectorAndHostResumeAfterLostResponse(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "response-loss"}[lost], func(t *testing.T) {
			f, n, l, _ := renewalRelayFixture(t)
			ctx := context.Background()
			if err := f.s.Release(ctx, f.lease); err != nil {
				t.Fatal(err)
			}
			client := &renewalRelayClient{f: f, dropActivation: lost}
			collector := &Collector{Store: f.s} // No CA key, Vault or issuer config.
			rotated, err := collector.renewNodeIdentity(ctx, n, l, client)
			if err != nil || rotated || client.prepared != 1 || client.activated != 0 {
				t.Fatal("public request was not queued independently", err)
			}
			// Restarted host consumes only committed SQL work and can have a
			// different process identity from the collector's shard lease.
			result, err := f.s.processNodeRenewalQueue(ctx, f.c, "host-issuer-b", 500)
			if err != nil || result.Signed != 1 || result.Failed != 0 {
				t.Fatal("host did not sign queued public request", result, err)
			}
			if err := os.Rename(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key"), filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key.offline")); err != nil {
				t.Fatal(err)
			}
			// A harmless runtime/config update occurs after issuance. New
			// collector rebinds delivery without changing issuance audit/history.
			n = changeRenewalRuntime(t, f, n.ServerName)
			rotated, err = collector.renewNodeIdentity(ctx, n, l, client)
			if lost {
				if err == nil || rotated {
					t.Fatal("lost response unexpectedly acknowledged", err)
				}
				// A new collector process knows nothing about the old call; the
				// authenticated live identity and SQL receipt close the gap.
				collector = &Collector{Store: f.s}
				rotated, err = collector.renewNodeIdentity(ctx, n, l, client)
			}
			if err != nil || !rotated || client.activated != 1 {
				t.Fatal("activation/reconciliation did not request fresh TLS", rotated, err)
			}
			rotated, err = collector.renewNodeIdentity(ctx, n, l, client)
			if err != nil || rotated || client.activated != 1 || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("completed rotation repeated", err)
			}
		})
	}
}

func TestNodeRenewalCollectorCompatibilityAndValidation(t *testing.T) {
	for _, scenario := range []string{"old-node", "bad-response", "lost-shard", "busy"} {
		t.Run(scenario, func(t *testing.T) {
			f, n, l, _ := renewalRelayFixture(t)
			client := &renewalRelayClient{f: f, unsupported: scenario == "old-node", forged: scenario == "bad-response"}
			if scenario == "lost-shard" {
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, l.Resource)
			}
			if scenario == "busy" {
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_jobs(id,node,username,kind,node_version,credential,plan,plan_digest) SELECT 'busy','node-a','admin','upgrade',1,id,'{}','test' FROM v3_credentials WHERE node='node-a' LIMIT 1`)
			}
			rotated, err := (&Collector{Store: f.s}).renewNodeIdentity(context.Background(), n, l, client)
			if rotated || (err == nil) != (scenario == "old-node" || scenario == "busy") || tableCount(t, f.s, "v3_node_renewal_jobs") != 0 {
				t.Fatal("compatibility or invalid relay result", rotated, err)
			}
			if scenario != "bad-response" && client.prepared != 0 {
				t.Fatal("old, busy or unfenced Agent was asked to rotate")
			}
		})
	}
}

func TestNodeRenewalHostBackoffAndLeaseTakeover(t *testing.T) {
	f, n, l, raw := renewalRelayFixture(t)
	ctx := context.Background()
	if _, err := f.s.queueNodeRenewal(ctx, n, l, raw, f.in.LifetimeHours); err != nil {
		t.Fatal(err)
	}
	result, err := f.s.processNodeRenewalQueue(ctx, f.c, "other-host", 500)
	if err != nil || result.Skipped != 1 || result.Signed != 0 {
		t.Fatal("host stole live dedicated signing lease", result, err)
	}
	if err := f.s.Release(ctx, f.lease); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")
	if err := os.Rename(key, key+".offline"); err != nil {
		t.Fatal(err)
	}
	result, err = f.s.processNodeRenewalQueue(ctx, f.c, "other-host", 500)
	if err != nil || result.Failed != 1 || result.Signed != 0 {
		t.Fatal("signing failure not reported", result, err)
	}
	jobs, err := f.s.pendingNodeRenewals(ctx, 500)
	if err != nil || len(jobs) != 0 {
		t.Fatal("bad request immediately retried", err)
	}
	var attempts int
	var reason string
	if err := f.s.DB.QueryRow(`SELECT attempts,last_error FROM v3_node_renewal_jobs`).Scan(&attempts, &reason); err != nil || attempts != 1 || reason == "" || bytes.Contains([]byte(reason), []byte(key)) {
		t.Fatal("retry status not persisted/sanitized", err)
	}
	if err := os.Rename(key+".offline", key); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_renewal_jobs SET next_attempt_at=clock_timestamp()-interval '1 second'`)
	result, err = f.s.processNodeRenewalQueue(ctx, f.c, "third-host", 500)
	if err != nil || result.Signed != 1 {
		t.Fatal("durable retry could not resume on new host", result, err)
	}
	// A stale owner cannot alter retry state after successful takeover.
	j := nodeRenewalJob{Node: n.ID, ParentSHA256: f.in.Request.CertificateSHA256, RequestSHA256: f.in.Request.SHA256(), Snapshot: f.in.Snapshot, RuntimeEpoch: f.in.RuntimeEpoch}
	if err := f.s.deferNodeRenewal(ctx, f.lease, j); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old issuer modified retry state", err)
	}
}

func TestNodeRenewalSingleHostMaintenanceDatabaseBoundary(t *testing.T) {
	store := testStore(t)
	spec, _, _ := prepareSinglePKIFixture(t)
	if err := os.WriteFile(spec.configuration().Database.DSNFile, environmentDSN(t, store), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := maintainSingleNodeRenewals(context.Background(), spec)
	if err != nil || result != (nodeRenewalSigningResult{}) {
		t.Fatal("installed host could not read the initialized queue", result, err)
	}
	c := spec.configuration()
	if c.NodePKI.Enabled || c.NodePKI.AuthorityDirectory != "" {
		t.Fatal("collector configuration gained private signing authority")
	}
	mustHistoryExec(t, store.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;ALTER TABLE v3_node_certificate_renewals DROP COLUMN request_kind;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE v3_node_renewal_jobs;DELETE FROM v3_schema WHERE version>=31`)
	if _, err := maintainSingleNodeRenewals(context.Background(), spec); err == nil {
		t.Fatal("maintenance silently adopted/migrated an old database")
	}
	if version, err := currentSchema(context.Background(), store.DB); err != nil || version != 30 {
		t.Fatal("timer performed an implicit schema migration", err)
	}
}

func TestNodeRenewalHostBadCandidateDoesNotBlockOtherNodes(t *testing.T) {
	f, n, l, raw := renewalRelayFixture(t)
	ctx := context.Background()
	if _, err := f.s.queueNodeRenewal(ctx, n, l, raw, f.in.LifetimeHours); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_renewal_jobs SET request=$1`, []byte("damaged persisted request"))
	next := nodeFixture("node-b")
	if err := f.s.PutNode(ctx, next, 0, 256); err != nil {
		t.Fatal(err)
	}
	f2 := f.provisioningFixture
	f2.in.Node = next.ID
	issued := issuedNode(t, f2, "second-node-seed")
	b, err := f.s.readNodeIdentity(ctx, f.c, f.t.vault, issued.ID, next.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	_, request := renewalPendingForTest(t, f2, b, "second-node-local")
	otherLease, err := f.s.Acquire(ctx, shardResource(next.Shard), "relay-a")
	if err != nil {
		t.Fatal(err)
	}
	otherRaw, _ := json.Marshal(request)
	if _, err := f.s.queueNodeRenewal(ctx, next, otherLease, otherRaw, 72); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Release(ctx, f.lease); err != nil {
		t.Fatal(err)
	}
	result, err := f.s.processNodeRenewalQueue(ctx, f.c, "host-multi-node", 500)
	if err != nil || result.Failed != 1 || result.Signed != 1 {
		t.Fatal("bad candidate blocked independent node", result, err)
	}
	var node string
	if err := f.s.DB.QueryRow(`SELECT node FROM v3_node_certificate_renewals`).Scan(&node); err != nil || node != next.ID {
		t.Fatal("wrong node issued after partial batch failure", err)
	}
}
