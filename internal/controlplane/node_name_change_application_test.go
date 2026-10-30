package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

// Store-level lifecycle coverage: phase completion below deliberately stands
// in for remote service receipts. It is not SSH/Agent/systemd acceptance.
func nameChangeApplicationFixture(t *testing.T) (nameChangeRegistryFixture, DeploymentJob, []byte) {
	t.Helper()
	f := newNameChangeRegistryFixture(t)
	ctx := context.Background()
	f.admit(t)
	signed, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.request, f.job.Intent, signed.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	leaf, err := provisioningCertificate(signed.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.confirmNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID, leaf); err != nil {
		t.Fatal(err)
	}
	in := f.provisioningFixture.in
	in.Kind, in.Expected, in.IdentityDirectory = "upgrade", f.input.Expected, ""
	if err := f.s.DB.QueryRow(`SELECT id FROM v3_node_certificates WHERE node=$1`, in.Node).Scan(&in.IdentityID); err != nil {
		t.Fatal(err)
	}
	// A name application must use the current node-local identity, not decrypt
	// the obsolete installation seed or silently mint another certificate.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificates SET ciphertext='unavailable-seed-key'::bytea`)
	request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, in)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := f.s.previewLocalDeployment(ctx, f.c, f.t, "admin", request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", "apply-name-target", preview.Token); err != nil {
		t.Fatal(err)
	}
	j := claimDeployment(t, f.s, "name-application-executor")
	return f, j, signed.Certificate
}

func advanceNameApplication(t *testing.T, f nameChangeRegistryFixture, j DeploymentJob, phase string) DeploymentJob {
	t.Helper()
	for j.Phase() != phase {
		if j.Phase() == "complete" {
			t.Fatalf("application completed before %s", phase)
		}
		if j.Phase() == "backup" {
			if err := f.s.ArmDeploymentRecovery(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			j = reloadDeployment(t, f.s, j.ID)
		}
		validateNameApplicationArtifact(t, f, j)
		if err := f.s.CompleteDeploymentPhase(context.Background(), j); err != nil {
			t.Fatal(j.Phase(), err)
		}
		j = reloadDeployment(t, f.s, j.ID)
	}
	return j
}

func validateNameApplicationArtifact(t *testing.T, f nameChangeRegistryFixture, j DeploymentJob) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.c.Executor.ConfigurationDirectory, j.Plan.Request.RuntimeArtifact.SHA256, "node.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.validateDeploymentRuntimeConfiguration(context.Background(), f.c, f.t.release, j, raw); err != nil {
		t.Fatal("production leased-runtime trust validation", j.Phase(), err)
	}
}

func nameApplicationEvent(t *testing.T, s *Store, n Node, l Lease, id string) {
	t.Helper()
	accepted, rejected, err := s.Ingest(context.Background(), n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{eventFixture(id, "modify")}})
	if err != nil || len(accepted) != 1 || accepted[0] != id || len(rejected) != 0 {
		t.Fatal("name transition could not commit event", id, accepted, rejected, err)
	}
}

func TestNodeNameChangeTargetActivationRollbackPreservesEvents(t *testing.T) {
	f, j, certificate := nameChangeApplicationFixture(t)
	ctx := context.Background()
	old := runtimeNodeForTest(t, f.s, j.Node)
	if old.ServerName != f.job.SourceName {
		t.Fatal("queue changed original active name")
	}
	collector, err := f.s.Acquire(ctx, shardResource(old.Shard), "name-application-collector")
	if err != nil {
		t.Fatal(err)
	}
	nameApplicationEvent(t, f.s, old, collector, "before-name-application")
	j = advanceNameApplication(t, f, j, "activate")
	validateNameApplicationArtifact(t, f, j)
	if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, f.s, j.ID)
	target := runtimeNodeForTest(t, f.s, j.Node)
	if target.ServerName != f.job.TargetName || target.Version != j.NodeVersion || target.RuntimeEpoch <= old.RuntimeEpoch || target.AppliedVersion != old.AppliedVersion {
		t.Fatal("target name was not atomically activated, or prematurely applied")
	}
	if err := runtimeFenceForTest(f.s, old, collector); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old-name collection survived activation", err)
	}
	nameApplicationEvent(t, f.s, target, collector, "after-name-application")
	if err := f.s.FailDeployment(ctx, j, "verification-failed"); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, f.s, j.ID)
	if _, err := f.s.RecoverDeployment(ctx, "admin", "rollback-name-target", j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
		t.Fatal(err)
	}
	j = claimDeployment(t, f.s, "name-rollback-executor")
	validateNameApplicationArtifact(t, f, j)
	if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal("restore", err)
	}
	j = reloadDeployment(t, f.s, j.ID)
	validateNameApplicationArtifact(t, f, j)
	restored := runtimeNodeForTest(t, f.s, j.Node)
	if restored.ServerName != old.ServerName || restored.Version != old.Version || restored.RuntimeEpoch <= target.RuntimeEpoch || !bytes.Equal(restored.Config, old.Config) {
		t.Fatal("rollback did not restore original registration with a fresh generation")
	}
	for _, stale := range []Node{old, target} {
		if err := runtimeFenceForTest(f.s, stale, collector); !errors.Is(err, ErrLeaseLost) {
			t.Fatal("stale collection survived rollback", err)
		}
	}
	nameApplicationEvent(t, f.s, restored, collector, "after-name-application") // lost ACK replay
	nameApplicationEvent(t, f.s, restored, collector, "after-name-rollback")
	if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal("verify rollback", err)
	}
	if count := tableCount(t, f.s, "v3_events"); count != 3 {
		t.Fatal("rollback lost or duplicated events", count)
	}
	if count := tableCount(t, f.s, "v3_event_keys"); count != 3 {
		t.Fatal("rollback lost event receipts", count)
	}
	b, _, err := nodepki.ReadIdentity(f.c.Collector.CAFile, f.identity, nodepki.Node, j.Node, time.Now())
	defer clear(b.Key)
	if err != nil || !bytes.Equal(b.Certificate, certificate) {
		t.Fatal("configuration rollback reverted node-local identity", err)
	}
	leaf, _ := provisioningCertificate(b.Certificate)
	if leaf.VerifyHostname(old.ServerName) != nil || leaf.VerifyHostname(target.ServerName) != nil {
		t.Fatal("rollback identity lost name overlap")
	}
	var saved string
	if err := f.s.DB.QueryRow(`SELECT server_name FROM v3_nodes WHERE id=$1`, j.Node).Scan(&saved); err != nil || saved != f.job.TargetName {
		t.Fatal("rollback overwrote saved target", err)
	}
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("configuration application or rollback reissued identity")
	}
}

func TestNodeNameChangeTargetAppliesOnlyAfterFreshTargetEvidence(t *testing.T) {
	f, j, _ := nameChangeApplicationFixture(t)
	ctx := context.Background()
	j = advanceNameApplication(t, f, j, "verify")
	if err := f.s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("target accepted without collector verification", err)
	}
	recordDeploymentReady(t, f.s, j)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_readiness SET server_name=$1`, f.job.SourceName)
	if err := f.s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("source-name evidence accepted for target", err)
	}
	recordDeploymentReady(t, f.s, j)
	if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, f.s, j.ID)
	recordDeploymentReady(t, f.s, j)
	if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	n := runtimeNodeForTest(t, f.s, j.Node)
	if n.ServerName != f.job.TargetName || n.AppliedVersion != j.NodeVersion || reloadDeployment(t, f.s, j.ID).Status != "succeeded" {
		t.Fatal("verified name target not finalized")
	}
	// The immutable preparation is still keyless after the whole coordinator
	// cycle; neither success nor rollback should restore an old private seed.
	raw, err := os.ReadFile(filepath.Join(f.c.Executor.ConfigurationDirectory, j.Plan.Request.RuntimeArtifact.SHA256, "node.json"))
	if err != nil || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("private seed present in managed application", err)
	}
}
