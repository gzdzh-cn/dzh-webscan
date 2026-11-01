package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"webscan/internal/nodeops"
)

// Real PostgreSQL, Vault, immutable source and task journals; service receipts
// are explicit synthetic evidence. Kernel acceptance exercises actual services.
func uninstallControllerFixture(t *testing.T) (provisioningFixture, DeploymentJob) {
	t.Helper()
	f := localProvisioningFixture(t)
	request, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.s.queueLocalDeployment(context.Background(), f.c, f.t, "admin", "source-install", request)
	if err != nil {
		t.Fatal(err)
	}
	var created struct{ ID string }
	if json.Unmarshal(raw, &created) != nil {
		t.Fatal("invalid fixture receipt")
	}
	source := finishRecoverySource(t, f, reloadDeployment(t, f.s, created.ID))
	return f, source
}

func queueControllerUninstall(t *testing.T, f provisioningFixture, key string) DeploymentJob {
	t.Helper()
	ctx := context.Background()
	n, err := scanNode(f.s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, f.in.Node))
	if err != nil {
		t.Fatal(err)
	}
	source, credential, _, _, err := f.s.webUninstallSource(ctx, f.t.vault, n)
	if err != nil {
		t.Fatal("actual source", err)
	}
	request, err := f.s.prepareUninstallDeployment(ctx, f.c, f.t, n, source, credential)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", key, request)
	if err != nil {
		t.Fatal("queue uninstall", err)
	}
	var created struct{ ID string }
	if json.Unmarshal(raw, &created) != nil {
		t.Fatal("invalid uninstall receipt")
	}
	return reloadDeployment(t, f.s, created.ID)
}
func advanceControllerUninstall(t *testing.T, f provisioningFixture, j DeploymentJob) DeploymentJob {
	t.Helper()
	ctx := context.Background()
	if j.Status == "queued" {
		j = claimDeployment(t, f.s, "uninstall-fixture")
	}
	for j.Phase() != "complete" {
		if j.Phase() == "backup" {
			if err := f.s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal("arm", err)
			}
			j = reloadDeployment(t, f.s, j.ID)
		}
		p := checkpoint(j, "complete")
		if j.Phase() == "finalize" {
			p.Removal = &nodeops.RemovalEvidence{CaptureSHA256: strings.Repeat("a", 64), IntentSHA256: strings.Repeat("b", 64), PreservedSHA256: strings.Repeat("c", 64), TombstoneSHA256: strings.Repeat("d", 64)}
		}
		if j.Phase() == "verify-rollback" {
			p.Restoration = &nodeops.RestorationEvidence{CaptureSHA256: strings.Repeat("a", 64), IntentSHA256: strings.Repeat("b", 64), PreservedSHA256: strings.Repeat("c", 64), ActiveSHA256: strings.Repeat("e", 64), ObjectSHA256: strings.Repeat("f", 64)}
		}
		if err := f.s.completeDeploymentPhase(ctx, j, f.t.vault, &p); err != nil {
			t.Fatalf("phase %s: %v", j.Phase(), err)
		}
		j = reloadDeployment(t, f.s, j.ID)
	}
	return j
}
func controllerLifecycle(t *testing.T, f provisioningFixture) *deploymentLifecycleState {
	t.Helper()
	tx, err := f.s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	state, err := readNodeLifecycleTx(context.Background(), tx, f.t.vault, f.in.Node)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func TestUninstallControllerCompletionRestorationAndRepeatedRemoval(t *testing.T) {
	f, source := uninstallControllerFixture(t)
	queued := queueControllerUninstall(t, f, "uninstall-one")
	done := advanceControllerUninstall(t, f, queued)
	if done.Status != "succeeded" || done.RecoveryRequired {
		t.Fatal("removal not completed", done.Status)
	}
	state := controllerLifecycle(t, f)
	if state == nil || state.State != "uninstalled" || state.Source.Job != source.ID {
		t.Fatal("unconfirmed lifecycle", state)
	}
	var runtime, applied int64
	if err := f.s.DB.QueryRow(`SELECT applied_version,(SELECT count(*) FROM v3_node_runtime WHERE node=$1) FROM v3_nodes WHERE id=$1`, done.Node).Scan(&applied, &runtime); err != nil || applied != 0 || runtime != 0 {
		t.Fatal("collection not suspended", applied, runtime, err)
	}
	raw, err := f.s.recoverDeploymentWithTrust(context.Background(), "admin", "restore-successful-uninstall", done.ID, "rollback", done.PlanDigest, done.LogCursor, true, f.t.vault)
	if err != nil {
		t.Fatal("explicit restore", err)
	}
	replay, err := f.s.recoverDeploymentWithTrust(context.Background(), "admin", "restore-successful-uninstall", done.ID, "rollback", done.PlanDigest, done.LogCursor, true, f.t.vault)
	if err != nil || !sameJSON(raw, replay) {
		t.Fatal("restore replay", err)
	}
	restored := advanceControllerUninstall(t, f, reloadDeployment(t, f.s, done.ID))
	if restored.Status != "rolled_back" {
		t.Fatal("restore not confirmed", restored.Status)
	}
	state = controllerLifecycle(t, f)
	if state == nil || state.State != "installed" || state.Source.Restoration == nil || state.Source.Restoration.Job != done.ID {
		t.Fatal("new actual object not bound", state)
	}
	again := queueControllerUninstall(t, f, "uninstall-two")
	if again.Plan.Uninstall.Source.Restoration == nil || uninstallReference(again.Plan.Uninstall.Source).RestorationSHA256 == "" {
		t.Fatal("old active identity reused")
	}
	if err := f.s.DB.QueryRow(`SELECT applied_version FROM v3_nodes WHERE id=$1`, done.Node).Scan(&applied); err != nil || applied != source.NodeVersion {
		t.Fatal("old applied version not restored", err)
	}
}
func TestUninstallControllerSuccessfulRestoreRequiresCurrentSource(t *testing.T) {
	for _, damage := range []string{"changed-config", "changed-lifecycle", "missing-backup", "forged-removal", "wrong-vault", "non-admin"} {
		t.Run(damage, func(t *testing.T) {
			f, _ := uninstallControllerFixture(t)
			done := advanceControllerUninstall(t, f, queueControllerUninstall(t, f, "uninstall"))
			vault, admin := f.t.vault, true
			switch damage {
			case "changed-config":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET version=version+1 WHERE id=$1`, done.Node)
			case "changed-lifecycle":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_lifecycle SET proof=repeat('f',64)`)
			case "missing-backup":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_configuration_backups WHERE id=$1`, done.Plan.BeforeBackup)
			case "forged-removal":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_lifecycle_receipts SET evidence=evidence||'{"tombstone_sha256":"forged"}'::jsonb WHERE kind='removal'`)
			case "wrong-vault":
				vault, _ = testVault(t)
			case "non-admin":
				admin = false
			}
			_, err := f.s.recoverDeploymentWithTrust(context.Background(), "admin", "blocked-restore", done.ID, "rollback", done.PlanDigest, done.LogCursor, admin, vault)
			if err == nil {
				t.Fatal("unsafe terminal restore accepted")
			}
			if got := reloadDeployment(t, f.s, done.ID); got.Status != "succeeded" || got.RecoveryRequired {
				t.Fatal("failed restore changed task", got.Status)
			}
		})
	}
}
func TestLifecycleReceiptReplayAuthenticatesExistingProof(t *testing.T) {
	f, _ := uninstallControllerFixture(t)
	done := advanceControllerUninstall(t, f, queueControllerUninstall(t, f, "uninstall"))
	tx, err := f.s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var evidence nodeops.RemovalEvidence
	if err := readLifecycleReceiptTx(context.Background(), tx, f.t.vault, done, "removal", &evidence); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`UPDATE v3_deployment_lifecycle_receipts SET proof=repeat('0',64)`); err != nil {
		t.Fatal(err)
	}
	if err := recordLifecycleReceiptTx(context.Background(), tx, f.t.vault, done, "removal", &evidence); err == nil {
		t.Fatal("identical but unauthenticated replay accepted")
	}
}
func TestUninstallArmingFencesOldCollectorAndRestoresExactEpoch(t *testing.T) {
	f, _ := uninstallControllerFixture(t)
	queued := queueControllerUninstall(t, f, "uninstall")
	j := claimDeployment(t, f.s, "uninstall-fence")
	if j.ID != queued.ID {
		t.Fatal("wrong claim")
	}
	for j.Phase() != "backup" {
		p := checkpoint(j, "complete")
		if err := f.s.completeDeploymentPhase(context.Background(), j, f.t.vault, &p); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, f.s, j.ID)
	}
	if err := f.s.ArmDeploymentRecovery(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, f.s, j.ID)
	if _, err := f.s.uninstallRequest(context.Background(), f.t.vault, j, "inspect"); err != nil {
		t.Fatal("paused runtime refused", err)
	}
	if err := f.s.FailDeployment(context.Background(), j, "remote-unavailable"); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, f.s, j.ID)
	if _, err := f.s.recoverDeploymentWithTrust(context.Background(), "admin", "rollback-interrupted", j.ID, "rollback", j.PlanDigest, j.LogCursor, true, f.t.vault); err != nil {
		t.Fatal(err)
	}
	done := advanceControllerUninstall(t, f, reloadDeployment(t, f.s, j.ID))
	state := controllerLifecycle(t, f)
	var generation int64
	if err := f.s.DB.QueryRow(`SELECT runtime_generation FROM v3_nodes WHERE id=$1`, j.Node).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if done.Status != "rolled_back" || state.RuntimeGeneration != generation || generation != j.Plan.PreviousRuntime.Epoch+2 {
		t.Fatal("restoration fence mismatch", done.Status, state.RuntimeGeneration, generation)
	}
	var snapshot string
	if err := f.s.DB.QueryRow(`SELECT snapshot FROM v3_node_runtime WHERE node=$1`, j.Node).Scan(&snapshot); err == sql.ErrNoRows || err != nil || snapshot != j.Plan.PreviousRuntime.Snapshot {
		t.Fatal("lost original registration", err)
	}
}

func TestUninstallControllerReinstallAndFailedReinstallKeepTombstone(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "rolled-back"}[rollback], func(t *testing.T) {
			f, _ := uninstallControllerFixture(t)
			removed := advanceControllerUninstall(t, f, queueControllerUninstall(t, f, "uninstall"))
			ctx := context.Background()
			request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "reinstall", request)
			if err != nil {
				t.Fatal("reinstall", err)
			}
			var created struct{ ID string }
			if json.Unmarshal(raw, &created) != nil {
				t.Fatal("bad receipt")
			}
			queued := reloadDeployment(t, f.s, created.ID)
			if queued.Plan.Reinstall == nil || queued.Plan.PreviousLifecycle == nil || queued.Plan.Reinstall.SourceJob != removed.ID {
				t.Fatal("tombstone not bound")
			}
			if err := f.s.checkLifecycleAuthorization(ctx, f.t.vault, queued); err != nil {
				t.Fatal("authorization missing", err)
			}
			if !rollback {
				done := finishRecoverySource(t, f, queued)
				state := controllerLifecycle(t, f)
				if state.State != "installed" || state.Source.Job != done.ID || state.Source.Reinstall == nil {
					t.Fatal("reinstall installation not bound", state)
				}
				queueControllerUninstall(t, f, "uninstall-reinstalled")
				return
			}
			j := claimDeployment(t, f.s, "failed-reinstall")
			for j.Phase() != "backup" {
				if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
					t.Fatal(err)
				}
				j = reloadDeployment(t, f.s, j.ID)
			}
			if err := f.s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
			if err := f.s.FailDeployment(ctx, j, "backup-failed"); err != nil {
				t.Fatal(err)
			}
			j = reloadDeployment(t, f.s, j.ID)
			if _, err := f.s.RecoverDeployment(ctx, "admin", "rollback-reinstall", j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
				t.Fatal(err)
			}
			j = claimDeployment(t, f.s, "restore-failed-reinstall")
			for j.Phase() != "complete" {
				p := checkpoint(j, "complete")
				if err := f.s.completeDeploymentPhase(ctx, j, f.t.vault, &p); err != nil {
					t.Fatal("reinstall rollback", err)
				}
				j = reloadDeployment(t, f.s, j.ID)
			}
			state := controllerLifecycle(t, f)
			if state.State != "uninstalled" || state.Job != removed.ID {
				t.Fatal("failed reinstall invented installation", state)
			}
			if _, err := f.s.recoverDeploymentWithTrust(ctx, "admin", "stale-removal-restore", removed.ID, "rollback", removed.PlanDigest, removed.LogCursor, true, f.t.vault); err == nil {
				t.Fatal("original uninstall restore accepted after an intervening reinstall")
			}
			if got := reloadDeployment(t, f.s, removed.ID); got.Status != "succeeded" || got.RecoveryRequired {
				t.Fatal("stale restore changed original removal")
			}
			request, err = f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "reinstall-again", request); err != nil {
				t.Fatal("failed reinstall discarded tombstone", err)
			}
		})
	}
}
