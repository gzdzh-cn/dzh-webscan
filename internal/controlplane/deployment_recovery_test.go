package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodeops"
)

// PostgreSQL, archives, immutable plans, SSH and task fences are real. Remote
// installation hashes and service actions in this file are explicit fixtures.
func finishRecoverySource(t *testing.T, f provisioningFixture, queued DeploymentJob) DeploymentJob {
	t.Helper()
	ctx := context.Background()
	j := claimDeployment(t, f.s, "recovery-source-executor")
	if j.ID != queued.ID {
		t.Fatal("unexpected job")
	}
	for j.Phase() != "finalize" {
		if j.Phase() == "backup" {
			if err := f.s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
		}
		if j.Phase() == "verify" {
			recordDeploymentReady(t, f.s, j)
		}
		if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, f.s, j.ID)
	}
	recordDeploymentReady(t, f.s, j)
	runtime := &SSHNodeRuntime{Store: f.s, Vault: f.t.vault, Release: f.t.release, Lifecycle: true, ConfigurationDirectory: f.c.Executor.ConfigurationDirectory}
	r, err := runtime.request(ctx, j, "inspect")
	if err != nil {
		t.Fatal(err)
	}
	p := checkpoint(j, "complete")
	p.Spec, p.Installation = &r.Spec, &nodeops.InstallationEvidence{CaptureSHA256: strings.Repeat("c", 64), ActiveSHA256: strings.Repeat("d", 64)}
	if err = f.s.completeDeploymentPhase(ctx, j, f.t.vault, &p); err != nil {
		t.Fatal(err)
	}
	return reloadDeployment(t, f.s, j.ID)
}

func queueRecoverySuccessor(t *testing.T, f provisioningFixture, key string) DeploymentJob {
	t.Helper()
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET version=version+1 WHERE id=$1`, f.in.Node)
	var version int64
	if err := f.s.DB.QueryRow(`SELECT version FROM v3_nodes WHERE id=$1`, f.in.Node).Scan(&version); err != nil {
		t.Fatal(err)
	}
	in := f.in
	in.Expected, in.Kind = version, "upgrade"
	request, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.s.queueLocalDeployment(context.Background(), f.c, f.t, "admin", key, request)
	if err != nil {
		t.Fatal(err)
	}
	var response struct{ ID string }
	if err = json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	return reloadDeployment(t, f.s, response.ID)
}

func rollbackRecoveryHead(t *testing.T, f provisioningFixture, queued DeploymentJob) DeploymentJob {
	t.Helper()
	ctx := context.Background()
	j := claimDeployment(t, f.s, "recovery-head-executor")
	if j.ID != queued.ID {
		t.Fatal("unexpected head")
	}
	for j.Phase() != "verify" {
		if j.Phase() == "backup" {
			if err := f.s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, f.s, j.ID)
	}
	if err := f.s.FailDeployment(ctx, j, "interrupted"); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, f.s, j.ID)
	if _, err := f.s.RecoverDeployment(ctx, "admin", "rollback-"+j.ID, j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
		t.Fatal(err)
	}
	j = claimDeployment(t, f.s, "recovery-head-rollback")
	if err := (&DeploymentRunner{Store: f.s, Runtime: &fakeDeploymentRuntime{}, Vault: f.t.vault}).Execute(ctx, j); err != nil {
		t.Fatal(err)
	}
	return reloadDeployment(t, f.s, j.ID)
}

func historicalRecoveryFixture(t *testing.T) (provisioningFixture, DeploymentJob, DeploymentJob, deploymentRecoveryInput) {
	t.Helper()
	f, j := deploymentConfigurationFixture(t, false)
	source := finishRecoverySource(t, f, j)
	head := rollbackRecoveryHead(t, f, queueRecoverySuccessor(t, f, "successor-for-recovery"))
	// A pending saved draft must survive historical recovery unchanged.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET version=version+1,config='{"private":{"token":"synthetic-pending-draft"}}' WHERE id=$1`, j.Node)
	in := deploymentRecoveryInput{Node: j.Node, Expected: head.NodeVersion + 1, Credential: f.in.Credential, Source: source.ID, SourceDigest: source.PlanDigest, Head: head.ID, HeadDigest: head.PlanDigest}
	return f, source, head, in
}

func queuedHistoricalRecovery(t *testing.T, f provisioningFixture, in deploymentRecoveryInput, key string) DeploymentJob {
	t.Helper()
	raw, err := f.s.queueLocalDeploymentRecovery(context.Background(), f.c, f.t, "admin", key, in)
	if err != nil {
		t.Fatal(err)
	}
	var response struct{ ID string }
	if err = json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	return reloadDeployment(t, f.s, response.ID)
}

func TestHistoricalRecoveryNewIdentityPreservesDraftAndMonotonicGeneration(t *testing.T) {
	f, source, head, in := historicalRecoveryFixture(t)
	ctx := context.Background()
	j := queuedHistoricalRecovery(t, f, in, "recover-source")
	if j.ID == source.ID || j.ID == head.ID || j.Direction != "rollback" || !j.RecoveryRequired || j.Plan.BeforeBackup == "" || deploymentBackupPinCount(t, f.s, j, "rollback") != 1 {
		t.Fatal("missing new recovery identity or archive pin")
	}
	if replay := queuedHistoricalRecovery(t, f, in, "recover-source"); replay.ID != j.ID {
		t.Fatal("duplicate request created another task")
	}
	if err := j.Plan.Request.validate(); err == nil {
		t.Fatal("internal recovery kind became a public deployment request")
	}
	if _, err := f.s.queueLocalDeploymentRecovery(ctx, f.c, f.t, "viewer", "replay-not-admin", in); err == nil {
		t.Fatal("non-administrator queued recovery")
	}
	j = claimDeployment(t, f.s, "historical-recovery-executor")
	if err := f.s.CompleteDeploymentPhase(ctx, j); err == nil {
		t.Fatal("recovery checkpoint completed without authenticated evidence")
	}
	// Restoration does not need the source's certificate/configuration package.
	if err := os.RemoveAll(filepath.Join(f.c.Executor.ConfigurationDirectory, source.Plan.Request.RuntimeArtifact.SHA256)); err != nil {
		t.Fatal(err)
	}
	runtime := &SSHNodeRuntime{Store: f.s, Vault: f.t.vault, Release: f.t.release, Lifecycle: true}
	r, err := runtime.request(ctx, j, "inspect")
	if err != nil || r.Recovery == nil || r.Recovery.SourceJob != source.ID || r.Recovery.HeadJob != head.ID || r.Spec.ConfigVersion != source.NodeVersion {
		t.Fatal("source-bound restore request unavailable without old package", err)
	}
	fake := &fakeDeploymentRuntime{}
	if err = (&DeploymentRunner{Store: f.s, Vault: f.t.vault, Runtime: fake}).Execute(ctx, j); err != nil {
		t.Fatal(err)
	}
	finished := reloadDeployment(t, f.s, j.ID)
	if finished.Status != "rolled_back" || finished.RecoveryRequired || deploymentBackupPinCount(t, f.s, finished, "") != 0 {
		t.Fatal("recovery terminal state or archive pin incorrect")
	}
	var version, applied, generation int64
	var config []byte
	if err = f.s.DB.QueryRow(`SELECT version,applied_version,runtime_generation,config FROM v3_nodes WHERE id=$1`, in.Node).Scan(&version, &applied, &generation, &config); err != nil || version != in.Expected || applied != source.Plan.Node.AppliedVersion || generation != j.Plan.Recovery.From.Epoch+1 || !bytes.Contains(config, []byte("synthetic-pending-draft")) {
		t.Fatal("draft/applied version/generation corrupted", version, applied, generation, err)
	}
	if old := reloadDeployment(t, f.s, source.ID); old.Status != "succeeded" || old.Epoch != source.Epoch || old.Direction != "forward" {
		t.Fatal("retired source job was reopened")
	}
	backup, err := f.s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	tx, err := restored.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = readDeploymentRecoveryTx(ctx, tx, f.t.vault, finished, map[string]bool{}); err != nil {
		t.Fatal("backup lost authenticated recovery chain", err)
	}
}

func TestHistoricalRecoveryRejectsUntrustedOrStaleSourcesAtomically(t *testing.T) {
	for _, damage := range []string{"source-digest", "head-digest", "head-status", "head-not-activated", "source-proof", "head-runtime", "runtime-generation", "wrong-key", "disabled", "version", "archive", "binding-write"} {
		t.Run(damage, func(t *testing.T) {
			f, source, head, in := historicalRecoveryFixture(t)
			switch damage {
			case "source-digest":
				in.SourceDigest = strings.Repeat("e", 64)
			case "head-digest":
				in.HeadDigest = strings.Repeat("e", 64)
			case "head-status":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET status='succeeded' WHERE id=$1`, head.ID)
			case "head-not-activated":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET step=2 WHERE id=$1`, head.ID)
			case "source-proof":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_installations SET proof=repeat('e',64) WHERE job=$1`, source.ID)
			case "head-runtime":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_runtime SET delivered_version=0`)
			case "runtime-generation":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1`)
			case "wrong-key":
				f.t.vault, _ = testVault(t)
			case "disabled":
				f.c.Executor.Enabled = false
			case "version":
				in.Expected++
			case "archive":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_recovery_archive() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic';END$$;CREATE TRIGGER fail_recovery_archive BEFORE INSERT ON v3_configuration_backup_parts FOR EACH ROW EXECUTE FUNCTION reject_recovery_archive()`)
			case "binding-write":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_recovery_binding() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic';END$$;CREATE TRIGGER fail_recovery_binding BEFORE INSERT ON v3_deployment_recoveries FOR EACH ROW EXECUTE FUNCTION reject_recovery_binding()`)
			}
			before := map[string]int{}
			for _, table := range []string{"v3_deployment_jobs", "v3_configuration_backups", "v3_configuration_backup_parts", "v3_configuration_backup_pins", "v3_requests", "v3_audit"} {
				before[table] = tableCount(t, f.s, table)
			}
			if _, err := f.s.queueLocalDeploymentRecovery(context.Background(), f.c, f.t, "admin", "invalid-recovery", in); err == nil {
				t.Fatal("invalid recovery queued")
			}
			for table, count := range before {
				if tableCount(t, f.s, table) != count {
					t.Fatal("partial recovery transaction", table)
				}
			}
			if tableCount(t, f.s, "v3_deployment_recoveries") != 0 {
				t.Fatal("partial binding persisted")
			}
		})
	}
}

func TestHistoricalRecoveryAuthorizationRecheckedBeforeRemoteAndCompletion(t *testing.T) {
	for _, damage := range []string{"binding", "source", "snapshot", "key", "epoch"} {
		t.Run(damage, func(t *testing.T) {
			f, source, _, in := historicalRecoveryFixture(t)
			queuedHistoricalRecovery(t, f, in, "authenticated-recovery")
			j := claimDeployment(t, f.s, "recovery-authorization-executor")
			v := f.t.vault
			switch damage {
			case "binding":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_recoveries SET proof=repeat('e',64)`)
			case "source":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_installations SET active_sha256=repeat('e',64) WHERE job=$1`, source.ID)
			case "snapshot":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET name='drift' WHERE id=$1`, source.Plan.TargetRuntime)
			case "key":
				v, _ = testVault(t)
			case "epoch":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1;UPDATE v3_node_runtime SET epoch=epoch+1`)
			}
			proof := checkpoint(j, "complete")
			if err := f.s.completeDeploymentPhase(context.Background(), j, v, &proof); err == nil {
				t.Fatal("untrusted completion committed")
			}
			fake := &fakeDeploymentRuntime{}
			runtime := &archiveCheckedRuntime{DeploymentRuntime: fake}
			if err := (&DeploymentRunner{Store: f.s, Vault: v, Runtime: runtime}).Execute(context.Background(), j); err == nil || len(runtime.inspected) != 0 || len(fake.calls) != 0 {
				t.Fatal("untrusted recovery reached remote service", err)
			}
			if deploymentBackupPinCount(t, f.s, reloadDeployment(t, f.s, j.ID), "rollback") != 1 {
				t.Fatal("failed recovery released rollback archive")
			}
		})
	}
}

func TestHistoricalRecoverySSHUsesSourceSpecAndCurrentHelperAfterLostResponse(t *testing.T) {
	f, source, _, in := historicalRecoveryFixture(t)
	ctx := context.Background()
	var mu sync.Mutex
	dropped, applied, uploads := false, false, 0
	var invalid []string
	remote := startNodeRPC(t, func(command string, ch ssh.Channel) {
		if strings.Contains(command, "artifact-missing") {
			io.WriteString(ch, "artifact-missing\n")
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(ch, nodeops.MaxRequestBytes+1))
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(command, "helper-ready") {
			uploads++
			if digest(raw) != f.t.release.manifest.Helper.SHA256 {
				invalid = append(invalid, "untrusted helper")
			}
			io.WriteString(ch, "helper-ready\n")
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		}
		var r nodeops.Request
		if json.Unmarshal(raw, &r) != nil || r.Validate() != nil || r.Recovery == nil || r.Recovery.SourceJob != source.ID || r.Spec.ConfigVersion != source.NodeVersion || r.Spec.ConfigSourceSHA256 != source.Plan.ConfigDigest || !strings.Contains(command, f.t.release.manifest.Helper.SHA256) {
			invalid = append(invalid, "unbound restoration")
			return
		}
		state := "complete"
		if r.Phase == "restore" && !applied {
			state = "absent"
		}
		if r.Operation == "apply" {
			if applied {
				invalid = append(invalid, "repeated service action")
			}
			applied, state = true, "complete"
			if !dropped {
				dropped = true
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
				return
			}
		}
		finishRPC(ch, nodeops.Result{Protocol: r.Protocol, Job: r.Job, Node: r.Node, PlanDigest: r.PlanDigest, Epoch: r.Epoch, Phase: r.Phase, State: state, Code: "ok"})
	})
	credential, err := f.s.AddCredential(ctx, f.t.vault, "admin", "recovery-ssh-credential", in.Node, in.Expected, remote.credential)
	if err != nil {
		t.Fatal(err)
	}
	var id struct{ ID string }
	if err = json.Unmarshal(credential, &id); err != nil {
		t.Fatal(err)
	}
	in.Credential = id.ID
	queuedHistoricalRecovery(t, f, in, "ssh-recovery")
	j := claimDeployment(t, f.s, "ssh-recovery-first")
	if err := os.RemoveAll(f.c.Executor.ConfigurationDirectory); err != nil {
		t.Fatal(err)
	}
	runtime := &SSHNodeRuntime{Store: f.s, Vault: f.t.vault, Release: f.t.release, Lifecycle: true, LocalHelper: f.c.DeploymentTrust.HelperFile, ValidateConfiguration: func(context.Context, nodeconfig.Material) error {
		t.Error("restoration parsed expired source configuration")
		return errProvisioning
	}}
	runner := &DeploymentRunner{Store: f.s, Vault: f.t.vault, Runtime: runtime}
	if err := runner.Execute(ctx, j); err == nil {
		t.Fatal("lost response ignored")
	}
	failed := reloadDeployment(t, f.s, j.ID)
	if !failed.CanRecover() || failed.RollbackStep != 0 {
		t.Fatal("response loss did not preserve recovery obligation")
	}
	if _, err := f.s.RecoverDeployment(ctx, "admin", "resume-historical-ssh", j.ID, "rollback", failed.PlanDigest, failed.LogCursor); err != nil {
		t.Fatal(err)
	}
	next := claimDeployment(t, f.s, "ssh-recovery-successor")
	if next.Epoch <= j.Epoch {
		t.Fatal("takeover did not advance fence")
	}
	if err := runner.Execute(ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := f.s.completeDeploymentPhase(ctx, j, f.t.vault, nil); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old owner completed recovery", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !dropped || !applied || uploads != 2 || len(invalid) != 0 || reloadDeployment(t, f.s, j.ID).Status != "rolled_back" {
		t.Fatal("SSH restoration evidence", dropped, applied, uploads, invalid)
	}
}

func TestHistoricalRecoveryMultipleAncestorsUseFreshRuntimeGeneration(t *testing.T) {
	f, queued := deploymentConfigurationFixture(t, false)
	first := finishRecoverySource(t, f, queued)
	second := finishRecoverySource(t, f, queueRecoverySuccessor(t, f, "second-source"))
	head := rollbackRecoveryHead(t, f, queueRecoverySuccessor(t, f, "third-head"))
	ctx := context.Background()
	for _, source := range []DeploymentJob{second, first} {
		var version int64
		if err := f.s.DB.QueryRow(`SELECT version FROM v3_nodes WHERE id=$1`, source.Node).Scan(&version); err != nil {
			t.Fatal(err)
		}
		in := deploymentRecoveryInput{Node: source.Node, Expected: version, Credential: f.in.Credential, Source: source.ID, SourceDigest: source.PlanDigest, Head: head.ID, HeadDigest: head.PlanDigest}
		queuedHistoricalRecovery(t, f, in, "ancestor-"+source.ID)
		j := claimDeployment(t, f.s, "ancestor-recovery-executor")
		if err := (&DeploymentRunner{Store: f.s, Vault: f.t.vault, Runtime: &fakeDeploymentRuntime{}}).Execute(ctx, j); err != nil {
			t.Fatal("ancestor chain failed", err)
		}
		var generation, applied int64
		if err := f.s.DB.QueryRow(`SELECT runtime_generation,applied_version FROM v3_nodes WHERE id=$1`, j.Node).Scan(&generation, &applied); err != nil || generation != j.Plan.Recovery.From.Epoch+1 || applied != source.Plan.Node.AppliedVersion {
			t.Fatal("historical epoch reused", generation, applied, err)
		}
		head = reloadDeployment(t, f.s, j.ID)
	}
	var snapshot string
	if err := f.s.DB.QueryRow(`SELECT snapshot FROM v3_node_runtime WHERE node=$1`, first.Node).Scan(&snapshot); err != nil || snapshot != first.Plan.PreviousRuntime.Snapshot || tableCount(t, f.s, "v3_deployment_recoveries") != 2 {
		t.Fatal("ancestor chain did not restore original registration", snapshot, err)
	}
}

func TestHistoricalRecoveryRestoresOriginallyUnregisteredNode(t *testing.T) {
	f := localProvisioningFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_runtime WHERE node=$1`, f.in.Node)
	request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "unregistered-source", request)
	if err != nil {
		t.Fatal(err)
	}
	var response struct{ ID string }
	if err = json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	source := finishRecoverySource(t, f, reloadDeployment(t, f.s, response.ID))
	if source.Plan.PreviousRuntime.Snapshot != "" {
		t.Fatal("fixture unexpectedly registered")
	}
	head := rollbackRecoveryHead(t, f, queueRecoverySuccessor(t, f, "unregistered-successor"))
	in := deploymentRecoveryInput{Node: source.Node, Expected: head.NodeVersion, Credential: f.in.Credential, Source: source.ID, SourceDigest: source.PlanDigest, Head: head.ID, HeadDigest: head.PlanDigest}
	queuedHistoricalRecovery(t, f, in, "restore-original-absence")
	j := claimDeployment(t, f.s, "restore-absence-executor")
	if err = (&DeploymentRunner{Store: f.s, Vault: f.t.vault, Runtime: &fakeDeploymentRuntime{}}).Execute(ctx, j); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, f.s, "v3_node_runtime") != 0 || tableCount(t, f.s, "v3_node_readiness") != 0 {
		t.Fatal("unregistered node retained collection authority")
	}
}

func TestHistoricalRecoveryConcurrentDuplicateQueueAndBusyNode(t *testing.T) {
	for _, sameKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-key", false: "different-keys"}[sameKey], func(t *testing.T) {
			f, _, _, in := historicalRecoveryFixture(t)
			var mu sync.Mutex
			var wg sync.WaitGroup
			var ids []string
			for i := 0; i < 4; i++ {
				key := "concurrent-recovery"
				if !sameKey {
					key += token()
				}
				wg.Add(1)
				go func(key string) {
					defer wg.Done()
					raw, err := f.s.queueLocalDeploymentRecovery(context.Background(), f.c, f.t, "admin", key, in)
					if err == nil {
						var result struct{ ID string }
						if err = json.Unmarshal(raw, &result); err != nil {
							t.Error(err)
						}
						mu.Lock()
						ids = append(ids, result.ID)
						mu.Unlock()
					} else if !errors.Is(err, ErrDeploymentBusy) {
						t.Error("unexpected queue error", err)
					}
				}(key)
			}
			wg.Wait()
			want := 1
			if sameKey {
				want = 4
			}
			if len(ids) != want || tableCount(t, f.s, "v3_deployment_recoveries") != 1 {
				t.Fatal("duplicate queue", ids)
			}
			for _, id := range ids {
				if id != ids[0] {
					t.Fatal("duplicate task identity")
				}
			}
			changed := in
			changed.HeadDigest = strings.Repeat("f", 64)
			if sameKey {
				if _, err := f.s.queueLocalDeploymentRecovery(context.Background(), f.c, f.t, "admin", "concurrent-recovery", changed); !errors.Is(err, ErrRequestConflict) {
					t.Fatal("changed idempotent request replayed", err)
				}
			}
		})
	}
}

func TestHistoricalRecoveryRestoreCheckpointRollbackIsAtomic(t *testing.T) {
	for _, failure := range []string{"checkpoint", "lease-during-restore"} {
		t.Run(failure, func(t *testing.T) {
			f, _, _, in := historicalRecoveryFixture(t)
			queuedHistoricalRecovery(t, f, in, "atomic-restore")
			j := claimDeployment(t, f.s, "atomic-restore-executor")
			var before int64
			if err := f.s.DB.QueryRow(`SELECT runtime_generation FROM v3_nodes WHERE id=$1`, j.Node).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if failure == "checkpoint" {
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_restore_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.rollback_step<>OLD.rollback_step THEN RAISE EXCEPTION 'synthetic';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_restore_checkpoint BEFORE UPDATE ON v3_deployment_jobs FOR EACH ROW EXECUTE FUNCTION reject_restore_checkpoint()`)
			} else {
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION expire_restore_lease() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE kind='recover';RETURN NEW;END$$;CREATE TRIGGER expire_restore_lease AFTER UPDATE OF runtime_generation ON v3_nodes FOR EACH ROW EXECUTE FUNCTION expire_restore_lease()`)
			}
			proof := checkpoint(j, "complete")
			if err := f.s.completeDeploymentPhase(context.Background(), j, f.t.vault, &proof); err == nil {
				t.Fatal("partial restoration committed")
			} else if failure == "lease-during-restore" && !errors.Is(err, ErrLeaseLost) {
				t.Fatal("missing final fence", err)
			}
			var after int64
			if err := f.s.DB.QueryRow(`SELECT runtime_generation FROM v3_nodes WHERE id=$1`, j.Node).Scan(&after); err != nil || before != after {
				t.Fatal("partial runtime generation committed", before, after, err)
			}
			if current := reloadDeployment(t, f.s, j.ID); current.RollbackStep != 0 || current.Status != "running" || deploymentBackupPinCount(t, f.s, current, "rollback") != 1 {
				t.Fatal("partial checkpoint or pin cleanup committed")
			}
		})
	}
}

func TestHistoricalRecoverySchema28UpgradeRequiresBackup(t *testing.T) {
	s := testStore(t)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_deployment_recoveries;ALTER TABLE v3_deployment_jobs DROP CONSTRAINT v3_deployment_jobs_kind_check;ALTER TABLE v3_deployment_jobs ADD CONSTRAINT v3_deployment_jobs_kind_check CHECK(kind IN ('install','upgrade'));DELETE FROM v3_schema WHERE version>=29`)
	ctx := context.Background()
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema upgraded without consistent backup")
	}
	blocked := filepath.Join(privateTestDir(t), "blocked")
	if err := os.WriteFile(blocked, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, blocked); err == nil {
		t.Fatal("upgraded after failed backup")
	}
	if version, err := currentSchema(ctx, s.DB); err != nil || version != 28 {
		t.Fatal("failed upgrade changed schema", version, err)
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if version, err := currentSchema(ctx, s.DB); err != nil || version != SchemaVersion || tableCount(t, s, "v3_deployment_recoveries") != 0 {
		t.Fatal("migration invented recovery history", version, err)
	}
}

func TestHistoricalRecoveryPinsCurrentHelperAndRetainsSourceMode(t *testing.T) {
	f, source, _, in := historicalRecoveryFixture(t)
	ctx := context.Background()
	next := newTrustToolFixture(t)
	if err := os.WriteFile(next.helper, []byte("isolated-new-recovery-helper"), 0600); err != nil {
		t.Fatal(err)
	}
	next.sign.Release = "v3.0.1-local-test"
	next.sign.Output = filepath.Join(next.root, "next-release")
	var out bytes.Buffer
	if err := ReleaseCommand(ctx, next.sign, &out); err != nil {
		t.Fatal(err)
	}
	next.signed = next.sign.Output
	c := next.config()
	c.VaultKeyFile = f.c.DeploymentTrust.VaultKeyFile
	trust, err := loadDeploymentTrust(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	f.t, f.c.DeploymentTrust = trust, c
	// Saved pending mode is deliberately different from the installed source.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET mode='docker' WHERE id=$1`, in.Node)
	queuedHistoricalRecovery(t, f, in, "recovery-current-helper")
	j := claimDeployment(t, f.s, "current-helper-executor")
	runtime := &SSHNodeRuntime{Store: f.s, Vault: trust.vault, Release: trust.release, Lifecycle: true}
	r, err := runtime.request(ctx, j, "inspect")
	if err != nil || r.Spec.Mode != "native" || r.Spec.Release != source.Plan.Request.Release || j.Plan.Request.Release != "v3.0.1-local-test" || j.Plan.Node.Mode != "docker" {
		t.Fatal("recovery used saved draft mode or old helper trust", err)
	}
	old := signedRelease(t, releaseFixture())
	runtime.Release = old
	if _, err = runtime.request(ctx, j, "inspect"); err == nil {
		t.Fatal("mismatched helper release accepted")
	}
	runtime.Release = trust.release
	for _, kind := range []string{"native", "image", "configuration"} {
		if err = runtime.provisionArtifact(ctx, j, "/must-not-be-read", kind); err == nil {
			t.Fatal("restoration staged forward artifact", kind)
		}
	}
}

func TestHistoricalRecoveryLocalCommandQueuesAndReplaysWithoutConfigurationDirectory(t *testing.T) {
	f, _, _, in := historicalRecoveryFixture(t)
	path := filepath.Join(privateTestDir(t), "recovery.json")
	writeProvisioningInput(t, path, in)
	if err := os.RemoveAll(f.c.Executor.ConfigurationDirectory); err != nil {
		t.Fatal(err)
	}
	o := Options{Action: "queue-deployment-recovery", Username: "admin", RequestKey: "local-historical-recovery", Source: path}
	var first, again bytes.Buffer
	ctx := context.Background()
	if err := f.s.localProvisioningCommand(ctx, f.c, o, &first); err != nil {
		t.Fatal("local recovery command unavailable", err)
	}
	if err := f.s.localProvisioningCommand(ctx, f.c, o, &again); err != nil || !sameProvisioningResponse(first.Bytes(), again.Bytes()) || tableCount(t, f.s, "v3_deployment_recoveries") != 1 {
		t.Fatal("local command replay changed recovery", err)
	}
	for _, private := range []string{in.Credential, in.Source, in.SourceDigest, "synthetic-pending-draft", "private_key", "password"} {
		if bytes.Contains(first.Bytes(), []byte(private)) {
			t.Fatal("local command exposed private recovery material")
		}
	}
	o.RequestKey = ""
	if err := f.s.localProvisioningCommand(ctx, f.c, o, io.Discard); err == nil {
		t.Fatal("local command accepted a write without request key")
	}
}
