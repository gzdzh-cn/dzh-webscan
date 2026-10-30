package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"webscan/internal/common"
)

// Count inspection as a remote operation too: it establishes SSH/fencing state
// even when Apply is never reached. All implementations here are in-process.
type archiveCheckedRuntime struct {
	DeploymentRuntime
	inspected []string
	after     func(DeploymentJob)
}

func (r *archiveCheckedRuntime) Inspect(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	r.inspected = append(r.inspected, j.Phase())
	return r.DeploymentRuntime.Inspect(ctx, j)
}

func (r *archiveCheckedRuntime) Apply(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	proof, err := r.DeploymentRuntime.Apply(ctx, j)
	if err == nil && r.after != nil {
		r.after(j)
	}
	return proof, err
}

func replaceDeploymentArchiveForTest(t *testing.T, f provisioningFixture, j DeploymentJob, change func(*configurationDocument)) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	doc, b, err := loadConfigurationBackup(ctx, tx, f.t.vault, j.Plan.BeforeBackup, true)
	if err != nil {
		t.Fatal(err)
	}
	change(&doc)
	raw, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	sealed, err := sealConfigurationBackup(f.t.vault, &b, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sealed)
	if _, err = tx.ExecContext(ctx, `UPDATE v3_configuration_backups SET nonce=$2,ciphertext_bytes=$3 WHERE id=$1`, b.ID, b.Nonce, b.Bytes); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_parts WHERE backup=$1`, b.ID); err != nil {
		t.Fatal(err)
	}
	if err = insertConfigurationBackupParts(ctx, tx, b.ID, sealed); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentConfigurationBackupAuthenticatedBeforeRemoteAccess(t *testing.T) {
	for _, scenario := range []string{"missing-vault", "wrong-vault", "ciphertext", "nonce", "metadata", "node-version", "node-endpoint", "node-config"} {
		t.Run(scenario, func(t *testing.T) {
			f, j := deploymentConfigurationFixture(t, false)
			j = claimDeployment(t, f.s, "archive-auth-executor")
			v := f.t.vault
			switch scenario {
			case "missing-vault":
				v = nil
			case "wrong-vault":
				v, _ = testVault(t)
			case "ciphertext":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_configuration_backup_parts SET payload=set_byte(payload,0,get_byte(payload,0)#1) WHERE backup=$1 AND part=0`, j.Plan.BeforeBackup)
			case "nonce":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_configuration_backups SET nonce=set_byte(nonce,0,get_byte(nonce,0)#1) WHERE id=$1`, j.Plan.BeforeBackup)
			case "metadata":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_configuration_backups SET settings_version=settings_version+1 WHERE id=$1`, j.Plan.BeforeBackup)
			default:
				replaceDeploymentArchiveForTest(t, f, j, func(doc *configurationDocument) {
					n := doc.Nodes[j.Node]
					switch scenario {
					case "node-version":
						n.Version++
					case "node-endpoint":
						n.Endpoint = "192.0.2.33:19100"
					case "node-config":
						p := doc.Profiles[n.Profile]
						p.Config = configurationValues{"different": true}
						doc.Profiles[n.Profile] = p
					}
					doc.Nodes[j.Node] = n
				})
			}
			fake := &fakeDeploymentRuntime{}
			runtime := &archiveCheckedRuntime{DeploymentRuntime: fake}
			err := (&DeploymentRunner{Store: f.s, Runtime: runtime, Vault: v}).Execute(context.Background(), j)
			var failure DeploymentFailure
			if !errors.As(err, &failure) || failure.Code != "backup-failed" || len(runtime.inspected) != 0 || len(fake.calls) != 0 {
				t.Fatal("unusable or wrong archive allowed remote access", err, runtime.inspected, fake.calls)
			}
			current := reloadDeployment(t, f.s, j.ID)
			if current.Status != "failed" || current.ErrorCode != "backup-failed" || current.RecoveryRequired || deploymentBackupPinCount(t, f.s, current, "") != 0 {
				t.Fatal("safe failure state or reference cleanup incorrect")
			}
		})
	}
}

func TestDeploymentConfigurationBackupRecheckedBeforeSwitchAndRollback(t *testing.T) {
	for _, scenario := range []string{"before-backup", "armed-takeover", "rollback"} {
		t.Run(scenario, func(t *testing.T) {
			f, j := deploymentConfigurationFixture(t, false)
			ctx := context.Background()
			j = claimDeployment(t, f.s, "archive-first-executor")
			fake := &fakeDeploymentRuntime{}
			runtime := &archiveCheckedRuntime{DeploymentRuntime: fake}
			corrupt := func() {
				mustHistoryExec(t, f.s.DB, `UPDATE v3_configuration_backup_parts SET payload=set_byte(payload,0,get_byte(payload,0)#1) WHERE backup=$1 AND part=0`, j.Plan.BeforeBackup)
			}
			if scenario == "before-backup" {
				runtime.after = func(phase DeploymentJob) {
					if phase.Phase() == "stage" {
						corrupt()
					}
				}
			} else {
				for j.Phase() != "backup" {
					if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
						t.Fatal(err)
					}
					j = reloadDeployment(t, f.s, j.ID)
				}
				if err := f.s.ArmDeploymentRecovery(ctx, j); err != nil {
					t.Fatal(err)
				}
				j = reloadDeployment(t, f.s, j.ID)
				if scenario == "rollback" {
					if err := f.s.FailDeployment(ctx, j, "interrupted"); err != nil {
						t.Fatal(err)
					}
					j = reloadDeployment(t, f.s, j.ID)
					if _, err := f.s.RecoverDeployment(ctx, "admin", "auth-rollback", j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
						t.Fatal(err)
					}
				} else {
					mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, j.ID)
				}
				j = claimDeployment(t, f.s, "archive-next-executor")
				corrupt()
			}
			err := (&DeploymentRunner{Store: f.s, Runtime: runtime, Vault: f.t.vault}).Execute(ctx, j)
			var failure DeploymentFailure
			if !errors.As(err, &failure) || failure.Code != "backup-failed" {
				t.Fatal("corrupt archive did not stop executor", err)
			}
			wantCalls := 0
			if scenario == "before-backup" {
				wantCalls = 2 // preflight and stage are safe; backup must not run.
			}
			if len(runtime.inspected) != wantCalls || len(fake.calls) != wantCalls {
				t.Fatal("service-changing phase was inspected/applied with unusable backup", runtime.inspected, fake.calls)
			}
			current := reloadDeployment(t, f.s, j.ID)
			if scenario == "before-backup" {
				if current.RecoveryRequired || deploymentBackupPinCount(t, f.s, current, "") != 0 {
					t.Fatal("pre-switch failure wrongly armed recovery")
				}
			} else if !current.RecoveryRequired || deploymentBackupPinCount(t, f.s, current, "rollback") != 1 {
				t.Fatal("unusable archive lost existing recovery protection")
			}
		})
	}
}

func TestDeploymentConfigurationBackupValidArchiveAndKeyRotation(t *testing.T) {
	for _, config := range []string{`{}`, `{"integer":9007199254740993123456789,"decimal":123.4500,"nested":{"token":"synthetic-config"}}`} {
		t.Run(config, func(t *testing.T) {
			f := localProvisioningFixture(t)
			mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config=$1`, config)
			ctx := context.Background()
			in, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "rotating-deployment", in)
			if err != nil {
				t.Fatal(err)
			}
			var receipt struct{ ID string }
			if err = json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			j := claimDeployment(t, f.s, "archive-rotation-executor")
			if j.ID != receipt.ID {
				t.Fatal("claimed another task")
			}
			_, newPath := testVault(t)
			rotating, err := OpenVault(newPath, f.c.DeploymentTrust.VaultKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.s.checkDeploymentConfigurationArchive(ctx, rotating, j); err != nil {
				t.Fatal("previous key or canonical numeric config rejected", err)
			}
			if err = f.s.rewrapConfigurationBackup(ctx, rotating, j.Plan.BeforeBackup); err != nil {
				t.Fatal(err)
			}
			newOnly, err := OpenVault(newPath)
			if err != nil {
				t.Fatal(err)
			}
			fake := &fakeDeploymentRuntime{}
			runtime := &archiveCheckedRuntime{DeploymentRuntime: readinessFixtureRuntime{fake, t, f.s}}
			if err = (&DeploymentRunner{Store: f.s, Runtime: runtime, Vault: newOnly}).Execute(ctx, j); err != nil {
				t.Fatal("valid archive blocked deployment", err)
			}
			current := reloadDeployment(t, f.s, j.ID)
			if current.Status != "succeeded" || len(runtime.inspected) != len(deploymentPhases) || len(fake.calls) != len(deploymentPhases) || deploymentBackupPinCount(t, f.s, current, "") != 0 {
				t.Fatal("valid deployment did not finish/release its reference")
			}
			logs, err := f.s.DB.Query(`SELECT code FROM v3_deployment_logs WHERE job=$1`, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			defer logs.Close()
			for logs.Next() {
				var code string
				if err := logs.Scan(&code); err != nil || bytes.Contains(common.JSON(code), []byte("synthetic")) {
					t.Fatal("archive contents leaked into logs", err)
				}
			}
			if err = logs.Err(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func deploymentConfigurationFixture(t *testing.T, confirmation bool) (provisioningFixture, DeploymentJob) {
	t.Helper()
	f := localProvisioningFixture(t)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_settings SET payload='{"email":{"enabled":false,"password":"synthetic-deployment-secret"}}';UPDATE v3_nodes SET config='{"private":{"token":"synthetic-node-secret"}}'`)
	in, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if confirmation {
		p, err := f.s.previewLocalDeployment(context.Background(), f.c, f.t, "admin", in)
		if err != nil {
			t.Fatal(err)
		}
		raw, err = f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "archive-confirm", p.Token)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		raw, err = f.s.queueLocalDeployment(context.Background(), f.c, f.t, "admin", "archive-queue", in)
		if err != nil {
			t.Fatal(err)
		}
	}
	var result struct{ ID string }
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return f, reloadDeployment(t, f.s, result.ID)
}

func deploymentBackupPinCount(t *testing.T, s *Store, j DeploymentJob, kind string) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM v3_configuration_backup_pins WHERE backup=$1 AND reference=$2 AND ($3='' OR kind=$3)`, j.Plan.BeforeBackup, "job:"+j.ID, kind).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestDeploymentConfigurationBackupQueueAndConfirmation(t *testing.T) {
	for _, confirmation := range []bool{false, true} {
		name := "queue"
		if confirmation {
			name = "confirmation"
		}
		t.Run(name, func(t *testing.T) {
			f, j := deploymentConfigurationFixture(t, confirmation)
			if !validArchiveSource(j.Plan.BeforeBackup) || deploymentBackupPinCount(t, f.s, j, "deployment") != 1 {
				t.Fatal("task has no immutable backup/reference")
			}
			doc := readPrivateConfigurationBackup(t, f.s, f.t.vault, j.Plan.BeforeBackup)
			raw, err := marshalConfigurationDocument(doc)
			if err != nil || !bytes.Contains(raw, []byte("synthetic-deployment-secret")) || !bytes.Contains(raw, []byte("synthetic-node-secret")) || doc.Nodes[j.Node].Version != j.NodeVersion {
				t.Fatal("backup omitted previous private configuration", err)
			}
			items, err := f.s.configurationBackups(context.Background(), "admin", retentionCursor{}, 20)
			if err != nil || len(items) != 1 || items[0].Source != "before_deploy" || items[0].CanDelete || items[0].DeleteReason != "部署任务引用" {
				t.Fatal("queued task backup not protected", err)
			}
			public, _ := json.Marshal(j)
			if bytes.Contains(public, []byte("synthetic-")) || bytes.Contains(public, []byte(j.Plan.BeforeBackup)) {
				t.Fatal("private plan exposed in public task")
			}
			if tableCount(t, f.s, "v3_configuration_backups") != 1 {
				t.Fatal("created multiple archives")
			}
		})
	}
}

func TestDeploymentConfigurationBackupTransactionalFailureAndRetry(t *testing.T) {
	for _, method := range []string{"queue", "confirm"} {
		for _, point := range []string{"header", "part", "pin", "backup-audit", "job-log", "task-audit"} {
			t.Run(method+"/"+point, func(t *testing.T) {
				f, in, p := preparedPreviewFixture(t)
				table, condition := "v3_configuration_backups", "NEW.source='before_deploy'"
				switch point {
				case "part":
					table, condition = "v3_configuration_backup_parts", "true"
				case "pin":
					table, condition = "v3_configuration_backup_pins", "NEW.kind='deployment'"
				case "backup-audit":
					table, condition = "v3_audit", "NEW.kind='configuration-backup-before-deploy'"
				case "job-log":
					table, condition = "v3_deployment_logs", "true"
				case "task-audit":
					table, condition = "v3_audit", "NEW.kind IN ('create-deployment','confirm-deployment')"
				}
				beforeReceipts, beforeAudit := tableCount(t, f.s, "v3_requests"), tableCount(t, f.s, "v3_audit")
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_deploy_archive() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF `+condition+` THEN RAISE EXCEPTION 'isolated archive write failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_deploy_archive BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION fail_deploy_archive()`)
				mutate := func() error {
					var err error
					if method == "queue" {
						_, err = f.s.queueLocalDeployment(context.Background(), f.c, f.t, "admin", "atomic-task", in)
					} else {
						_, err = f.s.confirmLocalDeployment(context.Background(), f.c, f.t, "admin", "atomic-task", p.Token)
					}
					return err
				}
				if err := mutate(); err == nil {
					t.Fatal("write failure ignored")
				}
				for _, table := range []string{"v3_deployment_jobs", "v3_deployment_logs", "v3_configuration_backups", "v3_configuration_backup_parts", "v3_configuration_backup_pins"} {
					if tableCount(t, f.s, table) != 0 {
						t.Fatal("partial task or backup committed", table)
					}
				}
				if tableCount(t, f.s, "v3_requests") != beforeReceipts || tableCount(t, f.s, "v3_audit") != beforeAudit {
					t.Fatal("failed task consumed receipt or left audit")
				}
				mustHistoryExec(t, f.s.DB, `DROP TRIGGER fail_deploy_archive ON `+table)
				if err := mutate(); err != nil || tableCount(t, f.s, "v3_configuration_backups") != 1 || tableCount(t, f.s, "v3_configuration_backup_pins") != 1 {
					t.Fatal("same-key retry failed", err)
				}
			})
		}
	}
}

func TestDeploymentConfigurationBackupFailureAndRollbackProtection(t *testing.T) {
	for _, scenario := range []string{"preflight-failure", "rollback", "success"} {
		t.Run(scenario, func(t *testing.T) {
			f, original := deploymentConfigurationFixture(t, true)
			ctx := context.Background()
			j := claimDeployment(t, f.s, "archive-executor")
			if scenario == "preflight-failure" {
				if err := f.s.FailDeployment(ctx, j, "preflight-failed"); err != nil || deploymentBackupPinCount(t, f.s, j, "") != 0 {
					t.Fatal("safe failure retained deployment protection", err)
				}
				return
			}
			for j.Phase() != "backup" {
				if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
					t.Fatal(err)
				}
				j = reloadDeployment(t, f.s, j.ID)
			}
			if err := f.s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
			j = reloadDeployment(t, f.s, j.ID)
			if deploymentBackupPinCount(t, f.s, j, "rollback") != 1 || deploymentBackupPinCount(t, f.s, j, "deployment") != 0 {
				t.Fatal("service-changing phase lost recovery pin")
			}
			// Another reference must survive this task's terminal transition.
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'rollback','unrelated-recovery')`, j.Plan.BeforeBackup)
			if scenario == "rollback" {
				if err := f.s.FailDeployment(ctx, j, "interrupted"); err != nil || deploymentBackupPinCount(t, f.s, j, "rollback") != 1 {
					t.Fatal("interruption released recovery backup", err)
				}
				j = reloadDeployment(t, f.s, j.ID)
				if _, err := f.s.RecoverDeployment(ctx, "admin", "rollback-archive", j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
					t.Fatal(err)
				}
				j = claimDeployment(t, f.s, "archive-rollback-executor")
			}
			for j.Status == "running" {
				if j.Phase() == "verify" || j.Phase() == "finalize" {
					recordDeploymentReady(t, f.s, j)
				}
				if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
					t.Fatal(err)
				}
				j = reloadDeployment(t, f.s, j.ID)
			}
			want := "succeeded"
			if scenario == "rollback" {
				want = "rolled_back"
			}
			if j.Status != want || j.PlanDigest != original.PlanDigest || deploymentBackupPinCount(t, f.s, j, "") != 0 {
				t.Fatal("terminal task did not release only its own references")
			}
			if tableCount(t, f.s, "v3_configuration_backups") != 1 || tableCount(t, f.s, "v3_configuration_backup_pins") != 1 {
				t.Fatal("terminal task deleted archive or unrelated recovery reference")
			}
		})
	}
}

func TestDeploymentConfigurationBackupMissingReferenceFailsClosed(t *testing.T) {
	for _, stage := range []string{"claim", "arm", "resume"} {
		t.Run(stage, func(t *testing.T) {
			f, j := deploymentConfigurationFixture(t, false)
			ctx := context.Background()
			if stage != "claim" {
				j = claimDeployment(t, f.s, "archive-executor")
				for j.Phase() != "backup" {
					if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
						t.Fatal(err)
					}
					j = reloadDeployment(t, f.s, j.ID)
				}
				if stage == "resume" {
					if err := f.s.ArmDeploymentRecovery(ctx, j); err != nil {
						t.Fatal(err)
					}
					j = reloadDeployment(t, f.s, j.ID)
					if err := f.s.FailDeployment(ctx, j, "interrupted"); err != nil {
						t.Fatal(err)
					}
					j = reloadDeployment(t, f.s, j.ID)
				}
			}
			mustHistoryExec(t, f.s.DB, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1 AND reference=$2`, j.Plan.BeforeBackup, "job:"+j.ID)
			var err error
			switch stage {
			case "claim":
				_, err = f.s.ClaimDeployment(ctx, "missing-archive-executor")
			case "arm":
				err = f.s.ArmDeploymentRecovery(ctx, j)
			case "resume":
				_, err = f.s.RecoverDeployment(ctx, "admin", "missing-archive-resume", j.ID, "forward", j.PlanDigest, j.LogCursor)
			}
			if !errors.Is(err, errDeploymentConfigurationBackup) {
				t.Fatal("missing reference did not block service transition", err)
			}
		})
	}
}

func TestDeploymentConfigurationBackupSnapshotRetryIsBounded(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "23505"} {
		calls := 0
		_, err := retryDeploymentConfigurationMutation(context.Background(), func() (json.RawMessage, error) {
			calls++
			return nil, &pgconn.PgError{Code: code}
		})
		if err == nil || code == "23505" && calls != 1 || code != "23505" && calls != 5 {
			t.Fatal("unsafe or unbounded retry", code, calls)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := retryDeploymentConfigurationMutation(ctx, func() (json.RawMessage, error) {
		calls++
		cancel()
		return nil, &pgconn.PgError{Code: "40001"}
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancelled retry continued", calls, err)
	}
	// No transient database error may be fabricated from a lookalike string.
	calls = 0
	_, _ = retryDeploymentConfigurationMutation(context.Background(), func() (json.RawMessage, error) {
		calls++
		return nil, errors.New("SQLSTATE 40001")
	})
	if calls != 1 {
		t.Fatal("retried an untyped error")
	}
}

func TestDeploymentConfigurationBackupLeaseAndReleaseAtomicity(t *testing.T) {
	f, original := deploymentConfigurationFixture(t, false)
	ctx := context.Background()
	stale := claimDeployment(t, f.s, "old-archive-executor")
	mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, original.ID)
	current := claimDeployment(t, f.s, "new-archive-executor")
	if current.Epoch != stale.Epoch+1 || current.Plan.BeforeBackup != original.Plan.BeforeBackup {
		t.Fatal("takeover changed archive identity")
	}
	if err := f.s.FailDeployment(ctx, stale, "preflight-failed"); !errors.Is(err, ErrLeaseLost) || deploymentBackupPinCount(t, f.s, current, "deployment") != 1 {
		t.Fatal("expired executor released protection", err)
	}
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_archive_release() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated release failure';END$$;CREATE TRIGGER reject_archive_release BEFORE DELETE ON v3_configuration_backup_pins FOR EACH ROW EXECUTE FUNCTION reject_archive_release()`)
	if err := f.s.FailDeployment(ctx, current, "preflight-failed"); err == nil {
		t.Fatal("release failure ignored")
	}
	j := reloadDeployment(t, f.s, current.ID)
	if j.Status != "running" || j.LogCursor != current.LogCursor || deploymentBackupPinCount(t, f.s, current, "deployment") != 1 {
		t.Fatal("failed release partially committed task transition")
	}
	mustHistoryExec(t, f.s.DB, `DROP TRIGGER reject_archive_release ON v3_configuration_backup_pins`)
	if err := f.s.FailDeployment(ctx, current, "preflight-failed"); err != nil {
		t.Fatal(err)
	}
	items, err := f.s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(items) != 1 || !items[0].CanDelete {
		t.Fatal("safe failure did not release archive", err)
	}
}

func TestDeploymentConfigurationBackupArmingIsAtomic(t *testing.T) {
	f, _ := deploymentConfigurationFixture(t, false)
	ctx := context.Background()
	j := claimDeployment(t, f.s, "arm-archive-executor")
	for j.Phase() != "backup" {
		if err := f.s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, f.s, j.ID)
	}
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_archive_arm() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.recovery_required AND NOT OLD.recovery_required THEN RAISE EXCEPTION 'isolated arm failure';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_archive_arm BEFORE UPDATE ON v3_deployment_jobs FOR EACH ROW EXECUTE FUNCTION reject_archive_arm()`)
	if err := f.s.ArmDeploymentRecovery(ctx, j); err == nil {
		t.Fatal("arming failure ignored")
	}
	current := reloadDeployment(t, f.s, j.ID)
	if current.RecoveryRequired || deploymentBackupPinCount(t, f.s, j, "deployment") != 1 || deploymentBackupPinCount(t, f.s, j, "rollback") != 0 {
		t.Fatal("failed arming lost original reference")
	}
	mustHistoryExec(t, f.s.DB, `DROP TRIGGER reject_archive_arm ON v3_deployment_jobs`)
	if err := f.s.ArmDeploymentRecovery(ctx, j); err != nil || deploymentBackupPinCount(t, f.s, j, "rollback") != 1 {
		t.Fatal("arming retry failed", err)
	}
}

func TestDeploymentConfigurationBackupWritersCoexistAndSnapshotGateBlocks(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	if err = lockDeploymentWriteRelationsTx(ctx, first); err != nil {
		t.Fatal(err)
	}
	second, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback()
	if err = lockDeploymentWriteRelationsTx(ctx, second); err != nil {
		t.Fatal("ordinary deployments globally serialized", err)
	}
	if err = second.Rollback(); err != nil {
		t.Fatal(err)
	}
	gate, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	short, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	if err = lockConfigurationRestoreStateTx(short, gate); err == nil || short.Err() == nil {
		t.Fatal("configuration snapshot bypassed active writer", err)
	}
}
