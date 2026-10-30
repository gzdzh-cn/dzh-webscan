package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func applicationSettingsFixture(t *testing.T, step int) (*Store, configurationLocalFixture, privateConfigurationApplication) {
	t.Helper()
	s, f, stage, revision := commitSavedFixture(t)
	ctx := context.Background()
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "settings-fixture-save", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	raw, err = s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "settings-fixture-queue", stage.ID, revision.Generation)
	_ = applicationReceipt(t, raw, err)
	// Synthetic preceding checkpoints isolate this adapter. They are NOT node
	// or bootstrap acceptance, and no application runner is enabled by this test.
	for i := 0; i < step; i++ {
		j := claimApplicationForTest(t, s, f, "settings-fixture-setup")
		if i > 0 {
			j, err = s.armConfigurationApplication(ctx, f.v, j)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err = s.checkpointConfigurationApplication(ctx, f.v, j, applicationComplete(j)); err != nil {
			t.Fatal(err)
		}
	}
	j := claimApplicationForTest(t, s, f, "actual-settings-worker")
	if step > 0 {
		j, err = s.armConfigurationApplication(ctx, f.v, j)
		if err != nil {
			t.Fatal(err)
		}
	}
	return s, f, j
}

func rollbackApplicationSettingsForTest(t *testing.T, s *Store, f configurationLocalFixture, j privateConfigurationApplication, revoke bool) privateConfigurationApplication {
	t.Helper()
	ctx := context.Background()
	if err := s.failConfigurationApplication(ctx, f.v, j, "interrupted"); err != nil {
		t.Fatal(err)
	}
	user := "admin"
	if revoke {
		mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1,role='viewer' WHERE username='admin'`)
		user = "other-admin"
	}
	if _, err := s.controlConfigurationApplication(ctx, f.v, user, "settings-request-rollback", j.ID, "rollback"); err != nil {
		t.Fatal(err)
	}
	return claimApplicationForTest(t, s, f, "actual-settings-rollback")
}

func TestConfigurationApplicationSettingsActualAtomicApplyAndInspect(t *testing.T) {
	s, f, j := applicationSettingsFixture(t, 3)
	r := configurationSettingsRuntime{s, f.v, f.c}
	ctx := context.Background()
	before := settingsStateForTest(t, s)
	files := localTree(t, f.f.root)
	if p, err := r.InspectConfigurationPhase(ctx, j); err != nil || p.State != "absent" {
		t.Fatal("initial inspection", err)
	}
	if !sameApplicationSettings(before, settingsStateForTest(t, s)) || tableCount(t, s, "v3_configuration_application_settings") != 0 {
		t.Fatal("inspection mutated runtime")
	}
	if p, err := r.ApplyConfigurationPhase(ctx, j); err != nil || !p.matches(j) {
		t.Fatal("actual settings apply", err)
	}
	policy, err := s.RetentionPolicy(ctx)
	if err != nil || policy.Policy.Events != 30 || policy.Version != before.RuntimeVersion+1 {
		t.Fatal("workers do not see target policy", err)
	}
	after := settingsStateForTest(t, s)
	if after.Pending || after.Generation != before.Generation || !configurationJSONEqual(after.Runtime, before.Desired) {
		t.Fatal("settings did not become live")
	}
	for i := 0; i < 2; i++ {
		if p, err := r.ApplyConfigurationPhase(ctx, j); err != nil || !p.matches(j) {
			t.Fatal("response-loss replay", err)
		}
		if p, err := r.InspectConfigurationPhase(ctx, j); err != nil || !p.matches(j) {
			t.Fatal("completed inspection", err)
		}
	}
	if !sameApplicationSettings(after, settingsStateForTest(t, s)) || tableCount(t, s, "v3_configuration_application_settings") != 1 || !reflect.DeepEqual(files, localTree(t, f.f.root)) {
		t.Fatal("replay applied twice or wrote files")
	}
	var raw []byte
	if err = s.DB.QueryRow(`SELECT jsonb_agg(row_to_json(t)) FROM v3_configuration_application_settings t`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private-revision-password")) || bytes.Contains(raw, []byte(j.planProof)) || bytes.Contains(raw, []byte("retention")) {
		t.Fatal("receipt stored private plaintext")
	}
	var count int
	if err = s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='configuration-application-settings'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("receipt/audit not idempotent", err)
	}
	if _, err = json.Marshal(privateApplicationSettingsReceipt{}); err == nil {
		t.Fatal("private receipt serialized")
	}
	if tableCount(t, s, "v3_notifications") != 0 || tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("settings adapter started unrelated work")
	}
}

func TestConfigurationApplicationSettingsTakeoverAfterCommittedEffect(t *testing.T) {
	s, f, old := applicationSettingsFixture(t, 3)
	r := configurationSettingsRuntime{s, f.v, f.c}
	ctx := context.Background()
	if _, err := r.ApplyConfigurationPhase(ctx, old); err != nil {
		t.Fatal(err)
	}
	after := settingsStateForTest(t, s)
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second'`)
	j := claimApplicationForTest(t, s, f, "settings-takeover")
	if _, err := r.ApplyConfigurationPhase(ctx, old); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale adapter changed effect", err)
	}
	p, err := r.InspectConfigurationPhase(ctx, j)
	if err != nil || !p.matches(j) || j.epoch <= old.epoch {
		t.Fatal("takeover lost real completion", err)
	}
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, j, p); err != nil {
		t.Fatal("takeover checkpoint", err)
	}
	if !sameApplicationSettings(after, settingsStateForTest(t, s)) {
		t.Fatal("takeover reapplied policy")
	}
}

func TestConfigurationApplicationSettingsActualRollbackWithNewAdministrator(t *testing.T) {
	s, f, j := applicationSettingsFixture(t, 3)
	r := configurationSettingsRuntime{s, f.v, f.c}
	ctx := context.Background()
	before := settingsStateForTest(t, s)
	if _, err := r.ApplyConfigurationPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = rollbackApplicationSettingsForTest(t, s, f, j, true)
	if p, err := r.InspectConfigurationPhase(ctx, j); err != nil || p.State != "absent" {
		t.Fatal("rollback inspect under new administrator", err)
	}
	if p, err := r.ApplyConfigurationPhase(ctx, j); err != nil || !p.matches(j) {
		t.Fatal("actual rollback", err)
	}
	after := settingsStateForTest(t, s)
	if !configurationJSONEqual(after.Runtime, before.Runtime) || !configurationJSONEqual(after.Desired, before.Desired) || !after.Pending || after.RuntimeVersion != before.RuntimeVersion+2 || after.Generation != before.Generation {
		t.Fatal("rollback did not restore original policy and preserve pending desired state")
	}
	policy, err := s.RetentionPolicy(ctx)
	if err != nil || policy.Policy.Events != 90 {
		t.Fatal("rollback not visible to worker", err)
	}
	if p, err := r.ApplyConfigurationPhase(ctx, j); err != nil || !p.matches(j) || !sameApplicationSettings(after, settingsStateForTest(t, s)) {
		t.Fatal("rollback replay changed versions", err)
	}
	if tableCount(t, s, "v3_configuration_application_settings") != 2 {
		t.Fatal("missing forward or rollback receipt")
	}
}

func TestConfigurationApplicationRollbackClaimAuthenticatesHistoricalEvidence(t *testing.T) {
	for _, kind := range []string{"pin", "candidate", "commit"} {
		t.Run(kind, func(t *testing.T) {
			s, f, j := applicationSettingsFixture(t, 1)
			ctx := context.Background()
			if err := s.failConfigurationApplication(ctx, f.v, j, "interrupted"); err != nil {
				t.Fatal(err)
			}
			mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1,role='viewer' WHERE username='admin'`)
			if _, err := s.controlConfigurationApplication(ctx, f.v, "other-admin", "historical-rollback", j.ID, "rollback"); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "pin":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins`)
			case "candidate":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET candidate_proof='forged'`)
			case "commit":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET proof='forged'`)
			}
			if _, err := s.claimConfigurationApplication(ctx, f.v, f.c.Central.Instance, "untrusted-rollback"); err == nil {
				t.Fatal("historical rollback evidence was not authenticated", kind)
			}
			if privateApplicationForTest(t, s, f.v, j.ID).Status != "queued" {
				t.Fatal("rejected claim changed task")
			}
		})
	}
}

func TestConfigurationApplicationSettingsRollbackBeforeEffectDoesNotApplyTarget(t *testing.T) {
	s, f, j := applicationSettingsFixture(t, 1)
	r := configurationSettingsRuntime{s, f.v, f.c}
	before := settingsStateForTest(t, s)
	j = rollbackApplicationSettingsForTest(t, s, f, j, true)
	if p, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil || !p.matches(j) {
		t.Fatal("no-effect rollback", err)
	}
	if !sameApplicationSettings(before, settingsStateForTest(t, s)) || tableCount(t, s, "v3_configuration_application_settings") != 1 {
		t.Fatal("rollback applied unstarted settings")
	}
}

func TestConfigurationApplicationSettingsTransactionFailuresAreRetryable(t *testing.T) {
	for _, phase := range []string{"forward", "rollback"} {
		for _, target := range []string{"v3_settings", "v3_settings_drafts", "v3_configuration_application_settings", "v3_audit"} {
			t.Run(phase+"/"+target, func(t *testing.T) {
				s, f, j := applicationSettingsFixture(t, 3)
				r := configurationSettingsRuntime{s, f.v, f.c}
				ctx := context.Background()
				if phase == "rollback" {
					if _, err := r.ApplyConfigurationPhase(ctx, j); err != nil {
						t.Fatal(err)
					}
					j = rollbackApplicationSettingsForTest(t, s, f, j, false)
				}
				before := settingsStateForTest(t, s)
				count := tableCount(t, s, "v3_configuration_application_settings")
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_application_settings() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic-private-db-failure';END$$;CREATE TRIGGER fail_application_settings BEFORE INSERT OR UPDATE ON `+target+` FOR EACH ROW EXECUTE FUNCTION fail_application_settings()`)
				if _, err := r.ApplyConfigurationPhase(ctx, j); err == nil {
					t.Fatal("injected failure ignored")
				}
				if !sameApplicationSettings(before, settingsStateForTest(t, s)) || tableCount(t, s, "v3_configuration_application_settings") != count {
					t.Fatal("partial settings transaction committed")
				}
				mustHistoryExec(t, s.DB, `DROP TRIGGER fail_application_settings ON `+target)
				if p, err := r.ApplyConfigurationPhase(ctx, j); err != nil || !p.matches(j) {
					t.Fatal("retry failed", err)
				}
			})
		}
	}
}

func TestConfigurationApplicationSettingsRejectsDriftOrLostAuthority(t *testing.T) {
	for _, kind := range []string{"generation", "desired", "runtime", "runtime-version", "draft-proof", "source-proof", "archive-pin", "account", "lease", "hold", "member", "rewritten-member-hint", "wrong-phase", "migration"} {
		t.Run(kind, func(t *testing.T) {
			s, f, j := applicationSettingsFixture(t, 3)
			r := configurationSettingsRuntime{s, f.v, f.c}
			switch kind {
			case "generation":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings_drafts SET generation=generation+1`)
			case "desired":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings_drafts SET payload='{}'`)
			case "runtime":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{}'`)
			case "runtime-version":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
			case "draft-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings_drafts SET proof='forged'`)
			case "source-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET proof='forged'`)
			case "archive-pin":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins`)
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "lease":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second'`)
			case "hold":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET recovery_hold=true`)
			case "member":
				r.bootstrap.Central.Instance = "different-member"
			case "rewritten-member-hint":
				r.bootstrap.Central.Instance = "different-member"
				j.member = "different-member"
			case "wrong-phase":
				j.step = 2
			case "migration":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('events',$1)`, token())
			}
			before := settingsStateForTest(t, s)
			if _, err := r.InspectConfigurationPhase(context.Background(), j); err == nil {
				t.Fatal("bad inspection accepted", kind)
			}
			if _, err := r.ApplyConfigurationPhase(context.Background(), j); err == nil {
				t.Fatal("bad application accepted", kind)
			}
			if !sameApplicationSettings(before, settingsStateForTest(t, s)) || tableCount(t, s, "v3_configuration_application_settings") != 0 {
				t.Fatal("failed authority changed state")
			}
		})
	}
}

func TestConfigurationApplicationSettingsExpiredDuringEffectRollsBack(t *testing.T) {
	s, f, j := applicationSettingsFixture(t, 3)
	r := configurationSettingsRuntime{s, f.v, f.c}
	before := settingsStateForTest(t, s)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION delay_application_settings() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(0.4);RETURN NEW;END$$;CREATE TRIGGER delay_application_settings BEFORE UPDATE ON v3_settings FOR EACH ROW EXECUTE FUNCTION delay_application_settings();UPDATE v3_configuration_applications SET lease_until=clock_timestamp()+interval '0.2 seconds'`)
	if _, err := r.ApplyConfigurationPhase(context.Background(), j); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("expired side effect committed", err)
	}
	if !sameApplicationSettings(before, settingsStateForTest(t, s)) || tableCount(t, s, "v3_configuration_application_settings") != 0 {
		t.Fatal("late effect escaped its transaction")
	}
}

func TestConfigurationApplicationSettingsUnchangedPolicyAndRollback(t *testing.T) {
	s, f, pub := applicationFixture(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		j := claimApplicationForTest(t, s, f, "unchanged-setup")
		if i > 0 {
			var err error
			j, err = s.armConfigurationApplication(ctx, f.v, j)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.checkpointConfigurationApplication(ctx, f.v, j, applicationComplete(j)); err != nil {
			t.Fatal(err)
		}
	}
	j := claimApplicationForTest(t, s, f, "unchanged-settings")
	r := configurationSettingsRuntime{s, f.v, f.c}
	before := settingsStateForTest(t, s)
	if before.Pending || before.Generation != 0 {
		t.Fatal("unchanged fixture unexpectedly pending")
	}
	if p, err := r.ApplyConfigurationPhase(ctx, j); err != nil || !p.matches(j) {
		t.Fatal("no-change receipt", err)
	}
	if !sameApplicationSettings(before, settingsStateForTest(t, s)) {
		t.Fatal("unchanged policy created a new version")
	}
	j = rollbackApplicationSettingsForTest(t, s, f, j, false)
	if p, err := r.ApplyConfigurationPhase(ctx, j); err != nil || !p.matches(j) || !sameApplicationSettings(before, settingsStateForTest(t, s)) {
		t.Fatal("unchanged rollback modified settings", err)
	}
	if j.ID != pub.ID || tableCount(t, s, "v3_configuration_application_settings") != 2 {
		t.Fatal("unchanged phases lack durable receipts")
	}
}

func TestConfigurationApplicationSettingsCannotStartThroughPartialRunner(t *testing.T) {
	s, f, j := applicationSettingsFixture(t, 3)
	r := configurationSettingsRuntime{s, f.v, f.c}
	before := settingsStateForTest(t, s)
	if err := s.executeConfigurationApplication(context.Background(), f.v, j, r); err == nil {
		t.Fatal("settings-only adapter bypassed full runtime gate")
	}
	if !sameApplicationSettings(before, settingsStateForTest(t, s)) || tableCount(t, s, "v3_configuration_application_settings") != 0 {
		t.Fatal("partial runtime applied a subset of configuration")
	}
}

func TestConfigurationApplicationSettingsReceiptsRejectCorruptionAndMissingEvidence(t *testing.T) {
	for _, kind := range []string{"ciphertext", "nonce", "phase-swap", "missing", "runtime-drift", "archive-pin"} {
		t.Run(kind, func(t *testing.T) {
			s, f, j := applicationSettingsFixture(t, 3)
			r := configurationSettingsRuntime{s, f.v, f.c}
			ctx := context.Background()
			if _, err := r.ApplyConfigurationPhase(ctx, j); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "ciphertext":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_application_settings SET ciphertext=set_byte(ciphertext,0,255-get_byte(ciphertext,0))`)
			case "nonce":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_application_settings SET nonce=decode('00','hex')`)
			case "phase-swap":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_application_settings SET phase='restore-settings'`)
			case "missing":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_application_settings`)
			case "runtime-drift":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
			case "archive-pin":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins`)
			}
			before := settingsStateForTest(t, s)
			if _, err := r.ApplyConfigurationPhase(ctx, j); err == nil {
				t.Fatal("invalid completion evidence accepted")
			}
			if !sameApplicationSettings(before, settingsStateForTest(t, s)) {
				t.Fatal("invalid receipt repeated side effect")
			}
		})
	}
}

func TestConfigurationApplicationSettingsConcurrentReplayAndBoundedCancellation(t *testing.T) {
	s, f, j := applicationSettingsFixture(t, 3)
	r := configurationSettingsRuntime{s, f.v, f.c}
	before := settingsStateForTest(t, s)
	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil || !p.matches(j) {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if failed.Load() != 0 || settingsStateForTest(t, s).RuntimeVersion != before.RuntimeVersion+1 || tableCount(t, s, "v3_configuration_application_settings") != 1 {
		t.Fatal("concurrent effect repeated or failed", failed.Load())
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`LOCK TABLE v3_nodes IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err = r.ApplyConfigurationPhase(ctx, j); err == nil || time.Since(started) > 2*time.Second {
		t.Fatal("cancelled adapter blocked or completed", err)
	}
}

func TestConfigurationApplicationSettingsDisasterRestoreDoesNotReplayEffect(t *testing.T) {
	s, f, old := applicationSettingsFixture(t, 3)
	r := configurationSettingsRuntime{s, f.v, f.c}
	ctx := context.Background()
	if _, err := r.ApplyConfigurationPhase(ctx, old); err != nil {
		t.Fatal(err)
	}
	after := settingsStateForTest(t, s)
	backup, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	r.store = restored
	if _, err = r.InspectConfigurationPhase(ctx, old); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("disaster restore reused old authority", err)
	}
	if _, err = restored.controlConfigurationApplication(ctx, f.v, "admin", "explicit-settings-recovery", old.ID, "resume"); err != nil {
		t.Fatal(err)
	}
	j := claimApplicationForTest(t, restored, f, "settings-post-disaster")
	if p, err := r.InspectConfigurationPhase(ctx, j); err != nil || !p.matches(j) || !sameApplicationSettings(after, settingsStateForTest(t, restored)) {
		t.Fatal("restored receipt did not recover real completion", err)
	}
}

func TestConfigurationApplicationSettingsKeyRotationAndPartialRuntimeGate(t *testing.T) {
	s, f, j := applicationSettingsFixture(t, 3)
	r := configurationSettingsRuntime{s, f.v, f.c}
	ctx := context.Background()
	if _, err := r.ApplyConfigurationPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	_, path := testVault(t)
	rotated, err := OpenVault(path, f.c.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	r.vault = rotated
	if p, err := r.InspectConfigurationPhase(ctx, j); err != nil || !p.matches(j) {
		t.Fatal("rotation lost receipt", err)
	}
	r.vault, err = OpenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.InspectConfigurationPhase(ctx, j); err == nil {
		t.Fatal("removed receipt key accepted")
	}
	for _, phase := range []string{"environment", "nodes", "bootstrap", "verify", "finalize", "restore-bootstrap", "restore-nodes", "verify-rollback"} {
		if r.SupportsConfigurationPhase(phase) {
			t.Fatal("partial adapter claims complete runtime support")
		}
	}
}

func TestConfigurationApplicationSettingsSchema22UpgradeRequiresBackup(t *testing.T) {
	s := testStore(t)
	dropBootstrapRuntimeForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE v3_configuration_application_settings;DELETE FROM v3_schema WHERE version=23`)
	if err := s.Migrate(context.Background()); err == nil {
		t.Fatal("schema22 upgraded without backup")
	}
	bad := filepath.Join(privateTestDir(t), "not-directory")
	localWrite(t, bad, []byte("file"))
	if err := s.Upgrade(context.Background(), bad); err == nil {
		t.Fatal("failed backup ignored")
	}
	if v, err := currentSchema(context.Background(), s.DB); err != nil || v != 22 {
		t.Fatal("backup failure changed schema", v, err)
	}
	if err := s.Upgrade(context.Background(), privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	var exists sql.NullString
	if err := s.DB.QueryRow(`SELECT to_regclass(current_schema()||'.v3_configuration_application_settings')::text`).Scan(&exists); err != nil || !exists.Valid {
		t.Fatal("settings receipt schema missing", err)
	}
}
