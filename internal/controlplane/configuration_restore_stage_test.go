package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webscan/internal/common"
	agentv1 "webscan/sdk/agent/v1"
)

func configurationStageReceipt(t *testing.T, raw []byte, err error) configurationRestoreStage {
	t.Helper()
	var out configurationRestoreStage
	if err != nil || json.Unmarshal(raw, &out) != nil || !validArchiveSource(out.ID) {
		t.Fatal("invalid restore intent receipt", err)
	}
	return out
}

func configurationStageFixture(t *testing.T) (*Store, *Vault, Config, string, configurationRestorePreview) {
	t.Helper()
	s, v, c, id := configurationRestoreFixture(t)
	// Deliberately differ from the source so an accidental apply is observable.
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=6,payload=jsonb_set(payload,'{retention,sqlite_events_days}','90')`)
	p, err := s.previewConfigurationRestore(context.Background(), v, c, "admin", id, configurationRestoreOptions{})
	if err != nil || !p.Summary.SettingsChanged {
		t.Fatal("stage preview fixture", err)
	}
	return s, v, c, id, p
}

func TestConfigurationRestoreStageArchivesBeforeAndDoesNotApply(t *testing.T) {
	s, v, c, source, p := configurationStageFixture(t)
	ctx := context.Background()
	raw, err := s.stageConfigurationRestore(ctx, v, c, "admin", "stage-once", p.Token)
	stage := configurationStageReceipt(t, raw, err)
	if stage.Status != "pending_validation" || stage.SettingsVersion != 6 || stage.Backup != source || stage.BeforeBackup == source || stage.Finished != nil {
		t.Fatal("intent represented as applied", stage.Status)
	}
	before := readPrivateConfigurationBackup(t, s, v, stage.BeforeBackup)
	if before.SettingsVersion != 6 || common.F(common.M(before.Settings["retention"])["sqlite_events_days"]) != 90 || common.M(before.Settings["email"])["password"] != "private-stored-mail-value" {
		t.Fatal("before-restore backup did not preserve current state")
	}
	var version int64
	var payload []byte
	if err := s.DB.QueryRow(`SELECT version,payload FROM v3_settings WHERE id=1`).Scan(&version, &payload); err != nil || version != 6 || !bytes.Contains(payload, []byte("90")) {
		t.Fatal("intent changed live settings", err)
	}
	if tableCount(t, s, "v3_configuration_backups") != 2 || tableCount(t, s, "v3_configuration_restore_stages") != 1 || tableCount(t, s, "v3_configuration_restore_previews") != 0 || tableCount(t, s, "v3_configuration_backup_pins") != 2 || tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("stage partially committed or activated work")
	}
	backups, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(backups) != 2 || backups[0].CanDelete || backups[1].CanDelete {
		t.Fatal("stage failed to protect source and before archive", err)
	}
	var stored, audit []byte
	if err := s.DB.QueryRow(`SELECT row_to_json(s) FROM v3_configuration_restore_stages s`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT result FROM v3_audit WHERE kind='configuration-restore-stage'`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{raw, stored, audit} {
		for _, value := range []string{p.Token, "private-stored", "192.0.2", "dsn_file", "vault_key_file"} {
			if bytes.Contains(data, []byte(value)) {
				t.Fatal("intent leaked private source")
			}
		}
	}
	again, err := s.stageConfigurationRestore(ctx, v, c, "admin", "stage-once", p.Token)
	if err != nil || canonicalBackupResponse(t, raw) != canonicalBackupResponse(t, again) || tableCount(t, s, "v3_configuration_backups") != 2 {
		t.Fatal("retry duplicated before backup/intent", err)
	}
	if _, err := s.stageConfigurationRestore(ctx, v, c, "admin", "other-key", p.Token); !errors.Is(err, errConfigurationRestorePending) {
		t.Fatal("second pending intent allowed", err)
	}
	fresh := &Store{DB: s.DB}
	live, summary, err := fresh.configurationRestoreStage(ctx, "admin", stage.ID)
	if err != nil || live.Status != "pending_validation" || !summary.RequiresLocalValidation || !summary.SettingsChanged {
		t.Fatal("restart lost actual pending status", err)
	}
}

func TestConfigurationRestoreStageAtomicFailuresPreserveCapability(t *testing.T) {
	for _, point := range []string{"before-backup", "before-part", "stage-pin", "audit"} {
		t.Run(point, func(t *testing.T) {
			s, v, c, _, p := configurationStageFixture(t)
			ctx := context.Background()
			switch point {
			case "before-backup":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_restore_stage() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.source='before_restore' THEN RAISE EXCEPTION 'synthetic full disk';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_stage BEFORE INSERT ON v3_configuration_backups FOR EACH ROW EXECUTE FUNCTION fail_restore_stage()`)
			case "before-part":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_restore_stage() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic write failure';END$$;CREATE TRIGGER fail_stage BEFORE INSERT ON v3_configuration_backup_parts FOR EACH ROW EXECUTE FUNCTION fail_restore_stage()`)
			case "stage-pin":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_restore_stage() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.reference LIKE 'stage:%' THEN RAISE EXCEPTION 'synthetic pin failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_stage BEFORE INSERT ON v3_configuration_backup_pins FOR EACH ROW EXECUTE FUNCTION fail_restore_stage()`)
			case "audit":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_restore_stage() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='configuration-restore-stage' THEN RAISE EXCEPTION 'synthetic audit failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_stage BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_restore_stage()`)
			}
			beforeReceipts := tableCount(t, s, "v3_requests")
			if _, err := s.stageConfigurationRestore(ctx, v, c, "admin", "failed-stage", p.Token); err == nil {
				t.Fatal("injected failure ignored")
			}
			if tableCount(t, s, "v3_configuration_backups") != 1 || tableCount(t, s, "v3_configuration_restore_stages") != 0 || tableCount(t, s, "v3_configuration_restore_previews") != 1 || tableCount(t, s, "v3_configuration_backup_pins") != 1 || tableCount(t, s, "v3_requests") != beforeReceipts {
				t.Fatal("failed stage partially committed")
			}
			if _, err := revalidateConfigurationRestoreForTest(t, s, v, c, "admin", p.Token); err != nil {
				t.Fatal("failure consumed usable preview", err)
			}
		})
	}
}

func TestConfigurationRestoreStageRejectsStaleBusyBlockedAndDemoted(t *testing.T) {
	for _, reason := range []string{"stale", "busy", "blocked", "demoted", "expired"} {
		t.Run(reason, func(t *testing.T) {
			s, v, c, source, p := configurationStageFixture(t)
			ctx := context.Background()
			switch reason {
			case "stale":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET name='changed-after-preview'`)
			case "busy":
				in := DeploymentRequest{Node: "saved-node", Kind: "install", Expected: 1, Credential: addCredential(t, s, v, "saved-node"), Release: "v3.0.0", SHA256: digest([]byte("synthetic-target"))}
				_ = createDeployment(t, s, in, "busy-install")
			case "blocked":
				doc := readPrivateConfigurationBackup(t, s, v, source)
				n := doc.Nodes["saved-node"]
				n.Mode = "docker"
				doc.Nodes["saved-node"] = n
				body, _ := marshalConfigurationDocument(doc)
				raw, err := s.importConfigurationBackup(ctx, v, "admin", "other-mode", body)
				id := configurationBackupReceiptID(t, raw, err)
				p, err = s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{})
				if err != nil || p.Summary.CanPrepare {
					t.Fatal("mode migration fixture", err)
				}
			case "demoted":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			case "expired":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_previews SET expires_at=clock_timestamp()-interval '1 second'`)
			}
			archives := tableCount(t, s, "v3_configuration_backups")
			if _, err := s.stageConfigurationRestore(ctx, v, c, "admin", "rejected-stage", p.Token); err == nil || tableCount(t, s, "v3_configuration_restore_stages") != 0 || tableCount(t, s, "v3_configuration_backups") != archives {
				t.Fatal("unsafe stage accepted or left an archive", err)
			}
		})
	}
}

func TestConfigurationRestoreStageCancellationAndGarbageCollection(t *testing.T) {
	s, v, c, source, p := configurationStageFixture(t)
	ctx := context.Background()
	raw, err := s.stageConfigurationRestore(ctx, v, c, "admin", "stage", p.Token)
	stage := configurationStageReceipt(t, raw, err)
	for _, user := range []string{"viewer", "operator", "missing"} {
		if _, _, err := s.configurationRestoreStage(ctx, user, stage.ID); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("read permission", user, err)
		}
		if _, err := s.cancelConfigurationRestore(ctx, user, "denied-cancel", stage.ID); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("cancel permission", user, err)
		}
	}
	// Another current administrator can release an abandoned, unusable intent.
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='admin' WHERE username='operator';UPDATE v3_accounts SET role='viewer',revision=revision+1 WHERE username='admin'`)
	raw, err = s.cancelConfigurationRestore(ctx, "operator", "cancel", stage.ID)
	cancelled := configurationStageReceipt(t, raw, err)
	if cancelled.Status != "cancelled" || cancelled.Finished == nil || cancelled.CancelledBy != "operator" || tableCount(t, s, "v3_configuration_backup_pins") != 0 || tableCount(t, s, "v3_configuration_backups") != 2 {
		t.Fatal("cancel removed data or retained intent pins")
	}
	// Only terminal intent history expires; receipts remain to prevent revival.
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_stages SET finished_at=clock_timestamp()-interval '366 days'`)
	if err := s.Housekeeping(ctx, "stage-cleaner"); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_configuration_restore_stages") != 0 {
		t.Fatal("terminal intent not collected")
	}
	again, err := s.cancelConfigurationRestore(ctx, "operator", "cancel", stage.ID)
	if err != nil || canonicalBackupResponse(t, raw) != canonicalBackupResponse(t, again) {
		t.Fatal("receipt lost after history expiry", err)
	}
	// Live state is still intact; new previews remain possible for administrators.
	if _, err := s.previewConfigurationRestore(ctx, v, c, "operator", source, configurationRestoreOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationRestoreStageCancellationAuditFailure(t *testing.T) {
	s, v, c, _, p := configurationStageFixture(t)
	ctx := context.Background()
	raw, err := s.stageConfigurationRestore(ctx, v, c, "admin", "stage", p.Token)
	stage := configurationStageReceipt(t, raw, err)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_cancel_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='configuration-restore-cancel' THEN RAISE EXCEPTION 'synthetic audit failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_cancel BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_cancel_audit()`)
	if _, err := s.cancelConfigurationRestore(ctx, "admin", "cancel", stage.ID); err == nil {
		t.Fatal("audit failure ignored")
	}
	live, _, err := s.configurationRestoreStage(ctx, "admin", stage.ID)
	if err != nil || live.Status != "pending_validation" || tableCount(t, s, "v3_configuration_backup_pins") != 2 {
		t.Fatal("failed cancellation released protection", err)
	}
}

func TestConfigurationRestoreStageConcurrentIdempotency(t *testing.T) {
	s, v, c, _, p := configurationStageFixture(t)
	ctx := context.Background()
	start := make(chan struct{})
	results := make(chan []byte, 2)
	failures := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			raw, err := s.stageConfigurationRestore(ctx, v, c, "admin", "concurrent-stage", p.Token)
			results <- raw
			failures <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first []byte
	for result := range results {
		if first == nil {
			first = result
		} else if canonicalBackupResponse(t, first) != canonicalBackupResponse(t, result) {
			t.Fatal("concurrent stage changed receipt")
		}
	}
	if tableCount(t, s, "v3_configuration_restore_stages") != 1 || tableCount(t, s, "v3_configuration_backups") != 2 {
		t.Fatal("concurrent duplicate intent")
	}
}

func TestConfigurationRestoreStateGateBlocksEveryWriteAndAllowsIngest(t *testing.T) {
	s, v, _, _, _ := configurationStageFixture(t)
	ctx := context.Background()
	in := DeploymentRequest{Node: "saved-node", Kind: "install", Expected: 1, Credential: addCredential(t, s, v, "saved-node"), Release: "v3.0.0", SHA256: digest([]byte("synthetic-target"))}
	gate, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback()
	if err := lockConfigurationRestoreStateTx(ctx, gate); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"put-node", "save-node", "save-policy", "create-deployment", "raw-node", "raw-settings", "raw-job"} {
		t.Run(kind, func(t *testing.T) {
			op, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
			defer cancel()
			var err error
			switch kind {
			case "put-node":
				err = s.PutNode(op, nodeFixture("new-node"), 0, 256)
			case "save-node":
				_, err = s.SaveNode(op, "admin", "blocked-save", nodeFixture("saved-node"), 1, 256)
			case "save-policy":
				_, err = s.SaveRetentionPolicy(op, "admin", "blocked-policy", RetentionPolicy{30, 30, 30, 30, 30}, 6)
			case "create-deployment":
				_, err = s.CreateDeployment(op, "admin", "blocked-deployment", in)
			case "raw-node":
				_, err = s.DB.ExecContext(op, `UPDATE v3_nodes SET name='unexpected'`)
			case "raw-settings":
				_, err = s.DB.ExecContext(op, `UPDATE v3_settings SET version=version+1`)
			case "raw-job":
				_, err = s.DB.ExecContext(op, `DELETE FROM v3_deployment_jobs WHERE false`)
			}
			if err == nil || op.Err() == nil {
				t.Fatal("write bypassed relation gate", err)
			}
		})
	}
	// Row-level fences and shared settings reads must continue to work.
	n := nodeFixture("saved-node")
	l, err := s.Acquire(ctx, shardResource(n.Shard), "gate-collector")
	if err != nil {
		t.Fatal(err)
	}
	op, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	event := &agentv1.Event{Id: "during-stage", Json: common.JSON(common.Map{"node_id": n.ID, "event_id": "during-stage", "operation": "modify", "path": "/tmp/synthetic"})}
	accepted, _, err := s.Ingest(op, n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{event}})
	if err != nil || len(accepted) != 1 {
		t.Fatal("relation gate blocked event collection", err)
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("blocked deploy created a job")
	}
	if err := gate.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := s.PutNode(ctx, nodeFixture("new-node"), 0, 256); err != nil {
		t.Fatal("write remained blocked after release", err)
	}
}

func TestConfigurationRestoreStageLockWaitUsesFreshStateAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-state", true: "cancelled-wait"}[cancelled], func(t *testing.T) {
			s, v, c, _, p := configurationStageFixture(t)
			ctx := context.Background()
			blocker, err := s.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			if _, err := blocker.ExecContext(ctx, `UPDATE v3_nodes SET name='committed-before-lock-acquired'`); err != nil {
				t.Fatal(err)
			}
			op, cancel := context.WithCancel(ctx)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := s.stageConfigurationRestore(op, v, c, "admin", "waiting-stage", p.Token)
				result <- err
			}()
			deadline := time.Now().Add(3 * time.Second)
			for {
				var waiting bool
				if err := s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation='v3_nodes'::regclass AND mode='ShareRowExclusiveLock' AND NOT granted)`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("stage did not wait on relational gate")
				}
				time.Sleep(5 * time.Millisecond)
			}
			if cancelled {
				cancel()
			} else if err := blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("stale or cancelled stage accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("stage did not stop")
			}
			if tableCount(t, s, "v3_configuration_restore_stages") != 0 || tableCount(t, s, "v3_configuration_backups") != 1 || tableCount(t, s, "v3_configuration_restore_previews") != 1 {
				t.Fatal("wait failure partially committed")
			}
			if cancelled {
				if err := blocker.Rollback(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.DB.Exec(`UPDATE v3_nodes SET name=name`); err != nil {
				t.Fatal("cancel leaked table locks", err)
			}
		})
	}
	for _, level := range []sql.IsolationLevel{sql.LevelRepeatableRead, sql.LevelSerializable} {
		s := testStore(t)
		tx, err := s.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: level})
		if err != nil {
			t.Fatal(err)
		}
		if err := lockConfigurationRestoreStateTx(context.Background(), tx); err == nil {
			t.Fatal("old-snapshot isolation accepted")
		}
		tx.Rollback()
	}
}

func TestConfigurationRestoreStageSchema16BackupAndDisasterCancellation(t *testing.T) {
	s, v, c, _, p := configurationStageFixture(t)
	ctx := context.Background()
	dropConfigurationStagesForTest(t, s)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema16 upgraded without backup")
	}
	bad := filepath.Join(privateTestDir(t), "file")
	if err := os.WriteFile(bad, []byte("not-a-directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, bad); err == nil {
		t.Fatal("failed backup allowed schema17")
	}
	if version, _ := currentSchema(ctx, s.DB); version != 16 {
		t.Fatal("failed backup changed schema")
	}
	dir := privateTestDir(t)
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 1 {
		t.Fatal("no preupgrade archive")
	}
	old := emptyTestStore(t)
	if err := old.RestorePostgres(ctx, files[0]); err != nil {
		t.Fatal(err)
	}
	if version, _ := currentSchema(ctx, old.DB); version != 16 {
		t.Fatal("schema16 snapshot lost")
	}
	if err := old.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	raw, err := s.stageConfigurationRestore(ctx, v, c, "admin", "stage-before-disaster", p.Token)
	stage := configurationStageReceipt(t, raw, err)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'rollback','unrelated-durable-reference')`, stage.BeforeBackup)
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err := restored.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	live, _, err := restored.configurationRestoreStage(ctx, "admin", stage.ID)
	if err != nil || live.Status != "cancelled" || live.CancelledBy != "disaster-recovery" || tableCount(t, restored, "v3_configuration_backups") != 2 || tableCount(t, restored, "v3_configuration_backup_pins") != 1 {
		t.Fatal("disaster revived intent or dropped unrelated reference", err)
	}
	again, err := restored.stageConfigurationRestore(ctx, v, c, "admin", "stage-before-disaster", p.Token)
	if err != nil || canonicalBackupResponse(t, raw) != canonicalBackupResponse(t, again) {
		t.Fatal("disaster lost idempotency receipt", err)
	}
	live, _, err = restored.configurationRestoreStage(ctx, "admin", stage.ID)
	if err != nil || live.Status != "cancelled" {
		t.Fatal("receipt replay revived intent", err)
	}
}

func TestConfigurationRestoreStageContinuationRechecksArchivesIdentityAndCurrentState(t *testing.T) {
	for _, change := range []string{"none", "display-only", "current-settings", "current-node", "bootstrap", "account-revision", "other-admin", "cancelled", "source-pin", "before-pin", "before-ciphertext", "options"} {
		t.Run(change, func(t *testing.T) {
			s, v, c, _, p := configurationStageFixture(t)
			ctx := context.Background()
			raw, err := s.stageConfigurationRestore(ctx, v, c, "admin", "stage", p.Token)
			stage := configurationStageReceipt(t, raw, err)
			user := "admin"
			switch change {
			case "display-only":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_stages SET summary='{"removed":999,"can_prepare":false}'`)
			case "current-settings":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{retention,sqlite_events_days}','91')`)
			case "current-node":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET name='new-name'`)
			case "bootstrap":
				c.Central.Listen = "127.0.0.1:29443"
			case "account-revision":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "other-admin":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='admin' WHERE username='operator'`)
				user = "operator"
			case "cancelled":
				if _, err := s.cancelConfigurationRestore(ctx, "admin", "cancel", stage.ID); err != nil {
					t.Fatal(err)
				}
			case "source-pin":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1`, stage.Backup)
			case "before-pin":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1`, stage.BeforeBackup)
			case "before-ciphertext":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_backup_parts SET payload=decode('00','hex') WHERE backup=$1`, stage.BeforeBackup)
			case "options":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_stages SET options='{"use_backup_credentials":true}'`)
			}
			tx, err := s.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			plan, err := revalidateConfigurationStageTx(ctx, tx, v, c, user, stage.ID)
			if change == "none" || change == "display-only" {
				if err != nil || !plan.Summary.CanPrepare || !plan.Summary.RequiresLocalValidation || plan.Summary.Removed != 0 || common.F(common.M(plan.Candidate.Settings["retention"])["sqlite_events_days"]) != 60 {
					t.Fatal("continuation did not reconstruct authenticated target", err)
				}
			} else if err == nil {
				t.Fatal("invalidated intent continued")
			}
		})
	}
}
