package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"webscan/internal/common"
)

func configurationRestoreFixture(t *testing.T) (*Store, *Vault, Config, string) {
	t.Helper()
	s, v, c := configurationBackupStoreFixture(t)
	raw, err := s.createConfigurationBackup(context.Background(), v, c, "admin", "restore-source")
	return s, v, c, configurationBackupReceiptID(t, raw, err)
}

func revalidateConfigurationRestoreForTest(t *testing.T, s *Store, v *Vault, c Config, user, preview string) (configurationRestorePlan, error) {
	t.Helper()
	tx, err := s.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	return revalidateConfigurationRestoreTx(context.Background(), tx, v, c, user, preview)
}

func TestConfigurationRestorePreviewDurablePrivateAndNonApplying(t *testing.T) {
	s, v, c, id := configurationRestoreFixture(t)
	ctx := context.Background()
	p, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{})
	if err != nil || !validArchiveSource(p.Token) || !p.Summary.CanPrepare || !p.Summary.RequiresLocalValidation || p.Summary.Unchanged != 1 {
		t.Fatal("preview failed", err, p.Summary)
	}
	if d := time.Until(p.Expires); d < 9*time.Minute || d > 11*time.Minute {
		t.Fatal("not a ten-minute preview")
	}
	raw, _ := json.Marshal(p)
	var row, audit []byte
	if err := s.DB.QueryRow(`SELECT row_to_json(p) FROM v3_configuration_restore_previews p`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT result FROM v3_audit WHERE kind='configuration-restore-preview'`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{raw, row, audit} {
		for _, secret := range []string{"private-stored", "192.0.2", "smtp", "dsn_file", "vault_key_file"} {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatal("preview leaked private configuration")
			}
		}
	}
	if bytes.Contains(row, []byte(p.Token)) {
		t.Fatal("stored bearer token")
	}
	// Fresh Store/Vault instances stand in for process restart. Capture timestamp
	// changes without invalidating otherwise identical desired configuration.
	fresh := &Store{DB: s.DB}
	freshVault := &Vault{active: v.active, keys: v.keys, receiptKeys: v.receiptKeys}
	plan, err := revalidateConfigurationRestoreForTest(t, fresh, freshVault, c, "admin", p.Token)
	if err != nil || !plan.Summary.CanPrepare || plan.Summary.Unchanged != 1 {
		t.Fatal("restart invalidated stable preview", err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_previews SET summary='{"can_prepare":false,"removed":999}'`)
	plan, err = revalidateConfigurationRestoreForTest(t, fresh, freshVault, c, "admin", p.Token)
	if err != nil || !plan.Summary.CanPrepare || plan.Summary.Removed != 0 {
		t.Fatal("trusted persisted summary as executable plan", err)
	}
	list, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(list) != 1 || list[0].CanDelete || list[0].DeleteReason == "" {
		t.Fatal("preview failed to protect source", err)
	}
	deletion := configurationDeletePreviewForTest(t, s, id)
	if deletion.Eligible != 0 || deletion.Protected != 1 {
		t.Fatal("deletion bypassed restore pin")
	}
	if tableCount(t, s, "v3_configuration_backups") != 1 || tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("preview applied work or created automatic backup")
	}
	var version int64
	if err := s.DB.QueryRow(`SELECT version FROM v3_settings WHERE id=1`).Scan(&version); err != nil || version != 5 {
		t.Fatal("preview changed live settings", err)
	}
}

func TestConfigurationRestorePreviewInvalidatesStateAndAuthorization(t *testing.T) {
	for _, name := range []string{"settings-version", "settings-unversioned", "node-version", "node-unversioned", "new-node", "removed-node", "bootstrap", "account-revision", "account-demotion", "expiry", "pin-expiry", "pin-missing", "options", "archive-proof", "state-proof", "backup-identity", "migration", "wrong-account", "busy-deployment", "completed-deployment"} {
		t.Run(name, func(t *testing.T) {
			s, v, c, id := configurationRestoreFixture(t)
			ctx := context.Background()
			p, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{})
			if err != nil {
				t.Fatal(err)
			}
			user := "admin"
			switch name {
			case "settings-version":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
			case "settings-unversioned":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{retention,sqlite_events_days}','61')`)
			case "node-version":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET version=version+1`)
			case "node-unversioned":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET name='changed-name'`)
			case "new-node":
				if err := s.PutNode(ctx, nodeFixture("new-node"), 0, 256); err != nil {
					t.Fatal(err)
				}
			case "removed-node":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_node_runtime;DELETE FROM v3_node_configurations;DELETE FROM v3_nodes`)
			case "bootstrap":
				c.Central.Listen = "127.0.0.1:29443"
			case "account-revision":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "account-demotion":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			case "expiry":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_previews SET expires_at=clock_timestamp()-interval '1 second'`)
			case "pin-expiry":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_backup_pins SET expires_at=clock_timestamp()-interval '1 second'`)
			case "pin-missing":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins`)
			case "options":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_previews SET options='{"use_backup_credentials":true}'`)
			case "archive-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_previews SET archive_proof=repeat('a',64)`)
			case "state-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_previews SET state_proof=repeat('a',64)`)
			case "backup-identity":
				doc := readPrivateConfigurationBackup(t, s, v, id)
				body, _ := marshalConfigurationDocument(doc)
				raw, e := s.importConfigurationBackup(ctx, v, "admin", "other-source", body)
				other := configurationBackupReceiptID(t, raw, e)
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_previews SET backup=$1`, other)
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_backup_pins SET backup=$1`, other)
			case "migration":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source,pending) VALUES('settings',repeat('a',64),true)`)
			case "wrong-account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='admin' WHERE username='operator'`)
				user = "operator"
			case "busy-deployment", "completed-deployment":
				// Deliberately synthetic state only; no executor is started.
				status := "queued"
				if name == "completed-deployment" {
					status = "succeeded"
				}
				mustHistoryExec(t, s.DB, `INSERT INTO v3_credentials(id,node,key_id,nonce,ciphertext) VALUES('synthetic-credential','saved-node','unused',''::bytea,''::bytea)`)
				mustHistoryExec(t, s.DB, `INSERT INTO v3_deployment_jobs(id,node,username,credential,kind,node_version,plan,plan_digest,status) VALUES('synthetic-job','saved-node','admin','synthetic-credential','upgrade',1,'{}',repeat('b',64),$1)`, status)
			}
			if _, err := revalidateConfigurationRestoreForTest(t, s, v, c, user, p.Token); err == nil {
				t.Fatal("stale preview accepted")
			}
		})
	}
}

func TestConfigurationRestorePreviewKeyRotationAndProofBoundaries(t *testing.T) {
	s, v, c, id := configurationRestoreFixture(t)
	ctx := context.Background()
	p, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	newVault, _ := testVault(t)
	newVault.keys[v.active], newVault.receiptKeys[v.active] = v.keys[v.active], v.receiptKeys[v.active]
	if err := s.rewrapConfigurationBackup(ctx, newVault, id); err != nil {
		t.Fatal(err)
	}
	if _, err := revalidateConfigurationRestoreForTest(t, s, newVault, c, "admin", p.Token); err != nil {
		t.Fatal("rewrap changed logical archive binding", err)
	}
	delete(newVault.receiptKeys, v.active)
	if _, err := revalidateConfigurationRestoreForTest(t, s, newVault, c, "admin", p.Token); err == nil {
		t.Fatal("removed proof key accepted")
	}
	doc := readPrivateConfigurationBackup(t, s, newVault, id)
	proof, err := configurationRestoreProof(v, v.active, "archive", "admin", 1, configurationRestoreOptions{}, doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if configurationRestoreProofMatches(v, proof, "state", "admin", 1, configurationRestoreOptions{}, doc, nil) || configurationRestoreProofMatches(v, proof, "archive", "other", 1, configurationRestoreOptions{}, doc, nil) || configurationRestoreProofMatches(v, proof, "archive", "admin", 2, configurationRestoreOptions{}, doc, nil) || configurationRestoreProofMatches(v, proof, "archive", "admin", 1, configurationRestoreOptions{true}, doc, nil) {
		t.Fatal("proof crossed domain/account/options boundary")
	}
}

func TestConfigurationRestorePreviewAtomicAuditAndPermission(t *testing.T) {
	s, v, c, id := configurationRestoreFixture(t)
	ctx := context.Background()
	for _, user := range []string{"viewer", "operator", "missing"} {
		if _, err := s.previewConfigurationRestore(ctx, v, c, user, id, configurationRestoreOptions{}); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("unauthorized preview", user, err)
		}
	}
	mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_restore_preview_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='configuration-restore-preview' THEN RAISE EXCEPTION 'isolated failure';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_restore_preview BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION reject_restore_preview_audit()`)
	if _, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{}); err == nil || tableCount(t, s, "v3_configuration_restore_previews") != 0 || tableCount(t, s, "v3_configuration_backup_pins") != 0 {
		t.Fatal("audit failure partially committed preview")
	}
}

func TestConfigurationRestorePreviewQuotaConcurrentAndHousekeeping(t *testing.T) {
	s, v, c, id := configurationRestoreFixture(t)
	ctx := context.Background()
	p, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_restore_previews(token_hash,username,account_revision,backup,options,archive_proof,state_proof,summary) SELECT md5(i::text),'admin',1,$1,'{}','','','{}' FROM generate_series(1,98) i`, id)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 || tableCount(t, s, "v3_configuration_restore_previews") != 100 {
		t.Fatal("concurrent quota exceeded")
	}
	if _, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{}); !errors.Is(err, errConfigurationRestoreQuota) {
		t.Fatal("quota did not reject", err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_previews SET expires_at=clock_timestamp()-interval '1 second';UPDATE v3_configuration_backup_pins SET expires_at=clock_timestamp()-interval '1 second'`)
	if err := s.Housekeeping(ctx, "restore-preview-cleaner"); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_configuration_restore_previews") != 0 || tableCount(t, s, "v3_configuration_backup_pins") != 0 || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("expired preview cleanup damaged archive")
	}
	if _, err := revalidateConfigurationRestoreForTest(t, s, v, c, "admin", p.Token); err == nil {
		t.Fatal("cleaned preview revived")
	}
}

func TestConfigurationRestorePreviewSchema15BackupAndDisasterRecovery(t *testing.T) {
	s, v, c, id := configurationRestoreFixture(t)
	ctx := context.Background()
	dropConfigurationRestoresForTest(t, s)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema15 upgraded without backup")
	}
	bad := filepath.Join(privateTestDir(t), "file")
	if err := os.WriteFile(bad, []byte("not-a-directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, bad); err == nil {
		t.Fatal("failed backup allowed schema16")
	}
	if version, _ := currentSchema(ctx, s.DB); version != 15 {
		t.Fatal("failed backup changed version")
	}
	dir := privateTestDir(t)
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 1 {
		t.Fatal("missing pre-upgrade backup")
	}
	old := emptyTestStore(t)
	if err := old.RestorePostgres(ctx, files[0]); err != nil {
		t.Fatal(err)
	}
	if version, _ := currentSchema(ctx, old.DB); version != 15 {
		t.Fatal("old backup not restored at source schema")
	}
	if err := old.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	p, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'rollback','durable-checkpoint')`, id)
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err := restored.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, restored, "v3_configuration_restore_previews") != 0 || tableCount(t, restored, "v3_configuration_backup_pins") != 1 || tableCount(t, restored, "v3_configuration_backups") != 1 {
		t.Fatal("disaster recovery revived preview or lost durable reference")
	}
	if _, err := revalidateConfigurationRestoreForTest(t, restored, v, c, "admin", p.Token); err == nil {
		t.Fatal("disaster recovery revived old capability")
	}
	if _, err := s.previewConfigurationRestore(ctx, nil, c, "admin", id, configurationRestoreOptions{}); err == nil {
		t.Fatal("missing vault accepted")
	}
}

func TestConfigurationRestorePreviewBlockedSourceIsExplainedAndPendingDeleteRejected(t *testing.T) {
	s, v, c, id := configurationRestoreFixture(t)
	ctx := context.Background()
	doc := readPrivateConfigurationBackup(t, s, v, id)
	doc.Nodes = map[string]configurationDocumentNode{}
	doc.Profiles = map[string]configurationDocumentRules{}
	plain, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.importConfigurationBackup(ctx, v, "admin", "removed-node-source", plain)
	other := configurationBackupReceiptID(t, raw, err)
	p, err := s.previewConfigurationRestore(ctx, v, c, "admin", other, configurationRestoreOptions{})
	if err != nil || p.Summary.CanPrepare || p.Summary.Removed != 1 || !strings.Contains(string(common.JSON(p.Summary.BlockedReasons)), "node_uninstall_required") {
		t.Fatal("blocked restore presented as applicable", err)
	}
	preview := configurationDeletePreviewForTest(t, s, id)
	_ = configurationDeleteQueueForTest(t, s, preview, "pending-delete")
	if _, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{}); !errors.Is(err, ErrConflict) {
		t.Fatal("pending deletion accepted restore pin", err)
	}
}

func TestConfigurationRestorePreviewPinsProtectPreviouslyPreviewedDelete(t *testing.T) {
	s, v, c, id := configurationRestoreFixture(t)
	ctx := context.Background()
	deletion := configurationDeletePreviewForTest(t, s, id)
	if deletion.Eligible != 1 {
		t.Fatal("source was unexpectedly protected before preview")
	}
	p, err := s.previewConfigurationRestore(ctx, v, c, "admin", id, configurationRestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	j := configurationDeleteQueueForTest(t, s, deletion, "earlier-delete-preview")
	finished := drainConfigurationDelete(t, s, configurationDeleteLease(t, s, "preview-pin-cleaner"), j.ID)
	if finished.Deleted != 0 || finished.Skipped != 1 || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("old delete preview bypassed new restore pin")
	}
	if _, err := revalidateConfigurationRestoreForTest(t, s, v, c, "admin", p.Token); err != nil {
		t.Fatal("skipped backup deletion invalidated stable restore", err)
	}
}
