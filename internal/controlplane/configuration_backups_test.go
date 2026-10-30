package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"webscan/internal/common"
)

func dropConfigurationBackupsForTest(t *testing.T, s *Store) {
	t.Helper()
	dropConfigurationDeletesForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_configuration_backup_pins;DROP TABLE v3_configuration_backup_parts;DROP TABLE v3_configuration_backups;DELETE FROM v3_schema WHERE version>=14`)
}

func dropConfigurationDeletesForTest(t *testing.T, s *Store) {
	t.Helper()
	dropConfigurationRestoresForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_configuration_delete_items;DROP TABLE v3_configuration_delete_jobs;DROP TABLE v3_configuration_delete_previews;DELETE FROM v3_schema WHERE version>=15`)
}

func dropConfigurationRestoresForTest(t *testing.T, s *Store) {
	t.Helper()
	dropConfigurationStagesForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_configuration_restore_previews;DELETE FROM v3_schema WHERE version>=16`)
}

func dropConfigurationStagesForTest(t *testing.T, s *Store) {
	t.Helper()
	dropConfigurationRevisionsForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_configuration_restore_stages;DELETE FROM v3_schema WHERE version>=17`)
}

func dropConfigurationRevisionsForTest(t *testing.T, s *Store) {
	t.Helper()
	dropNodeRuntimeForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_configuration_revision_parts;DROP TABLE v3_configuration_revisions;DELETE FROM v3_schema WHERE version>=18`)
}

func configurationBackupStoreFixture(t *testing.T) (*Store, *Vault, Config) {
	t.Helper()
	s := testStore(t)
	v, _ := testVault(t)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('admin','not-a-login-hash','admin'),('operator','not-a-login-hash','operator'),('viewer','not-a-login-hash','viewer')`)
	n := nodeFixture("saved-node")
	n.Config = []byte(`{"private":{"token":"private-stored-node-value"}}`)
	if err := s.PutNode(context.Background(), n, 0, 256); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=5,payload='{"retention":{"sqlite_events_days":60},"email":{"enabled":false,"password":"private-stored-mail-value"}}'`)
	return s, v, configurationBootstrapFixture(t)
}

func configurationBackupReceiptID(t *testing.T, raw []byte, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	var b ConfigurationBackup
	if json.Unmarshal(raw, &b) != nil || !validArchiveSource(b.ID) || b.RecordKey != "configuration-backup:"+b.ID {
		t.Fatal("invalid safe backup receipt")
	}
	return b.ID
}

func readPrivateConfigurationBackup(t *testing.T, s *Store, v *Vault, id string) configurationDocument {
	t.Helper()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	doc, _, err := loadConfigurationBackup(context.Background(), tx, v, id, false)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestConfigurationBackupStorageIsEncryptedAtomicAndIdempotent(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx := context.Background()
	raw, err := s.createConfigurationBackup(ctx, v, c, "admin", "manual-key")
	id := configurationBackupReceiptID(t, raw, err)
	if bytes.Contains(raw, []byte("private-")) || bytes.Contains(raw, []byte("192.0.2")) || bytes.Contains(raw, []byte("key_id")) {
		t.Fatal("receipt disclosed configuration")
	}
	doc := readPrivateConfigurationBackup(t, s, v, id)
	if doc.SettingsVersion != 5 || len(doc.Nodes) != 1 || common.M(doc.Settings["email"])["password"] != "private-stored-mail-value" {
		t.Fatal("snapshot incomplete")
	}
	var cipher, receipts, audit []byte
	if err = s.DB.QueryRow(`SELECT payload FROM v3_configuration_backup_parts WHERE backup=$1 AND part=0`, id).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, []byte("private-stored-mail-value")) || bytes.Contains(cipher, []byte("format_version")) {
		t.Fatal("stored plaintext configuration")
	}
	if err = s.DB.QueryRow(`SELECT response::text FROM v3_requests WHERE key='manual-key'`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(`SELECT result::text FROM v3_audit WHERE kind='configuration-backup-create'`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(receipts, []byte("private-")) || bytes.Contains(audit, []byte("private-")) {
		t.Fatal("receipt/audit disclosed private source")
	}
	// Receipt replay does not recapture newly invalid live settings or create
	// another backup. The request still denotes the original snapshot.
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET config='{"resources":{"agent_memory_mib":1}}';UPDATE v3_settings SET version=6`)
	again, err := s.createConfigurationBackup(ctx, v, c, "admin", "manual-key")
	if err != nil || canonicalBackupResponse(t, raw) != canonicalBackupResponse(t, again) || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("receipt replay changed snapshot", err)
	}
	if _, err = s.createConfigurationBackup(ctx, v, c, "admin", "invalid-current"); err == nil || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("invalid capture partially committed", err)
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("backup activated work")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
	if _, err = s.createConfigurationBackup(ctx, v, c, "admin", "manual-key"); !errors.Is(err, ErrConfigurationBackupPermission) {
		t.Fatal("receipt bypassed current authorization", err)
	}
}

func TestConfigurationBackupImportDoesNotApplyAndRedactedReexport(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx := context.Background()
	source := configurationDocumentFixture(t, nodeFixture("imported-node"))
	public, err := source.redacted()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := marshalConfigurationDocument(public)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.importConfigurationBackup(ctx, v, "admin", "import-redacted", plain)
	id := configurationBackupReceiptID(t, raw, err)
	var receipt ConfigurationBackup
	json.Unmarshal(raw, &receipt)
	if !receipt.NeedsCompletion || receipt.Source != "import" {
		t.Fatal("redacted import presented as complete")
	}
	again, err := s.importConfigurationBackup(ctx, v, "admin", "import-redacted", plain)
	if err != nil || canonicalBackupResponse(t, raw) != canonicalBackupResponse(t, again) || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("import retry duplicated snapshot", err)
	}
	exported, err := s.exportConfigurationBackup(ctx, v, "admin", id)
	if err != nil || !bytes.Equal(plain, exported) {
		t.Fatal("redacted import cannot be reexported unchanged", err)
	}
	parsed, err := parseConfigurationDocument(exported)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsed.redacted()
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := marshalConfigurationDocument(second)
	if err != nil || !bytes.Equal(secondRaw, exported) {
		t.Fatal("redaction is not idempotent", err)
	}
	password := "isolated-transfer-password-2026"
	cipher, err := encryptConfigurationDocument(source, password, password)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = s.importEncryptedConfigurationBackup(ctx, v, "admin", "import-age", cipher, password)
	fullID := configurationBackupReceiptID(t, raw, err)
	stored := readPrivateConfigurationBackup(t, s, v, fullID)
	if common.M(stored.Settings["email"])["password"] != "private-mail-value" {
		t.Fatal("encrypted import lost source credentials")
	}
	sealed, err := s.exportEncryptedConfigurationBackup(ctx, v, "admin", fullID, password, password)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decryptConfigurationDocument(sealed, password)
	if err != nil || len(restored.Nodes) != 1 || restored.Nodes["imported-node"].Version != 1 {
		t.Fatal("age archive roundtrip failed", err)
	}
	var version int64
	var payload []byte
	if err = s.DB.QueryRow(`SELECT version,payload FROM v3_settings WHERE id=1`).Scan(&version, &payload); err != nil || version != 5 || !bytes.Contains(payload, []byte("private-stored-mail-value")) {
		t.Fatal("import applied runtime settings", err)
	}
	nodes, err := s.Nodes(ctx, "", "", 20, nil)
	if err != nil || len(nodes) != 1 || nodes[0].ID != "saved-node" || nodes[0].AppliedVersion != 0 {
		t.Fatal("import registered/applied nodes", err)
	}
	if tableCount(t, s, "v3_configuration_backup_pins") != 0 || tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("import/export left work or pins")
	}
	for _, user := range []string{"viewer", "operator", "missing"} {
		if _, err = s.configurationBackups(ctx, user, retentionCursor{}, 20); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("metadata permission", user, err)
		}
		if _, err = s.createConfigurationBackup(ctx, v, c, user, "denied-create"); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("create permission", user, err)
		}
		if _, err = s.importConfigurationBackup(ctx, v, user, "denied-import", plain); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("import permission", user, err)
		}
		if _, err = s.exportConfigurationBackup(ctx, v, user, id); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("export permission", user, err)
		}
		if _, err = s.importEncryptedConfigurationBackup(ctx, v, user, "denied-age", []byte("malformed"), password); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("unauthorized KDF admission", user, err)
		}
	}
}

func TestConfigurationBackupPinsProtectDeletionAndRelease(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx := context.Background()
	raw, err := s.createConfigurationBackup(ctx, v, c, "admin", "pin-backup")
	id := configurationBackupReceiptID(t, raw, err)
	ready, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := s.withConfigurationBackup(ctx, v, "admin", id, "redacted", func(configurationDocument) ([]byte, error) {
			close(ready)
			<-release
			return []byte("fixture export"), nil
		})
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("export did not acquire pin")
	}
	items, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(items) != 1 || items[0].CanDelete || items[0].DeleteReason != "正在导出" {
		close(release)
		t.Fatal("missing live export protection", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	deleted, reason, err := deleteConfigurationBackupTx(ctx, tx, id)
	tx.Rollback()
	if err != nil || deleted || reason != "正在导出" {
		close(release)
		t.Fatal("export pin ignored", reason, err)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_configuration_backup_pins") != 0 {
		t.Fatal("completed export left pin")
	}
	for _, kind := range []string{"restore", "deployment", "rollback"} {
		mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,$2,'durable-reference')`, id, kind)
		tx, err = s.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		deleted, reason, err = deleteConfigurationBackupTx(ctx, tx, id)
		tx.Rollback()
		if err != nil || deleted || reason != configurationBackupPinReason(kind) {
			t.Fatal("durable reference ignored", kind, err)
		}
		mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1`, id)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference,expires_at) VALUES($1,'export','expired',clock_timestamp()-interval '1 second')`, id)
	items, err = s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || !items[0].CanDelete {
		t.Fatal("expired transfer remains protected", err)
	}
	tx, err = s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if deleted, reason, err = deleteConfigurationBackupTx(ctx, tx, id); err != nil || !deleted || reason != "" {
		t.Fatal("independent recent backup was not deletable", reason, err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"v3_configuration_backups", "v3_configuration_backup_parts", "v3_configuration_backup_pins"} {
		if tableCount(t, s, table) != 0 {
			t.Fatal("orphaned backup data", table)
		}
	}
}

func TestConfigurationBackupChunkIntegrityAndFailureAtomicity(t *testing.T) {
	s, v, _ := configurationBackupStoreFixture(t)
	ctx := context.Background()
	node := nodeFixture("large-node")
	node.Config = common.JSON(common.Map{"future_private": strings.Repeat("private-chunk-marker", 65000)})
	doc := configurationDocumentFixture(t, node)
	plain, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.importConfigurationBackup(ctx, v, "admin", "large-import", plain)
	id := configurationBackupReceiptID(t, raw, err)
	if tableCount(t, s, "v3_configuration_backup_parts") < 2 {
		t.Fatal("fixture did not cross part boundary")
	}
	for name, query := range map[string]string{
		"ciphertext":   `UPDATE v3_configuration_backup_parts SET payload=set_byte(payload,0,get_byte(payload,0)#1) WHERE backup=$1 AND part=0`,
		"missing-part": `DELETE FROM v3_configuration_backup_parts WHERE backup=$1 AND part=0`,
		"metadata":     `UPDATE v3_configuration_backups SET node_count=node_count+1 WHERE id=$1`,
		"source":       `UPDATE v3_configuration_backups SET source='before_edit' WHERE id=$1`,
		"key":          `UPDATE v3_configuration_backups SET key_id='unknown-key' WHERE id=$1`,
		"nonce":        `UPDATE v3_configuration_backups SET nonce='\x00' WHERE id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := s.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(ctx, query, id); err != nil {
				t.Fatal(err)
			}
			if _, _, err = loadConfigurationBackup(ctx, tx, v, id, false); !errors.Is(err, ErrConfigurationBackupKey) {
				t.Fatal("corrupted archive accepted or source leaked", err)
			}
		})
	}
	_ = readPrivateConfigurationBackup(t, s, v, id)
	beforeRequests, beforeAudit := tableCount(t, s, "v3_requests"), tableCount(t, s, "v3_audit")
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_configuration_part() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic disk failure'; END $$;CREATE TRIGGER fail_configuration_part BEFORE INSERT ON v3_configuration_backup_parts FOR EACH ROW EXECUTE FUNCTION fail_configuration_part()`)
	if _, err = s.importConfigurationBackup(ctx, v, "admin", "failed-import", plain); err == nil {
		t.Fatal("injected storage failure ignored")
	}
	if tableCount(t, s, "v3_configuration_backups") != 1 || tableCount(t, s, "v3_requests") != beforeRequests || tableCount(t, s, "v3_audit") != beforeAudit {
		t.Fatal("failed insert left metadata, receipt or audit")
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER fail_configuration_part ON v3_configuration_backup_parts;DROP FUNCTION fail_configuration_part()`)
	if _, err = s.importConfigurationBackup(ctx, v, "admin", "failed-import", plain); err != nil {
		t.Fatal("rolled-back import cannot retry", err)
	}
	archive, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, archive); err != nil {
		t.Fatal("multipart disaster restore failed", err)
	}
	if tableCount(t, restored, "v3_configuration_backups") != 2 || tableCount(t, restored, "v3_configuration_backup_parts") != tableCount(t, s, "v3_configuration_backup_parts") {
		t.Fatal("multipart archive was truncated")
	}
	restoredDoc := readPrivateConfigurationBackup(t, restored, v, id)
	encoded, err := marshalConfigurationDocument(restoredDoc)
	if err != nil || !bytes.Equal(encoded, plain) {
		t.Fatal("multipart document changed after disaster recovery", err)
	}
}

func TestConfigurationBackupVaultRotationAndExportCleanupFailure(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx := context.Background()
	raw, err := s.createConfigurationBackup(ctx, v, c, "admin", "rotate-backup")
	id := configurationBackupReceiptID(t, raw, err)
	newOnly, newPath := testVault(t)
	// Reconstruct old key-file path from a separate fixture: this backup is
	// recreated under that known key before exercising the rotation chain.
	old, oldPath := testVault(t)
	raw, err = s.createConfigurationBackup(ctx, old, c, "admin", "known-old-key")
	oldID := configurationBackupReceiptID(t, raw, err)
	rotating, err := OpenVault(newPath, oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.rewrapConfigurationBackup(ctx, rotating, oldID); err != nil {
		t.Fatal(err)
	}
	_ = readPrivateConfigurationBackup(t, s, newOnly, oldID)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = loadConfigurationBackup(ctx, tx, old, oldID, false)
	tx.Rollback()
	if !errors.Is(err, ErrConfigurationBackupKey) {
		t.Fatal("old key still opens rewrapped ciphertext", err)
	}
	var rev int64
	if err = s.DB.QueryRow(`SELECT revision FROM v3_configuration_backups WHERE id=$1`, oldID).Scan(&rev); err != nil || rev != 2 {
		t.Fatal("rotation did not preserve/version identity", err)
	}
	if err = s.rewrapConfigurationBackup(ctx, newOnly, oldID); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(`SELECT revision FROM v3_configuration_backups WHERE id=$1`, oldID).Scan(&rev); err != nil || rev != 2 {
		t.Fatal("same-key rewrap changed revision", err)
	}
	_, err = s.withConfigurationBackup(ctx, v, "admin", id, "redacted", func(configurationDocument) ([]byte, error) { return nil, errors.New("synthetic projection failure") })
	if err == nil || tableCount(t, s, "v3_configuration_backup_pins") != 0 {
		t.Fatal("failed output left transfer pinned", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	_, err = s.withConfigurationBackup(cancelled, v, "admin", id, "redacted", func(configurationDocument) ([]byte, error) { cancel(); return []byte("fixture"), nil })
	if err == nil || tableCount(t, s, "v3_configuration_backup_pins") != 0 {
		t.Fatal("cancelled output left transfer pinned", err)
	}
}

func TestConfigurationBackupDisasterRestorePreservesCipherAndDurableReferences(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx := context.Background()
	raw, err := s.createConfigurationBackup(ctx, v, c, "admin", "disaster-config")
	id := configurationBackupReceiptID(t, raw, err)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference,expires_at) VALUES($1,'export','in-flight',clock_timestamp()+interval '5 minutes'),($1,'rollback','rollback-needed',NULL)`, id)
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, restored, "v3_configuration_backups") != 1 || tableCount(t, restored, "v3_configuration_backup_pins") != 1 {
		t.Fatal("restore lost archive or revived transfer pin")
	}
	_ = readPrivateConfigurationBackup(t, restored, v, id)
	items, err := restored.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(items) != 1 || items[0].CanDelete || items[0].DeleteReason != "回退需要" {
		t.Fatal("restore lost rollback protection", err)
	}
	if _, err = restored.exportConfigurationBackup(ctx, v, "admin", id); err != nil {
		t.Fatal("restored encrypted archive unreadable", err)
	}
	if tableCount(t, restored, "v3_nodes") != 1 || tableCount(t, restored, "v3_accounts") != 3 {
		t.Fatal("disaster restore lost prior data")
	}
}

func TestConfigurationBackupSchema13UpgradeRequiresVerifiedBackup(t *testing.T) {
	s, _, _ := configurationBackupStoreFixture(t)
	ctx := context.Background()
	dropConfigurationBackupsForTest(t, s)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema13 upgraded without backup")
	}
	bad := filepath.Join(privateTestDir(t), "file")
	if err := os.WriteFile(bad, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, bad); err == nil {
		t.Fatal("failed backup allowed schema change")
	}
	if version, err := currentSchema(ctx, s.DB); err != nil || version != 13 {
		t.Fatal("failed migration changed version", err)
	}
	dir := privateTestDir(t)
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatal("missing pre-upgrade archive", err)
	}
	header, err := inspectPGBackup(files[0])
	if err != nil || header.Version != 13 {
		t.Fatal("wrong migration archive", err)
	}
	old := emptyTestStore(t)
	if err = old.RestorePostgres(ctx, files[0]); err != nil {
		t.Fatal(err)
	}
	if version, err := currentSchema(ctx, old.DB); err != nil || version != 13 || tableCount(t, old, "v3_nodes") != 1 {
		t.Fatal("schema13 source snapshot not restorable", err)
	}
	if err = old.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal("restored schema13 cannot upgrade", err)
	}
	if version, err := currentSchema(ctx, s.DB); err != nil || version != SchemaVersion {
		t.Fatal("upgrade incomplete", err)
	}
	if err = s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	files, _ = filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 1 {
		t.Fatal("current schema unnecessarily rebacked")
	}
}

func TestConfigurationBackupConcurrentCreationHasOneReceipt(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	var wg sync.WaitGroup
	out := make(chan []byte, 2)
	failures := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for attempt := 0; attempt < 3; attempt++ {
				raw, err := s.createConfigurationBackup(ctx, v, c, "admin", "concurrent-key")
				if err == nil {
					out <- raw
					return
				}
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "40001" {
					failures <- err
					return
				}
			}
			failures <- errors.New("serialization retries exhausted")
		}()
	}
	close(start)
	wg.Wait()
	close(out)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var first []byte
	count := 0
	for raw := range out {
		count++
		if first == nil {
			first = raw
		} else if canonicalBackupResponse(t, first) != canonicalBackupResponse(t, raw) {
			t.Fatal("concurrent receipts differed")
		}
	}
	if count != 2 || tableCount(t, s, "v3_configuration_backups") != 1 || tableCount(t, s, "v3_requests") != 1 || tableCount(t, s, "v3_audit") != 1 {
		t.Fatal("duplicate concurrent snapshot or receipt")
	}
}

func TestConfigurationBackupMetadataPaginationAndMigrationProtection(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		raw, err := s.createConfigurationBackup(ctx, v, c, "admin", fmt.Sprintf("page-%d", i))
		_ = configurationBackupReceiptID(t, raw, err)
	}
	first, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 2)
	if err != nil || len(first) != 2 {
		t.Fatal(err)
	}
	last := first[1]
	second, err := s.configurationBackups(ctx, "admin", retentionCursor{last.Created, last.ID}, 2)
	if err != nil || len(second) != 1 || second[0].ID == first[0].ID || second[0].ID == last.ID {
		t.Fatal("unstable metadata page", err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source,pending) VALUES('settings',$1,true)`, strings.Repeat("a", 64))
	items, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil || len(items) != 3 {
		t.Fatal(err)
	}
	for _, b := range items {
		if b.CanDelete || b.DeleteReason != "数据迁移期间保护备份" {
			t.Fatal("migration protection missing")
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	deleted, reason, err := deleteConfigurationBackupTx(ctx, tx, first[0].ID)
	if err != nil || deleted || reason != "数据迁移期间保护备份" {
		t.Fatal("delete ignored migration", err)
	}
}
