package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/website"
)

func privateTestDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestPostgresBackupRestorePreservesRowsAndSequences(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Provision(ctx, "admin", "backup-password-123"); err != nil {
		t.Fatal(err)
	}
	n := nodeFixture("node-a")
	n.Config = json.RawMessage(`{"private":{"test_secret":"fixture-only"}}`)
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	site := savedSite(t, s, "backup")
	if _, err := s.DB.Exec(`UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"health_failures":true}}}'`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		job := claimSite(t, s, site.ID, "one")
		if err := s.ApplySiteResult(ctx, job, website.Result{Time: time.Now().Unix(), Reason: "中文故障"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`INSERT INTO v3_legacy_records VALUES('source','fixture','9007199254740993','{"large_integer":"9007199254740993","bytes":"AP8=","nullable":null}','digest')`); err != nil {
		t.Fatal(err)
	}
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, err)
	}
	header, err := inspectPGBackup(path)
	if err != nil || header.Version != SchemaVersion {
		t.Fatal(header, err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err = target.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"v3_accounts", "v3_nodes", "v3_websites", "v3_website_incidents", "v3_website_outbox", "v3_notifications", "v3_requests", "v3_audit", "v3_legacy_records"} {
		if tableCount(t, s, table) != tableCount(t, target, table) {
			t.Fatal("restore count", table)
		}
	}
	restored, err := target.Site(ctx, site.ID)
	if err != nil || restored.State.Status != "down" || restored.State.Incident == 0 {
		t.Fatal(restored, err)
	}
	var private []byte
	if err = target.DB.QueryRow("SELECT config FROM v3_nodes WHERE id='node-a'").Scan(&private); err != nil || !strings.Contains(string(private), "fixture-only") {
		t.Fatal(string(private), err)
	}
	var payload []byte
	if err = target.DB.QueryRow("SELECT payload FROM v3_legacy_records").Scan(&payload); err != nil || !strings.Contains(string(payload), "9007199254740993") {
		t.Fatal(string(payload), err)
	}
	added := savedSite(t, target, "after-restore")
	if added.ID <= site.ID {
		t.Fatal("identity sequence rewound", added.ID)
	}
	if err = s.RestorePostgres(ctx, path); err == nil {
		t.Fatal("restored over live schema")
	}
}

func TestPostgresMigrationRequiresVerifiedBackupAndStopsOnFailure(t *testing.T) {
	s := emptyTestStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	if err := putNode(ctx, s.DB, nodeFixture("node-a"), 0, 256); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("upgraded without backup")
	}
	publicDir := filepath.Join(privateTestDir(t), "public")
	if err := os.Mkdir(publicDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, publicDir); err == nil {
		t.Fatal("accepted insecure backup directory")
	}
	version, err := currentSchema(ctx, s.DB)
	if err != nil || version != 1 {
		t.Fatal("failed migration changed version", version, err)
	}
	var exists bool
	if err = s.DB.QueryRow("SELECT to_regclass(current_schema()||'.v3_websites') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatal("failed migration changed tables", exists, err)
	}
	directory := privateTestDir(t)
	if err = s.Upgrade(ctx, directory); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	backup := filepath.Join(directory, files[0].Name())
	header, err := inspectPGBackup(backup)
	if err != nil || header.Version != 1 {
		t.Fatal(header, err)
	}
	before := emptyTestStore(t)
	if err = before.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, before, "v3_nodes") != 1 {
		t.Fatal("pre-migration data missing")
	}
	version, err = currentSchema(ctx, before.DB)
	if err != nil || version != 1 {
		t.Fatal(version, err)
	}
	version, err = currentSchema(ctx, s.DB)
	if err != nil || version != SchemaVersion {
		t.Fatal(version, err)
	}
	if _, err = s.DB.Exec("INSERT INTO v3_schema(version) VALUES(999)"); err != nil {
		t.Fatal(err)
	}
	if err = s.Upgrade(ctx, privateTestDir(t)); err == nil {
		t.Fatal("downgraded newer schema")
	}
}

func TestPostgresBackupIsConsistentAcrossConcurrentWrites(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	site := savedSite(t, s, "snapshot")
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = currentSchema(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("UPDATE v3_websites SET name='after snapshot' WHERE id=$1", site.ID); err != nil {
		t.Fatal(err)
	}
	path, err := backupPostgres(ctx, tx, SchemaVersion, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	restored, err := target.Site(ctx, site.ID)
	if err != nil || restored.Name != site.Name {
		t.Fatal("mixed snapshot", restored, err)
	}
}

func TestPostgresRestoreRejectsCorruptionAndSymlink(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	savedSite(t, s, "corrupt")
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(privateTestDir(t), "corrupt.jsonl")
	raw = []byte(strings.Replace(string(raw), "corrupt.example.test", "changed.example.test", 1))
	if err = os.WriteFile(corrupt, raw, 0600); err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, corrupt); err == nil {
		t.Fatal("accepted modified backup")
	}
	if version, err := currentSchema(ctx, target.DB); err != nil || version != 0 {
		t.Fatal("corrupt restore touched database", version, err)
	}
	link := filepath.Join(privateTestDir(t), "linked.jsonl")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err = target.RestorePostgres(ctx, link); err == nil {
		t.Fatal("accepted symlink")
	}
	directory := privateTestDir(t)
	alias := filepath.Join(privateTestDir(t), "alias")
	if err = os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BackupPostgres(ctx, alias); err == nil {
		t.Fatal("wrote through symlink directory")
	}
	// Include the actual footer in the test to catch accidental scanner EOF
	// acceptance, instead of only testing syntactically invalid JSON.
	good, _ := os.ReadFile(path)
	last := strings.LastIndex(string(good), "{\"type\":\"footer\"")
	if last < 0 {
		t.Fatal("missing fixture footer")
	}
	if _, err = inspectPGReader(strings.NewReader(string(good[:last]))); err == nil {
		t.Fatal("accepted truncated backup")
	}
}

func TestPostgresBackupIncludesLargeTypedValues(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	value := common.JSON(common.Map{"integer": "9223372036854775807", "bytes": "AAECAw==", "text": "配置\n中文", "null": nil})
	if _, err := s.DB.Exec("INSERT INTO v3_legacy_records VALUES('s','t','k',$1,'d')", value); err != nil {
		t.Fatal(err)
	}
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err = target.DB.QueryRow("SELECT payload FROM v3_legacy_records").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var got, want map[string]any
	json.Unmarshal(raw, &got)
	json.Unmarshal(value, &want)
	if string(common.JSON(got)) != string(common.JSON(want)) {
		t.Fatal(got, want)
	}
}
