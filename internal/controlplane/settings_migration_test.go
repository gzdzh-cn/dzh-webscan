package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/assets"
	"webscan/internal/common"
)

func legacySettingsFixture(t *testing.T) common.Map {
	t.Helper()
	raw, err := assets.Files.ReadFile("configuration-example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var m common.Map
	if err = yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	common.M(m["feishu"])["webhook_url"] = "https://open.feishu.cn/open-apis/bot/v2/hook/private-settings-token"
	common.M(m["feishu"])["signing_secret"] = "private-settings-signing-secret"
	common.M(m["email"])["password"] = "private-settings-email-password"
	common.M(common.M(m["central"])["website_monitor"])["admin_password"] = "private-settings-admin-password"
	common.M(m["registry"])["password"] = "private-settings-registry-password"
	for _, n := range common.A(m["nodes"]) {
		common.M(common.M(n)["ssh"])["password"] = "private-settings-ssh-password"
	}
	return m
}

func writeLegacySettings(t *testing.T, m common.Map) string {
	t.Helper()
	raw, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.yaml")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLegacySettingsPreviewInheritanceAndExcludedCredentials(t *testing.T) {
	m := legacySettingsFixture(t)
	r := common.M(m["retention"])
	r["sqlite_events_days"] = 87
	delete(r, "security_events_days")
	delete(r, "server_alerts_days")
	common.M(common.M(m["central"])["monitoring"])["history_days"] = 47
	raw, _ := yaml.Marshal(m)
	settings, report, err := legacySettings(raw)
	if err != nil || report.Policy != (RetentionPolicy{87, 87, 30, 47, 30}) || report.Complete || report.ReadyForCutover {
		t.Fatal(report, err)
	}
	encoded := string(common.JSON(settings))
	for _, secret := range []string{"private-settings-admin-password", "private-settings-registry-password", "private-settings-ssh-password", "admin_username", "private_key_path", "nodes", "host_metrics", "existing_env_file"} {
		if strings.Contains(encoded, secret) {
			t.Fatal("excluded deployment credentials entered runtime settings", secret)
		}
	}
	if !strings.Contains(encoded, "private-settings-email-password") || !strings.Contains(encoded, "private-settings-signing-secret") {
		t.Fatal("notification credentials not preserved internally")
	}
	preview, err := PreviewLegacySettings(writeLegacySettings(t, m))
	if err != nil || preview.Source != report.Source || strings.Contains(string(common.JSON(preview)), "private-settings") {
		t.Fatal("unsafe preview", err)
	}
	// Deployment-only changes neither leak nor invalidate the scoped import.
	common.M(m["registry"])["password"] = "another-registry-password"
	raw, _ = yaml.Marshal(m)
	_, second, err := legacySettings(raw)
	if err != nil || second.Source != report.Source {
		t.Fatal("deployment-only data entered settings identity", err)
	}
	common.M(m["email"])["password"] = "replacement-email-password"
	common.M(m["feishu"])["webhook_url"] = "https://open.feishu.cn/open-apis/bot/v2/hook/replacement-token"
	raw, _ = yaml.Marshal(m)
	_, second, err = legacySettings(raw)
	if err != nil || second.Source != report.Source {
		t.Fatal("public identity is an offline credential oracle", err)
	}
}

func TestLegacySettingsRejectsUnsafeFilesAndSecretDiagnostics(t *testing.T) {
	path := writeLegacySettings(t, legacySettingsFixture(t))
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewLegacySettings(link); err == nil {
		t.Fatal("symlink source accepted")
	}
	for _, tc := range []struct {
		name string
		body string
		mode os.FileMode
	}{
		{"public", "config_version: 2", 0644},
		{"empty", "", 0600},
		{"large", strings.Repeat("x", (2<<20)+1), 0600},
		{"duplicate", "config_version: 2\nconfig_version: private-settings-value", 0600},
		{"multiple", "config_version: 2\n---\nprivate-settings-value: true", 0600},
		{"syntax", "config_version: [private-settings-value", 0600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad.yaml")
			if err := os.WriteFile(p, []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := PreviewLegacySettings(p); err == nil || strings.Contains(err.Error(), "private-settings") {
				t.Fatal("invalid source accepted or leaked")
			}
		})
	}
	m := legacySettingsFixture(t)
	common.M(m["feishu"])["mode"] = "existing_env"
	common.M(m["feishu"])["existing_env_file"] = "/not-read/private-settings-env"
	if _, err := PreviewLegacySettings(writeLegacySettings(t, m)); err == nil || strings.Contains(err.Error(), "private-settings") {
		t.Fatal("external environment silently accepted or leaked")
	}
	common.M(m["feishu"])["enabled"] = false
	if _, err := PreviewLegacySettings(writeLegacySettings(t, m)); err != nil {
		t.Fatal("disabled channel unnecessarily opened an external file", err)
	}
}

func TestLegacySettingsAtomicImportBackupFreezeAndRestore(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	m := legacySettingsFixture(t)
	common.M(m["retention"])["sqlite_events_days"] = 91
	delete(common.M(m["retention"]), "security_events_days")
	path := writeLegacySettings(t, m)
	if r, err := s.ImportLegacySettings(ctx, path, ""); err == nil || r.Complete || tableCount(t, s, "v3_migration_domains") != 0 {
		t.Fatal("missing backup accepted", err)
	}
	badDir := filepath.Join(t.TempDir(), "public-backup")
	if err := os.Mkdir(badDir, 0755); err != nil {
		t.Fatal(err)
	}
	if r, err := s.ImportLegacySettings(ctx, path, badDir); err == nil || r.Complete || tableCount(t, s, "v3_migration_domains") != 0 {
		t.Fatal("failed backup mutated configuration", err)
	}
	dir := filepath.Join(t.TempDir(), "before")
	r, err := s.ImportLegacySettings(ctx, path, dir)
	if err != nil || !r.Complete || r.ReadyForCutover || r.Version != 2 || r.Policy.Security != 91 {
		t.Fatal(r, err)
	}
	before, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(before) != 1 {
		t.Fatal(before, err)
	}
	old := emptyTestStore(t)
	if err = old.RestorePostgres(ctx, before[0]); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err = old.DB.QueryRow(`SELECT payload::text FROM v3_settings`).Scan(&raw); err != nil || raw != "{}" || tableCount(t, old, "v3_migration_domains") != 0 {
		t.Fatal("backup did not capture pre-import state", err)
	}
	for range 2 {
		again, e := s.ImportLegacySettings(ctx, path, "")
		if e != nil || !again.Complete || again.Version != 2 {
			t.Fatal("lost-response repeat changed settings", again, e)
		}
	}
	if tableCount(t, s, "v3_audit") != 1 {
		t.Fatal("repeat duplicated audit")
	}
	var private bool
	if err = s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM v3_audit WHERE result::text LIKE '%private-settings%')`).Scan(&private); err != nil || private {
		t.Fatal("audit leaked settings", err)
	}
	if _, err = s.SaveRetentionPolicy(ctx, "admin", "not-live", r.Policy, 2); err != ErrMigrationPending {
		t.Fatal("import unblocked runtime writes", err)
	}
	l, err := s.Acquire(ctx, "retention", "frozen-retention")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ScheduleRetention(ctx, l); err != ErrMigrationPending {
		t.Fatal("import started cleanup", err)
	}
	if n, err := s.claimNotification(ctx, "feishu", "frozen-notifier"); err != nil || n != nil {
		t.Fatal("import activated channel", err)
	}
	backup, err := s.BackupPostgres(ctx, filepath.Join(t.TempDir(), "after"))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	view, err := restored.RetentionPolicy(ctx)
	if err != nil || view.Policy != r.Policy || view.Version != 2 || tableCount(t, restored, "v3_migration_domains") != 1 {
		t.Fatal("restore lost policy or migration fence", view, err)
	}
	common.M(m["retention"])["sqlite_events_days"] = 92
	if r, err := s.ImportLegacySettings(ctx, writeLegacySettings(t, m), dir); err == nil || r.Complete {
		t.Fatal("changed source overwrote imported settings")
	}
	common.M(m["retention"])["sqlite_events_days"] = 91
	common.M(m["email"])["password"] = "replacement-email-password"
	if changed, err := s.ImportLegacySettings(ctx, writeLegacySettings(t, m), dir); err == nil || changed.Complete || changed.Source != r.Source {
		t.Fatal("same public identity bypassed private payload check", err)
	}
}

func TestLegacySettingsRejectsLiveTargetsAndRollsBackPartialFailure(t *testing.T) {
	ctx := context.Background()
	path := writeLegacySettings(t, legacySettingsFixture(t))
	for _, tc := range []struct{ name, sql string }{
		{"settings", `UPDATE v3_settings SET version=2,payload='{"retention":{"sqlite_events_days":90}}'`},
		{"node", `INSERT INTO v3_nodes(id,name,endpoint,server_name,mode,shard) VALUES('node-a','node-a','192.0.2.1:19100','node-a','native',1)`},
		{"notice", `INSERT INTO v3_notifications(node,event_id,channel,payload) VALUES('node-a','event','feishu','{}')`},
		{"website", `INSERT INTO v3_websites(name,url) VALUES('test','https://example.test')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			mustHistoryExec(t, s.DB, tc.sql)
			if r, err := s.ImportLegacySettings(ctx, path, filepath.Join(t.TempDir(), "before")); err == nil || r.Complete || tableCount(t, s, "v3_migration_domains") != 0 {
				t.Fatal("live target overwritten", err)
			}
		})
	}
	s := testStore(t)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_settings_import() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-settings-database-detail'; END$$;CREATE TRIGGER fail_settings_import BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_settings_import()`)
	r, err := s.ImportLegacySettings(ctx, path, filepath.Join(t.TempDir(), "before"))
	if err == nil || r.Complete || strings.Contains(err.Error(), "private-settings") || tableCount(t, s, "v3_migration_domains") != 0 {
		t.Fatal("partial import or private error", err)
	}
	view, err := s.RetentionPolicy(ctx)
	if err != nil || view.Version != 1 || view.Policy.Events != 30 {
		t.Fatal("failed import did not roll back settings", view, err)
	}
}

func TestLegacySettingsImportSerializesWithLivePolicyWriter(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := writeLegacySettings(t, legacySettingsFixture(t))
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = migrationHeld(ctx, tx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	backupDirectory := filepath.Join(t.TempDir(), "before")
	go func() {
		_, err := s.ImportLegacySettings(ctx, path, backupDirectory)
		done <- err
	}()
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query='SELECT pg_advisory_xact_lock(773376002)' AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatal("import did not wait for live writer", err)
		default:
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The import cannot acquire the exclusive gate while this writer owns the
	// shared form. Commit a valid competing version before releasing it.
	if _, err = tx.ExecContext(ctx, `UPDATE v3_settings SET version=2,payload='{"retention":{"sqlite_events_days":120}}'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("import overwrote competing settings")
	}
	view, err := s.RetentionPolicy(ctx)
	if err != nil || view.Policy.Events != 120 || view.Version != 2 || tableCount(t, s, "v3_migration_domains") != 0 {
		t.Fatal(view, err)
	}
}

func TestLegacySettingsAndWebsiteMappingKeepAccountsAndFrozenWork(t *testing.T) {
	for _, first := range []string{"settings", "websites"} {
		t.Run(first, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			_, source, _ := legacyWebsiteFixture(t, 3)
			archive, err := s.ArchiveSQLite(ctx, source, filepath.Join(t.TempDir(), "snapshot"))
			if err != nil {
				t.Fatal(err)
			}
			config := writeLegacySettings(t, legacySettingsFixture(t))
			mapSettings := func() {
				t.Helper()
				if r, e := s.ImportLegacySettings(ctx, config, filepath.Join(t.TempDir(), "settings-backup")); e != nil || !r.Complete || r.ReadyForCutover {
					t.Fatal(r, e)
				}
			}
			mapWebsites := func() {
				t.Helper()
				if r, e := s.MapWebsiteArchive(ctx, archive.Source); e != nil || !r.Complete || r.ReadyForCutover {
					t.Fatal(r, e)
				}
			}
			if first == "settings" {
				mapSettings()
				mapWebsites()
			} else {
				mapWebsites()
				mapSettings()
			}
			if tableCount(t, s, "v3_websites") != 3 || tableCount(t, s, "v3_accounts") != 1 || tableCount(t, s, "v3_sessions") != 1 || tableCount(t, s, "v3_notifications") != 0 {
				t.Fatal("settings import changed original records or created notifications")
			}
			var username string
			if err = s.DB.QueryRow(`SELECT username FROM v3_accounts`).Scan(&username); err != nil || username != "original-admin" {
				t.Fatal("YAML initializer replaced actual account", err)
			}
			if jobs, e := s.ClaimSites(ctx, "migration-websites", 10); e != nil || len(jobs) != 0 {
				t.Fatal("settings import enabled checks", e)
			}
		})
	}
}

func TestLegacySettingsPreviewCommandNeedsNoDatabase(t *testing.T) {
	c := Config{Version: 3}
	c.Central.Instance = "preview-settings"
	c.Central.PublicURL = "https://example.test"
	c.Database.DSNFile = filepath.Join(t.TempDir(), "missing-dsn")
	c.Metrics.WriteURL, c.Metrics.QueryURL = "http://127.0.0.1:8428", "http://127.0.0.1:8428"
	configPath := filepath.Join(t.TempDir(), "v3.yaml")
	raw, _ := yaml.Marshal(c)
	if err := os.WriteFile(configPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := Command(context.Background(), Options{Config: configPath, Action: "preview-settings-v2", Source: writeLegacySettings(t, legacySettingsFixture(t)), NonInteractive: true}, strings.NewReader(""), &out)
	var report SettingsImportReport
	if err != nil || json.Unmarshal(out.Bytes(), &report) != nil || !validArchiveSource(report.Source) || report.Complete || strings.Contains(out.String(), "private-settings") {
		t.Fatal("preview used database or leaked secrets", err)
	}
}
