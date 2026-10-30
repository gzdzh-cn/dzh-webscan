package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
	configuration "webscan/internal/config"
)

// SettingsImportReport contains no settings payload, account names, addresses,
// credentials or source paths. YAML is an initialization input, not a second
// configuration authority after import.
type SettingsImportReport struct {
	Source          string          `json:"source"`
	Sections        []string        `json:"sections"`
	Policy          RetentionPolicy `json:"retention"`
	Version         int64           `json:"settings_version"`
	Complete        bool            `json:"complete"`
	ReadyForCutover bool            `json:"ready_for_cutover"`
}

// Capture once, with the same no-follow/ownership guarantees as credential
// files, but allow a complete 2 MiB deployment YAML. Parse never reopens it.
func readLegacySettings(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 2<<20 {
		return nil, errors.New("源 YAML 必须为不超过 2 MiB、仅运行账号可读写的普通文件")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("无法安全读取源 YAML")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) || opened.Mode().Perm()&0077 != 0 {
		return nil, errors.New("源 YAML 在读取期间发生变化")
	}
	owner, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("源 YAML 必须属于运行账号")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return nil, errors.New("源 YAML 读取失败、为空或超过 2 MiB")
	}
	end, err := f.Stat()
	if err != nil || end.Size() != opened.Size() || !end.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("源 YAML 在读取期间发生变化")
	}
	return raw, nil
}

func legacySettings(raw []byte) (common.Map, SettingsImportReport, error) {
	var report SettingsImportReport
	c, err := configuration.Parse(raw, "")
	if err != nil {
		// Parser errors and diagnostics may contain source fragments in future
		// versions. Keep the CLI error independent of any confidential input.
		return nil, report, errors.New("旧 YAML 版本、格式或参数校验失败，请先用原版本配置检查修正")
	}
	root := c.Raw
	f := common.Clone(common.M(root["feishu"]))
	if common.B(f["enabled"]) && common.S(f["mode"]) != "inline" {
		return nil, report, errors.New("飞书使用外部环境文件；请先将实际凭据整理到受保护的 inline 迁移配置，不会自动读取外部文件")
	}
	delete(f, "existing_env_file")
	f["mode"] = "inline"
	center := common.M(root["central"])
	health := common.M(root["health"])
	legacyMonitor := common.M(center["monitoring"])
	monitor := common.Map{"mode": "native", "raw_hours": legacyMonitor["raw_hours"], "history_days": legacyMonitor["history_days"],
		"interval_seconds": health["metrics_scrape_seconds"], "alerts": health["alerts"],
		"repeat_hours":              common.M(health["alertmanager"])["repeat_interval_hours"],
		"group_wait_seconds":        common.M(health["alertmanager"])["group_wait_seconds"],
		"group_interval_seconds":    common.M(health["alertmanager"])["group_interval_seconds"],
		"alert_on_inotify_overflow": health["alert_on_inotify_overflow"], "alert_on_dropped_events": health["alert_on_dropped_events"]}
	website := common.Map{}
	for _, k := range []string{"enabled", "interval_seconds", "timeout_seconds", "max_concurrent"} {
		website[k] = common.M(center["website_monitor"])[k]
	}
	settings := common.Map{"retention": root["retention"], "backup": root["backup"], "monitoring": monitor,
		"website_monitor": website, "feishu": f, "email": root["email"]}
	report.Policy, err = retentionPolicy(settings)
	if err != nil {
		return nil, report, err
	}
	// Public receipts must not become an offline password oracle. The source
	// fingerprint covers non-channel policy only; a repeat additionally checks
	// the entire private saved payload inside PostgreSQL before succeeding.
	public := common.Clone(settings)
	delete(public, "feishu")
	delete(public, "email")
	report.Source = digest(common.JSON(public))
	report.Sections = []string{"retention", "backup", "monitoring", "website_monitor", "feishu", "email"}
	return settings, report, nil
}

// PreviewLegacySettings is read-only and needs no PostgreSQL connection. It
// does not read external credentials, connect to nodes, or contact a channel.
func PreviewLegacySettings(path string) (SettingsImportReport, error) {
	raw, err := readLegacySettings(path)
	if err != nil {
		return SettingsImportReport{}, err
	}
	_, report, err := legacySettings(raw)
	return report, err
}

// ImportLegacySettings initializes only pristine settings. Binding a durable
// migration fence and taking the exclusive migration gate prevents a runtime
// writer or notification claim from slipping between checks and commit. A
// failed backup leaves the database untouched. Repeating a completed import
// verifies its original payload and never overwrites the saved settings.
func (s *Store) ImportLegacySettings(ctx context.Context, path, backupDirectory string) (report SettingsImportReport, err error) {
	defer func() {
		err = safeMappingError(err)
		if err != nil {
			report.Complete = false
		}
	}()
	raw, err := readLegacySettings(path)
	if err != nil {
		return report, err
	}
	settings, report, err := legacySettings(raw)
	if err != nil {
		return report, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return report, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(773376002)"); err != nil {
		return report, err
	}
	version, err := currentSchema(ctx, tx)
	if err != nil {
		return report, err
	}
	if version != SchemaVersion {
		return report, errors.New("请先完成数据库版本升级")
	}
	var saved []byte
	if err = tx.QueryRowContext(ctx, "SELECT version,payload FROM v3_settings WHERE id=1 FOR UPDATE").Scan(&report.Version, &saved); err != nil {
		return report, err
	}
	var previous string
	var pending bool
	err = tx.QueryRowContext(ctx, "SELECT source,pending FROM v3_migration_domains WHERE domain='settings' FOR UPDATE").Scan(&previous, &pending)
	if err == nil {
		var old common.Map
		if json.Unmarshal(saved, &old) != nil || !pending || previous != report.Source || !bytes.Equal(common.JSON(old), common.JSON(settings)) {
			return report, errors.New("设置迁移源或目标已变化，禁止覆盖；请核对原迁移资料")
		}
		report.Complete = true
		return report, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return report, err
	}
	var pristine bool
	if err = tx.QueryRowContext(ctx, `SELECT version=1 AND payload='{}'::jsonb AND NOT EXISTS(SELECT 1 FROM v3_settings_drafts) AND NOT EXISTS(SELECT 1 FROM v3_bootstrap_drafts) AND NOT EXISTS(SELECT 1 FROM v3_configuration_restore_commits) FROM v3_settings WHERE id=1`).Scan(&pristine); err != nil {
		return report, err
	}
	if !pristine {
		return report, errors.New("目标已有设置，禁止用旧 YAML 覆盖")
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_nodes WHERE enabled)
 OR EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE status IN ('queued','running') OR recovery_required)
 OR EXISTS(SELECT 1 FROM v3_notifications WHERE NOT migration_pending)
 OR EXISTS(SELECT 1 FROM v3_websites WHERE NOT migration_pending)`).Scan(&active); err != nil {
		return report, err
	}
	if active {
		return report, errors.New("目标已有运行节点、网站、通知或未完成部署，不能初始化设置迁移")
	}
	if backupDirectory == "" {
		return report, errors.New("设置迁移前必须指定私有一致性备份目录")
	}
	if _, err = backupPostgres(ctx, tx, version, backupDirectory); err != nil {
		return report, errors.New("设置迁移前一致性备份失败，未修改设置")
	}
	if err = bindMigrationDomain(ctx, tx, "settings", report.Source, "", nil); err != nil {
		return report, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_settings SET version=version+1,payload=$1,updated_at=clock_timestamp() WHERE id=1", common.JSON(settings)); err != nil {
		return report, err
	}
	report.Version++
	report.Complete = true
	safe, _ := json.Marshal(report)
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES('migration','settings-import','settings',$1)", safe); err != nil {
		return report, err
	}
	if err = tx.Commit(); err != nil {
		report.Complete = false
		return report, err
	}
	return report, nil
}
