package controlplane

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type pgBackupLine struct {
	Type    string          `json:"type"`
	Format  int             `json:"format,omitempty"`
	Version int             `json:"schema_version,omitempty"`
	Table   string          `json:"table,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Rows    int64           `json:"rows,omitempty"`
	SHA256  string          `json:"sha256,omitempty"`
}

// A stored website snapshot may be 24 MiB. Its containing JSONL row must fit
// both verification and restore, including JSONB formatting overhead.
const postgresBackupLineLimit = 64 << 20

// Open the directory once and perform all writes relative to its descriptor.
// Generated names and O_EXCL/O_NOFOLLOW prevent a path substitution from
// redirecting a backup containing credentials.
func privateDirectory(directory string) (*os.File, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("备份目录必须为绝对路径")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("备份目录不能为符号链接")
	}
	d := os.NewFile(uintptr(fd), directory)
	st, err := d.Stat()
	if err != nil {
		d.Close()
		return nil, err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0077 != 0 {
		d.Close()
		return nil, errors.New("备份目录必须属于运行账号且权限为 0700")
	}
	return d, nil
}

// BackupPostgres archives this application's tables only, using a repeatable
// read snapshot. It never changes a database or includes unrelated BT tables.
func (s *Store) BackupPostgres(ctx context.Context, directory string) (string, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	version, err := currentSchema(ctx, tx)
	if err != nil {
		return "", err
	}
	if version < 1 || version > SchemaVersion {
		return "", errors.New("不支持备份此数据库版本")
	}
	path, err := backupPostgres(ctx, tx, version, directory)
	if err != nil {
		return "", err
	}
	return path, tx.Commit()
}

func backupPostgres(ctx context.Context, tx *sql.Tx, version int, directory string) (result string, err error) {
	dir, err := privateDirectory(directory)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	name := "postgres-" + time.Now().UTC().Format("20060102T150405") + "-" + token()[:16] + ".jsonl"
	temporary := "." + name + ".partial"
	fd, err := unix.Openat(int(dir.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), temporary)
	defer f.Close()
	defer func() {
		if err != nil {
			_ = unix.Unlinkat(int(dir.Fd()), temporary, 0)
		}
	}()
	hash := sha256.New()
	buffer := bufio.NewWriterSize(io.MultiWriter(f, hash), 64<<10)
	encoder := json.NewEncoder(buffer)
	if err = encoder.Encode(pgBackupLine{Type: "header", Format: 1, Version: version}); err != nil {
		return "", err
	}
	tables, err := postgresTables(ctx, tx)
	if err != nil {
		return "", err
	}
	var total int64
	for _, table := range tables {
		if err = encoder.Encode(pgBackupLine{Type: "table", Table: table}); err != nil {
			return "", err
		}
		rows, e := tx.QueryContext(ctx, "SELECT row_to_json(t) FROM "+quotePG(table)+" t")
		if e != nil {
			return "", e
		}
		for rows.Next() {
			var raw json.RawMessage
			if e = rows.Scan(&raw); e == nil {
				e = encoder.Encode(pgBackupLine{Type: "row", Table: table, Data: raw})
			}
			if e != nil {
				rows.Close()
				return "", e
			}
			total++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return "", e
		}
	}
	if err = buffer.Flush(); err != nil {
		return "", err
	}
	if err = json.NewEncoder(f).Encode(pgBackupLine{Type: "footer", Rows: total, SHA256: hex.EncodeToString(hash.Sum(nil))}); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = unix.Renameat(int(dir.Fd()), temporary, int(dir.Fd()), name); err != nil {
		return "", err
	}
	if err = dir.Sync(); err != nil {
		return "", err
	}
	result = filepath.Join(directory, name)
	// Verify the finalized bytes before allowing a schema change.
	if _, err = inspectPGBackup(result); err != nil {
		return "", err
	}
	return result, nil
}

func postgresTables(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','p') AND NOT relispartition AND relname LIKE 'v3\_%' ESCAPE '\' ORDER BY CASE WHEN relname='v3_accounts' THEN 0 WHEN relname='v3_notifications' THEN 1 WHEN relname='v3_websites' THEN 2 WHEN relname='v3_node_identities' THEN 3 WHEN relname='v3_nodes' THEN 4 WHEN relname='v3_pki_authorities' THEN 5 WHEN relname='v3_credentials' THEN 6 WHEN relname='v3_node_certificates' THEN 7 WHEN relname='v3_deployment_jobs' THEN 8 WHEN relname='v3_node_configurations' THEN 9 WHEN relname='v3_node_runtime' THEN 10 WHEN relname IN ('v3_website_backups','v3_configuration_backups','v3_configuration_revisions') THEN 9 WHEN relname IN ('v3_history_previews','v3_configuration_delete_previews') THEN 10 WHEN relname IN ('v3_history_jobs','v3_configuration_delete_jobs','v3_configuration_applications','v3_deployment_preparations') THEN 11 ELSE 12 END,relname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tables := []string{}
	for rows.Next() {
		var table string
		if err = rows.Scan(&table); err != nil {
			return nil, err
		}
		if !identifier.MatchString(table) {
			return nil, errors.New("数据库表名不正确")
		}
		tables = append(tables, table)
	}
	return tables, rows.Err()
}

func quotePG(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// RestorePostgres only accepts an empty application schema. It cannot replace
// a running v3 database or rewind leases in an existing cluster. Node epochs
// still require reconciliation before a disaster-recovery cutover.
func (s *Store) RestorePostgres(ctx context.Context, path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("备份必须为属于运行账号的私有普通文件")
	}
	header, err := inspectPGReader(f)
	if err != nil {
		return err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(773376001)"); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname LIKE 'v3\_%' ESCAPE '\'`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return errors.New("恢复目标必须为空；禁止覆盖正在使用的数据库")
	}
	if _, err = tx.ExecContext(ctx, Schema); err != nil {
		return err
	}
	if header.Version >= 2 {
		if _, err = tx.ExecContext(ctx, websiteSchema); err != nil {
			return err
		}
	}
	if header.Version >= 3 {
		if _, err = tx.ExecContext(ctx, deploymentSchema); err != nil {
			return err
		}
	}
	if header.Version >= 4 {
		if _, err = tx.ExecContext(ctx, deploymentReadinessSchema); err != nil {
			return err
		}
	}
	if header.Version >= 5 {
		if _, err = tx.ExecContext(ctx, healthSchema); err != nil {
			return err
		}
	}
	if header.Version >= 6 {
		if _, err = tx.ExecContext(ctx, migrationSchema); err != nil {
			return err
		}
	}
	if header.Version >= 7 {
		if _, err = tx.ExecContext(ctx, eventHistorySchema); err != nil {
			return err
		}
	}
	if header.Version >= 8 {
		if _, err = tx.ExecContext(ctx, websiteOutboxSchema); err != nil {
			return err
		}
	}
	if header.Version >= 9 {
		if _, err = tx.ExecContext(ctx, retentionSchema); err != nil {
			return err
		}
	}
	if header.Version >= 10 {
		if _, err = tx.ExecContext(ctx, websiteBackupSchema); err != nil {
			return err
		}
	}
	if header.Version >= 11 {
		if _, err = tx.ExecContext(ctx, manualHistorySchema); err != nil {
			return err
		}
	}
	if header.Version >= 12 {
		if _, err = tx.ExecContext(ctx, pkiRegistrySchema); err != nil {
			return err
		}
	}
	if header.Version >= 13 {
		if _, err = tx.ExecContext(ctx, deploymentPreviewSchema); err != nil {
			return err
		}
	}
	if header.Version >= 14 {
		if _, err = tx.ExecContext(ctx, configurationBackupSchema); err != nil {
			return err
		}
	}

	if header.Version >= 15 {
		if _, err = tx.ExecContext(ctx, configurationDeleteSchema); err != nil {
			return err
		}
	}
	if header.Version >= 16 {
		if _, err = tx.ExecContext(ctx, configurationRestoreSchema); err != nil {
			return err
		}
	}
	if header.Version >= 17 {
		if _, err = tx.ExecContext(ctx, configurationStageSchema); err != nil {
			return err
		}
	}
	if header.Version >= 18 {
		if _, err = tx.ExecContext(ctx, configurationRevisionSchema); err != nil {
			return err
		}
	}
	if header.Version >= 19 {
		if _, err = tx.ExecContext(ctx, nodeRuntimeSchema); err != nil {
			return err
		}
	}

	if header.Version >= 20 {
		if _, err = tx.ExecContext(ctx, settingsDraftSchema); err != nil {
			return err
		}
	}
	if header.Version >= 21 {
		if _, err = tx.ExecContext(ctx, configurationSavedSchema); err != nil {
			return err
		}
	}
	if header.Version >= 22 {
		if _, err = tx.ExecContext(ctx, configurationApplicationSchema); err != nil {
			return err
		}
	}
	if header.Version >= 23 {
		if _, err = tx.ExecContext(ctx, configurationApplicationSettingsSchema); err != nil {
			return err
		}
	}
	if header.Version >= 24 {
		if _, err = tx.ExecContext(ctx, bootstrapRuntimeSchema); err != nil {
			return err
		}
	}
	if header.Version >= 25 {
		if _, err = tx.ExecContext(ctx, configurationOperationGateSchema); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM v3_configuration_operation_gate`); err != nil {
			return err
		}
	}
	if header.Version >= 26 {
		if _, err = tx.ExecContext(ctx, configurationApplicationRegistrationSchema); err != nil {
			return err
		}
	}
	if header.Version >= 27 {
		if _, err = tx.ExecContext(ctx, nodeProvisioningSchema); err != nil {
			return err
		}
	}
	if header.Version >= 28 {
		if _, err = tx.ExecContext(ctx, deploymentInstallationSchema); err != nil {
			return err
		}
	}
	if header.Version >= 29 {
		if _, err = tx.ExecContext(ctx, deploymentRecoverySchema); err != nil {
			return err
		}
	}
	if header.Version >= 30 {
		if _, err = tx.ExecContext(ctx, nodeRenewalSchema); err != nil {
			return err
		}
	}
	if header.Version >= 31 {
		if _, err = tx.ExecContext(ctx, nodeRenewalQueueSchema); err != nil {
			return err
		}
	}
	if header.Version >= 32 {
		if _, err = tx.ExecContext(ctx, nodeIdentityRecoverySchema); err != nil {
			return err
		}
	}
	if header.Version >= 33 {
		if _, err = tx.ExecContext(ctx, nodeNameChangeSchema); err != nil {
			return err
		}
	}
	if header.Version >= 34 {
		if _, err = tx.ExecContext(ctx, nodeNamePruningSchema); err != nil {
			return err
		}
	}
	if header.Version >= 35 {
		if _, err = tx.ExecContext(ctx, webDeploymentSchema); err != nil {
			return err
		}
	}
	tables, err := postgresTables(ctx, tx)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, table := range tables {
		allowed[table] = true
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM v3_settings;DELETE FROM v3_schema"); err != nil {
		return err
	}
	// Validate the same bytes while restoring, so even a concurrent local
	// modification after the first checksum cannot be committed.
	hash := sha256.New()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), postgresBackupLineLimit)
	seen := map[string]bool{}
	var rows int64
	footer := false
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw := scanner.Bytes()
		var line pgBackupLine
		if json.Unmarshal(raw, &line) != nil || footer {
			return errors.New("备份在恢复期间发生变化")
		}
		switch line.Type {
		case "header":
			if line.Version != header.Version || line.Format != header.Format {
				return errors.New("备份头发生变化")
			}
		case "table":
			if !allowed[line.Table] || seen[line.Table] {
				return errors.New("备份包含未知或重复表")
			}
			seen[line.Table] = true
		case "row":
			if !allowed[line.Table] || !seen[line.Table] {
				return errors.New("备份记录的表不正确")
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO "+quotePG(line.Table)+" SELECT (jsonb_populate_record(NULL::"+quotePG(line.Table)+",$1::jsonb)).*", []byte(line.Data)); err != nil {
				return errors.New("备份记录恢复失败，数据库未修改")
			}
			rows++
		case "footer":
			if line.Rows != rows || line.SHA256 != hex.EncodeToString(hash.Sum(nil)) {
				return errors.New("恢复校验失败，数据库未修改")
			}
			footer = true
		default:
			return errors.New("备份格式不正确")
		}
		if !footer {
			hash.Write(raw)
			hash.Write([]byte{'\n'})
		}
	}
	if err = scanner.Err(); err != nil {
		return err
	}
	if !footer || len(seen) != len(allowed) {
		return errors.New("备份不完整，数据库未修改")
	}
	version, err := currentSchema(ctx, tx)
	if err != nil || version != header.Version {
		return errors.New("恢复数据库版本与备份不一致")
	}
	if header.Version >= 4 {
		// Runtime evidence is not historical business data. A restore must await
		// new collector observations even if the archived lease is still fresh.
		if _, err = tx.ExecContext(ctx, "DELETE FROM v3_node_readiness"); err != nil {
			return err
		}
	}
	if header.Version >= 22 {
		if header.Version >= 24 {
			if _, err = tx.ExecContext(ctx, `DELETE FROM v3_bootstrap_processes`); err != nil {
				return err
			}
		}
		// Archive ownership cannot authorize execution in a restored cluster.
		// Do not rewrite signed checkpoints without the independently held key.
		// The hold revokes execution until a current administrator explicitly
		// reauthorizes recovery and a new epoch probes the actual runtime.
		if _, err = tx.ExecContext(ctx, `UPDATE v3_configuration_applications SET recovery_hold=true WHERE status NOT IN ('succeeded','rolled_back','cancelled')`); err != nil {
			return err
		}
	}
	if header.Version >= 34 {
		// Restore retains issuance ancestry, not permission to finish a
		// destructive name change using an archived task or SSH authority.
		if _, err = tx.ExecContext(ctx, `UPDATE v3_node_name_prunings SET status='canceled',updated_at=clock_timestamp() WHERE status IN ('prepared','requested','signed')`); err != nil {
			return err
		}
	}
	if header.Version >= 35 {
		if _, err = tx.ExecContext(ctx, `UPDATE v3_deployment_preparations SET status='expired',phase='expired',expires_at=clock_timestamp(),lease_until=NULL;DELETE FROM v3_deployment_private_inputs;DELETE FROM v3_role_status WHERE role IN ('executor','deployment-preparations')`); err != nil {
			return err
		}
	}
	if header.Version >= 9 {
		// A restored cleanup cursor is durable work; an archived heartbeat is
		// not proof that its old worker is still alive in the restored cluster.
		if _, err = tx.ExecContext(ctx, "DELETE FROM v3_role_status WHERE role='retention'"); err != nil {
			return err
		}
	}
	if header.Version >= 10 {
		if _, err = tx.ExecContext(ctx, "DELETE FROM v3_website_backup_previews"); err != nil {
			return err
		}
	}
	if header.Version >= 11 {
		// Export files are external to this archive. Never resume an operator's
		// destructive task using missing export evidence or old authorization.
		if _, err = tx.ExecContext(ctx, `UPDATE v3_history_jobs SET status='cancelled',phase='finished',finished_at=clock_timestamp(),message='灾备恢复后请重新预览；未继续清理' WHERE status IN ('queued','running');
UPDATE v3_history_jobs SET export_ready=false,export_expires_at=NULL;
UPDATE v3_history_export_parts SET ready=false,bytes=0,sha256='',created_at=clock_timestamp()-interval '24 hours';
UPDATE v3_history_previews SET expires_at=clock_timestamp(),used=true`); err != nil {
			return err
		}
	}
	if header.Version >= 14 {
		// A transfer cannot continue across disaster recovery. Durable restore,
		// deployment and rollback references keep their protection.
		if _, err = tx.ExecContext(ctx, "DELETE FROM v3_configuration_backup_pins WHERE kind='export'"); err != nil {
			return err
		}
	}
	if header.Version >= 16 {
		// A backup cannot revive a capability granted before disaster recovery.
		// Preserve durable restore/deployment/rollback pins; remove preview pins.
		if _, err = tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins WHERE kind='restore' AND reference IN(SELECT 'preview:'||token_hash FROM v3_configuration_restore_previews);DELETE FROM v3_configuration_restore_previews`); err != nil {
			return err
		}
	}
	if header.Version >= 17 {
		// An archived pending intent is historical evidence, never authority to
		// resume restoration after disaster recovery under old authorization.
		if _, err = tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins p USING v3_configuration_restore_stages s WHERE s.status IN ('pending_validation','pending_application') AND p.kind='restore' AND p.reference IN('stage:'||s.id||':source','stage:'||s.id||':before');
 UPDATE v3_configuration_restore_stages SET status='cancelled',message='灾备恢复后需重新预览；运行配置未修改',updated_at=clock_timestamp(),finished_at=clock_timestamp(),cancelled_by='disaster-recovery' WHERE status IN ('pending_validation','pending_application')`); err != nil {
			return err
		}
	}
	if header.Version >= 18 {
		if _, err = tx.ExecContext(ctx, `UPDATE v3_configuration_revisions SET status='cancelled',message='灾备恢复后需重新预览；待应用配置未应用',updated_at=clock_timestamp(),finished_at=clock_timestamp() WHERE status='pending_application'`); err != nil {
			return err
		}
	}
	if header.Version >= 15 {
		// A normal restart resumes checkpoints, but disaster recovery never
		// replays destructive operator intent under old authorization.
		if _, err = tx.ExecContext(ctx, `WITH pending AS (
 UPDATE v3_configuration_delete_items i SET status='skipped',reason='灾备恢复后需重新预览确认'
 FROM v3_configuration_delete_jobs j WHERE i.job=j.id AND i.status='pending' AND j.status IN ('queued','running') RETURNING i.job
 ), counts AS (SELECT job,count(*)::integer AS n FROM pending GROUP BY job)
 UPDATE v3_configuration_delete_jobs j SET skipped=j.skipped+c.n FROM counts c WHERE j.id=c.job;
 UPDATE v3_configuration_delete_jobs SET status='cancelled',message='灾备恢复后需重新预览；已完成部分保留，未继续删除',updated_at=clock_timestamp(),finished_at=clock_timestamp() WHERE status IN ('queued','running');
 UPDATE v3_configuration_delete_previews SET used=true,expires_at=clock_timestamp()`); err != nil {
			return err
		}
	}

	// Explicit IDs preserve business identity; advance their backing sequences
	// so the next insert cannot reuse a restored ID.
	for _, table := range tables {
		columns, err := tx.QueryContext(ctx, "SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND is_identity='YES'", table)
		if err != nil {
			return err
		}
		names := []string{}
		for columns.Next() {
			var name string
			if err = columns.Scan(&name); err != nil {
				columns.Close()
				return err
			}
			names = append(names, name)
		}
		err = columns.Err()
		columns.Close()
		if err != nil {
			return err
		}
		for _, column := range names {
			var sequence string
			if err = tx.QueryRowContext(ctx, "SELECT pg_get_serial_sequence($1,$2)", quotePG(table), column).Scan(&sequence); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "SELECT setval($1::regclass,COALESCE(max("+quotePG(column)+"),1),count(*)>0) FROM "+quotePG(table), sequence); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// Inspection bounds an individual record but streams the whole archive. It
// verifies the checksum before a restore is allowed to write anything.
func inspectPGBackup(path string) (header pgBackupLine, err error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return header, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return header, errors.New("备份必须为私有普通文件")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return header, errors.New("备份必须属于运行账号")
	}
	return inspectPGReader(f)
}

func inspectPGReader(reader io.Reader) (header pgBackupLine, err error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), postgresBackupLineLimit)
	hash := sha256.New()
	var count int64
	line, table, footer := 0, "", false
	seen := map[string]bool{}
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		var v pgBackupLine
		if err = json.Unmarshal(raw, &v); err != nil || footer {
			return header, errors.New("备份格式损坏")
		}
		if line == 1 {
			if v.Type != "header" || v.Format != 1 || v.Version < 1 || v.Version > SchemaVersion {
				return header, errors.New("备份格式或数据库版本不兼容")
			}
			header = v
		} else {
			switch v.Type {
			case "table":
				if !strings.HasPrefix(v.Table, "v3_") || !identifier.MatchString(v.Table) || seen[v.Table] {
					return header, errors.New("备份表定义不正确")
				}
				table = v.Table
				seen[table] = true
			case "row":
				if table == "" || v.Table != table || len(v.Data) == 0 || v.Data[0] != '{' {
					return header, errors.New("备份记录不正确")
				}
				count++
			case "footer":
				if v.Rows != count || v.SHA256 != hex.EncodeToString(hash.Sum(nil)) {
					return header, errors.New("备份校验失败")
				}
				footer = true
			default:
				return header, errors.New("备份记录类型不正确")
			}
		}
		if !footer {
			hash.Write(raw)
			hash.Write([]byte{'\n'})
		}
	}
	if err = scanner.Err(); err != nil {
		return header, err
	}
	if !footer || !seen["v3_schema"] {
		return header, fmt.Errorf("备份不完整")
	}
	return header, nil
}
