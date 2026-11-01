package controlplane

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
	"webscan/internal/deploy"
	"webscan/internal/progress"
)

var errSingleBackupSchedule = errors.New("自动备份策略或任务校验失败；已保留原策略与备份，请核对签名程序、安装绑定及任务回执")

type singleBackupScheduleSpec struct {
	Format    int              `json:"format"`
	Directory string           `json:"backup_directory"`
	Keep      int              `json:"keep"`
	Request   singleBackupSpec `json:"backup"`
}

type singleBackupSchedule struct {
	Format  int                      `json:"format"`
	Spec    singleBackupScheduleSpec `json:"policy"`
	Helper  string                   `json:"helper_file"`
	Hash    string                   `json:"helper_sha256"`
	Release string                   `json:"release"`
}

func (p singleBackupScheduleSpec) validate() error {
	if p.Format != 1 || !singlePKIUpgradePath(p.Directory) || p.Keep < 1 || p.Keep > 365 {
		return errSingleBackupSchedule
	}
	return nil
}

func prepareSingleBackupSchedule(ctx context.Context, p singleBackupScheduleSpec, output string) error {
	if p.Keep == 0 {
		p.Keep = 7
	}
	if p.validate() != nil || !singlePKIUpgradePath(output) || singleBackupContains(output, p.Directory) || singleBackupContains(p.Directory, output) {
		return errSingleBackupSchedule
	}
	plan, err := planSingleBackup(ctx, p.Request, filepath.Join(p.Directory, "binding-check"))
	if err != nil || singleBackupContains(plan.spec.Root, output) || singleBackupContains(output, plan.spec.Root) {
		return errSingleBackupSchedule
	}
	trust, err := loadDeploymentTrust(ctx, plan.config.DeploymentTrust)
	if err != nil {
		return errSingleBackupSchedule
	}
	policy := singleBackupSchedule{Format: 1, Spec: p, Helper: plan.config.DeploymentTrust.HelperFile, Hash: trust.release.manifest.Helper.SHA256, Release: trust.release.manifest.Release}
	service, timer := singleBackupScheduleUnits(policy, filepath.Join(output, "schedule.json"))
	raw, _ := json.Marshal(policy)
	return publishTrustFiles(ctx, output, map[string][]byte{"schedule.json": raw, "backup.service": service, "backup.timer": timer})
}

func singleBackupScheduleUnits(p singleBackupSchedule, source string) ([]byte, []byte) {
	// No Requires/PartOf dependency on the central stack: timer failure or a
	// restart must never stop the API, database, metrics engine or executor.
	service := []byte("[Unit]\nDescription=Webscan consistent single-center backup\nAfter=network-online.target\n\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=360\nNoNewPrivileges=yes\nNice=10\nIOSchedulingClass=best-effort\nIOSchedulingPriority=7\nExecStart=" + strconv.Quote(p.Helper) + " control-v3 --action run-single-backup --source " + strconv.Quote(source) + "\n")
	timer := []byte("[Unit]\nDescription=Webscan single-center backup schedule check\n\n[Timer]\nOnCalendar=*-*-* *:*:00\nAccuracySec=1s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n")
	return service, timer
}

func readSingleBackupSchedule(ctx context.Context, source, executable, release string) (singleBackupSchedule, singleBackupPlan, []byte, error) {
	var p singleBackupSchedule
	raw, err := readTrustData(source, true, 64<<10)
	if err != nil || singleDecode(raw, &p) != nil || p.Format != 1 || p.Spec.validate() != nil || (filepath.Base(source) != "schedule.json" && filepath.Base(source) != "backup-schedule.json") {
		return p, singleBackupPlan{}, nil, errSingleBackupSchedule
	}
	plan, err := planSingleBackup(ctx, p.Spec.Request, filepath.Join(p.Spec.Directory, "binding-check"))
	if err != nil || (p.Helper != plan.config.DeploymentTrust.HelperFile && p.Helper != filepath.Join(plan.spec.Root, "webscan")) || p.Hash != plan.bindings[p.Helper] || p.Hash != plan.bindings[plan.config.DeploymentTrust.HelperFile] {
		return p, plan, nil, errSingleBackupSchedule
	}
	trust, err := loadDeploymentTrust(ctx, plan.config.DeploymentTrust)
	if err != nil || p.Release != trust.release.manifest.Release {
		return p, plan, nil, errSingleBackupSchedule
	}
	if executable != "" && (executable != p.Helper || release != p.Release) {
		return p, plan, nil, errSingleBackupSchedule
	}
	dir, err := trustDirectory(p.Spec.Directory, true)
	if err != nil {
		return p, plan, nil, errSingleBackupSchedule
	}
	dir.Close()
	return p, plan, raw, nil
}

func (i singleInstaller) activateSingleBackup(ctx context.Context, s singleInstallSpec) error {
	parent, err := trustDirectory(filepath.Dir(s.Backup.Directory), false)
	if err != nil {
		return errSingleBackupSchedule
	}
	err = unix.Mkdirat(int(parent.Fd()), filepath.Base(s.Backup.Directory), 0700)
	parent.Close()
	if err != nil && err != unix.EEXIST {
		return errSingleBackupSchedule
	}
	p, plan, raw, err := readSingleBackupSchedule(ctx, filepath.Join(s.Root, "backup-schedule.json"), "", "")
	if err != nil || p.Spec.Keep != s.Backup.Keep || p.Spec.Directory != s.Backup.Directory {
		return errSingleBackupSchedule
	}
	store, err := Open(ctx, plan.config)
	if err != nil {
		return err
	}
	defer store.DB.Close()
	if err := store.configureSingleBackup(ctx, s.Instance, raw); err != nil {
		return err
	}
	for _, suffix := range []string{"service", "timer"} {
		unit, err := readTrustData(filepath.Join(s.Root, "backup."+suffix), true, 64<<10)
		if err != nil {
			return errSingleBackupSchedule
		}
		if err := i.publishSingleUnit(singleProject(s.Root)+"-backup."+suffix, unit); err != nil {
			return err
		}
	}
	if _, err := i.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return errSingleBackupSchedule
	}
	if _, err := i.run(ctx, "systemctl", "enable", "--now", singleProject(s.Root)+"-backup.timer"); err != nil {
		return errSingleBackupSchedule
	}
	return nil
}

// Keep an existing policy byte-for-byte. Upgrades do not reset retention or
// replace an operator's schedule; an explicit new binding is required instead.
func (s *Store) configureSingleBackup(ctx context.Context, instance string, raw []byte) error {
	hash := digest(raw)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO v3_single_backup_policies(instance,sha256,policy) VALUES($1,$2,$3) ON CONFLICT(instance) DO NOTHING`, instance, hash, raw)
	if err != nil {
		return err
	}
	var existing string
	var enabled bool
	if err := s.DB.QueryRowContext(ctx, `SELECT sha256,enabled FROM v3_single_backup_policies WHERE instance=$1`, instance).Scan(&existing, &enabled); err != nil || existing != hash || !enabled {
		return errSingleBackupSchedule
	}
	return nil
}

type singleBackupRunResult struct {
	ID      string               `json:"id,omitempty"`
	State   string               `json:"state"`
	Receipt *singleBackupReceipt `json:"backup,omitempty"`
}

func (s *Store) runSingleBackupSchedule(ctx context.Context, p singleBackupSchedule, plan singleBackupPlan, raw []byte) (singleBackupRunResult, error) {
	return s.runSingleBackupScheduleMode(ctx, p, plan, raw, false)
}

func (s *Store) runSingleBackupScheduleMode(ctx context.Context, p singleBackupSchedule, plan singleBackupPlan, raw []byte, timer bool) (singleBackupRunResult, error) {
	result := singleBackupRunResult{State: "failed"}
	// Session-scoped ownership spans the filesystem publication and subsequent
	// task commit. A crashed process releases it; another host cannot overlap.
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return result, err
	}
	defer conn.Close()
	resource := "single-backup:" + plan.spec.Instance
	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, resource).Scan(&locked); err != nil || !locked {
		return result, errSingleBackupSchedule
	}
	defer func() {
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(release, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, resource); err != nil {
			// Do not return a possibly locked session to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	var policyHash string
	var enabled bool
	if err := conn.QueryRowContext(ctx, `SELECT sha256,enabled FROM v3_single_backup_policies WHERE instance=$1`, plan.spec.Instance).Scan(&policyHash, &enabled); err != nil || !enabled || policyHash != digest(raw) {
		return result, errSingleBackupSchedule
	}
	runtimePolicy, err := readSingleBackupRuntimePolicy(ctx, conn)
	if err != nil {
		return result, err
	}
	if !runtimePolicy.Enabled {
		result.State = "disabled"
		return result, nil
	}
	var now time.Time
	if err := conn.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return result, err
	}
	if timer && !runtimePolicy.configured && !singleBackupLegacyTimerDue(now) {
		result.State = "not-due"
		return result, nil
	}
	// Interrupted archives are preserved for explicit inspection, never guessed
	// to be successful or adopted from a path lacking a committed digest.
	if _, err := conn.ExecContext(ctx, `UPDATE v3_single_backup_runs SET status='interrupted',reason='上次进程中断，归档保留待核验',updated_at=clock_timestamp() WHERE instance=$1 AND status='running'`, plan.spec.Instance); err != nil {
		return result, err
	}
	if err := s.pruneSingleBackupsPolicy(ctx, p, plan.spec.Instance, policyHash, runtimePolicy, now); err != nil {
		return result, err
	}
	var recent bool
	localDate := ""
	if runtimePolicy.configured {
		latest, err := singleBackupLatestSuccess(ctx, conn, plan.spec.Instance, policyHash)
		if err != nil {
			return result, err
		}
		var due bool
		localDate, due = singleBackupRuntimeDue(runtimePolicy, now, latest)
		recent = !due
		if due {
			if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_single_backup_slots WHERE instance=$1 AND local_date=$2 AND completed_at IS NOT NULL)`, plan.spec.Instance, localDate).Scan(&recent); err != nil {
				return result, err
			}
		}
	} else {
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_single_backup_runs WHERE instance=$1 AND status='captured' AND policy_sha256=$2 AND created_at>clock_timestamp()-interval '24 hours')`, plan.spec.Instance, policyHash).Scan(&recent); err != nil {
			return result, err
		}
	}
	if recent {
		result.State = "not-due"
		return result, nil
	}
	id := token()
	plan.output = filepath.Join(p.Spec.Directory, "backup-"+id)
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_single_backup_runs(id,instance,policy_sha256,status,directory) VALUES($1,$2,$3,'running',$4)`, id, plan.spec.Instance, policyHash, plan.output); err != nil {
		return result, err
	}
	if runtimePolicy.configured {
		claimed, err := tx.ExecContext(ctx, `INSERT INTO v3_single_backup_slots(instance,local_date,settings_version,policy,run_id) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(instance,local_date) DO UPDATE SET settings_version=excluded.settings_version,policy=excluded.policy,run_id=excluded.run_id WHERE v3_single_backup_slots.completed_at IS NULL`, plan.spec.Instance, localDate, runtimePolicy.version, common.JSON(runtimePolicy), id)
		if err != nil {
			return result, err
		}
		if rows, err := claimed.RowsAffected(); err != nil || rows != 1 {
			return result, errSingleBackupSchedule
		}
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	result.ID = id
	receipt, backupErr := s.backupSingle(ctx, plan)
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	state, reason := "captured", ""
	if backupErr != nil {
		state, reason = "failed", "备份失败，原服务和已保留备份未覆盖；请检查宿主任务回执"
	}
	finishTx, err := conn.BeginTx(finish, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return result, err
	}
	defer finishTx.Rollback()
	finished, err := finishTx.ExecContext(finish, `UPDATE v3_single_backup_runs SET status=$2,reason=$3,manifest_sha256=$4,files=$5,bytes=$6,updated_at=clock_timestamp() WHERE id=$1 AND status='running'`, id, state, reason, receipt.ManifestSHA256, receipt.Files, receipt.Bytes)
	if err != nil {
		return result, err
	}
	if rows, err := finished.RowsAffected(); err != nil || rows != 1 {
		return result, errSingleBackupSchedule
	}
	if runtimePolicy.configured && backupErr == nil {
		completed, err := finishTx.ExecContext(finish, `UPDATE v3_single_backup_slots SET completed_at=clock_timestamp() WHERE instance=$1 AND local_date=$2 AND run_id=$3 AND completed_at IS NULL`, plan.spec.Instance, localDate, id)
		if err != nil {
			return result, err
		}
		if rows, err := completed.RowsAffected(); err != nil || rows != 1 {
			return result, errSingleBackupSchedule
		}
	}
	if err := finishTx.Commit(); err != nil {
		return result, err
	}
	result.State = state
	result.Receipt = &receipt
	if backupErr != nil {
		return result, backupErr
	}
	return result, s.pruneSingleBackupsPolicy(ctx, p, plan.spec.Instance, policyHash, runtimePolicy, now)
}

// Retention touches only tasks created under this exact policy and verified
// immutable manifest. Foreign directories, uncommitted archives and failed
// tasks are never enumerated for removal.
func (s *Store) pruneSingleBackups(ctx context.Context, p singleBackupSchedule, instance, policyHash string) error {
	runtimePolicy, err := readSingleBackupRuntimePolicy(ctx, s.DB)
	if err != nil {
		return err
	}
	return s.pruneSingleBackupsPolicy(ctx, p, instance, policyHash, runtimePolicy, time.Now())
}

func (s *Store) pruneSingleBackupsPolicy(ctx context.Context, p singleBackupSchedule, instance, policyHash string, runtimePolicy singleBackupRuntimePolicy, now time.Time) error {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,directory,manifest_sha256,status,created_at FROM v3_single_backup_runs WHERE instance=$1 AND policy_sha256=$2 AND status IN ('captured','purging') ORDER BY created_at DESC,id DESC`, instance, policyHash)
	if err != nil {
		return err
	}
	type item struct {
		id, directory, hash, state string
		created                    time.Time
	}
	var pending []item
	kept := 0
	for rows.Next() {
		var v item
		if err := rows.Scan(&v.id, &v.directory, &v.hash, &v.state, &v.created); err != nil {
			rows.Close()
			return err
		}
		if v.state == "captured" {
			kept++
			if runtimePolicy.configured && (kept == 1 || !v.created.Before(now.Add(-time.Duration(runtimePolicy.KeepDays)*24*time.Hour))) || !runtimePolicy.configured && kept <= p.Spec.Keep {
				continue
			}
		}
		pending = append(pending, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range pending {
		if !identifier.MatchString(v.id) || v.directory != filepath.Join(p.Spec.Directory, "backup-"+v.id) || !releaseDigest(v.hash) {
			return errSingleBackupSchedule
		}
		// A pending purge can have partially removed contents. Its durable task
		// transition was committed only after full hash verification.
		if v.state == "captured" {
			manifest, err := verifySingleBackup(ctx, v.directory, v.hash)
			if err != nil || manifest.Instance != instance {
				return errSingleBackupSchedule
			}
			if _, err := s.DB.ExecContext(ctx, `UPDATE v3_single_backup_runs SET status='purging',updated_at=clock_timestamp() WHERE id=$1 AND status='captured'`, v.id); err != nil {
				return err
			}
		}
		if err := removeScheduledBackup(p.Spec.Directory, "backup-"+v.id); err != nil {
			return err
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE v3_single_backup_runs SET status='expired',updated_at=clock_timestamp() WHERE id=$1 AND status='purging'`, v.id); err != nil {
			return err
		}
	}
	return nil
}

func removeScheduledBackup(parentPath, name string) error {
	parent, err := trustDirectory(parentPath, true)
	if err != nil {
		return errSingleBackupSchedule
	}
	defer parent.Close()
	var st unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err == unix.ENOENT {
		return nil
	} else if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errSingleBackupSchedule
	}
	dir, err := openSnapshotDirectory(parent, name)
	if err != nil {
		return errSingleBackupSchedule
	}
	defer dir.Close()
	if err := removeSnapshotStage(dir); err != nil {
		return errSingleBackupSchedule
	}
	if unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR) != nil || parent.Sync() != nil {
		return errSingleBackupSchedule
	}
	return nil
}

func singleBackupScheduleCommand(ctx context.Context, o Options, out io.Writer) (result error) {
	defer func() {
		if result != nil {
			code, message := "single_backup_schedule_failed", errSingleBackupSchedule.Error()
			if errors.Is(result, errSingleBackupHost) {
				code, message = "single_backup_host_required", errSingleBackupHost.Error()
			}
			result = &progress.Failure{Code: code, Message: message}
		}
	}()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errSingleBackupHost
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if o.Action == "prepare-single-backup-schedule" {
		var p singleBackupScheduleSpec
		raw, err := readTrustData(o.Source, true, 64<<10)
		if err != nil || singleDecode(raw, &p) != nil {
			return errSingleBackupSchedule
		}
		if err := prepareSingleBackupSchedule(ctx, p, o.Output); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"state": "prepared", "activated": false, "default_keep": 7})
	}
	executable, err := os.Executable()
	if err != nil {
		return errSingleBackupSchedule
	}
	p, plan, raw, err := readSingleBackupSchedule(ctx, o.Source, executable, deploy.Release)
	if err != nil {
		return err
	}
	s, err := Open(ctx, plan.config)
	if err != nil {
		return err
	}
	defer s.DB.Close()
	version, err := currentSchema(ctx, s.DB)
	if err != nil || version != SchemaVersion {
		return errSingleBackupSchedule
	}
	if o.Action == "configure-single-backup-schedule" {
		if err := s.configureSingleBackup(ctx, plan.spec.Instance, raw); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"state": "configured", "activated": false, "keep": p.Spec.Keep})
	}
	if o.Action == "enable-single-backup-schedule" {
		result, err := s.DB.ExecContext(ctx, `UPDATE v3_single_backup_policies SET enabled=true WHERE instance=$1 AND sha256=$2`, plan.spec.Instance, digest(raw))
		if err != nil {
			return errSingleBackupSchedule
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errSingleBackupSchedule
		}
		return json.NewEncoder(out).Encode(map[string]any{"state": "enabled", "activated": false, "keep": p.Spec.Keep})
	}
	if o.Action != "run-single-backup" {
		return errSingleBackupSchedule
	}
	r, err := s.runSingleBackupScheduleMode(ctx, p, plan, raw, true)
	if encodeErr := json.NewEncoder(out).Encode(r); encodeErr != nil {
		return encodeErr
	}
	return err
}
