package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/sys/unix"
)

// Replace only a fixed unit whose current bytes are independently authenticated.
// Unknown units and symlinks are rejected; the old installation files are untouched.
func singleMetricsUpgradeUnit(i singleInstaller, name string, expected, next []byte) error {
	if filepath.Base(name) != name || len(next) == 0 {
		return errSingleMetricsUpgrade
	}
	d, err := trustDirectory(i.unitDirectory, false)
	if err != nil {
		return errSingleMetricsUpgrade
	}
	defer d.Close()
	path := filepath.Join(i.unitDirectory, name)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return i.publishSingleUnit(name, next)
	} else if err != nil {
		return errSingleMetricsUpgrade
	}
	before, err := readTrustData(path, true, 64<<10)
	if err != nil {
		return errSingleMetricsUpgrade
	}
	if bytes.Equal(before, next) {
		return nil
	}
	if len(expected) == 0 || !bytes.Equal(before, expected) {
		return errSingleMetricsUpgrade
	}
	temporary := ".webscan-metrics-unit-" + token()
	fd, err := unix.Openat(int(d.Fd()), temporary, unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_WRONLY|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errSingleMetricsUpgrade
	}
	f := os.NewFile(uintptr(fd), temporary)
	defer func() { f.Close(); _ = unix.Unlinkat(int(d.Fd()), temporary, 0) }()
	if _, err = f.Write(next); err != nil {
		return errSingleMetricsUpgrade
	}
	if err = f.Sync(); err != nil {
		return errSingleMetricsUpgrade
	}
	if err = f.Close(); err != nil {
		return errSingleMetricsUpgrade
	}
	// Recheck immediately before rename, while the task's coordinator is held.
	current, err := readTrustData(path, true, 64<<10)
	if err != nil || !bytes.Equal(current, before) {
		return errSingleMetricsUpgrade
	}
	if unix.Renameat(int(d.Fd()), temporary, int(d.Fd()), name) != nil || d.Sync() != nil {
		return errSingleMetricsUpgrade
	}
	return nil
}

func singleMetricsUpgradeUnitAllowed(i singleInstaller, name string, expected, next []byte) error {
	path := filepath.Join(i.unitDirectory, name)
	if filepath.Base(name) != name {
		return errSingleMetricsUpgrade
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return errSingleMetricsUpgrade
	}
	raw, err := readTrustData(path, true, 64<<10)
	if err != nil || !bytes.Equal(raw, next) && (len(expected) == 0 || !bytes.Equal(raw, expected)) {
		return errSingleMetricsUpgrade
	}
	return nil
}

func singleMetricsUpgradeUnitsAllowed(ctx context.Context, i singleInstaller, m singleMetricsUpgradeManifest) error {
	previous, err := readTrustData(filepath.Join(m.Effective.Root, "stack.service"), true, 64<<10)
	if err != nil {
		return errSingleMetricsUpgrade
	}
	next, err := readTrustData(filepath.Join(m.Directory, "stack.service"), true, 64<<10)
	if err != nil || singleMetricsUpgradeUnitAllowed(i, singleProject(m.Effective.Root)+".service", previous, next) != nil {
		return errSingleMetricsUpgrade
	}
	for _, suffix := range []string{"service", "timer"} {
		unit, err := readTrustData(filepath.Join(filepath.Dir(m.Effective.configuration().Metrics.PolicyFile), "retention."+suffix), true, 64<<10)
		if err != nil || singleMetricsUpgradeUnitAllowed(i, singleProject(m.Effective.Root)+"-metrics-retention."+suffix, nil, unit) != nil {
			return errSingleMetricsUpgrade
		}
	}
	if m.Request.BackupSchedule != "" {
		p, _, _, err := readSingleBackupSchedule(ctx, m.Request.BackupSchedule, "", "")
		if err != nil {
			return errSingleMetricsUpgrade
		}
		oldService, oldTimer := singleBackupScheduleUnits(p, m.Request.BackupSchedule)
		newService, newTimer := singleBackupUpgradeUnits(m.HelperFile, filepath.Join(m.Request.BackupUpgradeDirectory, "upgrade.json"))
		for suffix, units := range map[string][][]byte{"service": {oldService, newService}, "timer": {oldTimer, newTimer}} {
			if singleMetricsUpgradeUnitAllowed(i, singleProject(m.Effective.Root)+"-backup."+suffix, units[0], units[1]) != nil {
				return errSingleMetricsUpgrade
			}
		}
	}
	return nil
}

func singleMetricsUpgradeRawDirectory(m singleMetricsUpgradeManifest, sourceHash string, create bool) error {
	directory := filepath.Join(m.Effective.Root, "raw-metrics-data")
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		if !create {
			return nil
		}
		if os.Mkdir(directory, 0700) != nil {
			return errSingleMetricsUpgrade
		}
	} else if err != nil {
		return errSingleMetricsUpgrade
	}
	d, err := trustDirectory(directory, true)
	if err != nil {
		return errSingleMetricsUpgrade
	}
	d.Close()
	marker := filepath.Join(directory, ".webscan-upgrade-owner")
	if _, err := os.Lstat(marker); os.IsNotExist(err) {
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			return errSingleMetricsUpgrade
		}
		if !create {
			return nil
		}
		return metricsRetentionAtomicFile(directory, filepath.Base(marker), []byte(sourceHash))
	} else if err != nil {
		return errSingleMetricsUpgrade
	}
	raw, err := readTrustData(marker, true, 4096)
	if err != nil || string(raw) != sourceHash {
		return errSingleMetricsUpgrade
	}
	return nil
}

func singleMetricsUpgradeRecoverBackup(ctx context.Context, p singleBackupPlan) (singleBackupReceipt, bool, error) {
	var result singleBackupReceipt
	if _, err := os.Lstat(p.output); os.IsNotExist(err) {
		return result, false, nil
	} else if err != nil {
		return result, false, errSingleMetricsUpgrade
	}
	raw, err := readTrustData(filepath.Join(p.output, "backup.json"), true, 16<<20)
	if err != nil {
		return result, false, errSingleMetricsUpgrade
	}
	m, err := verifySingleBackup(ctx, p.output, digest(raw))
	if err != nil || m.Installation != p.installation || m.Instance != p.spec.Instance || m.Schema != SchemaVersion || (m.RawMetrics != "") != (p.rawMetrics != nil) || !reflect.DeepEqual(m.Sources, p.sources) || verifySingleBackupBindings(p, metricsSnapshotManifest{Files: m.Files}) != nil {
		return result, false, errSingleMetricsUpgrade
	}
	result = singleBackupReceipt{State: "captured", Directory: p.output, ManifestSHA256: digest(raw), Files: len(m.Files)}
	for _, file := range m.Files {
		result.Bytes += file.Bytes
	}
	return result, true, nil
}

func singleMetricsUpgradeCheckBackupPolicy(ctx context.Context, store *Store, m singleMetricsUpgradeManifest) error {
	var saved []byte
	var hash string
	var enabled bool
	err := store.DB.QueryRowContext(ctx, `SELECT policy,sha256,enabled FROM v3_single_backup_policies WHERE instance=$1`, m.Effective.Instance).Scan(&saved, &hash, &enabled)
	if errors.Is(err, sql.ErrNoRows) && m.Request.BackupSchedule == "" {
		return nil
	}
	if err != nil || m.Request.BackupSchedule == "" {
		return errSingleMetricsUpgrade
	}
	raw, err := readTrustData(m.Request.BackupSchedule, true, 64<<10)
	var actual, expected singleBackupSchedule
	if err != nil || hash != digest(raw) || singleDecode(saved, &actual) != nil || singleDecode(raw, &expected) != nil || !reflect.DeepEqual(actual, expected) || hash != m.Dependencies[m.Request.BackupSchedule] {
		return errSingleMetricsUpgrade
	}
	return nil
}

func singleMetricsUpgradeBackupMaintenance(ctx context.Context, i singleInstaller, m singleMetricsUpgradeManifest) error {
	if m.Request.BackupSchedule == "" {
		return nil
	}
	request := singleBackupUpgradeSpec{Format: 1, ScheduleFile: m.Request.BackupSchedule, Backup: singleMetricsUpgradeBackupRequest(m)}
	files, err := singleBackupUpgradeFiles(ctx, request, m.Request.BackupUpgradeDirectory)
	if err != nil {
		return errSingleMetricsUpgrade
	}
	source := filepath.Join(m.Request.BackupUpgradeDirectory, "upgrade.json")
	if _, err := os.Lstat(m.Request.BackupUpgradeDirectory); os.IsNotExist(err) {
		if publishTrustFiles(ctx, m.Request.BackupUpgradeDirectory, files) != nil {
			return errSingleMetricsUpgrade
		}
	} else if err != nil {
		return errSingleMetricsUpgrade
	}
	p, old, next, raw, _, err := readSingleBackupUpgrade(ctx, source, "", "")
	if err != nil {
		return errSingleMetricsUpgrade
	}
	s, enabled, err := checkSingleBackupUpgradeStore(ctx, old, next, raw)
	if err != nil {
		return errSingleMetricsUpgrade
	}
	s.DB.Close()
	oldService, oldTimer := singleBackupScheduleUnits(p, m.Request.BackupSchedule)
	for suffix, previous := range map[string][]byte{"service": oldService, "timer": oldTimer} {
		if err := singleMetricsUpgradeUnit(i, singleProject(m.Effective.Root)+"-backup."+suffix, previous, files["backup."+suffix]); err != nil {
			return err
		}
	}
	if _, err := i.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return errSingleMetricsUpgrade
	}
	if enabled {
		if _, err := i.run(ctx, "systemctl", "enable", "--now", singleProject(m.Effective.Root)+"-backup.timer"); err != nil {
			return errSingleMetricsUpgrade
		}
	} else {
		if _, err := i.run(ctx, "systemctl", "disable", "--now", singleProject(m.Effective.Root)+"-backup.timer"); err != nil {
			return errSingleMetricsUpgrade
		}
	}
	return nil
}

func singleMetricsUpgradeRetentionConfirmed(ctx context.Context, s *Store, m singleMetricsUpgradeManifest) error {
	var raw []byte
	if s.DB.QueryRowContext(ctx, `SELECT details FROM v3_role_status WHERE role='metrics-retention' AND instance=$1 AND error='' AND heartbeat > clock_timestamp()-interval '2 minutes' AND heartbeat <= clock_timestamp()+interval '5 seconds'`, m.Effective.Instance).Scan(&raw) != nil {
		return errSingleMetricsUpgrade
	}
	var status MetricsRetentionStatus
	desired, err := s.metricsRetentionDesired(ctx, m.Effective)
	if err != nil || json.Unmarshal(raw, &status) != nil || status.State != "confirmed" || status.Effective == nil || *status.Effective != desired {
		return errSingleMetricsUpgrade
	}
	return nil
}
