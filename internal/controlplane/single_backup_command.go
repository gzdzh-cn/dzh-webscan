package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/progress"
)

var errSingleBackupHost = errors.New("单中心备份及离线恢复仅允许在 Linux amd64 主控宿主机以 root 执行")

func singleBackupCommand(ctx context.Context, o Options, out io.Writer) (result error) {
	caller := ctx
	defer func() {
		if result == nil {
			return
		}
		code, message := "single_backup_failed", errSingleBackup.Error()
		switch {
		case errors.Is(result, errSingleBackupHost):
			code, message = "single_backup_host_required", errSingleBackupHost.Error()
		case errors.Is(result, errMetricsSnapshotCleanup):
			code, message = "single_backup_snapshot_cleanup_pending", errMetricsSnapshotCleanup.Error()
		case errors.Is(result, errMetricsSnapshotCreateUnknown):
			code, message = "single_backup_snapshot_unconfirmed", errMetricsSnapshotCreateUnknown.Error()
		case errors.Is(result, context.Canceled), errors.Is(caller.Err(), context.Canceled):
			code, message = "single_backup_canceled", "备份或隔离恢复已取消，未覆盖原服务及数据"
		case errors.Is(result, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
			code, message = "single_backup_timeout", "备份或隔离恢复超时，未覆盖原服务及数据"
		}
		result = &progress.Failure{Code: code, Message: message}
	}()
	if o.Action != "verify-single-backup" && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0) {
		return errSingleBackupHost
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if o.Action == "backup-single" {
		var request singleBackupSpec
		raw, err := readTrustData(o.Source, true, 64<<10)
		if err != nil || singleDecode(raw, &request) != nil {
			return errSingleBackup
		}
		plan, err := planSingleBackup(ctx, request, o.Output)
		if err != nil {
			return err
		}
		s, err := Open(ctx, plan.config)
		if err != nil {
			return err
		}
		defer s.DB.Close()
		receipt, err := s.backupSingle(ctx, plan)
		if err != nil {
			if receipt.PendingSnapshot != "" {
				if encode := json.NewEncoder(out).Encode(receipt); encode != nil {
					return encode
				}
			}
			return err
		}
		return json.NewEncoder(out).Encode(receipt)
	}
	var request metricsSnapshotRestoreSpec
	raw, err := readTrustData(o.Source, true, 64<<10)
	if err != nil || singleDecode(raw, &request) != nil || request.Format != 1 || !snapshotAbsolutePath(request.Directory) || !releaseDigest(request.ManifestSHA256) {
		return errSingleBackup
	}
	manifest, err := verifySingleBackup(ctx, request.Directory, request.ManifestSHA256)
	if err != nil {
		return err
	}
	state := "verified"
	if o.Action == "restore-single-offline" {
		if err := restoreSingleBackupOffline(ctx, request.Directory, request.ManifestSHA256, o.Output); err != nil {
			return err
		}
		state = "staged"
	} else if o.Action != "verify-single-backup" || o.Output != "" {
		return errSingleBackup
	}
	return json.NewEncoder(out).Encode(map[string]any{"state": state, "schema_version": manifest.Schema, "files": len(manifest.Files), "manifest_sha256": request.ManifestSHA256, "runtime_started": false, "postgres_imported": false, "isolated_restore_validated": false, "cutover_authorized": false})
}

// Materialize private recovery data only. Neither the archive's source paths,
// DSN nor service units are activated. PG restore into a distinct empty schema
// and a real VM start/query are separate explicit isolated validation steps.
func restoreSingleBackupOffline(ctx context.Context, directory, expected, output string) error {
	manifest, err := verifySingleBackup(ctx, directory, expected)
	if err != nil || !snapshotAbsolutePath(output) || singleBackupContains(directory, output) || singleBackupContains(output, directory) {
		return errSingleBackup
	}
	for _, source := range manifest.Sources {
		if singleBackupContains(source.Path, output) || singleBackupContains(output, source.Path) {
			return errSingleBackup
		}
	}
	stage, err := newMetricsSnapshotStage(output)
	if err != nil {
		return errSingleBackup
	}
	defer stage.close()
	from, err := trustDirectory(directory, true)
	if err != nil {
		return errSingleBackup
	}
	defer from.Close()
	actual := metricsSnapshotManifest{Files: []metricsSnapshotFile{}, Directories: []string{}}
	var total int64
	for _, name := range []string{"host", "postgres"} {
		if unix.Mkdirat(int(stage.directory.Fd()), name, 0700) != nil {
			return errSingleBackup
		}
		source, err := openSnapshotDirectory(from, name)
		if err != nil {
			return errSingleBackup
		}
		target, err := openSnapshotDirectory(stage.directory, name)
		if err != nil {
			source.Close()
			return errSingleBackup
		}
		err = walkMetricsSnapshot(ctx, source, target, name, true, &actual, &total)
		source.Close()
		if target.Sync() != nil {
			err = errSingleBackup
		}
		target.Close()
		if err != nil {
			return errSingleBackup
		}
	}
	// Verify exactly the copied subset, rather than trusting an earlier pass
	// over files that might have been changed between verification and copy.
	wanted := metricsSnapshotManifest{Files: []metricsSnapshotFile{}, Directories: []string{}}
	for _, file := range manifest.Files {
		if filepath.Dir(file.Path) == "postgres" || len(file.Path) > 5 && file.Path[:5] == "host/" {
			wanted.Files = append(wanted.Files, file)
		}
	}
	for _, directory := range manifest.Directories {
		if directory == "postgres" || directory == "host" || len(directory) > 5 && directory[:5] == "host/" {
			wanted.Directories = append(wanted.Directories, directory)
		}
	}
	sort.Strings(actual.Directories)
	sort.Slice(actual.Files, func(i, j int) bool { return actual.Files[i].Path < actual.Files[j].Path })
	if !reflect.DeepEqual(actual.Files, wanted.Files) || !reflect.DeepEqual(actual.Directories, wanted.Directories) {
		return errSingleBackup
	}
	if err := restoreMetricsSnapshot(ctx, filepath.Join(directory, "metrics"), manifest.Metrics, filepath.Join(stage.path, "metrics")); err != nil {
		return errSingleBackup
	}
	if _, err := writeSingleBackupJSON(stage.directory, "recovery-manifest.json", manifest); err != nil {
		return err
	}
	if _, err := writeSingleBackupJSON(stage.directory, "recovery-state.json", map[string]any{"backup_manifest_sha256": expected, "staged_at": time.Now().UTC(), "runtime_started": false, "postgres_imported": false, "cutover_authorized": false, "requires_node_epoch_reconciliation": true, "requires_latest_retirement_reconciliation": true}); err != nil {
		return err
	}
	return stage.publish(ctx)
}
