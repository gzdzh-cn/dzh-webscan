package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
	"webscan/internal/progress"
)

type metricsSnapshotRestoreSpec struct {
	Format         int    `json:"format"`
	Directory      string `json:"directory"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

var errMetricsSnapshotHost = errors.New("时序备份及隔离恢复命令仅允许在 Linux amd64 主控宿主机以 root 执行")

// Root-local maintenance only. No web API accepts storage paths or can create
// privileged snapshots. The installation fixes the source and VM endpoint.
func metricsSnapshotCommand(ctx context.Context, o Options, out io.Writer) (result error) {
	defer func() {
		if result == nil {
			return
		}
		code, message := "metrics_snapshot_failed", errMetricsSnapshot.Error()
		switch {
		case errors.Is(result, errMetricsSnapshotCleanup):
			code, message = "metrics_snapshot_cleanup_pending", errMetricsSnapshotCleanup.Error()
		case errors.Is(result, errMetricsSnapshotCreateUnknown):
			code, message = "metrics_snapshot_create_unconfirmed", errMetricsSnapshotCreateUnknown.Error()
		case errors.Is(result, errMetricsSnapshotHost):
			code, message = "metrics_snapshot_host_required", errMetricsSnapshotHost.Error()
		case errors.Is(result, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
			code, message = "metrics_snapshot_canceled", "时序备份或隔离恢复已取消，未覆盖原数据"
		case errors.Is(result, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
			code, message = "metrics_snapshot_timeout", "时序备份或隔离恢复超时，未覆盖原数据"
		}
		result = &progress.Failure{Code: code, Message: message}
	}()
	if o.Action != "verify-metrics-backup" && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0) {
		return errMetricsSnapshotHost
	}
	if o.Action == "backup-metrics" {
		store, err := metricsSnapshotInstallation(o)
		if err != nil {
			return err
		}
		receipt, result := store.backup(ctx, o.Output)
		// A valid artifact with pending source-snapshot cleanup is explicitly a
		// failed operation, but its path/hash are retained for controlled recovery.
		if receipt.Snapshot != "" {
			if err := json.NewEncoder(out).Encode(receipt); err != nil {
				return err
			}
		}
		return result
	}
	var request metricsSnapshotRestoreSpec
	raw, err := readTrustData(o.Source, true, 64<<10)
	if err != nil || singleDecode(raw, &request) != nil || request.Format != 1 || !snapshotAbsolutePath(request.Directory) || !releaseDigest(request.ManifestSHA256) {
		return errMetricsSnapshot
	}
	manifest, err := verifyMetricsSnapshot(ctx, request.Directory, request.ManifestSHA256)
	if err != nil {
		return err
	}
	state := "verified"
	if o.Action == "restore-metrics-offline" {
		if err := restoreMetricsSnapshot(ctx, request.Directory, request.ManifestSHA256, o.Output); err != nil {
			return err
		}
		state = "staged"
	} else if o.Action != "verify-metrics-backup" || o.Output != "" {
		return errMetricsSnapshot
	}
	return json.NewEncoder(out).Encode(map[string]any{"state": state, "snapshot": manifest.Snapshot, "files": len(manifest.Files), "manifest_sha256": request.ManifestSHA256, "runtime_started": false, "postgres_and_host_recovery_included": false})
}

func metricsSnapshotInstallation(o Options) (metricsSnapshotStore, error) {
	m, _, j, err := singlePKIUpgradeInstallation(o.Source)
	if err != nil || j.Step != 6 {
		return metricsSnapshotStore{}, errMetricsSnapshot
	}
	raw, err := readTrustData(o.Config, true, 2<<20)
	if err != nil {
		return metricsSnapshotStore{}, errMetricsSnapshot
	}
	var c Config
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF || c.Validate() != nil ||
		c.Central.Topology != "single" || c.Central.Instance != m.Spec.Instance || c.Database.DSNFile != m.Spec.configuration().Database.DSNFile || c.Metrics.QueryURL != m.Spec.configuration().Metrics.QueryURL {
		return metricsSnapshotStore{}, errMetricsSnapshot
	}
	return metricsSnapshotStore{URL: c.Metrics.QueryURL, Directory: filepath.Join(m.Spec.Root, "metrics-data")}, nil
}
