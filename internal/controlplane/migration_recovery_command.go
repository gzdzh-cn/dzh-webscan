package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"runtime"
)

type migrationRecoveryCommandRequest struct {
	Format     int    `json:"format"`
	Generation string `json:"generation"`
	Confirm    bool   `json:"confirm,omitempty"`
}

func isMigrationRecoveryCommand(action string) bool {
	switch action {
	case "migration-recovery-status", "begin-migration-recovery", "run-migration-recovery", "replay-migration-recovery-metrics", "suppress-migration-recovery-notifications":
		return true
	}
	return false
}

func decodeMigrationRecoveryCommand(path, action string) (migrationRecoveryCommandRequest, error) {
	var in migrationRecoveryCommandRequest
	raw, err := readTrustData(path, true, 64<<10)
	if !isMigrationRecoveryCommand(action) || err != nil || singleDecode(raw, &in) != nil || in.Format != 1 || !(validArchiveSource(in.Generation) || action == "migration-recovery-status" && in.Generation == "") {
		return in, ErrMigrationRecovery
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return in, ErrMigrationRecovery
	}
	for key := range keys {
		if key != "format" && key != "generation" && !(key == "confirm" && action == "suppress-migration-recovery-notifications") {
			return in, ErrMigrationRecovery
		}
	}
	if action == "suppress-migration-recovery-notifications" && !in.Confirm {
		return in, ErrMigrationRecovery
	}
	return in, nil
}

// Root-only local tooling. Neither a report nor notification suppression
// releases the recovery fence; the separate host verifier performs handoff.
func migrationRecoveryCommand(ctx context.Context, o Options, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || o.Output != "" {
		return ErrMigrationRecovery
	}
	in, err := decodeMigrationRecoveryCommand(o.Source, o.Action)
	if err != nil {
		return err
	}
	c, err := LoadConfig(o.Config)
	if err != nil {
		return ErrMigrationRecovery
	}
	s, err := Open(ctx, c)
	if err != nil {
		return ErrMigrationRecovery
	}
	defer s.DB.Close()
	var report MigrationRecoveryReport
	switch o.Action {
	case "migration-recovery-status":
		if in.Generation == "" {
			if err = s.DB.QueryRowContext(ctx, `SELECT generation FROM v3_migration_recovery_state WHERE id=1`).Scan(&in.Generation); err != nil {
				return ErrMigrationRecovery
			}
		}
		report, err = s.MigrationRecoveryReport(ctx, in.Generation)
	case "begin-migration-recovery":
		report, err = s.BeginMigrationRecovery(ctx, in.Generation)
	case "run-migration-recovery":
		report, err = s.RunMigrationRecovery(ctx, c, in.Generation)
	case "replay-migration-recovery-metrics":
		report, err = s.ReplayMigrationRecoveryMetrics(ctx, c, in.Generation)
	case "suppress-migration-recovery-notifications":
		if !identifier.MatchString(o.Username) {
			return ErrMigrationRecovery
		}
		err = s.SuppressMigrationRecoveryNotifications(ctx, in.Generation, o.Username)
		if err == nil {
			report, err = s.MigrationRecoveryReport(ctx, in.Generation)
		}
	default:
		return ErrMigrationRecovery
	}
	if err != nil {
		return ErrMigrationRecovery
	}
	return json.NewEncoder(out).Encode(report)
}
