package controlplane

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	"webscan/internal/common"
	"webscan/internal/persist"
)

// Registered by the shared migration and restore entry points.
const hostWatchdogHistorySchema = `
CREATE TABLE IF NOT EXISTS v3_host_notification_imports(local_id text PRIMARY KEY,notification bigint NOT NULL UNIQUE REFERENCES v3_notifications(id) ON DELETE CASCADE,attempt_key text NOT NULL UNIQUE);
`

type hostWatchdogHistoryRecord struct {
	ID         string    `json:"id"`
	AttemptKey string    `json:"attempt_key"`
	Component  string    `json:"component"`
	Phase      string    `json:"phase"`
	Channel    string    `json:"channel"`
	Recipient  string    `json:"recipient"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	FinishedAt time.Time `json:"finished_at"`
}

func (s *hostWatchdogStore) history(ctx context.Context) ([]hostWatchdogHistoryRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT o.id,a.id,o.component,o.phase,o.channel,o.recipient,a.state,o.created_at,a.finished_at FROM outbox o JOIN attempts a ON a.outbox=o.id WHERE o.imported=0 AND a.state IN ('accepted','unknown') ORDER BY o.created_at,o.id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []hostWatchdogHistoryRecord{}
	for rows.Next() {
		var r hostWatchdogHistoryRecord
		var created, finished int64
		if err = rows.Scan(&r.ID, &r.AttemptKey, &r.Component, &r.Phase, &r.Channel, &r.Recipient, &r.State, &created, &finished); err != nil {
			return nil, err
		}
		r.CreatedAt, r.FinishedAt = time.Unix(created, 0).UTC(), time.Unix(finished, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *hostWatchdogStore) ackHistory(ctx context.Context, ids []string) error {
	if len(ids) > 100 {
		return errHostWatchdog
	}
	tx, err := persist.BeginWrite(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if !validArchiveSource(id) {
			return errHostWatchdog
		}
		if _, err = tx.ExecContext(ctx, `UPDATE outbox SET imported=1 WHERE id=? AND state IN ('accepted','unknown')`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func SyncHostWatchdogHistory(ctx context.Context, s *Store, c *HostQuotaClient) error {
	if c == nil {
		return nil
	}
	var records []hostWatchdogHistoryRecord
	if err := c.call(ctx, "/v1/history", struct{}{}, &records); err != nil {
		return err
	}
	if len(records) > 100 {
		return errHostWatchdog
	}
	ids := make([]string, 0, len(records))
	for _, r := range records {
		if !validArchiveSource(r.ID) || !validArchiveSource(r.AttemptKey) || !hostComponent(r.Component) || (r.Phase != "firing" && r.Phase != "resolved") || (r.Channel != "email" && r.Channel != "feishu") || (r.State != "accepted" && r.State != "unknown") || r.CreatedAt.IsZero() || r.FinishedAt.Before(r.CreatedAt) {
			return errHostWatchdog
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "host-watchdog-history:"+r.ID); err != nil {
			tx.Rollback()
			return err
		}
		var notification int64
		err = tx.QueryRowContext(ctx, `SELECT notification FROM v3_host_notification_imports WHERE local_id=$1`, r.ID).Scan(&notification)
		if err == sql.ErrNoRows {
			payload := common.JSON(common.Map{"kind": "host_" + r.Component, "phase": r.Phase, "members": []common.Map{{"component": r.Component}}, "message": hostNoticeMessage(r.Component, r.Phase)})
			err = tx.QueryRowContext(ctx, `INSERT INTO v3_notifications(node,event_id,channel,recipient,payload,created_at,done_at,attempts,result) VALUES('central',$1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT(node,event_id,channel,recipient) DO NOTHING RETURNING id`, "host-watchdog:"+r.ID, r.Channel, r.Recipient, payload, r.CreatedAt, r.FinishedAt, "host_watchdog_"+r.State).Scan(&notification)
			if err == nil {
				err = tx.QueryRowContext(ctx, `INSERT INTO v3_host_notification_imports(local_id,notification,attempt_key) VALUES($1,$2,$3) ON CONFLICT(local_id) DO NOTHING RETURNING notification`, r.ID, notification, r.AttemptKey).Scan(&notification)
				if err == sql.ErrNoRows {
					if e := tx.Commit(); e != nil {
						return e
					}
					ids = append(ids, r.ID)
					continue
				}
			}
			if err == nil {
				_, err = tx.ExecContext(ctx, `INSERT INTO v3_notification_attempts(notification,epoch,success,result,created_at) VALUES($1,0,$2,$3,$4)`, notification, r.State == "accepted", "host_watchdog_"+r.State, r.FinishedAt)
			}
			if err == nil {
				err = projectNotificationTx(ctx, tx, notification, "server_health")
			}
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		ids = append(ids, r.ID)
	}
	if len(ids) == 0 {
		return nil
	}
	return c.call(ctx, "/v1/history/ack", struct {
		IDs []string `json:"ids"`
	}{ids}, &struct{}{})
}
func RunHostWatchdogHistory(ctx context.Context, s *Store, c *HostQuotaClient) error {
	if c == nil {
		return nil
	}
	for ctx.Err() == nil {
		op, cancel := context.WithTimeout(ctx, 10*time.Second)
		_ = SyncHostWatchdogHistory(op, s, c)
		cancel()
		if !waitRetry(ctx, 10*time.Second) {
			return nil
		}
	}
	return nil
}

type HostWatchdogBackupResult struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Backup uses VACUUM INTO on the live WAL database; WAL/SHM files are never copied.
func BackupHostWatchdog(ctx context.Context, c Config, destination string) (HostWatchdogBackupResult, error) {
	var out HostWatchdogBackupResult
	if !c.HostWatchdog.Enabled || !snapshotAbsolutePath(destination) || c.HostWatchdog.StateDirectory == "" {
		return out, errHostWatchdog
	}
	source := filepath.Join(c.HostWatchdog.StateDirectory, "watchdog.sqlite3")
	raw, err := os.Lstat(source)
	if err != nil || !raw.Mode().IsRegular() || raw.Mode().Perm()&0077 != 0 || !snapshotOwned(raw) {
		return out, errHostWatchdog
	}
	db, err := persist.OpenReadOnly(source)
	if err != nil {
		return out, errHostWatchdog
	}
	defer db.Close()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if err = persist.BackupDB(db, destination); err != nil {
		return out, errHostWatchdog
	}
	check, err := persist.OpenReadOnly(destination)
	if err != nil {
		return out, errHostWatchdog
	}
	defer check.Close()
	var integrity string
	if check.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity) != nil || integrity != "ok" {
		return out, errHostWatchdog
	}
	artifact, err := hashTrustArtifact(ctx, destination, 256<<20)
	if err != nil {
		return out, errHostWatchdog
	}
	st, err := os.Stat(destination)
	if err != nil {
		return out, errHostWatchdog
	}
	return HostWatchdogBackupResult{File: destination, SHA256: artifact.SHA256, Size: st.Size()}, nil
}

// Restore only targets a stopped, empty state directory. Existing state is never
// replaced by a stale snapshot. Restored quotas remain consumed; liveness and
// delivery leases are discarded, and sending remains frozen for reconciliation.
func RestoreHostWatchdog(ctx context.Context, c Config, snapshot string) error {
	if !c.HostWatchdog.Enabled || !snapshotAbsolutePath(snapshot) || c.HostWatchdog.StateDirectory == "" {
		return errHostWatchdog
	}
	if _, err := os.Lstat(c.HostWatchdog.Socket); !os.IsNotExist(err) {
		return errHostWatchdog
	}
	v, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return errHostWatchdog
	}
	spec, err := loadHostSpec(c.HostWatchdog.SpecFile, v)
	if err != nil {
		return err
	}
	destination := filepath.Join(c.HostWatchdog.StateDirectory, "watchdog.sqlite3")
	if _, err = os.Lstat(destination); !os.IsNotExist(err) {
		return errHostWatchdog
	}
	st, err := os.Lstat(snapshot)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !snapshotOwned(st) {
		return errHostWatchdog
	}
	if os.MkdirAll(c.HostWatchdog.StateDirectory, 0700) != nil {
		return errHostWatchdog
	}
	directory, err := trustDirectory(c.HostWatchdog.StateDirectory, true)
	if err != nil {
		return errHostWatchdog
	}
	directory.Close()
	src, err := persist.OpenReadOnly(snapshot)
	if err != nil {
		return errHostWatchdog
	}
	defer src.Close()
	var integrity, instance, installation string
	if src.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity) != nil || integrity != "ok" || src.QueryRowContext(ctx, `SELECT instance,installation FROM host_state WHERE id=1`).Scan(&instance, &installation) != nil || instance != spec.Instance || installation != spec.InstallationSHA256 {
		return errHostWatchdog
	}
	if err = persist.BackupDB(src, destination); err != nil {
		return errHostWatchdog
	}
	dst, err := persist.OpenDB(destination)
	if err != nil {
		return errHostWatchdog
	}
	defer dst.Close()
	_, err = dst.ExecContext(ctx, `BEGIN IMMEDIATE;UPDATE host_state SET frozen=1,reason='restored_requires_reconciliation';UPDATE outbox SET state='unknown' WHERE state='sending';UPDATE attempts SET state='unknown',finished_at=strftime('%s','now') WHERE state='sending';DELETE FROM observations;DELETE FROM components;DELETE FROM maintenance;UPDATE preparations SET state='restored' WHERE state='frozen';COMMIT;`)
	return err
}
