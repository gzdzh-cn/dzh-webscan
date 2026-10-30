package controlplane

import (
	"context"
	"time"
)

// Housekeeping removes expired authentication data, stale worker heartbeats
// and audit older than 365 days. It never deletes business history or queues.
func (s *Store) Housekeeping(ctx context.Context, instance string) error {
	l, err := s.Acquire(ctx, "housekeeping", instance)
	if err != nil {
		return err
	}
	op, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	queries := []string{
		`DELETE FROM v3_bootstrap_processes WHERE instance IN(SELECT instance FROM v3_bootstrap_processes WHERE heartbeat<clock_timestamp()-interval '1 day' ORDER BY heartbeat,instance LIMIT 500)`,
		`DELETE FROM v3_role_status WHERE (role,instance) IN(SELECT role,instance FROM v3_role_status WHERE heartbeat<clock_timestamp()-interval '1 day' ORDER BY heartbeat LIMIT 500)`,
		`DELETE FROM v3_login_attempts WHERE key IN(SELECT key FROM v3_login_attempts WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 500)`,
		`DELETE FROM v3_sessions WHERE token_hash IN(SELECT token_hash FROM v3_sessions WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 500)`,
		`DELETE FROM v3_configuration_backup_pins WHERE (backup,kind,reference) IN(SELECT backup,kind,reference FROM v3_configuration_backup_pins WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 500)`,
		`DELETE FROM v3_configuration_restore_previews WHERE token_hash IN(SELECT token_hash FROM v3_configuration_restore_previews WHERE expires_at<=clock_timestamp() ORDER BY expires_at,token_hash LIMIT 500)`,
		`DELETE FROM v3_configuration_revision_parts WHERE (revision,part) IN(SELECT p.revision,p.part FROM v3_configuration_revision_parts p JOIN v3_configuration_revisions r ON r.id=p.revision WHERE r.status='cancelled' AND r.finished_at<clock_timestamp()-interval '365 days' AND NOT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending) ORDER BY r.finished_at,r.id,p.part LIMIT 500)`,
		`DELETE FROM v3_configuration_revisions WHERE id IN(SELECT r.id FROM v3_configuration_revisions r WHERE r.status='cancelled' AND r.finished_at<clock_timestamp()-interval '365 days' AND NOT EXISTS(SELECT 1 FROM v3_configuration_revision_parts p WHERE p.revision=r.id) AND NOT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending) ORDER BY r.finished_at,r.id LIMIT 500)`,
		`DELETE FROM v3_configuration_restore_stages WHERE id IN(SELECT s.id FROM v3_configuration_restore_stages s WHERE s.status='cancelled' AND s.finished_at<clock_timestamp()-interval '365 days' AND NOT EXISTS(SELECT 1 FROM v3_configuration_revisions r WHERE r.stage=s.id) AND NOT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending) ORDER BY s.finished_at,s.id LIMIT 500)`,
		`DELETE FROM v3_configuration_delete_items WHERE (job,ordinal) IN(SELECT i.job,i.ordinal FROM v3_configuration_delete_items i JOIN v3_configuration_delete_jobs j ON j.id=i.job WHERE NOT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending) AND j.status NOT IN ('queued','running') AND j.finished_at<clock_timestamp()-interval '365 days' ORDER BY j.finished_at,i.ordinal LIMIT 500)`,
		`DELETE FROM v3_configuration_delete_jobs WHERE id IN(SELECT j.id FROM v3_configuration_delete_jobs j WHERE NOT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending) AND j.status NOT IN ('queued','running') AND j.finished_at<clock_timestamp()-interval '365 days' AND NOT EXISTS(SELECT 1 FROM v3_configuration_delete_items i WHERE i.job=j.id) ORDER BY j.finished_at LIMIT 500)`,
		`DELETE FROM v3_configuration_delete_previews WHERE id IN(SELECT p.id FROM v3_configuration_delete_previews p WHERE NOT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending) AND p.expires_at<clock_timestamp() AND NOT EXISTS(SELECT 1 FROM v3_configuration_delete_jobs j WHERE j.preview=p.id) ORDER BY p.expires_at LIMIT 500)`,
		`DELETE FROM v3_audit WHERE id IN(SELECT id FROM v3_audit WHERE NOT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending) AND created_at<clock_timestamp()-interval '365 days' ORDER BY created_at LIMIT 500)`,
	}
	for _, q := range queries {
		for op.Err() == nil {
			tx, err := s.DB.BeginTx(op, nil)
			if err != nil {
				return err
			}
			if err = s.Fence(op, tx, l); err != nil {
				tx.Rollback()
				return err
			}
			r, err := tx.ExecContext(op, q)
			if err != nil {
				tx.Rollback()
				return err
			}
			count, err := r.RowsAffected()
			if err != nil {
				tx.Rollback()
				return err
			}
			if err = tx.Commit(); err != nil {
				return err
			}
			if count < 500 {
				break
			}
		}
	}
	return op.Err()
}

func (s *Store) RunHousekeeping(ctx context.Context, instance string) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		op, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = s.Housekeeping(op, instance)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
