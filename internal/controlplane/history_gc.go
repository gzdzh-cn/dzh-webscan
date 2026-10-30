package controlplane

import (
	"context"
	"database/sql"
	"errors"
)

// File intents make crash leftovers discoverable without unbounded directory
// walks. Parts expire after 24h; operation/audit metadata is retained 365 days.
func (s *Store) HistoryGC(ctx context.Context, l Lease) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if l.Resource != "retention" {
		return ErrLeaseLost
	}
	if err = s.Fence(ctx, tx, l); err != nil {
		return err
	}
	if held, e := migrationHeld(ctx, tx); e != nil {
		return e
	} else if held {
		return ErrMigrationPending
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_history_jobs SET export_ready=false WHERE export_ready AND export_expires_at<=clock_timestamp()"); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT p.id FROM v3_history_export_parts p JOIN v3_history_jobs j ON j.id=p.job WHERE (NOT p.ready AND p.created_at<clock_timestamp()-interval '24 hours') OR (j.status NOT IN ('queued','running') AND COALESCE(j.export_expires_at,j.finished_at+interval '24 hours')<=clock_timestamp()) ORDER BY p.created_at LIMIT 100 FOR UPDATE OF p`)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		d, e := s.historyDirectory()
		if e != nil {
			return e
		}
		defer d.Close()
		for _, id := range ids {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if e = removeHistoryPart(d, id); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM v3_history_export_parts WHERE id=$1", id); e != nil {
				return e
			}
		}
	}
	// Large fixed previews are reclaimed in short batches too, never cascaded.
	for _, q := range []string{
		`DELETE FROM v3_history_items WHERE ordinal IN (SELECT i.ordinal FROM v3_history_items i JOIN v3_history_previews p ON p.id=i.preview WHERE (p.expires_at<clock_timestamp() AND NOT EXISTS(SELECT 1 FROM v3_history_jobs j WHERE j.preview=p.id)) OR EXISTS(SELECT 1 FROM v3_history_jobs j WHERE j.preview=p.id AND j.status NOT IN ('queued','running') AND j.finished_at<clock_timestamp()-interval '24 hours') ORDER BY i.ordinal LIMIT 500)`,
		`DELETE FROM v3_history_jobs WHERE id IN (SELECT j.id FROM v3_history_jobs j WHERE j.status NOT IN ('queued','running') AND j.finished_at<clock_timestamp()-interval '365 days' AND NOT EXISTS(SELECT 1 FROM v3_history_export_parts p WHERE p.job=j.id) AND NOT EXISTS(SELECT 1 FROM v3_history_items i WHERE i.preview=j.preview) ORDER BY j.finished_at LIMIT 500)`,
		`DELETE FROM v3_history_previews WHERE id IN (SELECT p.id FROM v3_history_previews p WHERE p.expires_at<clock_timestamp() AND NOT EXISTS(SELECT 1 FROM v3_history_jobs j WHERE j.preview=p.id) AND NOT EXISTS(SELECT 1 FROM v3_history_items i WHERE i.preview=p.id) ORDER BY p.expires_at LIMIT 500)`,
	} {
		if _, err = tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	if err = s.Fence(ctx, tx, l); err != nil {
		return err
	}
	return tx.Commit()
}

// Keep expiry housekeeping separate from an operator task's failure state.
func (s *Store) runHistoryGC(ctx context.Context, l Lease) error {
	err := s.HistoryGC(ctx, l)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}
