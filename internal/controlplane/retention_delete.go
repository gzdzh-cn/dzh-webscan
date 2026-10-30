package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Automatic and operator-requested cleanup use exactly the same dependency,
// replay and final protection checks, under the same persistent retention lease.
func deleteRetentionRecords(ctx context.Context, tx *sql.Tx, stage int, selected []map[string]any, cutoff time.Time) (deletedCount, dependentCount, protectedCount int64, unfinished bool, failure error) {
	x, err := retentionSourceFor(stage)
	if err != nil {
		return 0, 0, 0, false, err
	}
	raw, _ := json.Marshal(selected)
	keys := `jsonb_to_recordset($1::jsonb) AS k(node text,id text,stamp timestamptz)`
	match := x.node + `=k.node AND ` + x.id + `=k.id AND ` + x.tm + `=k.stamp AND NOT COALESCE((` + strings.ReplaceAll(x.protected, "__cutoff__", "$2") + `),false)`
	// The cutoff is also used by multi-recipient completion protection.
	match += ` AND k.stamp<$2`
	var dependentDeleted int64
	deferred := false
	// Bound large dependent graphs too. Retain their parent until all eligible
	// attempts/display copies are gone, and retry this cursor on the next batch.
	// This avoids a large cascade repeatedly exhausting the two-second budget.
	if stage == 0 || stage == 1 || stage == 6 {
		dependentTable, foreign, join := "v3_imported_events", "h.id", "h.node=t.node AND h.event_id=t.id"
		if stage == 6 {
			dependentTable, join = "v3_notification_attempts", "h.notification=t.id"
		}
		res, e := tx.ExecContext(ctx, `DELETE FROM `+dependentTable+` WHERE id IN (SELECT `+foreign+` FROM `+dependentTable+` h JOIN `+x.table+` t ON `+join+`,`+keys+` WHERE `+match+` ORDER BY h.id LIMIT 500)`, raw, cutoff)
		if e != nil {
			return 0, 0, 0, false, e
		}
		dependentDeleted, e = res.RowsAffected()
		if e != nil {
			return 0, 0, 0, false, e
		}
		remaining := `EXISTS(SELECT 1 FROM ` + dependentTable + ` h WHERE ` + join + `)`
		match += ` AND NOT ` + remaining
	}
	if stage == 2 || stage == 3 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO v3_event_history_tombstones(node,event_id,digest) SELECT t.node,t.event_id,t.digest FROM `+x.table+` t,`+keys+` WHERE `+match+` AND t.event_id<>'' AND t.digest<>'' ON CONFLICT DO NOTHING`, raw, cutoff); err != nil {
			return 0, 0, 0, false, err
		}
	}
	if stage == 5 {
		res, e := tx.ExecContext(ctx, `DELETE FROM v3_health_outbox o USING v3_health_events t,`+keys+` WHERE o.id=t.id AND `+match, raw, cutoff)
		if e != nil {
			return 0, 0, 0, false, e
		}
		dependentDeleted, e = res.RowsAffected()
		if e != nil {
			return 0, 0, 0, false, e
		}
	}
	var deleted int64
	if stage == 0 || stage == 1 {
		// A receipt prevents display resurrection; remove duplicate Loki copies
		// as part of the same transaction, without inflating selected-row counts.
		err = tx.QueryRowContext(ctx, `WITH gone AS (DELETE FROM `+x.table+` t USING `+keys+` WHERE `+match+` RETURNING t.id) SELECT count(*) FROM gone`, raw, cutoff).Scan(&deleted)
	} else {
		var res sql.Result
		res, err = tx.ExecContext(ctx, `DELETE FROM `+x.table+` t USING `+keys+` WHERE `+match, raw, cutoff)
		if err == nil {
			deleted, err = res.RowsAffected()
		}
	}
	if err != nil {
		return 0, 0, 0, false, err
	}
	var newlyProtected, remainingWork int64
	check := `SELECT count(*) FILTER(WHERE COALESCE((` + strings.ReplaceAll(x.protected, "__cutoff__", "$2") + `),false)),count(*) FILTER(WHERE NOT COALESCE((` + strings.ReplaceAll(x.protected, "__cutoff__", "$2") + `),false)) FROM ` + x.table + ` t,` + keys + ` WHERE ` + x.node + `=k.node AND ` + x.id + `=k.id AND ` + x.tm + `=k.stamp AND k.stamp<$2`
	if err = tx.QueryRowContext(ctx, check, raw, cutoff).Scan(&newlyProtected, &remainingWork); err != nil {
		return 0, 0, 0, false, err
	}
	deferred = remainingWork > 0
	return deleted, dependentDeleted, newlyProtected, deferred, nil
}
