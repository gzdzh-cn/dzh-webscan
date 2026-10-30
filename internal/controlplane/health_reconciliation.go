package controlplane

import (
	"context"
	"database/sql"
	"errors"
)

// The two legacy databases cannot commit atomically. A native task proves
// queue admission even if the metrics database never recorded the reply.
// Reconciliation only links imported data; it never enables a sender.
func (s *Store) reconcileHealthArchive(ctx context.Context) error {
	for {
		again, err := s.reconcileHealthArchiveBatch(ctx)
		if err != nil || !again {
			return err
		}
	}
}

func (s *Store) reconcileHealthArchiveBatch(ctx context.Context) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(773376002)"); err != nil {
		return false, err
	}
	var health, notices, healthPair, noticePair string
	err = tx.QueryRowContext(ctx, `SELECT h.source,n.source,h.related_source,n.related_source
 FROM v3_migration_domains h JOIN v3_migration_domains n ON n.domain='notifications'
 WHERE h.domain='server-health' AND h.pending AND n.pending`).Scan(&health, &notices, &healthPair, &noticePair)
	if err == sql.ErrNoRows {
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	if healthPair != notices || noticePair != health {
		return false, errors.New("告警与通知迁移源不配套，禁止继续")
	}
	// Both manifests, including empty tables, must have mapped checkpoints.
	var remaining bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(
 SELECT 1 FROM v3_imports i WHERE ((i.source=$1 AND i.table_name=ANY(ARRAY['health_rules','health_events','alert_batches','alert_outbox','alert_members']))
 OR (i.source=$2 AND i.table_name=ANY(ARRAY['tasks','email_recipients','delivery_records','email_attempts','kv'])))
 AND NOT EXISTS(SELECT 1 FROM v3_domain_imports d WHERE d.source=i.source AND d.table_name=i.table_name
 AND d.domain=CASE WHEN i.source=$1 THEN 'server-health' ELSE 'notifications' END AND d.complete AND d.processed=i.count))`, health, notices).Scan(&remaining); err != nil {
		return false, err
	}
	if remaining {
		return false, tx.Commit()
	}
	var invalid bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_health_batches b
 WHERE (b.done_at IS NULL AND (NOT EXISTS(SELECT 1 FROM v3_health_outbox o WHERE o.batch=b.id) OR (SELECT count(*) FROM v3_health_outbox o WHERE o.batch=b.id)>500))
 OR EXISTS(SELECT 1 FROM v3_health_outbox o WHERE o.batch=b.id AND
 (o.node<>b.node OR o.phase<>b.phase OR (o.done_at IS NULL)<>(b.done_at IS NULL))))`).Scan(&invalid); err != nil {
		return false, err
	}
	if invalid {
		return false, errors.New("旧告警批次成员或完成状态不一致，请核对配套快照")
	}
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_notifications n JOIN v3_health_batches b ON n.event_id='server-alert:'||b.id
 WHERE n.migration_source=$1 AND (n.node<>b.node OR n.payload->>'node_id' IS DISTINCT FROM b.node
 OR n.payload->>'notice_kind' IS DISTINCT FROM b.phase OR n.payload->>'message' IS DISTINCT FROM b.message))`, notices).Scan(&invalid); err != nil {
		return false, err
	}
	if invalid {
		return false, errors.New("原通知与告警批次内容不一致，请核对配套快照")
	}
	// A single original channel task proves the old atomic enqueue committed.
	// Preserve the original channels and recipients, including their completion
	// state, instead of expanding them from today's notification settings.
	rows, err := tx.QueryContext(ctx, `WITH candidates AS (
 SELECT b.id,b.created,q.admitted,(SELECT count(*) FROM v3_health_outbox o WHERE o.batch=b.id) members
 FROM v3_health_batches b JOIN LATERAL(SELECT min(created_at) admitted FROM v3_notifications
 WHERE migration_source=$1 AND event_id='server-alert:'||b.id) q ON q.admitted IS NOT NULL
 WHERE b.done_at IS NULL ORDER BY b.created,b.id LIMIT 500
 ), bounded AS (SELECT id,admitted,sum(members) OVER(ORDER BY created,id) total FROM candidates)
 UPDATE v3_health_batches b SET done_at=c.admitted FROM bounded c WHERE c.id=b.id AND c.total<=500 RETURNING b.id`, notices)
	if err != nil {
		return false, err
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
		return false, err
	}
	if len(ids) > 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE v3_health_outbox o SET done_at=b.done_at,result='原通知队列已接收，迁移核对完成'
 FROM v3_health_batches b WHERE o.batch=b.id AND b.id=ANY($1::text[]) AND o.done_at IS NULL`, ids); err != nil {
			return false, err
		}
	}
	return len(ids) > 0, tx.Commit()
}
