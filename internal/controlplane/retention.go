package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const retentionStages = 9

type RetentionJob struct {
	ID               string          `json:"id"`
	SettingsVersion  int64           `json:"settings_version"`
	Policy           RetentionPolicy `json:"policy"`
	Status           string          `json:"status"`
	Stage            int             `json:"stage"`
	Scanned          int64           `json:"scanned"`
	Deleted          int64           `json:"deleted"`
	Protected        int64           `json:"protected"`
	DependentDeleted int64           `json:"dependent_deleted"`
	Message          string          `json:"message"`
	Created          time.Time       `json:"created_at"`
	Updated          time.Time       `json:"updated_at"`
	Finished         *time.Time      `json:"finished_at"`
}

const retentionJobColumns = `id,settings_version,policy,status,stage,scanned,deleted,protected,dependent_deleted,message,created_at,updated_at,finished_at`

func scanRetentionJob(row interface{ Scan(...any) error }) (RetentionJob, error) {
	var j RetentionJob
	var raw []byte
	err := row.Scan(&j.ID, &j.SettingsVersion, &raw, &j.Status, &j.Stage, &j.Scanned, &j.Deleted, &j.Protected, &j.DependentDeleted, &j.Message, &j.Created, &j.Updated, &j.Finished)
	if err == nil {
		err = json.Unmarshal(raw, &j.Policy)
	}
	return j, err
}

// Scheduling and deletion share a persistent fenced lease. At most one hourly
// run exists; restarts continue its committed cursor instead of rescanning an
// unbounded table. No filesystem, time-series deletion or VACUUM occurs here.
func (s *Store) ScheduleRetention(ctx context.Context, l Lease) (RetentionJob, error) {
	if l.Resource != "retention" {
		return RetentionJob{}, ErrLeaseLost
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return RetentionJob{}, err
	}
	defer tx.Rollback()
	if err = s.Fence(ctx, tx, l); err != nil {
		return RetentionJob{}, err
	}
	if held, e := migrationHeld(ctx, tx); e != nil {
		return RetentionJob{}, e
	} else if held {
		return RetentionJob{}, ErrMigrationPending
	}
	j, err := scanRetentionJob(tx.QueryRowContext(ctx, "SELECT "+retentionJobColumns+" FROM v3_retention_jobs WHERE status='running' FOR UPDATE"))
	if err == nil {
		return j, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return j, err
	}
	j, err = scanRetentionJob(tx.QueryRowContext(ctx, "SELECT "+retentionJobColumns+" FROM v3_retention_jobs WHERE slot=floor(extract(epoch FROM clock_timestamp())/3600)::bigint"))
	if err == nil {
		return j, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return j, err
	}
	p, version, err := retentionTxSettings(ctx, tx)
	if err != nil {
		return j, err
	}
	raw, _ := json.Marshal(p)
	j, err = scanRetentionJob(tx.QueryRowContext(ctx, `INSERT INTO v3_retention_jobs(id,slot,settings_version,policy,status)
 VALUES($1,floor(extract(epoch FROM clock_timestamp())/3600)::bigint,$2,$3,'running') ON CONFLICT(slot) DO UPDATE SET slot=excluded.slot RETURNING `+retentionJobColumns, token(), version, raw))
	if err != nil {
		return j, err
	}
	return j, tx.Commit()
}

type retentionSource struct{ table, tm, node, id, condition, protected string }

const retentionEventProtection = `EXISTS(SELECT 1 FROM v3_notifications n WHERE n.node=t.node AND n.event_id=%s AND (n.done_at IS NULL OR n.migration_pending OR n.lease_until>clock_timestamp()))
 OR t.payload->'scan'->>'status' IN ('pending','queued','running')
 OR EXISTS(SELECT 1 FROM v3_health_rules r WHERE r.node=t.node AND r.phase IN ('pending','firing') AND to_timestamp(r.since)<=t.received_at)`

func retentionSourceFor(stage int) (retentionSource, error) {
	x := retentionSource{condition: "true"}
	switch stage {
	case 0, 1:
		x.table, x.tm, x.node, x.id = "v3_events", "t.received_at", "t.node", "t.id"
		x.condition = fmt.Sprintf("t.security=%t", stage == 1)
		x.protected = fmt.Sprintf(retentionEventProtection, "t.id")
	case 2, 3:
		x.table, x.tm, x.node, x.id = "v3_imported_events", "t.received_at", "t.node", "t.id"
		x.condition = fmt.Sprintf("t.security=%t", stage == 3)
		x.protected = fmt.Sprintf(retentionEventProtection, "t.event_id")
	case 4:
		x.table, x.tm, x.node, x.id = "v3_website_incidents", "to_timestamp(COALESCE(t.ended,t.started))", "''::text", "t.id::text"
		x.protected = `t.ended IS NULL
 OR EXISTS(SELECT 1 FROM v3_website_outbox o WHERE o.site=t.site AND o.done_at IS NULL)
 OR EXISTS(SELECT 1 FROM v3_notifications n WHERE (n.payload->>'source'='website' OR n.event_id LIKE 'website:%' OR n.event_id LIKE 'website-v3:%') AND (n.done_at IS NULL OR n.migration_pending OR n.lease_until>clock_timestamp()))`
	case 5:
		x.table, x.tm, x.node, x.id = "v3_health_events", "to_timestamp(t.time)", "t.node", "t.id"
		x.protected = `EXISTS(SELECT 1 FROM v3_health_rules r WHERE r.node=t.node AND r.kind=t.kind AND r.phase IN ('pending','firing') AND r.since<=t.time)
 OR EXISTS(SELECT 1 FROM v3_health_outbox o WHERE o.id=t.id AND (o.done_at IS NULL OR EXISTS(SELECT 1 FROM v3_health_batches b WHERE b.id=o.batch AND b.done_at IS NULL) OR EXISTS(SELECT 1 FROM v3_notifications n WHERE n.node=o.node AND n.event_id='server-alert:'||o.batch AND (n.done_at IS NULL OR n.migration_pending OR n.lease_until>clock_timestamp()))))
 OR EXISTS(SELECT 1 FROM v3_notifications n WHERE n.node=t.node AND n.event_id='native:'||t.id AND (n.done_at IS NULL OR n.migration_pending OR n.lease_until>clock_timestamp()))`
	case 6:
		x.table, x.tm, x.node, x.id = "v3_notifications", "COALESCE(t.done_at,t.created_at)", "t.node", "t.id::text"
		x.protected = `t.done_at IS NULL OR t.migration_pending OR t.lease_until>clock_timestamp()
 OR EXISTS(SELECT 1 FROM v3_notifications n WHERE n.node=t.node AND n.event_id=t.event_id AND (n.done_at IS NULL OR n.done_at>=__cutoff__ OR n.migration_pending OR n.lease_until>clock_timestamp()))
 OR EXISTS(SELECT 1 FROM v3_notifications n WHERE n.node=t.node AND n.channel=t.channel AND n.recipient=t.recipient AND n.id<t.id AND n.done_at IS NULL)
 OR EXISTS(SELECT 1 FROM v3_health_rules r WHERE r.node=t.node AND r.phase IN ('pending','firing') AND to_timestamp(r.since)<=t.created_at)
 OR ((t.payload->>'source'='website' OR t.event_id LIKE 'website:%' OR t.event_id LIKE 'website-v3:%') AND EXISTS(SELECT 1 FROM v3_website_incidents i WHERE i.ended IS NULL))`
	case 7:
		x.table, x.tm, x.node, x.id = "v3_website_outbox", "COALESCE(t.done_at,to_timestamp(t.created))", "t.node", "t.id::text"
		x.protected = `t.done_at IS NULL OR EXISTS(SELECT 1 FROM v3_website_incidents i WHERE i.site=t.site AND i.ended IS NULL)
 OR EXISTS(SELECT 1 FROM v3_notifications n WHERE (n.payload->>'source'='website' OR n.event_id LIKE 'website:%' OR n.event_id LIKE 'website-v3:%') AND (n.done_at IS NULL OR n.migration_pending OR n.lease_until>clock_timestamp()))`
	case 8:
		x.table, x.tm, x.node, x.id = "v3_health_batches", "COALESCE(t.done_at,to_timestamp(t.created))", "t.node", "t.id"
		x.protected = `t.done_at IS NULL OR EXISTS(SELECT 1 FROM v3_health_outbox o WHERE o.batch=t.id)
 OR EXISTS(SELECT 1 FROM v3_notifications n WHERE n.node=t.node AND n.event_id='server-alert:'||t.id AND (n.done_at IS NULL OR n.migration_pending OR n.lease_until>clock_timestamp()))`
	default:
		return x, errors.New("历史清理阶段不正确")
	}
	if stage <= 6 {
		// A queued export/cleanup pins exactly its selected records against
		// automatic retention. The fenced manual worker bypasses these pins,
		// while still checking all business dependencies in the same transaction.
		x.protected += fmt.Sprintf(` OR (COALESCE(current_setting('webscan.history_job',true),'')='' AND EXISTS(SELECT 1 FROM v3_history_items h JOIN v3_history_jobs j ON j.preview=h.preview WHERE h.stage=%d AND h.node=%s AND h.id=%s AND h.stamp=%s AND j.status IN ('queued','running')))`, stage, x.node, x.id, x.tm)
	}
	return x, nil
}

// RetentionBatch scans at most 500 primary records and commits cursor, counts,
// dependent deletion and audit together. Protection is checked after row locks
// and again immediately before deletion. Error rollback never advances cursor.
func (s *Store) RetentionBatch(ctx context.Context, l Lease, id string) (RetentionJob, error) {
	if l.Resource != "retention" || !validArchiveSource(id) {
		return RetentionJob{}, ErrLeaseLost
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return RetentionJob{}, err
	}
	defer tx.Rollback()
	if err = s.Fence(ctx, tx, l); err != nil {
		return RetentionJob{}, err
	}
	if held, e := migrationHeld(ctx, tx); e != nil {
		return RetentionJob{}, e
	} else if held {
		return RetentionJob{}, ErrMigrationPending
	}
	_, version, err := retentionTxSettings(ctx, tx)
	if err != nil {
		return RetentionJob{}, err
	}
	j, err := scanRetentionJob(tx.QueryRowContext(ctx, "SELECT "+retentionJobColumns+" FROM v3_retention_jobs WHERE id=$1 FOR UPDATE", id))
	if err != nil {
		return j, err
	}
	if j.Status != "running" {
		return j, tx.Commit()
	}
	if j.SettingsVersion != version {
		j, err = scanRetentionJob(tx.QueryRowContext(ctx, "UPDATE v3_retention_jobs SET status='cancelled',message='配置已变化，保留已完成部分，后续轮次按新期限检查',updated_at=clock_timestamp(),finished_at=clock_timestamp() WHERE id=$1 RETURNING "+retentionJobColumns, id))
		if err != nil {
			return j, err
		}
		result, _ := json.Marshal(map[string]any{"status": j.Status, "scanned": j.Scanned, "deleted": j.Deleted, "protected": j.Protected, "dependent_deleted": j.DependentDeleted})
		if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES('system','retention-cancelled',$1,$2)", j.ID, result); err != nil {
			return j, err
		}
		return j, tx.Commit()
	}
	if err = j.Policy.Validate(); err != nil {
		return j, err
	}
	days, err := retentionDaysForStage(j.Policy, j.Stage)
	if err != nil {
		return j, err
	}
	x, err := retentionSourceFor(j.Stage)
	if err != nil {
		return j, err
	}
	var cursor time.Time
	var node, key string
	if err = tx.QueryRowContext(ctx, "SELECT cursor_time,cursor_node,cursor_id FROM v3_retention_jobs WHERE id=$1", id).Scan(&cursor, &node, &key); err != nil {
		return j, err
	}
	// created_at fixes the cutoff across process restarts and policy checks.
	cutoff := j.Created.Add(-time.Duration(days) * 24 * time.Hour)
	query := `SELECT ` + x.tm + `,` + x.node + `,` + x.id + `,COALESCE((` + strings.ReplaceAll(x.protected, "__cutoff__", "$1") + `),false) FROM ` + x.table + ` t WHERE ` + x.condition + ` AND ` + x.tm + `<$1 AND (` + x.tm + `,` + x.node + `,` + x.id + `)>($2,$3,$4) ORDER BY ` + x.tm + `,` + x.node + `,` + x.id + ` LIMIT 500 FOR UPDATE OF t`
	rows, err := tx.QueryContext(ctx, query, cutoff, cursor, node, key)
	if err != nil {
		return j, err
	}
	type record struct {
		stamp     time.Time
		node, id  string
		protected bool
	}
	items := []record{}
	for rows.Next() {
		var v record
		if err = rows.Scan(&v.stamp, &v.node, &v.id, &v.protected); err != nil {
			break
		}
		items = append(items, v)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return j, err
	}
	if j.Stage < 4 {
		nodes := map[string]bool{}
		for _, v := range items {
			nodes[v.node] = true
		}
		ordered := []string{}
		for n := range nodes {
			ordered = append(ordered, n)
		}
		sort.Strings(ordered)
		for _, n := range ordered {
			if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,773376010))", n); err != nil {
				return j, err
			}
		}
	}
	selected := []map[string]any{}
	for _, v := range items {
		if !v.protected {
			selected = append(selected, map[string]any{"node": v.node, "id": v.id, "stamp": v.stamp})
		}
	}
	deleted, dependentDeleted, newlyProtected, deferred, err := deleteRetentionRecords(ctx, tx, j.Stage, selected, cutoff)
	if err != nil {
		return j, err
	}
	j.Scanned += int64(len(items))
	j.Deleted += deleted
	j.DependentDeleted += dependentDeleted
	// Deferred parents are unfinished work, rather than a protected condition.
	protected := newlyProtected
	for _, v := range items {
		if v.protected {
			protected++
		}
	}
	j.Protected += protected
	if deferred {
		// Keep the committed cursor until these bounded children are complete.
	} else if len(items) < 500 {
		j.Stage++
		cursor = time.Unix(0, 0)
		node, key = "", ""
	} else {
		last := items[len(items)-1]
		cursor, node, key = last.stamp, last.node, last.id
	}
	if j.Stage == retentionStages {
		j.Status = "succeeded"
	}
	message := "正在分批清理；记录删除不等于立即释放磁盘空间"
	if j.Status == "succeeded" {
		message = "本轮历史清理完成；受保护记录保留，磁盘空间由后续写入复用"
	}
	if j, err = scanRetentionJob(tx.QueryRowContext(ctx, `UPDATE v3_retention_jobs SET status=$2,stage=$3,cursor_time=$4,cursor_node=$5,cursor_id=$6,scanned=$7,deleted=$8,protected=$9,message=$10,dependent_deleted=$11,updated_at=clock_timestamp(),finished_at=CASE WHEN $2='succeeded' THEN clock_timestamp() ELSE NULL END WHERE id=$1 RETURNING `+retentionJobColumns, id, j.Status, j.Stage, cursor, node, key, j.Scanned, j.Deleted, j.Protected, message, j.DependentDeleted)); err != nil {
		return j, err
	}
	if len(items) > 0 || j.Status == "succeeded" {
		result, _ := json.Marshal(map[string]any{"stage": j.Stage, "scanned": len(items), "deleted": deleted, "protected": protected, "dependent_deleted": dependentDeleted, "continuing_dependencies": deferred, "status": j.Status})
		if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES('system','retention-batch',$1,$2)", id, result); err != nil {
			return j, err
		}
	}
	if err = s.Fence(ctx, tx, l); err != nil {
		return j, err
	}
	j.Message = message
	return j, tx.Commit()
}

func (s *Store) RunRetentionRound(ctx context.Context, instance string) (resultErr error) {
	op, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	l, err := s.Acquire(op, "retention", instance)
	if err != nil {
		return err
	}
	automaticWork := false
	defer func() {
		op, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Release(op, l)
	}()
	defer func() {
		if !automaticWork || resultErr == nil || errors.Is(resultErr, context.Canceled) || errors.Is(resultErr, context.DeadlineExceeded) || errors.Is(resultErr, ErrMigrationPending) {
			return
		}
		op, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		tx, e := s.DB.BeginTx(op, nil)
		if e != nil {
			return
		}
		defer tx.Rollback()
		if s.Fence(op, tx, l) != nil {
			return
		}
		if _, e = tx.ExecContext(op, `WITH failed AS (UPDATE v3_retention_jobs SET message='本轮清理失败，已完成部分保留，等待自动重试',updated_at=clock_timestamp() WHERE status='running' AND message IS DISTINCT FROM '本轮清理失败，已完成部分保留，等待自动重试' RETURNING id,scanned,deleted,protected,dependent_deleted)
 INSERT INTO v3_audit(username,kind,resource,result) SELECT 'system','retention-retrying',id,jsonb_build_object('scanned',scanned,'deleted',deleted,'protected',protected,'dependent_deleted',dependent_deleted,'retrying',true) FROM failed`); e == nil {
			_ = tx.Commit()
		}
	}()
	gcContext, gcCancel := context.WithTimeout(op, 250*time.Millisecond)
	gcErr := s.runHistoryGC(gcContext, l)
	gcCancel()
	// Reserve time for automatic retention even when operators continuously
	// submit large exports. A manual budget timeout is a yield, not a failure.
	backupContext, backupCancel := context.WithTimeout(op, 500*time.Millisecond)
	backupErr := s.runConfigurationDeleteRound(backupContext, l)
	backupCancel()
	if errors.Is(backupErr, context.DeadlineExceeded) && ctx.Err() == nil {
		backupErr = nil // Exhausted budget yields; committed work is durable.
	}
	if errors.Is(backupErr, ErrLeaseLost) || errors.Is(backupErr, ErrMigrationPending) || ctx.Err() != nil {
		return backupErr
	}
	// An archive-specific failure must not starve independent history cleanup.
	// Still report it after that work; its own worker journals the retry state.
	historyContext, historyCancel := context.WithTimeout(op, 500*time.Millisecond)
	_, err = s.runHistoryRound(historyContext, l)
	historyCancel()
	if err != nil && !(errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil) {
		return err
	}
	automaticWork = true
	j, err := s.ScheduleRetention(op, l)
	if err != nil {
		return err
	}
	for j.Status == "running" && op.Err() == nil {
		j, err = s.RetentionBatch(op, l, j.ID)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				automaticWork = false
				return errors.Join(gcErr, backupErr)
			}
			return err
		}
	}
	// The budget is a normal yield; each committed cursor is already durable.
	if errors.Is(op.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		automaticWork = false
		return errors.Join(gcErr, backupErr)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	automaticWork = false
	return errors.Join(gcErr, backupErr)
}

// The five-second wakeup only continues a bounded unfinished round. The
// durable hourly slot prevents repeated full scans by multiple API instances.
func (s *Store) RunRetention(ctx context.Context, instance string) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		err := s.RunRetentionRound(ctx, instance)
		state := "active"
		if errors.Is(err, ErrLeaseLost) {
			state = "standby"
		}
		reason := ""
		if err != nil && !errors.Is(err, ErrLeaseLost) {
			reason = "历史清理暂未完成，已保留进度并等待重试"
		}
		if errors.Is(err, ErrMigrationPending) {
			reason = "数据迁移期间暂停历史清理"
		}
		op, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, _ = s.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('retention',$1,clock_timestamp(),$2,jsonb_build_object('state',$3::text)) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details=excluded.details`, instance, reason, state)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
