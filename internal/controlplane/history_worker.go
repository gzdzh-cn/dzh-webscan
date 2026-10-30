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

	"webscan/internal/common"
)

type historyItem struct {
	Ordinal  int64     `json:"ordinal"`
	Stage    int       `json:"-"`
	Node     string    `json:"node"`
	ID       string    `json:"id"`
	Stamp    time.Time `json:"stamp"`
	Eligible bool      `json:"-"`
	Exported bool      `json:"-"`
	Part     string    `json:"-"`
}
type historyValue struct {
	Protected bool
	Data      json.RawMessage
}

func historyRecordKey(v historyItem) string {
	switch v.Stage {
	case 0, 1:
		return eventRecordKey("events", v.Node, v.ID)
	case 2, 3:
		return eventRecordKey("migrated_events", v.Node, v.ID)
	case 4:
		return "website-incident:" + v.ID
	case 5:
		return "server-health:" + v.ID
	case 6:
		return "notification:" + v.ID
	}
	return ""
}

// Only fields exposed as history are exported. Notification payloads, SMTP
// responses, request receipts, leases, session and deployment secrets are absent.
func historyPublicSQL(stage int) string {
	switch stage {
	case 0, 1, 2, 3:
		return `jsonb_build_object('node',t.node,'id',t.id,'received_at',t.received_at,'payload',t.payload)`
	case 4:
		return `jsonb_build_object('id',t.id,'site',t.site,'kind',t.kind,'started',t.started,'ended',t.ended,'reason',t.reason)`
	case 5:
		return `jsonb_build_object('id',t.id,'node',t.node,'kind',t.kind,'phase',t.phase,'time',t.time,'message',t.message,'state',t.payload)`
	case 6:
		return `jsonb_build_object('id',t.id,'node',t.node,'event_id',t.event_id,'channel',t.channel,'recipient',t.recipient,'created_at',t.created_at,'done_at',t.done_at,'attempts',t.attempts,'completed',t.done_at IS NOT NULL)`
	}
	return `'{}'::jsonb`
}

func historyValues(ctx context.Context, tx *sql.Tx, stage int, items []historyItem, cutoff time.Time, lock bool) (map[int64]historyValue, error) {
	x, err := retentionSourceFor(stage)
	if err != nil {
		return nil, err
	}
	query := `SELECT k.ordinal,(` + x.tm + `>=$2 OR COALESCE((` + strings.ReplaceAll(x.protected, "__cutoff__", "$2") + `),false)),` + historyPublicSQL(stage) + ` FROM ` + x.table + ` t JOIN jsonb_to_recordset($1::jsonb) AS k(ordinal bigint,node text,id text,stamp timestamptz) ON ` + x.node + `=k.node AND ` + x.id + `=k.id AND ` + x.tm + `=k.stamp WHERE ` + x.condition
	if lock {
		query += ` FOR UPDATE OF t`
	}
	rows, err := tx.QueryContext(ctx, query, common.JSON(items), cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]historyValue{}
	for rows.Next() {
		var n int64
		var v historyValue
		if err = rows.Scan(&n, &v.Protected, &v.Data); err != nil {
			return nil, err
		}
		out[n] = v
	}
	return out, rows.Err()
}

func historyItems(ctx context.Context, tx *sql.Tx, j HistoryJob) ([]historyItem, error) {
	q := `SELECT ordinal,stage,node,id,stamp,eligible,exported,export_part FROM v3_history_items WHERE preview=$1 AND NOT done ORDER BY ordinal LIMIT 500 FOR UPDATE`
	if j.Phase == "export" {
		q = `SELECT ordinal,stage,node,id,stamp,eligible,exported,export_part FROM v3_history_items WHERE preview=$1 AND ordinal>$2 ORDER BY ordinal LIMIT 20 FOR UPDATE`
	}
	var rows *sql.Rows
	var err error
	if j.Phase == "export" {
		rows, err = tx.QueryContext(ctx, q, j.Preview, j.ExportCursor)
	} else {
		if j.ExportFirst {
			q = strings.Replace(q, "LIMIT 500", "LIMIT 20", 1)
		}
		rows, err = tx.QueryContext(ctx, q, j.Preview)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []historyItem{}
	for rows.Next() {
		var v historyItem
		if err = rows.Scan(&v.Ordinal, &v.Stage, &v.Node, &v.ID, &v.Stamp, &v.Eligible, &v.Exported, &v.Part); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func saveHistoryJob(ctx context.Context, tx *sql.Tx, j HistoryJob) (HistoryJob, error) {
	return scanHistoryJob(tx.QueryRowContext(ctx, `UPDATE v3_history_jobs SET status=$2,phase=$3,cursor=$4,export_cursor=$5,scanned=$6,deleted=$7,skipped=$8,dependent_deleted=$9,exported=$10,export_bytes=$11,export_ready=$12,export_expires_at=$13,message=$14,updated_at=clock_timestamp(),finished_at=CASE WHEN $2 IN ('queued','running') THEN NULL ELSE clock_timestamp() END WHERE id=$1 RETURNING `+historyJobColumns, j.ID, j.Status, j.Phase, j.Cursor, j.ExportCursor, j.Scanned, j.Deleted, j.Skipped, j.DependentDeleted, j.Exported, j.ExportBytes, j.ExportReady, j.ExportExpires, j.Message))
}

func (s *Store) HistoryBatch(ctx context.Context, l Lease, id string) (HistoryJob, error) {
	if l.Resource != "retention" || !validArchiveSource(id) {
		return HistoryJob{}, ErrLeaseLost
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return HistoryJob{}, err
	}
	defer tx.Rollback()
	if err = s.Fence(ctx, tx, l); err != nil {
		return HistoryJob{}, err
	}
	if held, e := migrationHeld(ctx, tx); e != nil {
		return HistoryJob{}, e
	} else if held {
		return HistoryJob{}, ErrMigrationPending
	}
	// NO KEY UPDATE lets the separate file-intent journal reference this job.
	j, err := scanHistoryJob(tx.QueryRowContext(ctx, "SELECT "+historyJobColumns+" FROM v3_history_jobs WHERE id=$1 FOR NO KEY UPDATE", id))
	if err != nil {
		return j, err
	}
	if j.Status != "queued" && j.Status != "running" {
		return j, tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('webscan.history_job',$1,true)", j.ID); err != nil {
		return j, err
	}
	_, version, err := retentionTxSettings(ctx, tx)
	if err != nil {
		return j, err
	}
	if version != j.Version {
		j.Status = "cancelled"
		j.Phase = "finished"
		j.Message = "配置已变化；保留已完成部分，请重新预览"
	} else {
		j.Status = "running"
		items, e := historyItems(ctx, tx, j)
		if e != nil {
			return j, e
		}
		if j.Phase == "export" {
			j, err = s.exportHistoryBatch(ctx, tx, j, items)
		} else {
			j, err = s.cleanupHistoryBatch(ctx, tx, j, items)
		}
		if err != nil {
			return j, err
		}
	}
	j, err = saveHistoryJob(ctx, tx, j)
	if err != nil {
		return j, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'retention-progress',$2,$3)", j.Username, j.ID, common.JSON(common.Map{"kind": j.Kind, "phase": j.Phase, "status": j.Status, "scanned": j.Scanned, "deleted": j.Deleted, "skipped": j.Skipped, "dependent_deleted": j.DependentDeleted, "exported": j.Exported})); err != nil {
		return j, err
	}
	if err = s.Fence(ctx, tx, l); err != nil {
		return j, err
	}
	return j, tx.Commit()
}

func (s *Store) exportHistoryBatch(ctx context.Context, tx *sql.Tx, j HistoryJob, items []historyItem) (HistoryJob, error) {
	d, err := s.historyDirectory()
	if err != nil {
		return j, err
	}
	defer d.Close()
	if len(items) == 0 {
		var now time.Time
		if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
			return j, err
		}
		expires := now.Add(24 * time.Hour)
		j.ExportExpires = &expires
		j.ExportReady = true
		if j.Kind == "cleanup" {
			j.Phase = "cleanup"
			j.Message = "导出完成，准备按原预览范围重新检查保护并清理"
		} else {
			j.Status = "succeeded"
			if j.Skipped > 0 {
				j.Status = "partial"
			}
			j.Phase = "finished"
			j.Message = "导出完成，文件保留 24 小时；未删除原记录"
		}
		return j, nil
	}
	values := map[int64]historyValue{}
	for stage := 0; stage <= 6; stage++ {
		group := []historyItem{}
		for _, v := range items {
			if v.Stage == stage && v.Eligible {
				group = append(group, v)
			}
		}
		if len(group) == 0 {
			continue
		}
		found, e := historyValues(ctx, tx, stage, group, j.Cutoff, false)
		if e != nil {
			return j, e
		}
		for n, v := range found {
			values[n] = v
		}
	}
	raw := []byte{}
	exported := []int64{}
	scanned := int64(0)
	for _, v := range items {
		value, present := values[v.Ordinal]
		if present && !value.Protected && v.Eligible {
			line := common.JSON(common.Map{"record_key": historyRecordKey(v), "record": json.RawMessage(value.Data)})
			if len(line)+1 > historyPartLimit {
				return j, fmt.Errorf("%w：单条历史超过导出分片上限", ErrHistoryInput)
			}
			if len(raw) > 0 && len(raw)+len(line)+1 > historyPartLimit {
				break
			}
			raw = append(raw, line...)
			raw = append(raw, '\n')
			exported = append(exported, v.Ordinal)
		}
		scanned++
		j.ExportCursor = v.Ordinal
	}
	if len(raw) > 0 {
		// Commit the file intent independently BEFORE creating bytes. An interrupted
		// file/DB commit leaves a known, bounded orphan for expiry cleanup. Random
		// IDs ensure an expired worker cannot overwrite a successor's artifact.
		p := historyPart{ID: token(), Ordinal: j.ExportCursor, Bytes: int64(len(raw)), SHA256: digest(raw)}
		if _, err = s.DB.ExecContext(ctx, "INSERT INTO v3_history_export_parts(id,job,ordinal) VALUES($1,$2,$3)", p.ID, j.ID, p.Ordinal); err != nil {
			return j, err
		}
		if err = writeHistoryPart(ctx, d, p.ID, raw); err != nil {
			return j, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_history_export_parts SET ready=true,bytes=$2,sha256=$3 WHERE id=$1", p.ID, p.Bytes, p.SHA256); err != nil {
			return j, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_history_items SET exported=true,export_part=$2 WHERE ordinal IN (SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb)) AND preview=$3", common.JSON(exported), p.ID, j.Preview); err != nil {
			return j, err
		}
		j.Exported += int64(len(exported))
		j.ExportBytes += p.Bytes
	}
	if j.Kind == "export" {
		j.Scanned += scanned
		j.Skipped += scanned - int64(len(exported))
	}
	j.Message = "正在分批导出；导出完成前不会启动清理"
	return j, nil
}

func (s *Store) cleanupHistoryBatch(ctx context.Context, tx *sql.Tx, j HistoryJob, items []historyItem) (HistoryJob, error) {
	if len(items) == 0 {
		j.Status = "succeeded"
		if j.Skipped > 0 {
			j.Status = "partial"
		}
		j.Phase = "finished"
		j.Message = "处理完成；受保护或已不存在的记录已跳过，删除记录不等于立即释放磁盘空间"
		return j, nil
	}
	if j.ExportFirst {
		var valid bool
		if err := tx.QueryRowContext(ctx, "SELECT export_ready AND export_expires_at>clock_timestamp() FROM v3_history_jobs WHERE id=$1", j.ID).Scan(&valid); err != nil {
			return j, err
		}
		if !valid {
			return j, ErrHistoryExport
		}
		d, err := s.historyDirectory()
		if err != nil {
			return j, err
		}
		defer d.Close()
		seen := map[string]bool{}
		for _, v := range items {
			if !v.Exported || seen[v.Part] {
				continue
			}
			seen[v.Part] = true
			var p historyPart
			if err = tx.QueryRowContext(ctx, "SELECT id,ordinal,bytes,sha256 FROM v3_history_export_parts WHERE id=$1 AND job=$2 AND ready", v.Part, j.ID).Scan(&p.ID, &p.Ordinal, &p.Bytes, &p.SHA256); err != nil {
				return j, ErrHistoryExport
			}
			if _, err = readHistoryPart(ctx, d, p); err != nil {
				return j, err
			}
		}
	}
	done := []int64{}
	nodes := map[string]bool{}
	for _, v := range items {
		if v.Stage < 4 {
			nodes[v.Node] = true
		}
	}
	ordered := []string{}
	for n := range nodes {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	for _, n := range ordered {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,773376010))", n); err != nil {
			return j, err
		}
	}
	for stage := 0; stage <= 6; stage++ {
		group := []historyItem{}
		for _, v := range items {
			if v.Stage != stage {
				continue
			}
			if !v.Eligible || j.ExportFirst && !v.Exported {
				done = append(done, v.Ordinal)
				j.Scanned++
				j.Skipped++
			} else {
				group = append(group, v)
			}
		}
		if len(group) == 0 {
			continue
		}
		before, err := historyValues(ctx, tx, stage, group, j.Cutoff, true)
		if err != nil {
			return j, err
		}
		selected := []map[string]any{}
		for _, v := range group {
			current, exists := before[v.Ordinal]
			if !exists || current.Protected {
				done = append(done, v.Ordinal)
				j.Scanned++
				j.Skipped++
			} else {
				selected = append(selected, map[string]any{"node": v.Node, "id": v.ID, "stamp": v.Stamp})
			}
		}
		if len(selected) == 0 {
			continue
		}
		deleted, dependent, _, _, err := deleteRetentionRecords(ctx, tx, stage, selected, j.Cutoff)
		if err != nil {
			return j, err
		}
		j.Deleted += deleted
		j.DependentDeleted += dependent
		after, err := historyValues(ctx, tx, stage, group, j.Cutoff, false)
		if err != nil {
			return j, err
		}
		for _, v := range group {
			old, exists := before[v.Ordinal]
			if !exists || old.Protected {
				continue
			}
			current, remaining := after[v.Ordinal]
			if !remaining || current.Protected {
				done = append(done, v.Ordinal)
				j.Scanned++
				if current.Protected {
					j.Skipped++
				}
			}
		}
	}
	if len(done) > 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE v3_history_items SET done=true WHERE preview=$1 AND ordinal IN (SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb))", j.Preview, common.JSON(done)); err != nil {
			return j, err
		}
	}
	j.Message = "正在分批清理；已提交进度会保留，受保护记录不会删除"
	return j, nil
}

func (s *Store) runHistoryRound(ctx context.Context, l Lease) (bool, error) {
	var id string
	err := s.DB.QueryRowContext(ctx, "SELECT id FROM v3_history_jobs WHERE status IN ('queued','running') ORDER BY created_at,id LIMIT 1").Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	for ctx.Err() == nil {
		j, e := s.HistoryBatch(ctx, l, id)
		if e != nil {
			if !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) && !errors.Is(e, ErrLeaseLost) && !errors.Is(e, ErrMigrationPending) {
				op, cancel := context.WithTimeout(context.Background(), time.Second)
				tx, x := s.DB.BeginTx(op, nil)
				if x == nil {
					defer tx.Rollback()
					if s.Fence(op, tx, l) == nil {
						_, x = tx.ExecContext(op, "UPDATE v3_history_jobs SET status='failed',phase='finished',finished_at=clock_timestamp(),updated_at=clock_timestamp(),message='操作失败；已完成部分保留，请检查存储后重新预览' WHERE id=$1 AND status IN ('queued','running')", id)
						if x == nil {
							_, x = tx.ExecContext(op, "INSERT INTO v3_audit(username,kind,resource,result) SELECT username,'retention-failed',id,jsonb_build_object('deleted',deleted,'skipped',skipped,'exported',exported) FROM v3_history_jobs WHERE id=$1", id)
							if x == nil {
								_ = tx.Commit()
							}
						}
					}
					_ = tx.Rollback()
				}
				cancel()
			}
			return true, e
		}
		if j.Status != "queued" && j.Status != "running" {
			return true, nil
		}
	}
	return true, ctx.Err()
}
