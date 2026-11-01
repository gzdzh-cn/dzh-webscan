package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"webscan/internal/common"
)

type healthNotice struct {
	id, node, phase, message string
	created                  int64
}

// FlushHealth atomically transfers stable batches to the existing independent
// channel queues. No network I/O runs under this transaction. A crash can
// neither lose a batch nor enqueue a second identity for its members.
func (s *Store) FlushHealth(ctx context.Context, l Lease) error {
	if l.Resource != "health-flush" {
		return ErrLeaseLost
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.Fence(ctx, tx, l); err != nil {
		return err
	}
	if held, e := migrationHeld(ctx, tx); e != nil {
		return e
	} else if held {
		return tx.Commit()
	}
	config, _, err := healthSettings(ctx, tx)
	if err != nil {
		return err
	}
	if common.B(config["notifications_paused"]) {
		return tx.Commit()
	}
	// Filter inhibited/waiting entries before LIMIT. A long outage on one
	// node must not starve notifications for every other node in the cluster.
	var now int64
	if err = tx.QueryRowContext(ctx, "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").Scan(&now); err != nil {
		return err
	}
	used, err := flushExistingHealthBatches(ctx, tx, config)
	if err != nil {
		return err
	}
	remaining := 500 - used
	if remaining <= 0 {
		return tx.Commit()
	}
	wait := int64(max(15, common.I(config["group_wait_seconds"])))
	interval := int64(max(0, common.I(config["group_interval_seconds"])))
	args := []any{now, wait, interval, common.SS(config["maintenance_nodes"]), remaining}
	joins := ` FROM v3_health_outbox o JOIN v3_active_nodes n ON n.id=o.node JOIN v3_health_events e ON e.id=o.id
 LEFT JOIN v3_health_rules r ON r.key=(e.payload->>'key')
 LEFT JOIN v3_health_rules u ON u.key=o.node||':node_unreachable'
 LEFT JOIN LATERAL(SELECT done_at FROM v3_health_batches WHERE node=o.node AND phase=o.phase AND done_at IS NOT NULL ORDER BY done_at DESC LIMIT 1) b ON true `
	eligible := `o.done_at IS NULL AND o.batch IS NULL AND (NOT n.enabled OR r.phase='disabled' OR (
 o.created<=$1::bigint-$2::bigint AND ($3::bigint=0 OR b.done_at IS NULL OR extract(epoch FROM b.done_at)<=$1::bigint-$3::bigint)
 AND (e.kind='node_unreachable' OR COALESCE(u.phase,'')<>'firing')
 AND NOT (o.node=ANY($4::text[]))
 AND NOT EXISTS(SELECT 1 FROM v3_deployment_jobs j WHERE j.node=o.node AND j.status='running' AND j.recovery_required AND j.lease_until>clock_timestamp())))`
	// Node-before-outbox locking also serializes disabling a node and queueing
	// its alarms. Recheck eligibility after acquiring those node locks.
	rows, err := tx.QueryContext(ctx, `SELECT id FROM v3_nodes WHERE id IN(SELECT o.node`+joins+`WHERE `+eligible+` ORDER BY o.created,o.id LIMIT $5) ORDER BY id FOR SHARE`, args...)
	if err != nil {
		return err
	}
	nodes := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		nodes = append(nodes, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	args = append(args, nodes)
	rows, err = tx.QueryContext(ctx, `SELECT o.id,o.node,o.phase,o.message,o.created,n.enabled,COALESCE(r.phase,'')`+joins+`WHERE `+eligible+` AND o.node=ANY($6::text[]) ORDER BY o.created,o.id FOR UPDATE OF o SKIP LOCKED LIMIT $5`, args...)
	if err != nil {
		return err
	}
	groups := [][]healthNotice{}
	lookup := map[string]int{}
	cancelled := []string{}
	for rows.Next() {
		var v healthNotice
		var enabled bool
		var state string
		if err = rows.Scan(&v.id, &v.node, &v.phase, &v.message, &v.created, &enabled, &state); err != nil {
			break
		}
		if !enabled || state == "disabled" {
			cancelled = append(cancelled, v.id)
			continue
		}
		key := fmt.Sprintf("%s:%s:%d", v.node, v.phase, v.created/15)
		index, ok := lookup[key]
		if !ok {
			index = len(groups)
			lookup[key] = index
			groups = append(groups, nil)
		}
		groups[index] = append(groups[index], v)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if len(cancelled) > 0 {
		if _, err = tx.ExecContext(ctx, "UPDATE v3_health_outbox SET done_at=clock_timestamp(),result='监控已停用，取消待入队通知' WHERE id=ANY($1::text[])", cancelled); err != nil {
			return err
		}
	}
	for _, group := range groups {
		batches := [][]healthNotice{group}
		if len(group) <= 5 {
			batches = nil
			for _, v := range group {
				batches = append(batches, []healthNotice{v})
			}
		}
		for _, batch := range batches {
			ids := []string{}
			messages := []string{}
			for _, v := range batch {
				ids = append(ids, v.id)
				if len(messages) < 5 {
					messages = append(messages, v.message)
				}
			}
			id := common.Hash(common.JSON(ids))
			message := strings.Join(messages, "\n\n")
			if len(batch) > 5 {
				message = fmt.Sprintf("监控告警汇总：%d 项（前 5 项）\n", len(batch)) + message
			}
			first := batch[0]
			if _, err = tx.ExecContext(ctx, "INSERT INTO v3_health_batches VALUES($1,$2,$3,$4,$5,clock_timestamp())", id, first.node, first.phase, message, first.created); err != nil {
				return err
			}
			category := "health_failures"
			if first.phase == "resolved" {
				category = "health_recoveries"
			}
			payload := common.Map{"operation": "server_alert", "node_id": first.node, "phase": first.phase, "message": message, "members": ids, "source": "server_health"}
			if err = enqueueNotice(ctx, tx, first.node, "server-alert:"+id, payload, category, "server_health"); err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "UPDATE v3_health_outbox SET batch=$1,done_at=clock_timestamp(),result='已处理通知入队' WHERE id=ANY($2::text[])", id, ids); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// Imported pending batches already have immutable identities and membership.
// Never regroup them with newer alarms, or recreate already admitted queues.
func flushExistingHealthBatches(ctx context.Context, tx *sql.Tx, config common.Map) (int, error) {
	joins := ` FROM v3_health_batches b JOIN v3_active_nodes n ON n.id=b.node `
	eligible := `b.done_at IS NULL AND EXISTS(SELECT 1 FROM v3_health_outbox o WHERE o.batch=b.id)
 AND (NOT n.enabled OR EXISTS(SELECT 1 FROM v3_health_outbox o JOIN v3_health_events e ON e.id=o.id
 JOIN v3_health_rules r ON r.key=e.payload->>'key' WHERE o.batch=b.id AND r.phase='disabled') OR (
 NOT (b.node=ANY($1::text[])) AND NOT EXISTS(SELECT 1 FROM v3_health_outbox o JOIN v3_health_events e ON e.id=o.id
 JOIN v3_health_rules u ON u.key=b.node||':node_unreachable' WHERE o.batch=b.id AND e.kind<>'node_unreachable' AND u.phase='firing')
 AND NOT EXISTS(SELECT 1 FROM v3_deployment_jobs j WHERE j.node=b.node AND j.status='running' AND j.recovery_required AND j.lease_until>clock_timestamp())))`
	maintenance := common.SS(config["maintenance_nodes"])
	rows, err := tx.QueryContext(ctx, `SELECT id FROM v3_nodes WHERE id IN(SELECT b.node`+joins+`WHERE `+eligible+` ORDER BY b.created,b.id LIMIT 100) ORDER BY id FOR SHARE`, maintenance)
	if err != nil {
		return 0, err
	}
	nodes := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		nodes = append(nodes, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil || len(nodes) == 0 {
		return 0, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT b.id,b.node,b.phase,b.message,n.enabled,
	 EXISTS(SELECT 1 FROM v3_health_outbox o JOIN v3_health_events e ON e.id=o.id JOIN v3_health_rules r ON r.key=e.payload->>'key' WHERE o.batch=b.id AND r.phase='disabled'),
 (SELECT count(*) FROM v3_health_outbox o WHERE o.batch=b.id)`+joins+`WHERE `+eligible+` AND b.node=ANY($2::text[]) ORDER BY b.created,b.id FOR UPDATE OF b SKIP LOCKED LIMIT 100`, maintenance, nodes)
	if err != nil {
		return 0, err
	}
	type pending struct {
		healthNotice
		enabled, disabled bool
	}
	batches := []pending{}
	used := 0
	for rows.Next() {
		var b pending
		var count int
		if err = rows.Scan(&b.id, &b.node, &b.phase, &b.message, &b.enabled, &b.disabled, &count); err != nil {
			break
		}
		if count > 500 {
			err = errors.New("告警批次成员超过上限，请核对迁移来源")
			break
		}
		if used+count > 500 {
			break
		}
		used += count
		batches = append(batches, b)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, b := range batches {
		result := "已处理通知入队"
		if !b.enabled || b.disabled {
			result = "监控已停用，取消待入队通知"
		} else {
			var raw []byte
			if err = tx.QueryRowContext(ctx, `SELECT jsonb_agg(id ORDER BY created,id) FROM v3_health_outbox WHERE batch=$1`, b.id).Scan(&raw); err != nil {
				return 0, err
			}
			var ids []string
			if err = json.Unmarshal(raw, &ids); err != nil {
				return 0, err
			}
			category := "health_failures"
			if b.phase == "resolved" {
				category = "health_recoveries"
			}
			payload := common.Map{"operation": "server_alert", "node_id": b.node, "phase": b.phase, "message": b.message, "members": ids, "source": "server_health"}
			if err = enqueueNotice(ctx, tx, b.node, "server-alert:"+b.id, payload, category, "server_health"); err != nil {
				return 0, err
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_health_batches SET done_at=clock_timestamp() WHERE id=$1", b.id); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_health_outbox SET done_at=clock_timestamp(),result=$2 WHERE batch=$1 AND done_at IS NULL", b.id, result); err != nil {
			return 0, err
		}
	}
	return used, nil
}

func (n *Notifier) runHealth(ctx context.Context) {
	for ctx.Err() == nil {
		op, cancel := context.WithTimeout(ctx, 5*time.Second)
		l, err := n.Store.Acquire(op, "health-flush", n.Instance)
		if err == nil {
			err = n.Store.FlushHealth(op, l)
		}
		reason := ""
		if err != nil && !errors.Is(err, ErrLeaseLost) {
			reason = "服务器告警入队失败，将自动重试"
		}
		_, heartbeatError := n.Store.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error) VALUES('server-health',$1,clock_timestamp(),$2)
   ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error`, n.Instance, reason)
		if reason == "" && heartbeatError == nil {
			runtimeReady(ctx, "server-health")
		}
		cancel()
		if !waitRetry(ctx, 5*time.Second) {
			break
		}
	}
	// The short lease is not shared with the channel workers. Letting it expire
	// after a cancelled transaction is safe; another instance can take over.
}
