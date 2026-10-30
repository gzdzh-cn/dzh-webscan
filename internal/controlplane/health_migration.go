package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"webscan/internal/common"
	"webscan/internal/telemetry"
)

func archiveText(r archivedRecord, key string, limit int) (string, error) {
	v, err := r.text(key)
	if err != nil || v == "" || len(v) > limit || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
		return "", errors.New("迁移源文本字段缺失或超出支持范围")
	}
	return v, nil
}
func archivePhase(r archivedRecord, key string, rule bool) (string, error) {
	phase, err := r.text(key)
	valid := phase == "firing" || phase == "resolved" || phase == "reminder"
	if rule {
		valid = phase == "normal" || phase == "pending" || phase == "firing" || phase == "disabled"
	}
	if err != nil || !valid {
		return "", errors.New("原告警状态不正确")
	}
	return phase, nil
}
func archiveRule(r archivedRecord, key, node, kind, phase string) (telemetry.RuleState, error) {
	var st telemetry.RuleState
	raw, err := r.text("payload")
	if err != nil || json.Unmarshal([]byte(raw), &st) != nil || st.Node != node || st.Kind != kind || st.Key != key || st.Since < 0 || st.Last < 0 || st.Recovery < 0 || st.Reminder < 0 {
		return st, errors.New("原告警状态与主键不一致")
	}
	st.Phase = phase
	return st, nil
}

func (s *Store) MapHealthArchive(ctx context.Context, source, notificationsSource string) (DomainImportReport, error) {
	var complete bool
	if !validArchiveSource(notificationsSource) {
		return DomainImportReport{Source: source, Domain: "server-health"}, errors.New("请指定同次迁移的通知队列归档 SHA256")
	}
	if err := s.DB.QueryRowContext(ctx, "SELECT complete FROM v3_imports WHERE source=$1 AND table_name='tasks'", notificationsSource).Scan(&complete); err != nil || !complete {
		return DomainImportReport{Source: source, Domain: "server-health"}, errors.New("配套通知队列尚未完整归档")
	}
	tables := []string{"health_rules", "health_events", "alert_batches", "alert_outbox", "alert_members"}
	report, err := s.mapArchiveDomain(ctx, source, notificationsSource, "server-health", tables, tables, func(ctx context.Context, tx *sql.Tx) error {
		if err := bindMigrationDomain(ctx, tx, "notifications", notificationsSource, source, []string{"v3_notifications", "v3_notification_attempts"}); err != nil {
			return err
		}
		return bindMigrationDomain(ctx, tx, "server-health", source, notificationsSource, []string{"v3_health_rules", "v3_health_events", "v3_health_batches", "v3_health_outbox", "v3_health_cursors", "v3_health_samples"})
	}, mapHealthRecord)
	if err == nil {
		err = s.reconcileHealthArchive(ctx)
	}
	if err != nil {
		report.Complete = false
	}
	return report, safeMappingError(err)
}

func mapHealthRecord(ctx context.Context, tx *sql.Tx, table string, r archivedRecord) (bool, error) {
	if table == "alert_members" {
		id, err := archiveText(r, "event", 256)
		if err != nil {
			return false, err
		}
		batch, err := archiveText(r, "batch", 256)
		if err != nil {
			return false, err
		}
		result, err := tx.ExecContext(ctx, `UPDATE v3_health_outbox o SET batch=b.id FROM v3_health_batches b WHERE o.id=$1 AND b.id=$2 AND o.node=b.node AND o.phase=b.phase AND o.batch IS NULL`, id, batch)
		if err != nil {
			return false, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return false, err
		}
		if count != 1 {
			return false, errors.New("原告警批次成员缺少关联或身份不一致")
		}
		return true, nil
	}
	node, err := archiveText(r, "node", 512)
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_node_identities VALUES($1) ON CONFLICT DO NOTHING", node); err != nil {
		return false, err
	}
	switch table {
	case "health_rules":
		key, err := archiveText(r, "key", 2048)
		if err != nil {
			return false, err
		}
		kind, err := archiveText(r, "kind", 1536)
		if err != nil {
			return false, err
		}
		if key != node+":"+kind {
			return false, errors.New("原告警规则主键不一致")
		}
		phase, err := archivePhase(r, "phase", true)
		if err != nil {
			return false, err
		}
		st, err := archiveRule(r, key, node, kind, phase)
		if err != nil {
			return false, err
		}
		for field, want := range map[string]int64{"since": st.Since, "last": st.Last, "recovery": int64(st.Recovery), "reminder": st.Reminder} {
			got, err := r.integer(field)
			if err != nil || got != want {
				return false, errors.New("原告警列与状态载荷不一致")
			}
		}
		return true, saveHealthRules(ctx, tx, []telemetry.RuleState{st})
	case "health_events":
		id, err := archiveText(r, "id", 256)
		if err != nil {
			return false, err
		}
		kind, err := archiveText(r, "kind", 1536)
		if err != nil {
			return false, err
		}
		phase, err := archivePhase(r, "phase", false)
		if err != nil {
			return false, err
		}
		at, err := r.integer("time")
		if err != nil || at < 0 {
			return false, errors.New("原告警时间不正确")
		}
		message, err := r.text("message")
		if err != nil {
			return false, err
		}
		statePhase := "firing"
		if phase == "resolved" {
			statePhase = "normal"
		}
		st, err := archiveRule(r, node+":"+kind, node, kind, statePhase)
		if err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO v3_health_events VALUES($1,$2,$3,$4,$5,$6,$7)", id, node, kind, phase, at, message, common.JSON(st))
		return err == nil, err
	case "alert_batches":
		id, err := archiveText(r, "id", 256)
		if err != nil {
			return false, err
		}
		phase, err := archivePhase(r, "kind", false)
		if err != nil {
			return false, err
		}
		message, err := r.text("message")
		if err != nil {
			return false, err
		}
		at, err := r.integer("created")
		if err != nil || at < 0 {
			return false, errors.New("原告警批次时间不正确")
		}
		done, err := r.timestamp("done", true)
		if err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO v3_health_batches VALUES($1,$2,$3,$4,$5,$6)", id, node, phase, message, at, done)
		return err == nil, err
	case "alert_outbox":
		id, err := archiveText(r, "id", 256)
		if err != nil {
			return false, err
		}
		phase, err := archivePhase(r, "kind", false)
		if err != nil {
			return false, err
		}
		message, err := r.text("message")
		if err != nil {
			return false, err
		}
		at, err := r.integer("created")
		if err != nil || at < 0 {
			return false, errors.New("原告警出箱时间不正确")
		}
		done, err := r.timestamp("done", true)
		if err != nil {
			return false, err
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO v3_health_outbox(id,node,phase,message,created,done_at,result) SELECT $1,$2,$3,$4,$5,$6,'从旧告警出箱迁入' FROM v3_health_events WHERE id=$1 AND node=$2 AND phase=$3`, id, node, phase, message, at, done)
		if err != nil {
			return false, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return false, err
		}
		if count != 1 {
			return false, errors.New("原告警出箱缺少对应事件或身份不一致")
		}
		return true, nil
	}
	return false, errors.New("不支持的告警迁移表")
}
