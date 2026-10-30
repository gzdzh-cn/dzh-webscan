package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"webscan/internal/common"
)

// MapEventArchive is a frozen initial import, not a production cutover. Native
// receipts are restored without running notification policy; Loki history is
// display-only evidence and cannot by itself acknowledge an Agent event.
func (s *Store) MapEventArchive(ctx context.Context, source string) (DomainImportReport, error) {
	var complete bool
	if !validArchiveSource(source) {
		return DomainImportReport{Source: source, Domain: "file-events"}, errors.New("迁移源必须为已归档快照的 SHA256")
	}
	if err := s.DB.QueryRowContext(ctx, "SELECT complete FROM v3_imports WHERE source=$1 AND table_name='tasks'", source).Scan(&complete); err != nil || !complete {
		return DomainImportReport{Source: source, Domain: "file-events"}, errors.New("配套通知队列尚未完整归档")
	}
	tables := []string{"events", "migrated_logs"}
	report, err := s.mapArchiveDomain(ctx, source, "", "file-events", tables, []string{"events"}, func(ctx context.Context, tx *sql.Tx) error {
		if err := bindMigrationDomain(ctx, tx, "notifications", source, "", []string{"v3_notifications", "v3_notification_attempts"}); err != nil {
			return err
		}
		return bindMigrationDomain(ctx, tx, "file-events", source, "", []string{"v3_events", "v3_event_keys", "v3_event_rejections", "v3_imported_events"})
	}, func(ctx context.Context, tx *sql.Tx, table string, r archivedRecord) (bool, error) {
		return mapEventRecord(ctx, tx, source, table, r)
	})
	return report, safeMappingError(err)
}

func archivedEventPayload(r archivedRecord, node, id string, native bool) (common.Map, string, error) {
	raw, err := r.text("payload")
	if err != nil || len(raw) > 2<<20 {
		return nil, "", errors.New("旧事件载荷缺失或超过 2 MiB")
	}
	v, err := common.Decode([]byte(raw))
	if err != nil {
		return nil, "", errors.New("旧事件载荷格式不正确")
	}
	p, ok := v.(common.Map)
	if !ok || !eventText(common.S(p["operation"]), 128) {
		return nil, "", errors.New("旧事件缺少有效类型")
	}
	if value, present := p["node_id"]; present && common.S(value) != node {
		return nil, "", errors.New("旧事件节点与载荷不一致")
	}
	if native {
		if common.S(p["event_id"]) != id || common.S(p["node_id"]) != node {
			return nil, "", errors.New("旧原生事件身份与载荷不一致")
		}
		if _, err = time.Parse(time.RFC3339Nano, common.S(p["time"])); err != nil {
			return nil, "", errors.New("旧原生事件时间不正确")
		}
	}
	identity := common.Map{}
	for k, value := range p {
		identity[k] = value
	}
	identity["node_id"] = node
	_, hash, err := canonicalEvent(identity)
	return p, hash, err
}

func mapEventRecord(ctx context.Context, tx *sql.Tx, source, table string, r archivedRecord) (bool, error) {
	node, err := archiveText(r, "node", 512)
	if err != nil {
		return false, err
	}
	id, err := archiveText(r, "id", 256)
	if err != nil {
		return false, err
	}
	native := table == "events"
	p, hash, err := archivedEventPayload(r, node, id, native)
	if err != nil {
		return false, err
	}
	field := "time"
	if native {
		field = "received"
	}
	at, err := r.timestamp(field, false)
	if err != nil {
		return false, err
	}
	op := common.S(p["operation"])
	security := op == "scan" && common.S(common.M(p["scan"])["status"]) == "matched"
	if native {
		stored, err := r.text("digest")
		if err != nil || stored != hash {
			return false, errors.New("旧原生事件摘要与载荷不一致")
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO v3_node_identities VALUES($1) ON CONFLICT DO NOTHING", node); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO v3_event_keys(node,id,digest,received_at,digest_format) VALUES($1,$2,$3,$4,'canonical-v1')", node, id, hash, at); err != nil {
			return false, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO v3_events(node,id,received_at,operation,security,payload) VALUES($1,$2,$3,$4,$5,$6)", node, id, at, op, security, common.JSON(p))
		return err == nil, err
	}
	if table != "migrated_logs" {
		return false, errors.New("不支持的事件迁移表")
	}
	storedOp, err := r.text("operation")
	if err != nil || storedOp != op {
		return false, errors.New("旧迁移日志类型与载荷不一致")
	}
	eventID := ""
	if v, ok := p["event_id"]; ok && v != nil {
		var text bool
		eventID, text = v.(string)
		if !text || eventID != "" && !eventText(eventID, 256) {
			return false, errors.New("旧迁移日志事件身份不正确")
		}
	}
	var nativeExists bool
	if eventID != "" {
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_event_keys WHERE node=$1 AND id=$2)", node, eventID).Scan(&nativeExists); err != nil {
			return false, err
		}
	}
	if nativeExists {
		return false, nil
	} // The lossless archive still retains it.
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_node_identities VALUES($1) ON CONFLICT DO NOTHING", node); err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO v3_imported_events VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", id, node, eventID, at, op, security, common.JSON(p), hash, source)
	return err == nil, err
}
