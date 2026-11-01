package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"webscan/internal/common"
	"webscan/internal/notify"
	agentv1 "webscan/sdk/agent/v1"
)

// Ingest commits deduplication, events and both notification channels together.
// It returns permanent rejections separately; transient database errors must
// never be acknowledged to an Agent.
func (s *Store) Ingest(ctx context.Context, n Node, l Lease, b *agentv1.EventBatch) ([]string, []*agentv1.Rejection, error) {
	if b == nil || b.NodeId != n.ID || len(b.Events) > 100 {
		return nil, nil, errors.New("事件批次身份或数量不正确")
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, nil, e
	}
	defer tx.Rollback()
	if e = s.FenceNode(ctx, tx, n, l); e != nil {
		return nil, nil, e
	}
	if held, err := migrationHeld(ctx, tx); err != nil {
		return nil, nil, err
	} else if held {
		// Do not acknowledge events before the migration owns all queue state.
		return nil, nil, ErrMigrationPending
	}
	// Serialize history deletion and late Agent replay for this node. This is
	// independent of receipt ownership and never turns a Loki row into an ack.
	if _, e = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,773376010))", n.ID); e != nil {
		return nil, nil, e
	}
	var settingsRaw []byte
	if e = tx.QueryRowContext(ctx, "SELECT payload FROM v3_settings WHERE id=1").Scan(&settingsRaw); e != nil {
		return nil, nil, e
	}
	var settings common.Map
	if e = json.Unmarshal(settingsRaw, &settings); e != nil {
		return nil, nil, e
	}
	accepted := []string{}
	rejected := []*agentv1.Rejection{}
	seen := map[string]bool{}
	size := 0
	for _, item := range b.Events {
		if item == nil || !eventText(item.Id, 256) || seen[item.Id] {
			return nil, nil, errors.New("事件标识为空或重复")
		}
		seen[item.Id] = true
		size += len(item.Json)
		if size > 2<<20 {
			return nil, nil, errors.New("事件批次超限")
		}
		value, parseErr := common.Decode(item.Json)
		p, object := value.(common.Map)
		code := ""
		if parseErr != nil || !object || p == nil {
			code = "invalid_event"
		} else if common.S(p["node_id"]) != n.ID || common.S(p["event_id"]) != item.Id {
			code = "identity_mismatch"
		} else if common.S(p["operation"]) == "" {
			code = "invalid_event"
		}
		original := p
		var hash string
		if code == "" {
			var err error
			p, hash, err = canonicalEvent(p)
			if err != nil {
				code = "invalid_event"
			}
		}
		if code != "" {
			if _, e = tx.ExecContext(ctx, "INSERT INTO v3_event_rejections(node,id,code) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", n.ID, item.Id, code); e != nil {
				return nil, nil, e
			}
			rejected = append(rejected, &agentv1.Rejection{Id: item.Id, Code: code})
			continue
		}
		canonical := common.JSON(p)
		var inserted string
		e = tx.QueryRowContext(ctx, "INSERT INTO v3_event_keys(node,id,digest,received_at,digest_format) VALUES($1,$2,$3,clock_timestamp(),'canonical-v1') ON CONFLICT DO NOTHING RETURNING id", n.ID, item.Id, hash).Scan(&inserted)
		if e == sql.ErrNoRows {
			var same bool
			if same, e = matchesEventReceipt(ctx, tx, n.ID, item.Id, hash, item.Json, original); e != nil {
				return nil, nil, e
			}
			if !same {
				if _, e = tx.ExecContext(ctx, "INSERT INTO v3_event_rejections(node,id,code) VALUES($1,$2,'event_id_conflict') ON CONFLICT DO NOTHING", n.ID, item.Id); e != nil {
					return nil, nil, e
				}
				rejected = append(rejected, &agentv1.Rejection{Id: item.Id, Code: "event_id_conflict"})
				continue
			}
			accepted = append(accepted, item.Id)
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		security := common.S(p["operation"]) == "scan" && common.S(common.M(p["scan"])["status"]) == "matched"
		var removed bool
		if e = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_event_history_tombstones WHERE node=$1 AND event_id=$2 AND digest=$3)", n.ID, item.Id, hash).Scan(&removed); e != nil {
			return nil, nil, e
		}
		// A tombstone never acknowledges an Agent by itself. Only now, after
		// validating its actual payload and persisting the canonical receipt,
		// honor the prior history deletion without resurrecting rows or notices.
		if !removed {
			if _, e = tx.ExecContext(ctx, "INSERT INTO v3_events SELECT node,id,received_at,$3,$4,$5 FROM v3_event_keys WHERE node=$1 AND id=$2", n.ID, item.Id, common.S(p["operation"]), security, canonical); e != nil {
				return nil, nil, e
			}
		}
		category := category(p)
		// A matching archived Loki record is historical evidence, not a native
		// receipt. Save the actual Agent payload before acknowledging it, but do
		// not create fresh channel/recipient notices for this old observation.
		var historical bool
		if e = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_imported_events WHERE node=$1 AND event_id=$2 AND digest=$3)", n.ID, item.Id, hash).Scan(&historical); e != nil {
			return nil, nil, e
		}
		if category != "skip" && !historical && !removed {
			for _, channel := range []string{"feishu", "email"} {
				if !notify.Allows(settings, channel, category) {
					continue
				}
				recipients := []string{""}
				if channel == "email" {
					recipients = notify.Recipients(common.M(settings["email"]))
				}
				for _, recipient := range recipients {
					var notificationID int64
					e = tx.QueryRowContext(ctx, "INSERT INTO v3_notifications(node,event_id,channel,recipient,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id", n.ID, item.Id, channel, recipient, canonical).Scan(&notificationID)
					if errors.Is(e, sql.ErrNoRows) {
						continue
					}
					if e != nil {
						return nil, nil, e
					}
					if e = projectNotificationTx(ctx, tx, notificationID, "event"); e != nil {
						return nil, nil, e
					}
				}
			}
		}
		accepted = append(accepted, item.Id)
	}
	if e = tx.Commit(); e != nil {
		return nil, nil, e
	}
	return accepted, rejected, nil
}
func category(p common.Map) string {
	if common.DeploymentPHPTest(common.S(p["path"])) && common.S(p["operation"]) != "scan" {
		return "skip"
	}
	switch common.S(p["operation"]) {
	case "test":
		return ""
	case "probe":
		return "skip"
	case "scan":
		switch common.S(common.M(p["scan"])["status"]) {
		case "matched":
			return "scan_matches"
		case "error":
			return "scan_errors"
		}
		return "skip"
	case "health":
		return "health_failures"
	}
	if common.B(p["important_config"]) {
		return "important_config_changes"
	}
	return "file_changes"
}

type EventFilter struct {
	Node, Operation, Keyword string
	IncludeProbes            bool
	Since, Until             time.Time
	BeforeTime               time.Time
	BeforeNode, BeforeID     string
	BeforeSource             string
	Limit                    int
}
type EventRecord struct {
	Node         string          `json:"node"`
	ID           string          `json:"id"`
	Received     time.Time       `json:"received_at"`
	Payload      json.RawMessage `json:"payload"`
	Source       string          `json:"source"`
	RecordKey    string          `json:"record_key"`
	CanDelete    bool            `json:"can_delete"`
	DeleteReason string          `json:"delete_reason"`
}

// A native receipt remains authoritative after history cleanup too: removing
// a native record must not cause its older migrated display copy to reappear.
const visibleEvents = `SELECT node,id,received_at,operation,security,payload,'events'::text source,id event_id FROM v3_events
 UNION ALL SELECT h.node,h.id,h.received_at,h.operation,h.security,h.payload,'migrated_events'::text,h.event_id
 FROM v3_imported_events h WHERE h.event_id='' OR NOT EXISTS(SELECT 1 FROM v3_event_keys k WHERE k.node=h.node AND k.id=h.event_id)`

func eventRecordKey(source, node, id string) string {
	return "event:" + base64.RawURLEncoding.EncodeToString(common.JSON([]string{source, node, id}))
}

func (s *Store) Events(ctx context.Context, f EventFilter) ([]EventRecord, error) {
	if f.Operation == "probe" && !f.IncludeProbes {
		return nil, errors.New("查询链路探针前请开启包含链路探针")
	}
	if f.Limit < 1 || f.Limit > 200 || f.Since.IsZero() || !f.Until.After(f.Since) || f.Until.Sub(f.Since) > 31*24*time.Hour {
		return nil, errors.New("事件每页须为 1～200 条，时间范围须在 31 天内")
	}
	q := `WITH visible AS (` + visibleEvents + `) SELECT node,id,received_at,payload,source,` + historyEventDeleteReasonSQL() + ` FROM visible t WHERE received_at >= $1 AND received_at <= $2 AND ($3='' OR node=$3) AND ($4='' OR operation=$4) AND ($5 OR operation<>'probe') AND ($6='' OR payload->>'path' ILIKE $6 ESCAPE '\' OR payload->>'reason' ILIKE $6 ESCAPE '\' OR payload->>'message' ILIKE $6 ESCAPE '\')`
	key := ""
	if f.Keyword != "" {
		key = "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(f.Keyword) + "%"
	}
	args := []any{f.Since, f.Until, f.Node, f.Operation, f.IncludeProbes, key}
	if !f.BeforeTime.IsZero() {
		source := f.BeforeSource
		if source == "" {
			source = "events"
		}
		if source != "events" && source != "migrated_events" {
			return nil, errors.New("事件分页来源不正确")
		}
		q += " AND (received_at,node,id,source)<($7,$8,$9,$10)"
		args = append(args, f.BeforeTime, f.BeforeNode, f.BeforeID, source)
	}
	q += fmt.Sprintf(" ORDER BY received_at DESC,node DESC,id DESC,source DESC LIMIT $%d", len(args)+1)
	args = append(args, f.Limit)
	rows, e := s.DB.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []EventRecord{}
	for rows.Next() {
		var v EventRecord
		if e = rows.Scan(&v.Node, &v.ID, &v.Received, &v.Payload, &v.Source, &v.DeleteReason); e != nil {
			return nil, e
		}
		v.RecordKey = eventRecordKey(v.Source, v.Node, v.ID)
		v.CanDelete = v.DeleteReason == ""
		out = append(out, v)
	}
	return out, rows.Err()
}
