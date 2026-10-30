//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"webscan/internal/common"
	"webscan/internal/persist"
)

type deliveryEvent struct {
	id      string
	payload any
}

func (a *Agent) direct() bool {
	return common.B(a.C["direct_transport"]) || common.S(a.C["transport_mode"]) == "pull"
}
func (a *Agent) directSchema() error {
	var exists int
	if e := a.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='delivery_failures'").Scan(&exists); e != nil {
		return e
	}
	if exists == 0 {
		var count int
		if e := a.DB.QueryRow("SELECT count(*) FROM events").Scan(&count); e != nil {
			return e
		}
		if count > 0 {
			dir := filepath.Join(a.Data, "migration-backups")
			if e := os.MkdirAll(dir, 0700); e != nil {
				return e
			}
			if e := persist.BackupDB(a.DB, filepath.Join(dir, "before-direct-"+common.ID()+".sqlite3")); e != nil {
				return e
			}
		}
	}
	_, e := a.DB.Exec("CREATE TABLE IF NOT EXISTS delivery_failures(id TEXT PRIMARY KEY,error TEXT NOT NULL,created REAL NOT NULL); CREATE TABLE IF NOT EXISTS delivery_status(id INTEGER PRIMARY KEY,error TEXT NOT NULL,updated REAL NOT NULL)")
	return e
}
func (a *Agent) DirectExport(ctx context.Context) error {
	if _, e := os.Stat(filepath.Join(a.Data, "transport-paused")); e == nil {
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	rows, e := a.DB.QueryContext(ctx, "SELECT id,payload FROM events WHERE accepted IS NULL AND NOT EXISTS(SELECT 1 FROM delivery_failures f WHERE f.id=events.id) ORDER BY created,id LIMIT 100")
	if e != nil {
		return e
	}
	items := []deliveryEvent{}
	bytes := 2
	limit := max(1, common.I(a.C["max_request_mib"])) * 1048576
	for rows.Next() {
		var id, raw string
		if e = rows.Scan(&id, &raw); e != nil {
			break
		}
		p, err := common.Decode([]byte(raw))
		if err != nil {
			items = append(items, deliveryEvent{id, nil})
			continue
		}
		if bytes+len(raw)+4096 > limit && len(items) > 0 {
			break
		}
		bytes += len(raw) + 1
		items = append(items, deliveryEvent{id, p})
	}
	readErr := rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if readErr != nil {
		return readErr
	}
	if len(items) == 0 {
		if e = a.Prune(); e != nil {
			return e
		}
		_, e = a.DB.ExecContext(ctx, "DELETE FROM events WHERE accepted IS NOT NULL AND accepted<? AND exported IS NULL", common.Now()-float64(max(1, common.I(a.C["retention_days"]))*86400))
		return e
	}
	if e = a.sendBatch(ctx, items); e != nil {
		return e
	}
	return a.Prune()
}
func (a *Agent) sendBatch(ctx context.Context, items []deliveryEvent) error {
	payload := []any{}
	ids := []string{}
	for _, item := range items {
		if item.payload == nil {
			if e := a.reject(ctx, item.id, "invalid_local_json"); e != nil {
				return e
			}
			continue
		}
		payload = append(payload, item.payload)
		ids = append(ids, item.id)
	}
	if len(ids) == 0 {
		return nil
	}
	if len(common.JSON(payload)) > max(1, common.I(a.C["max_request_mib"]))*1048576 {
		if len(items) > 1 {
			for _, item := range items {
				if e := a.sendBatch(ctx, []deliveryEvent{item}); e != nil {
					return e
				}
			}
			return nil
		}
		return a.reject(ctx, ids[0], "event_exceeds_request_limit")
	}
	status, response, e := common.Request(ctx, a.HTTP, "POST", common.S(a.C["public_url"])+"/webscan/v1/events", payload, map[string]string{"Authorization": "Bearer " + common.S(a.C["token"])})
	if status >= 500 || e != nil && (status == 0 || status >= 200 && status < 300) {
		_, receipt, err := common.Request(ctx, a.HTTP, "POST", common.S(a.C["public_url"])+"/webscan/v1/receipts", common.Map{"event_ids": ids}, map[string]string{"Authorization": "Bearer " + common.S(a.C["token"])})
		if err == nil {
			accepted := common.SS(common.M(receipt)["accepted"])
			if err = a.acceptIDs(ctx, ids, accepted); err != nil {
				return err
			}
			if len(accepted) == len(ids) {
				a.counter("transport_last_success_seconds", common.Now(), true)
				return nil
			}
		}
		return errors.New("event_delivery_unconfirmed")
	}
	if status == 400 || status == 413 {
		if len(payload) > 1 {
			for _, item := range items {
				if e := a.sendBatch(ctx, []deliveryEvent{item}); e != nil {
					return e
				}
			}
			return nil
		}
		return a.reject(ctx, ids[0], fmt.Sprintf("event_rejected_http_%d", status))
	}
	if status != 200 {
		return fmt.Errorf("event_delivery_http_%d", status)
	}
	accepted := common.SS(common.M(response)["accepted"])
	if e = a.acceptIDs(ctx, ids, accepted); e != nil {
		return e
	}
	if len(accepted) != len(ids) {
		return errors.New("event_partial_confirmation")
	}
	a.counter("transport_last_success_seconds", common.Now(), true)
	return nil
}
func (a *Agent) acceptIDs(ctx context.Context, requested, accepted []string) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	tx, e := a.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	seen := map[string]bool{}
	for _, id := range accepted {
		if seen[id] {
			return errors.New("duplicate_event_confirmation")
		}
		seen[id] = true
		if !common.Contains(requested, id) {
			return errors.New("unexpected_event_confirmation")
		}
		if _, e = tx.Exec("UPDATE events SET accepted=? WHERE id=? AND accepted IS NULL", common.Now(), id); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (a *Agent) reject(ctx context.Context, id, reason string) error {
	a.writeMu.Lock()
	_, e := a.DB.ExecContext(ctx, "INSERT OR IGNORE INTO delivery_failures VALUES(?,?,?)", id, reason, common.Now())
	a.writeMu.Unlock()
	if e != nil {
		return e
	}
	return a.health("event_delivery_rejected", common.Map{"rejected_event_id": id, "detail": reason})
}

// ImportLegacyLogs reconciles JSONL records before direct delivery, preserving IDs.
// It runs only while the writer is stopped, from the deployment tool.
func ImportLegacyLogs(ctx context.Context, data, logs string) error {
	db, e := persist.OpenDB(filepath.Join(data, "agent.sqlite3"))
	if e != nil {
		return e
	}
	defer db.Close()
	return importLegacyLogs(ctx, db, logs)
}
