package central

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/notify"
	"webscan/internal/persist"
)

// WatchdogNotice uses the same durable queue and delivery receipts. The host
// supervisor sends only these notices while the receiver is unavailable.
func WatchdogNotice(ctx context.Context, runtime common.Map, id, message string, send bool) error {
	db, e := persist.OpenDB(filepath.Join(common.S(runtime["data_dir"]), "events-v1.sqlite3"))
	if e != nil {
		return e
	}
	defer db.Close()
	if e = ensureEmailSchema(db, runtime); e != nil {
		return e
	}
	client, e := common.HTTPClient("", 10*time.Second)
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	s := &Store{DB: db, Config: runtime, HTTP: client}
	f := common.M(runtime["feishu"])
	key := "health_failures"
	if strings.HasSuffix(id, ":resolved") {
		key = "health_recoveries"
	}
	if id != "" && notify.Enabled(runtime) {
		if e = s.enqueueNotice(ctx, id, common.Map{"message": message, "source": "host_watchdog", "node_id": "central", "notice_kind": "health"}, key); e != nil {
			return e
		}
	}
	if send && common.B(common.M(runtime["email"])["enabled"]) {
		t, recipient, err := s.claimEmail(ctx, true)
		if err != nil {
			return err
		}
		if t != nil {
			if err = s.emailAttempt(ctx, t, recipient); err != nil {
				return err
			}
		}
	}
	if !send || !common.B(f["enabled"]) {
		return nil
	}
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	t := Task{}
	e = tx.QueryRowContext(ctx, "SELECT id,node,event_id,target,payload,attempts FROM tasks WHERE target='feishu' AND event_id LIKE 'watchdog:%' AND done IS NULL AND next_try<=? AND lease<=? AND NOT EXISTS(SELECT 1 FROM tasks earlier WHERE earlier.event_id LIKE 'watchdog:%' AND earlier.target='feishu' AND earlier.done IS NULL AND earlier.id<tasks.id) ORDER BY id LIMIT 1", common.Now(), common.Now()).Scan(&t.ID, &t.Node, &t.EventID, &t.Target, &t.Payload, &t.Attempts)
	if e == sql.ErrNoRows {
		return nil
	}
	if e != nil {
		return e
	}
	// Share the persisted limiter with the receiver; failed requests count too.
	var raw string
	history := []float64{}
	if e = tx.QueryRowContext(ctx, "SELECT value FROM kv WHERE key='feishu_rate_history'").Scan(&raw); e == nil {
		v, _ := common.Decode([]byte(raw))
		for _, n := range common.A(v) {
			if common.F(n) > common.Now()-60 {
				history = append(history, common.F(n))
			}
		}
	} else if e != sql.ErrNoRows {
		return e
	}
	if len(history) >= max(1, common.I(common.M(f["rate_limit"])["max_per_minute"])) {
		return nil
	}
	if len(history) > 0 && common.Now()-history[len(history)-1] < 1 {
		return nil
	}
	history = append(history, common.Now())
	if _, e = tx.ExecContext(ctx, "INSERT INTO kv VALUES('feishu_rate_history',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", string(common.JSON(history))); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE tasks SET lease=? WHERE id=?", common.Now()+120, t.ID); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	result, err := s.send(ctx, &t)
	if err != nil {
		result = "host_watchdog_delivery_failed"
	}
	if e = s.finish(ctx, &t, result, err != nil); e != nil {
		return e
	}
	if err != nil {
		return fmt.Errorf("宿主机看门狗通知暂未送达，持久化队列将重试")
	}
	return nil
}
