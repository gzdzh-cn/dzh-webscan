package management

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"time"
	"webscan/internal/central"
	"webscan/internal/common"
	"webscan/internal/config"
)

func (s *Service) watchdog(ctx context.Context) {
	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()
	failures, successes := 0, 0
	for ctx.Err() == nil {
		s.watchdogBeat.Store(time.Now().Unix())
		c, e := config.Load(s.ConfigPath)
		if e == nil {
			runtime, e := common.ReadJSON(filepath.Join(c.CentralRoot(), "runtime.json"))
			state, se := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
			if e == nil && se == nil && common.B(state["central_installed"]) {
				port := common.I(runtime["port"])
				status, value, err := common.Request(ctx, client, "GET", fmt.Sprintf("http://127.0.0.1:%d/ready", port), nil, nil)
				healthy := err == nil && status == 200 && common.B(common.M(value)["ready"])
				s.mu.Lock()
				maintenance := s.running
				s.mu.Unlock()
				if maintenance || s.pending() || time.Since(start) < 180*time.Second {
					failures, successes = 0, 0
				} else {
					if healthy {
						successes++
						failures = 0
					} else {
						failures++
						successes = 0
					}
					if err := s.watchdogTransition(ctx, healthy, failures, successes, time.Now().Unix()); err != nil {
						fmt.Println("看门狗状态持久化失败：", common.SecretFree(err))
					}
				}
				// Replays a crash between queue insertion and the host receipt with the same id.
				rows, err := s.DB.QueryContext(ctx, "SELECT id,message FROM watchdog_outbox WHERE done=0 ORDER BY created,id")
				if err == nil {
					pending := []common.Map{}
					for rows.Next() {
						var id, msg string
						if rows.Scan(&id, &msg) == nil {
							pending = append(pending, common.Map{"id": id, "message": msg})
						}
					}
					rows.Close()
					for _, v := range pending {
						if central.WatchdogNotice(ctx, runtime, common.S(v["id"]), common.S(v["message"]), false) == nil {
							if _, err := s.DB.ExecContext(ctx, "UPDATE watchdog_outbox SET done=1 WHERE id=?", v["id"]); err != nil {
								fmt.Println("看门狗回执持久化失败：", common.SecretFree(err))
							}
						}
					}
				}
				if !healthy {
					if e := central.WatchdogNotice(ctx, runtime, "", "", true); e != nil {
						fmt.Println(common.SecretFree(e))
					}
				}
			}
		}
		if !common.Sleep(ctx, 30*time.Second) {
			return
		}
	}
}

func (s *Service) watchdogTransition(ctx context.Context, healthy bool, failures, successes int, now int64) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var phase string
	var since int64
	e = tx.QueryRowContext(ctx, "SELECT phase,since FROM watchdog_state WHERE id='central'").Scan(&phase, &since)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	kind, next, message := "", "firing", "主服务器监控服务无法连接，宿主机看门狗已记录异常"
	if healthy && phase == "firing" && successes >= 2 {
		kind, next = "resolved", "normal"
		message = fmt.Sprintf("主服务器监控服务已恢复；故障持续 %d 秒", now-since)
	} else if !healthy && phase != "firing" && failures >= 3 {
		kind = "firing"
		since = now
	}
	if kind == "" {
		return nil
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO watchdog_state VALUES('central',?,?) ON CONFLICT(id) DO UPDATE SET phase=excluded.phase,since=excluded.since", next, since); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO watchdog_outbox VALUES(?,?,?,0)", fmt.Sprintf("watchdog:%d:%s", since, kind), message, now); e != nil {
		return e
	}
	return tx.Commit()
}
