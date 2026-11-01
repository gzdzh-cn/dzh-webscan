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
	"webscan/internal/website"
)

func websiteNotificationSettings(ctx context.Context, tx *sql.Tx) (common.Map, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT payload FROM v3_settings WHERE id=1 FOR SHARE").Scan(&raw); err != nil {
		return nil, err
	}
	var root common.Map
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	return root, nil
}
func websiteNotificationsEnabled(root common.Map) bool {
	return common.B(common.M(root["feishu"])["enabled"]) || common.B(common.M(root["email"])["enabled"])
}
func insertWebsiteNotice(ctx context.Context, tx *sql.Tx, site int64, node, kind, message string) error {
	root, err := websiteNotificationSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !websiteNotificationsEnabled(root) {
		return nil
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO v3_website_outbox(site,node,kind,message,created) VALUES($1,$2,$3,$4,floor(extract(epoch FROM clock_timestamp()))::bigint)", site, node, kind, message)
	return err
}

// FlushWebsiteNotices commits at most 500 transitions / 8 MiB per window with
// channel admission and completion in one transaction. No external I/O runs
// under the lease. Pending notices survive pauses, restarts and soft deletion.
func (s *Store) FlushWebsiteNotices(ctx context.Context, l Lease) error {
	if l.Resource != "website-flush" {
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
	root, err := websiteNotificationSettings(ctx, tx)
	if err != nil {
		return err
	}
	if !websiteNotificationsEnabled(root) || common.B(common.M(root["monitoring"])["notifications_paused"]) {
		return tx.Commit()
	}
	var first sql.NullInt64
	// Only heads determine the window. A clock adjustment must not let a newer
	// recovery bypass its older failure, or stall unrelated sites forever.
	err = tx.QueryRowContext(ctx, `SELECT min(o.created) FROM v3_website_outbox o WHERE o.done_at IS NULL
 AND o.created<=floor(extract(epoch FROM clock_timestamp()))::bigint-15
 AND NOT EXISTS(SELECT 1 FROM v3_website_outbox older WHERE older.site=o.site AND older.id<o.id AND older.done_at IS NULL)`).Scan(&first)
	if err != nil {
		return err
	}
	if !first.Valid {
		return tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT o.id,o.site,o.node,o.kind,o.message,o.migration_source FROM v3_website_outbox o
 WHERE o.done_at IS NULL AND o.created<=$1
 AND NOT EXISTS(SELECT 1 FROM v3_website_outbox older WHERE older.site=o.site AND older.id<o.id AND older.done_at IS NULL AND older.created>$1)
 ORDER BY o.id FOR UPDATE OF o LIMIT 500`, first.Int64+14)
	if err != nil {
		return err
	}
	items := []website.Notice{}
	size := 0
	for rows.Next() {
		var v website.Notice
		if err = rows.Scan(&v.ID, &v.Site, &v.Node, &v.Kind, &v.Message, &v.Origin); err != nil {
			break
		}
		cost := len(v.Message) + len(v.Node) + len(v.Kind) + len(v.Origin) + 64
		if cost > 8<<20 {
			err = errors.New("单条网站通知超过处理上限，请检查历史记录")
			break
		}
		if len(items) > 0 && size+cost > 8<<20 {
			break
		}
		size += cost
		items = append(items, v)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	console := common.S(common.M(root["website_monitor"])["console_url"])
	for _, g := range website.GroupNotices(items) {
		category := "health_failures"
		if strings.Contains(g.Kind, "recover") {
			category = "health_recoveries"
		}
		prefix := "website-v3"
		if g.Origin != "" {
			prefix = "website"
		}
		for i, message := range g.NotificationMessages(console) {
			payload := common.Map{"message": message, "source": "website", "node_id": g.Node, "notice_kind": g.Kind, "site_ids": g.Sites}
			if err = enqueueNotice(ctx, tx, "central", fmt.Sprintf("%s:%d:%d", prefix, g.IDs[0], i), payload, category, "website"); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_website_outbox SET done_at=clock_timestamp(),result='通知策略已处理入队' WHERE id=ANY($1::bigint[])", g.IDs); err != nil {
			return err
		}
	}
	if err = s.Fence(ctx, tx, l); err != nil {
		return err
	}
	return tx.Commit()
}

func (n *Notifier) runWebsites(ctx context.Context) {
	for ctx.Err() == nil {
		op, cancel := context.WithTimeout(ctx, 5*time.Second)
		l, err := n.Store.Acquire(op, "website-flush", n.Instance)
		if err == nil {
			err = n.Store.FlushWebsiteNotices(op, l)
		}
		reason := ""
		if err != nil && !errors.Is(err, ErrLeaseLost) {
			reason = "网站通知入队失败，将自动重试"
		}
		_, heartbeatError := n.Store.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error) VALUES('website-notifications',$1,clock_timestamp(),$2)
 ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error`, n.Instance, reason)
		if reason == "" && heartbeatError == nil {
			runtimeReady(ctx, "website-notifications")
		}
		cancel()
		if !waitRetry(ctx, 5*time.Second) {
			return
		}
	}
}
