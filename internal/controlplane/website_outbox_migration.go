package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func mapWebsiteOutboxRecord(ctx context.Context, tx *sql.Tx, source string, r archivedRecord) (bool, error) {
	id, err := r.integer("id")
	if err != nil || id < 1 {
		return false, errors.New("旧网站通知编号不正确")
	}
	site, err := r.integer("site")
	if err != nil || site < 1 {
		return false, errors.New("旧网站通知关联网站不正确")
	}
	node, err := r.text("node")
	if err != nil || len(node) > 512 || !eventJSONCompatible(node) {
		return false, errors.New("旧网站通知节点不正确")
	}
	kind, err := archiveText(r, "kind", 128)
	if err != nil {
		return false, err
	}
	message, err := archiveText(r, "message", 256<<10)
	if err != nil {
		return false, err
	}
	created, err := r.integer("created")
	if err != nil || created <= 0 || created >= 253402300800 {
		return false, errors.New("旧网站通知时间不正确")
	}
	var invalid bool
	if err = tx.QueryRowContext(ctx, "SELECT NOT EXISTS(SELECT 1 FROM v3_websites WHERE id=$1)", site).Scan(&invalid); err != nil {
		return false, err
	}
	if invalid {
		return false, errors.New("旧网站通知缺少关联网站，请核对同一快照")
	}
	// v2 enqueues channel tasks and deletes its outbox in the SAME SQLite
	// transaction. Both cannot legitimately coexist in an immutable snapshot.
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_legacy_records WHERE source=$1 AND table_name='tasks'
 AND payload->'node'->>'value'='central' AND payload->'target'->>'value' IN ('feishu','email')
 AND payload->'event_id'->>'value' LIKE $2)`, source, fmt.Sprintf("website:%d:%%", id)).Scan(&invalid); err != nil {
		return false, err
	}
	if invalid {
		return false, errors.New("旧网站出箱与已入队任务重叠，请核对一致性快照")
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO v3_website_outbox(id,site,node,kind,message,created,migration_source) VALUES($1,$2,$3,$4,$5,$6,$7)", id, site, node, kind, message, created, source)
	return err == nil, err
}
