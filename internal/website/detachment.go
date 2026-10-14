package website

import (
	"context"
	"webscan/internal/common"
)

func (m *Monitor) NodeSites(ctx context.Context, node string) ([]common.Map, error) {
	rows, e := m.DB.QueryContext(ctx, "SELECT id,name,url FROM websites WHERE node=? AND deleted=0", node)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []common.Map{}
	for rows.Next() {
		var id int64
		var name, url string
		if e = rows.Scan(&id, &name, &url); e != nil {
			return nil, e
		}
		out = append(out, common.Map{"id": id, "name": name, "url": url})
	}
	return out, rows.Err()
}
func (m *Monitor) DetachNode(ctx context.Context, node string) error {
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	sites, e := m.NodeSites(ctx, node)
	if e != nil || len(sites) == 0 {
		return e
	}
	doc, e := m.snapshot(ctx)
	if e != nil {
		return e
	}
	if _, e = m.storeBackup(ctx, doc, "before_node_removal"); e != nil {
		return e
	}
	tx, e := m.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO website_incident_origins SELECT i.id,w.node,w.name FROM website_incidents i JOIN websites w ON i.site=w.id WHERE w.node=?`, node); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE websites SET node='',version=version+1 WHERE node=?", node); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	for _, s := range sites {
		m.cancel(int64(common.I(s["id"])))
	}
	return nil
}
