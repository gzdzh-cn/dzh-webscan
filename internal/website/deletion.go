package website

import (
	"context"
	"database/sql"
	"strconv"
	"time"
	"webscan/internal/recordops"
)

func (m *Monitor) backupDeletable(ctx context.Context, id string) (bool, string) {
	var n int
	if e := m.DB.QueryRowContext(ctx, "SELECT count(*) FROM website_backup_pins WHERE backup=? AND expires>?", id, time.Now().Unix()).Scan(&n); e != nil {
		return false, "保护状态暂不可用"
	}
	if n > 0 {
		return false, "恢复预览在 10 分钟有效期内"
	}
	if m.Operations.Busy(ctx, "website-backup", id) {
		return false, "删除任务执行中"
	}
	return true, ""
}
func (m *Monitor) applyRecordOperation(ctx context.Context, kind, id string) (string, string, error) {
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	if kind == "website-backup" {
		var n int
		if e := m.DB.QueryRowContext(ctx, "SELECT count(*) FROM website_backup_pins WHERE backup=? AND expires>?", id, time.Now().Unix()).Scan(&n); e != nil {
			return "", "", e
		}
		if n > 0 {
			return "skipped", "恢复预览仍有效", nil
		}
		var stored string
		e := m.DB.QueryRowContext(ctx, "SELECT id FROM website_backups WHERE id=?", id).Scan(&stored)
		if e == sql.ErrNoRows {
			return "deleted", "已删除", nil
		}
		if e != nil {
			return "", "", e
		}
		if len(stored) != 32 {
			return "skipped", "备份编号异常", nil
		}
		if e = recordops.RemoveFile(m.backupDir(), stored+".json"); e != nil {
			return "", "", e
		}
		_, e = m.DB.ExecContext(ctx, "DELETE FROM website_backups WHERE id=?", stored)
		return "deleted", "备份文件及历史已删除", e
	}
	if kind != "website" {
		return "skipped", "不支持的记录类别", nil
	}
	site, e := strconv.ParseInt(id, 10, 64)
	if e != nil || site <= 0 {
		return "skipped", "网站编号无效", nil
	}
	tx, e := m.DB.BeginTx(ctx, nil)
	if e != nil {
		return "", "", e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, "UPDATE websites SET deleted=1,version=version+1 WHERE id=? AND deleted=0", site)
	if e != nil {
		return "", "", e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return "skipped", "网站已删除或不存在", nil
	}
	if _, e = tx.ExecContext(ctx, "UPDATE website_incidents SET ended=? WHERE site=? AND ended IS NULL", time.Now().Unix(), site); e != nil {
		return "", "", e
	}
	if e = tx.Commit(); e != nil {
		return "", "", e
	}
	m.cancel(site)
	return "deleted", "已软删除，历史及通知保留", nil
}
