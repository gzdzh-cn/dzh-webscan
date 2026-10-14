package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/recordops"
)

const backupSchema = `CREATE TABLE IF NOT EXISTS config_backup_details(id TEXT PRIMARY KEY,omitted TEXT DEFAULT '[]',restored INTEGER DEFAULT 0,result TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS config_backup_previews(token TEXT PRIMARY KEY,backup TEXT,owner TEXT,revision TEXT,digest TEXT,keep_credentials INTEGER,expires INTEGER);
CREATE TABLE IF NOT EXISTS job_archives(id TEXT PRIMARY KEY,time INTEGER);
CREATE TABLE IF NOT EXISTS backup_import_attempts(owner TEXT PRIMARY KEY,count INTEGER,until INTEGER);`

func operationOwner(r *http.Request) string {
	if owner := r.Header.Get("X-Webscan-Owner"); owner != "" {
		return owner
	}
	return "root"
}
func (s *Service) backupDeletable(ctx context.Context, id string) (bool, string) {
	if s.pending() || s.removalPending() {
		return false, "未完成任务可能需要此回退备份"
	}
	var n int
	if e := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM config_backup_previews WHERE backup=? AND expires>?", id, time.Now().Unix()).Scan(&n); e != nil {
		return false, "保护状态暂不可用"
	}
	if n > 0 {
		return false, "恢复预览仍有效"
	}
	if s.Operations.Busy(ctx, "deployment-backup", id) {
		return false, "删除任务执行中"
	}
	return true, ""
}
func (s *Service) jobDeletable(ctx context.Context, j Job) (bool, string) {
	if j.Status != "complete" {
		return false, "运行、失败或中断任务保留继续及回退职责"
	}
	if j.Updated > time.Now().Unix()-86400 {
		return false, "保护最近 24 小时记录"
	}
	if s.pending() || s.removalPending() {
		return false, "存在未完成部署，暂保留任务历史"
	}
	if s.Operations.Busy(ctx, "deployment-job", j.ID) {
		return false, "删除任务执行中"
	}
	return true, ""
}
func (s *Service) applyRecordOperation(ctx context.Context, kind, id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.pending() || s.removalPending() {
		return "skipped", "存在未完成部署，记录受保护", nil
	}
	if kind == "deployment-job" {
		j, e := scanJob(s.DB.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
		if e == sql.ErrNoRows {
			return "deleted", "已删除", nil
		}
		if e != nil {
			return "", "", e
		}
		if j.Status != "complete" || j.Updated > time.Now().Unix()-86400 {
			return "skipped", "任务仍受保护", nil
		}
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			return "", "", e
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO job_archives VALUES(?,?)", id, time.Now().Unix()); e != nil {
			return "", "", e
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM logs WHERE job=?", id); e != nil {
			return "", "", e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE jobs SET message='' WHERE id=?", id); e != nil {
			return "", "", e
		}
		return "deleted", "页面历史及日志已删除；防重记录、部署状态和回退资料保留", tx.Commit()
	}
	if kind != "deployment-backup" {
		return "skipped", "不支持的记录类别", nil
	}
	var n int
	if e := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM config_backup_previews WHERE backup=? AND expires>?", id, time.Now().Unix()).Scan(&n); e != nil {
		return "", "", e
	}
	if n > 0 {
		return "skipped", "恢复预览仍有效", nil
	}
	var path string
	e := s.DB.QueryRowContext(ctx, "SELECT path FROM config_backups WHERE id=?", id).Scan(&path)
	if e == sql.ErrNoRows {
		return "deleted", "已删除", nil
	}
	if e != nil {
		return "", "", e
	}
	root := filepath.Join(s.StateDir, "config-backups")
	if filepath.Dir(path) != root {
		return "skipped", "路径异常，禁止删除", nil
	}
	if e = recordops.RemoveFile(root, filepath.Base(path)); e != nil {
		return "", "", e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return "", "", e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "DELETE FROM config_backups WHERE id=?", id); e != nil {
		return "", "", e
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM config_backup_details WHERE id=?", id); e != nil {
		return "", "", e
	}
	return "deleted", "备份文件及历史已删除", tx.Commit()
}
func (s *Service) indexLegacyBackups() error {
	root := filepath.Join(s.StateDir, "config-backups")
	entries, e := os.ReadDir(root)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	for _, item := range entries {
		if !strings.HasSuffix(item.Name(), ".yaml") || strings.HasPrefix(item.Name(), ".delete-") {
			continue
		}
		path := filepath.Join(root, item.Name())
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > yamlLimit {
			continue
		}
		var n int
		if e = s.DB.QueryRow("SELECT count(*) FROM config_backups WHERE path=?", path).Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			continue
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if _, e = validateBytes(s.ConfigPath, raw); e != nil {
			continue
		}
		if _, e = s.DB.Exec("INSERT INTO config_backups VALUES(?,?,?,?,?)", common.Hash([]byte(item.Name()))[:32], info.ModTime().Unix(), common.Hash(raw), "部署前", path); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) configBackups(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == "POST" {
		raw, e := os.ReadFile(s.ConfigPath)
		var id string
		if e == nil {
			id, e = s.backup(raw, "手动")
		}
		if e != nil {
			failure(w, e)
			return
		}
		reply(w, 201, common.Map{"id": id, "message": "已备份磁盘 YAML，可能包含尚未应用修改"})
		return
	}
	if r.Method != "GET" {
		reply(w, 405, common.Map{"message": "请求方法不正确"})
		return
	}
	if e := s.indexLegacyBackups(); e != nil {
		failure(w, e)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	page = max(1, page)
	size := 20
	var total int
	if e := s.DB.QueryRow("SELECT count(*) FROM config_backups").Scan(&total); e != nil {
		failure(w, e)
		return
	}
	rows, e := s.DB.Query(`SELECT b.id,b.time,b.revision,b.source,coalesce(d.omitted,'[]'),coalesce(d.restored,0),coalesce(d.result,'') FROM config_backups b LEFT JOIN config_backup_details d ON d.id=b.id ORDER BY b.time DESC,b.rowid DESC LIMIT ? OFFSET ?`, size, (page-1)*size)
	if e != nil {
		failure(w, e)
		return
	}
	items := []common.Map{}
	for rows.Next() {
		var id, rev, source, omitted, result string
		var tm, restored int64
		if e = rows.Scan(&id, &tm, &rev, &source, &omitted, &restored, &result); e != nil {
			rows.Close()
			failure(w, e)
			return
		}
		items = append(items, common.Map{"id": id, "time": tm, "revision": rev, "source": source, "restored": restored, "result": result, "needs_completion": omitted != "[]"})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		failure(w, e)
		return
	}
	for _, item := range items {
		item["can_delete"], item["delete_reason"] = s.backupDeletable(r.Context(), common.S(item["id"]))
	}
	reply(w, 200, common.Map{"items": items, "total": total})
}
func (s *Service) loadConfigBackup(ctx context.Context, id string) ([]byte, error) {
	if s.Operations.Busy(ctx, "deployment-backup", id) {
		return nil, userError("备份正在删除")
	}
	var path string
	if e := s.DB.QueryRowContext(ctx, "SELECT path FROM config_backups WHERE id=?", id).Scan(&path); e != nil {
		return nil, userError("备份不存在")
	}
	if filepath.Dir(path) != filepath.Join(s.StateDir, "config-backups") {
		return nil, userError("备份路径不正确")
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > yamlLimit {
		return nil, userError("备份文件缺失、超限或权限不正确")
	}
	return os.ReadFile(path)
}
func decodeBackupRequest(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 6<<20))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return userError("备份请求格式或大小不正确")
	}
	return nil
}
func (s *Service) importConfigBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		reply(w, 405, common.Map{"message": "请求方法不正确"})
		return
	}
	var in struct {
		Content   string `json:"content"`
		Encrypted bool   `json:"encrypted"`
		Password  string `json:"password"`
	}
	if e := decodeBackupRequest(w, r, &in); e != nil {
		failure(w, e)
		return
	}
	raw := []byte(in.Content)
	if in.Encrypted {
		if r.Header.Get("X-Webscan-Secure") != "true" {
			failure(w, userError("包含凭据的加密操作仅允许 HTTPS 后台"))
			return
		}
		var n, until int64
		s.DB.QueryRow("SELECT count,until FROM backup_import_attempts WHERE owner=?", operationOwner(r)).Scan(&n, &until)
		if n >= 5 && until > time.Now().Unix() {
			reply(w, 429, common.Map{"message": "解密失败次数过多，请 5 分钟后重试"})
			return
		}
		select {
		case s.decryptSlot <- struct{}{}:
			defer func() { <-s.decryptSlot }()
		default:
			reply(w, 429, common.Map{"message": "正在解密备份，请稍后重试"})
			return
		}
		var e error
		raw, e = decryptDocument(in.Content, in.Password)
		if e != nil {
			s.DB.Exec(`INSERT INTO backup_import_attempts VALUES(?,1,?) ON CONFLICT(owner) DO UPDATE SET count=CASE WHEN until>? THEN count+1 ELSE 1 END,until=excluded.until`, operationOwner(r), time.Now().Unix()+300, time.Now().Unix())
			failure(w, e)
			return
		}
		s.DB.Exec("DELETE FROM backup_import_attempts WHERE owner=?", operationOwner(r))
	}
	doc, e := parseDocument(raw)
	if e != nil {
		failure(w, e)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		failure(w, e)
		return
	}
	var currentValues common.Map
	if e = yaml.Unmarshal(current, &currentValues); e != nil {
		failure(w, e)
		return
	}
	merged := common.Clone(doc.Configuration)
	mergeMissing(merged, currentValues, false)
	// Validate incomplete redacted imports without ever writing placeholders into stored configuration.
	for i, n := range common.A(merged["nodes"]) {
		node := common.M(n)
		ssh := common.M(node["ssh"])
		if len(ssh) == 0 {
			ssh = common.Map{}
			node["ssh"] = ssh
		}
		if common.S(node["host"]) == "" {
			node["host"] = fmt.Sprintf("198.51.100.%d", i%250+1)
		}
		if common.S(ssh["username"]) == "" {
			ssh["username"] = "root"
		}
		if common.S(ssh["auth_method"]) == "password" && common.S(ssh["password"]) == "" {
			ssh["password"] = "validation-placeholder"
		}
		if common.S(ssh["auth_method"]) == "key" && common.S(ssh["private_key_path"]) == "" {
			ssh["private_key_path"] = "/required-private-key"
		}
	}

	checked, e := yaml.Marshal(yamlValue(merged))
	if e == nil {
		_, e = validateBytes(s.ConfigPath, checked)
	}
	// Missing secrets only may remain pending; all structural errors still reject the document.
	if e != nil {
		failure(w, userError("备份参数校验失败，请补全所需主机地址、认证及参数后导入"))
		return
	}
	stored, e := yaml.Marshal(doc.Configuration)
	if e != nil {
		failure(w, e)
		return
	}
	id, e := s.backup(stored, "导入")
	if e != nil {
		failure(w, e)
		return
	}
	_, e = s.DB.Exec("INSERT INTO config_backup_details(id,omitted) VALUES(?,?)", id, string(common.JSON(doc.Omitted)))
	if e != nil {
		failure(w, e)
		return
	}
	reply(w, 201, common.Map{"id": id, "needs_completion": len(doc.Omitted) > 0, "message": "已加入备份列表，未覆盖配置或部署"})
}
