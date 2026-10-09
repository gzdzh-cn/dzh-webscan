package website

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
	"webscan/internal/common"
)

const backupLimit = 2 * 1024 * 1024

// Manual snapshots support all legal configurations; the smaller limit applies
// only to untrusted imports. Stored snapshots are still strictly bounded.
const storedBackupLimit = 24 * 1024 * 1024

type SiteConfig struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Node    string `json:"node"`
	Keyword string `json:"keyword"`
	Slow    bool   `json:"slow_alert"`
	Paused  bool   `json:"paused"`
}
type BackupDocument struct {
	Format  int          `json:"format_version"`
	Created string       `json:"created_at"`
	Sites   []SiteConfig `json:"websites"`
}
type Backup struct {
	ID       string `json:"id"`
	Created  int64  `json:"created"`
	Source   string `json:"source"`
	Count    int    `json:"count"`
	Digest   string `json:"-"`
	Restored int64  `json:"restored"`
	Result   string `json:"result"`
}
type RestorePreview struct {
	Added     int      `json:"added"`
	Updated   int      `json:"updated"`
	Unchanged int      `json:"unchanged"`
	Unknown   []string `json:"unknown_nodes"`
	Token     string   `json:"token"`
}

func configuration(s Site) SiteConfig {
	return SiteConfig{s.Name, s.URL, s.Node, s.Keyword, s.Slow, s.Paused}
}
func parseBackup(data []byte) (BackupDocument, error) { return parseBackupDocument(data, backupLimit) }
func parseBackupDocument(data []byte, limit int) (BackupDocument, error) {
	var doc BackupDocument
	if len(data) > limit {
		return doc, fmt.Errorf("备份文件不能超过 %d MiB", limit/1024/1024)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&doc); e != nil {
		return doc, errors.New("备份 JSON 格式或字段不正确")
	}
	if d.Decode(new(any)) != io.EOF {
		return doc, errors.New("备份文件包含多余内容")
	}
	if doc.Format != 1 {
		return doc, errors.New("不支持此备份格式版本，仅支持 format_version: 1")
	}
	if _, e := time.Parse(time.RFC3339, doc.Created); e != nil {
		return doc, errors.New("created_at 必须是 RFC3339 日期时间")
	}
	if doc.Sites == nil || len(doc.Sites) > 1000 {
		return doc, errors.New("websites 必须为网站列表，最多 1000 个")
	}
	seen := map[string]bool{}
	for i := range doc.Sites {
		s := &doc.Sites[i]
		s.Name = strings.TrimSpace(s.Name)
		if s.Name == "" || utf8.RuneCountInString(s.Name) > 100 {
			return doc, fmt.Errorf("第 %d 个网站：名称不能为空且最多 100 个字", i+1)
		}
		u, e := normalizeURL(s.URL)
		if e != nil {
			return doc, fmt.Errorf("第 %d 个网站网址：%s", i+1, e)
		}
		s.URL = u
		if seen[u] {
			return doc, fmt.Errorf("第 %d 个网站：规范化后的网址重复", i+1)
		}
		seen[u] = true
		if utf8.RuneCountInString(s.Keyword) > 200 {
			return doc, fmt.Errorf("第 %d 个网站：关键词最多 200 个字", i+1)
		}
		if len(s.Node) > 128 {
			return doc, fmt.Errorf("第 %d 个网站：关联节点编号过长", i+1)
		}
	}
	return doc, nil
}
func (m *Monitor) backupDir() string {
	dir := common.S(m.Config["backup_dir"])
	if dir == "" {
		var seq int
		var name, path string
		_ = m.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path)
		dir = filepath.Join(filepath.Dir(path), "backups")
	}
	return filepath.Join(dir, "website-config")
}
func (m *Monitor) snapshot(ctx context.Context) (BackupDocument, error) {
	sites, e := m.sites(ctx)
	doc := BackupDocument{Format: 1, Created: time.Now().UTC().Format(time.RFC3339), Sites: []SiteConfig{}}
	for _, s := range sites {
		doc.Sites = append(doc.Sites, configuration(s))
	}
	return doc, e
}

// Caller holds WriteMu, so both file and metadata represent one configuration.
func (m *Monitor) storeBackup(ctx context.Context, doc BackupDocument, source string) (Backup, error) {
	data := common.JSON(doc)
	if len(data) > storedBackupLimit {
		return Backup{}, errors.New("网站配置超过服务器备份大小限制，备份未创建")
	}
	b := Backup{ID: common.ID(), Created: time.Now().Unix(), Source: source, Count: len(doc.Sites), Digest: common.Hash(data)}
	dir := m.backupDir()
	if e := os.MkdirAll(dir, 0700); e != nil {
		return b, e
	}
	if e := os.Chmod(dir, 0700); e != nil {
		return b, e
	}
	path := filepath.Join(dir, b.ID+".json")
	if e := common.Atomic(path, data, 0600); e != nil {
		return b, e
	}
	if _, e := m.DB.ExecContext(ctx, "INSERT INTO website_backups(id,created,source,count,digest) VALUES(?,?,?,?,?)", b.ID, b.Created, b.Source, b.Count, b.Digest); e != nil {
		_ = os.Remove(path)
		return b, e
	}
	return b, nil
}
func (m *Monitor) loadBackup(ctx context.Context, id string) (BackupDocument, Backup, error) {
	b := Backup{}
	e := m.DB.QueryRowContext(ctx, "SELECT id,created,source,count,digest,restored,result FROM website_backups WHERE id=?", id).Scan(&b.ID, &b.Created, &b.Source, &b.Count, &b.Digest, &b.Restored, &b.Result)
	if e != nil {
		return BackupDocument{}, b, e
	}
	// The DB supplies the filename; reject invalid IDs even if metadata was edited.
	if len(b.ID) != 32 || strings.Trim(b.ID, "0123456789abcdef") != "" {
		return BackupDocument{}, b, errors.New("备份编号无效")
	}
	path := filepath.Join(m.backupDir(), b.ID+".json")
	info, e := os.Lstat(path)
	if e != nil {
		return BackupDocument{}, b, e
	}
	if !info.Mode().IsRegular() || info.Size() > storedBackupLimit {
		return BackupDocument{}, b, errors.New("备份文件无效或过大")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return BackupDocument{}, b, e
	}
	if common.Hash(data) != b.Digest {
		return BackupDocument{}, b, errors.New("备份校验失败，文件可能已被修改")
	}
	doc, e := parseBackupDocument(data, storedBackupLimit)
	return doc, b, e
}
func (m *Monitor) preview(ctx context.Context, doc BackupDocument, b Backup) (RestorePreview, error) {
	out := RestorePreview{Unknown: []string{}}
	sites, e := m.sites(ctx)
	if e != nil {
		return out, e
	}
	active := map[string]Site{}
	for _, s := range sites {
		active[s.URL] = s
	}
	unknown := map[string]bool{}
	for _, s := range doc.Sites {
		if s.Node != "" {
			if _, ok := m.Nodes[s.Node]; !ok {
				if !unknown[s.Node] {
					out.Unknown = append(out.Unknown, s.Node)
					unknown[s.Node] = true
				}
				s.Node = ""
			}
		}
		old, ok := active[s.URL]
		if !ok {
			out.Added++
		} else if configuration(old) == s {
			out.Unchanged++
		} else {
			out.Updated++
		}
	}
	if len(active)+out.Added > 1000 {
		return out, errors.New("合并后的未删除网站超过 1000 个，请先删除不再需要的网站")
	}
	// Include soft-deleted records and versions, but not probe state. Periodic
	// checks cannot invalidate a preview; any configuration edit does.
	rows, e := m.DB.QueryContext(ctx, "SELECT id,version,deleted FROM websites ORDER BY id")
	if e != nil {
		return out, e
	}
	revisions := [][3]int64{}
	for rows.Next() {
		var row [3]int64
		if e = rows.Scan(&row[0], &row[1], &row[2]); e != nil {
			rows.Close()
			return out, e
		}
		revisions = append(revisions, row)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	out.Token = common.Hash(common.JSON(common.Map{"backup": b.Digest, "revisions": revisions, "nodes": m.publicNodes()}))
	return out, nil
}
func (m *Monitor) restore(ctx context.Context, doc BackupDocument, b Backup, token string) (out RestorePreview, failure error) {
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	defer func() {
		if failure != nil {
			_, _ = m.DB.Exec("UPDATE website_backups SET restored=?,result=? WHERE id=?", time.Now().Unix(), "恢复失败，未合并；请查看操作提示", b.ID)
		}
	}()
	p, e := m.preview(ctx, doc, b)
	if e != nil {
		return p, e
	}
	if token == "" || token != p.Token {
		return p, errors.New("网站配置或关联节点已变化，请重新预览后恢复")
	}
	snapshot, e := m.snapshot(ctx)
	if e != nil {
		return p, e
	}
	if _, e = m.storeBackup(ctx, snapshot, "before_restore"); e != nil {
		return p, fmt.Errorf("恢复前自动备份失败，未修改网站：%w", e)
	}
	tx, e := m.DB.BeginTx(ctx, nil)
	if e != nil {
		return p, e
	}
	defer tx.Rollback()
	changed := []int64{}
	for _, s := range doc.Sites {
		if s.Node != "" {
			if _, ok := m.Nodes[s.Node]; !ok {
				s.Node = ""
			}
		}
		old, e := scanSite(tx.QueryRowContext(ctx, "SELECT "+columns+" FROM websites WHERE url=? ORDER BY deleted ASC,id DESC LIMIT 1", s.URL))
		if e != nil && e != sql.ErrNoRows {
			return p, e
		}
		if e == sql.ErrNoRows {
			if _, e = tx.ExecContext(ctx, "INSERT INTO websites(name,url,node,keyword,slow,paused,state) VALUES(?,?,?,?,?,?,?)", s.Name, s.URL, s.Node, s.Keyword, s.Slow, s.Paused, string(common.JSON(State{Status: "pending", Next: time.Now().Unix()}))); e != nil {
				return p, e
			}
			continue
		}
		var deleted bool
		if e = tx.QueryRowContext(ctx, "SELECT deleted FROM websites WHERE id=?", old.ID).Scan(&deleted); e != nil {
			return p, e
		}
		if !deleted && configuration(old) == s {
			continue
		}
		state := old.State
		if deleted || old.Keyword != s.Keyword || old.Slow != s.Slow || old.Paused != s.Paused {
			state = State{Status: "pending", Next: time.Now().Unix()}
			if _, e = tx.ExecContext(ctx, "UPDATE website_incidents SET ended=? WHERE site=? AND ended IS NULL", time.Now().Unix(), old.ID); e != nil {
				return p, e
			}
		}
		if _, e = tx.ExecContext(ctx, "UPDATE websites SET name=?,node=?,keyword=?,slow=?,paused=?,deleted=0,version=version+1,state=? WHERE id=?", s.Name, s.Node, s.Keyword, s.Slow, s.Paused, string(common.JSON(state)), old.ID); e != nil {
			return p, e
		}
		changed = append(changed, old.ID)
	}
	result := fmt.Sprintf("新增 %d，更新 %d，不变 %d", p.Added, p.Updated, p.Unchanged)
	if _, e = tx.ExecContext(ctx, "UPDATE website_backups SET restored=?,result=? WHERE id=?", time.Now().Unix(), result, b.ID); e != nil {
		return p, e
	}
	if e = tx.Commit(); e != nil {
		return p, e
	}
	for _, id := range changed {
		m.cancel(id)
	}
	return p, nil
}
func backupError(w http.ResponseWriter, e error) {
	if e == sql.ErrNoRows {
		apiError(w, 404, "backup_not_found", "备份不存在", "id")
		return
	}
	apiError(w, 400, "backup_failed", "备份操作未完成："+e.Error(), "backup")
}
func (m *Monitor) backups(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/backups" {
		switch r.Method {
		case "GET":
			p, size := page(r)
			var total int
			if e := m.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM website_backups").Scan(&total); e != nil {
				m.dbError(w, e)
				return
			}
			rows, e := m.DB.QueryContext(r.Context(), "SELECT id,created,source,count,restored,result FROM website_backups ORDER BY created DESC,rowid DESC LIMIT ? OFFSET ?", size, (p-1)*size)
			if e != nil {
				m.dbError(w, e)
				return
			}
			defer rows.Close()
			items := []Backup{}
			for rows.Next() {
				var b Backup
				if e = rows.Scan(&b.ID, &b.Created, &b.Source, &b.Count, &b.Restored, &b.Result); e != nil {
					m.dbError(w, e)
					return
				}
				items = append(items, b)
			}
			if e = rows.Err(); e != nil {
				m.dbError(w, e)
				return
			}
			respond(w, 200, common.Map{"items": items, "total": total})
			return
		case "POST":
			m.WriteMu.Lock()
			doc, e := m.snapshot(r.Context())
			var b Backup
			if e == nil {
				b, e = m.storeBackup(r.Context(), doc, "manual")
			}
			m.WriteMu.Unlock()
			if e != nil {
				backupError(w, e)
				return
			}
			respond(w, 201, b)
			return
		}
	}
	if r.URL.Path == "/api/backups/import" && r.Method == "POST" {
		data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, backupLimit))
		if e != nil {
			apiError(w, 413, "backup_too_large", "备份文件不能超过 2 MiB", "file")
			return
		}
		doc, e := parseBackup(data)
		if e != nil {
			backupError(w, e)
			return
		}
		m.WriteMu.Lock()
		b, e := m.storeBackup(r.Context(), doc, "import")
		m.WriteMu.Unlock()
		if e != nil {
			backupError(w, e)
			return
		}
		respond(w, 201, b)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/backups/"), "/")
	if len(parts) == 2 {
		doc, b, e := m.loadBackup(r.Context(), parts[0])
		if e != nil {
			backupError(w, e)
			return
		}
		switch parts[1] {
		case "export":
			if r.Method == "GET" {
				w.Header().Set("Content-Disposition", "attachment; filename=webscan-websites-"+b.ID+".json")
				respond(w, 200, doc)
				return
			}
		case "preview":
			if r.Method == "POST" {
				m.WriteMu.Lock()
				p, e := m.preview(r.Context(), doc, b)
				m.WriteMu.Unlock()
				if e != nil {
					backupError(w, e)
					return
				}
				respond(w, 200, p)
				return
			}
		case "restore":
			if r.Method == "POST" {
				var input struct {
					Token string `json:"token"`
				}
				if !decode(w, r, &input) {
					return
				}
				p, e := m.restore(r.Context(), doc, b, input.Token)
				if e != nil {
					backupError(w, e)
					return
				}
				respond(w, 200, p)
				return
			}
		}
	}
	apiError(w, 405, "method_not_allowed", "备份操作或请求方法不正确", "")
}
