// Package recordops executes bounded, persistent record operations and keeps an audit trail.
package recordops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

const Schema = `CREATE TABLE IF NOT EXISTS record_operations(id TEXT PRIMARY KEY,owner TEXT,kind TEXT,request_key TEXT,created INTEGER,updated INTEGER,status TEXT,ids TEXT,cursor INTEGER DEFAULT 0,results TEXT DEFAULT '[]',UNIQUE(owner,request_key));
CREATE TABLE IF NOT EXISTS record_operation_lock(id INTEGER PRIMARY KEY,owner TEXT,expires INTEGER);`

type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}
type Job struct {
	ID      string   `json:"id"`
	Owner   string   `json:"owner"`
	Kind    string   `json:"kind"`
	Created int64    `json:"created"`
	Updated int64    `json:"updated"`
	Status  string   `json:"status"`
	IDs     []string `json:"ids"`
	Cursor  int      `json:"cursor"`
	Results []Result `json:"results"`
}
type Service struct {
	DB      *sql.DB
	Apply   func(context.Context, string, string) (string, string, error)
	Gate    *sync.Mutex
	mu      sync.Mutex
	owner   string
	auditAt int64
}

func New(db *sql.DB, backupDir string) (*Service, error) {
	var n int
	if e := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='record_operations'").Scan(&n); e != nil {
		return nil, e
	}
	if n == 0 {
		if e := persist.BackupDB(db, filepath.Join(backupDir, "record-operations-before-"+common.ID()+".sqlite3")); e != nil {
			return nil, e
		}
	}
	if _, e := db.Exec(Schema); e != nil {
		return nil, e
	}
	return &Service{DB: db, owner: common.ID()}, nil
}
func scan(row interface{ Scan(...any) error }) (*Job, error) {
	j := &Job{}
	var ids, results string
	e := row.Scan(&j.ID, &j.Owner, &j.Kind, &j.Created, &j.Updated, &j.Status, &ids, &j.Cursor, &results)
	if e == nil {
		e = json.Unmarshal([]byte(ids), &j.IDs)
	}
	if e == nil {
		e = json.Unmarshal([]byte(results), &j.Results)
	}
	return j, e
}

const columns = "id,owner,kind,created,updated,status,ids,cursor,results"

func (s *Service) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	if s.Gate != nil {
		s.Gate.Lock()
		defer s.Gate.Unlock()
	}
	return s.DB.ExecContext(ctx, q, args...)
}
func (s *Service) Job(ctx context.Context, owner, id string) (*Job, error) {
	return scan(s.DB.QueryRowContext(ctx, "SELECT "+columns+" FROM record_operations WHERE owner=? AND id=?", owner, id))
}
func (s *Service) Create(ctx context.Context, owner, kind, key string, ids []string) (*Job, error) {
	if owner == "" || key == "" || len(key) > 128 || len(ids) < 1 || len(ids) > 200 {
		return nil, errors.New("请选择 1～200 条记录并提供重复提交标识")
	}
	seen := map[string]bool{}
	unique := []string{}
	for _, id := range ids {
		if id == "" || len(id) > 256 {
			return nil, errors.New("记录编号不正确")
		}
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	now := time.Now().Unix()
	id := common.ID()
	_, e := s.exec(ctx, "INSERT OR IGNORE INTO record_operations(id,owner,kind,request_key,created,updated,status,ids) VALUES(?,?,?,?,?,?,'pending',?)", id, owner, kind, key, now, now, string(common.JSON(unique)))
	if e != nil {
		return nil, e
	}
	j, e := scan(s.DB.QueryRowContext(ctx, "SELECT "+columns+" FROM record_operations WHERE owner=? AND request_key=?", owner, key))
	if e == nil && (j.Kind != kind || string(common.JSON(j.IDs)) != string(common.JSON(unique))) {
		return nil, errors.New("重复提交标识与原操作不一致")
	}
	return j, e
}
func (s *Service) Busy(ctx context.Context, kind, id string) bool {
	var n int
	e := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM record_operations o,json_each(o.ids) i WHERE o.kind=? AND o.status IN ('pending','running') AND i.value=?", kind, id).Scan(&n)
	return e != nil || n > 0
}
func (s *Service) Tick(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pending int
	if e := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM record_operations WHERE status IN ('pending','running')").Scan(&pending); e != nil {
		return e
	}
	if pending == 0 {
		now := time.Now().Unix()
		if now-s.auditAt >= 3600 {
			s.auditAt = now
			_, e := s.exec(ctx, "DELETE FROM record_operations WHERE id IN(SELECT id FROM record_operations WHERE status NOT IN ('pending','running') AND updated<? LIMIT 200)", now-365*86400)
			return e
		}
		return nil
	}
	now := time.Now().Unix()
	r, e := s.exec(ctx, `INSERT INTO record_operation_lock VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires WHERE expires<?`, s.owner, now+30, now)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return nil
	}
	defer s.exec(context.WithoutCancel(ctx), "UPDATE record_operation_lock SET expires=0 WHERE owner=?", s.owner)
	j, e := scan(s.DB.QueryRowContext(ctx, "SELECT "+columns+" FROM record_operations WHERE status IN ('pending','running') ORDER BY created,id LIMIT 1"))
	if e == sql.ErrNoRows {
		_, e = s.exec(ctx, "DELETE FROM record_operations WHERE id IN(SELECT id FROM record_operations WHERE status NOT IN ('pending','running') AND updated<? LIMIT 200)", now-365*86400)
		return e
	}
	if e != nil {
		return e
	}
	if s.Apply == nil {
		return nil
	}
	deadline := time.Now().Add(2 * time.Second)
	for j.Cursor < len(j.IDs) && time.Now().Before(deadline) && ctx.Err() == nil {
		id := j.IDs[j.Cursor]
		status, reason, e := s.Apply(ctx, j.Kind, id)
		if e != nil {
			status = "failed"
			reason = "操作未完成，请检查服务器存储或任务状态后重试"
		}
		j.Results = append(j.Results, Result{id, status, reason})
		j.Cursor++
		j.Status = "running"
		if j.Cursor == len(j.IDs) {
			j.Status = "complete"
			for _, r := range j.Results {
				if r.Status == "failed" {
					j.Status = "partial"
				}
			}
		}
		_, e = s.exec(ctx, "UPDATE record_operations SET cursor=?,results=?,status=?,updated=? WHERE id=?", j.Cursor, string(common.JSON(j.Results)), j.Status, time.Now().Unix(), j.ID)
		if e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if e := s.Tick(ctx); e != nil && ctx.Err() == nil {
			fmt.Println("record_operation_tick_failed")
		}
		if !common.Sleep(ctx, time.Second) {
			return
		}
	}
}

// A root-owned private directory, fixed basename and resumable tombstone keep file deletion constrained.
func RemoveFile(root, name string) error {
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("invalid_backup_directory")
	}
	if filepath.Base(name) != name {
		return errors.New("invalid_backup_filename")
	}
	path := filepath.Join(root, name)
	trash := filepath.Join(root, ".delete-"+name)
	for _, p := range []string{path, trash} {
		info, e := os.Lstat(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("invalid_backup_file")
		}
	}
	if _, e := os.Lstat(path); e == nil {
		if e = os.Rename(path, trash); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := os.Remove(trash); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}
func (s *Service) Handler(w http.ResponseWriter, r *http.Request, owner, kind string) {
	var j *Job
	var e error
	if r.Method == "GET" {
		j, e = s.Job(r.Context(), owner, r.URL.Query().Get("id"))
	} else if r.Method == "POST" {
		var b struct {
			IDs     []string `json:"ids"`
			Confirm bool     `json:"confirm"`
			Key     string   `json:"request_key"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
		d.DisallowUnknownFields()
		if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF || !b.Confirm {
			http.Error(w, `{"message":"请确认选中的删除范围"}`, 400)
			return
		}
		j, e = s.Create(r.Context(), owner, kind, b.Key, b.IDs)
	} else {
		w.WriteHeader(405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if e != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(common.Map{"message": "操作记录不存在或请求范围不正确"})
		return
	}
	json.NewEncoder(w).Encode(j)
}

func (s *Service) List(ctx context.Context, owner string, page int) (common.Map, error) {
	var total int
	if e := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM record_operations WHERE owner=?", owner).Scan(&total); e != nil {
		return nil, e
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+columns+" FROM record_operations WHERE owner=? ORDER BY created DESC,id DESC LIMIT 20 OFFSET ?", owner, (max(1, page)-1)*20)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []*Job{}
	for rows.Next() {
		j, e := scan(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, j)
	}
	return common.Map{"items": items, "total": total}, rows.Err()
}

func PrivateDirectory(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() {
		return errors.New("invalid_private_directory")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return errors.New("invalid_directory_owner")
	}
	return os.Chmod(path, 0700)
}
