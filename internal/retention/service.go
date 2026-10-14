// Package retention provides bounded, resumable cleanup and export of historical records.
package retention

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

const schema = `CREATE TABLE IF NOT EXISTS website_incident_origins(id INTEGER PRIMARY KEY,node TEXT,name TEXT);
CREATE TABLE IF NOT EXISTS retention_previews(id TEXT PRIMARY KEY,owner TEXT,created INTEGER,revision TEXT,scope TEXT,counts TEXT);
CREATE TABLE IF NOT EXISTS retention_jobs(id TEXT PRIMARY KEY,owner TEXT,kind TEXT,created INTEGER,updated INTEGER,status TEXT,scope TEXT,source INTEGER DEFAULT 0,cursor INTEGER DEFAULT 0,processed INTEGER DEFAULT 0,skipped INTEGER DEFAULT 0,message TEXT DEFAULT '',preview TEXT DEFAULT '',export_job TEXT DEFAULT '',export_expired INTEGER DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS retention_jobs_request ON retention_jobs(owner,kind,preview) WHERE preview<>'';
CREATE TABLE IF NOT EXISTS retention_batches(job TEXT PRIMARY KEY,source INTEGER,cursor INTEGER,records TEXT);
CREATE INDEX IF NOT EXISTS retention_jobs_ready ON retention_jobs(status,created);
CREATE TABLE IF NOT EXISTS retention_lock(id INTEGER PRIMARY KEY,owner TEXT,expires INTEGER);
CREATE TABLE IF NOT EXISTS retention_export_progress(job TEXT PRIMARY KEY,source INTEGER,rowid_value INTEGER,bytes INTEGER);
CREATE TABLE IF NOT EXISTS retention_exports(job TEXT,source INTEGER,rowid_value INTEGER,line TEXT,PRIMARY KEY(job,source,rowid_value));
CREATE INDEX IF NOT EXISTS retention_events_category_time ON events((COALESCE(json_extract(payload,'$.operation'),'')='scan' AND COALESCE(json_extract(payload,'$.scan.status'),'')='matched'),received);
CREATE INDEX IF NOT EXISTS retention_events_time ON events(received);
CREATE INDEX IF NOT EXISTS retention_tasks_completed ON tasks(done);
CREATE INDEX IF NOT EXISTS retention_delivery_task ON delivery_records(task_id);
CREATE INDEX IF NOT EXISTS retention_pending_event ON tasks(node,event_id,done);
`

var Categories = []string{"events", "security", "website", "server", "notifications"}

type Filter struct {
	Category string   `json:"category"`
	Node     string   `json:"node"`
	Before   int64    `json:"before"`
	Records  []string `json:"records,omitempty"`
}
type Scope struct {
	Source       string            `json:"source"`
	Node         string            `json:"node"`
	Before       int64             `json:"before"`
	Upper        int64             `json:"upper"`
	IDs          []int64           `json:"ids,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}
type Counts struct {
	Eligible  int64 `json:"eligible"`
	Protected int64 `json:"protected"`
}
type Job struct {
	ID        string  `json:"id"`
	Owner     string  `json:"owner"`
	Kind      string  `json:"kind"`
	Created   int64   `json:"created"`
	Updated   int64   `json:"updated"`
	Status    string  `json:"status"`
	Scope     []Scope `json:"scope"`
	Source    int     `json:"source"`
	Cursor    int64   `json:"cursor"`
	Processed int64   `json:"processed"`
	Skipped   int64   `json:"skipped"`
	Message   string  `json:"message"`
	Preview   string  `json:"preview"`
	ExportJob string  `json:"export_job"`
}
type Service struct {
	DB, Metrics *sql.DB
	Directory   string
	Config      func() common.Map
	owner       string
}

func New(db, metrics *sql.DB, c func() common.Map) (*Service, error) {
	s := &Service{DB: db, Metrics: metrics, Config: c, owner: common.ID()}
	root := common.S(c()["backup_dir"])
	if root == "" {
		root = filepath.Join(common.S(c()["data_dir"]), "backups")
	}
	s.Directory = filepath.Join(root, "history-exports")
	var exists int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='retention_jobs'").Scan(&exists); err != nil {
		return nil, err
	}
	missingExpiry := false
	if exists > 0 {
		rows, err := db.Query("PRAGMA table_info(retention_jobs)")
		if err != nil {
			return nil, err
		}
		found := false
		for rows.Next() {
			var cid, notNull, pk int
			var name, kind string
			var def any
			if err = rows.Scan(&cid, &name, &kind, &notNull, &def, &pk); err != nil {
				rows.Close()
				return nil, err
			}
			if name == "export_expired" {
				found = true
			}
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		missingExpiry = !found
	}
	var origins int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='website_incident_origins'").Scan(&origins); err != nil {
		return nil, err
	}
	if exists == 0 || missingExpiry || origins == 0 {
		if err := persist.BackupDB(db, filepath.Join(root, "retention-migration-"+common.ID()+".sqlite3")); err != nil {
			return nil, fmt.Errorf("历史清理迁移前备份失败：%w", err)
		}
		if metrics != nil {
			if err := persist.BackupDB(metrics, filepath.Join(root, "retention-metrics-"+common.ID()+".sqlite3")); err != nil {
				return nil, err
			}
		}
	}
	if metrics != nil {
		if _, err := metrics.Exec("CREATE INDEX IF NOT EXISTS retention_health_time ON health_events(time);CREATE INDEX IF NOT EXISTS retention_health_kind ON health_events(node,kind,time)"); err != nil {
			return nil, err
		}
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	if missingExpiry {
		if _, err := db.Exec("ALTER TABLE retention_jobs ADD COLUMN export_expired INTEGER DEFAULT 0"); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func Days(c common.Map) common.Map {
	r := common.Clone(common.M(c["retention"]))
	defaults := map[string]int{"sqlite_events_days": 30, "delivery_records_days": 30, "website_incidents_days": 30, "server_alerts_days": max(1, common.I(common.M(c["monitoring"])["history_days"]))}
	if defaults["server_alerts_days"] == 1 && common.M(c["monitoring"])["history_days"] == nil {
		defaults["server_alerts_days"] = 15
	}
	for k, v := range defaults {
		if common.I(r[k]) < 1 {
			r[k] = v
		}
	}
	if common.I(r["security_events_days"]) < 1 {
		r["security_events_days"] = r["sqlite_events_days"]
	}
	return r
}
func (s *Service) Revision() string { return common.Hash(common.JSON(Days(s.Config()))) }
func (s *Service) has(db *sql.DB, table string) bool {
	if db == nil {
		return false
	}
	var n int
	// A failed availability check must reach the real query and report an error,
	// rather than turning a closed or inaccessible database into an empty scope.
	err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name=?", table).Scan(&n)
	return err != nil || n > 0
}

type source struct {
	db                                         *sql.DB
	table, node, tm, raw, condition, protected string
}

func (s *Service) source(name string) (source, bool) {
	eventProtect := `EXISTS(SELECT 1 FROM tasks p WHERE p.node=t.node AND p.event_id=t.id AND (p.done IS NULL OR p.lease>strftime('%s','now') OR EXISTS(SELECT 1 FROM email_recipients er WHERE er.task_id=p.id AND (er.done IS NULL OR er.lease>strftime('%s','now')))))`
	match := `COALESCE(json_extract(t.payload,'$.operation'),'')='scan' AND COALESCE(json_extract(t.payload,'$.scan.status'),'')='matched'`
	x := source{db: s.DB, node: "t.node", condition: "1=1", protected: "0", raw: "t.payload"}
	switch name {
	case "events", "security":
		x.table = "events"
		x.tm = "t.received"
		x.protected = eventProtect
		if name == "security" {
			x.condition = match
		} else {
			x.condition = "NOT (" + match + ")"
		}
	case "migrated_events", "migrated_security":
		x.table = "migrated_logs"
		x.tm = "t.time"
		x.condition = `NOT EXISTS(SELECT 1 FROM events e WHERE e.node=t.node AND e.id=json_extract(t.payload,'$.event_id'))`
		if name == "migrated_security" {
			x.condition += " AND (" + match + ")"
		} else {
			x.condition += " AND NOT (" + match + ")"
		}
		x.protected = `EXISTS(SELECT 1 FROM tasks p WHERE p.node=t.node AND p.event_id=json_extract(t.payload,'$.event_id') AND p.done IS NULL)`
	case "website":
		x.table = "website_incidents"
		x.node = "COALESCE((SELECT o.node FROM website_incident_origins o WHERE o.id=t.id),(SELECT w.node FROM websites w WHERE w.id=t.site),'')"
		x.tm = "COALESCE(t.ended,t.started)"
		x.raw = `json_object('id',t.id,'site',t.site,'kind',t.kind,'started',t.started,'ended',t.ended,'reason',t.reason)`
		x.protected = `t.ended IS NULL OR EXISTS(SELECT 1 FROM website_outbox o WHERE o.site=t.site) OR EXISTS(SELECT 1 FROM tasks p WHERE p.done IS NULL AND p.event_id LIKE 'website:%')`
	case "server":
		x.db = s.Metrics
		x.table = "health_events"
		x.tm = "t.time"
		x.raw = `json_object('id',t.id,'kind',t.kind,'phase',t.phase,'message',t.message,'time',t.time)`
		x.protected = `EXISTS(SELECT 1 FROM health_rules r WHERE r.Node=t.node AND r.kind=t.kind AND r.phase IN ('pending','firing') AND t.time>=r.since) OR EXISTS(SELECT 1 FROM alert_outbox o WHERE o.id=t.id AND o.done IS NULL) OR EXISTS(SELECT 1 FROM alert_members m JOIN alert_batches b ON m.batch=b.id WHERE m.event=t.id AND b.done IS NULL)`
	case "notification_orphans":
		x.table = "delivery_records"
		x.node = "''"
		x.tm = "t.time"
		x.raw = "json_object('id',t.id,'target',t.target,'time',t.time,'status',t.status)"
		x.condition = "NOT EXISTS(SELECT 1 FROM tasks p WHERE p.id=t.task_id)"
	case "server_batches":
		x.db = s.Metrics
		x.table = "alert_batches"
		x.node = "COALESCE(t.node,'')"
		x.tm = "COALESCE(t.done,t.created)"
		x.raw = "json_object('id',t.id,'kind',t.kind,'message',t.message,'created',t.created,'done',t.done)"
		x.protected = "t.done IS NULL OR EXISTS(SELECT 1 FROM alert_members m JOIN alert_outbox o ON m.event=o.id WHERE m.batch=t.id AND o.done IS NULL)"
	case "notifications":
		x.table = "tasks"
		x.node = "COALESCE(NULLIF(json_extract(t.payload,'$.node_id'),''),t.node)"
		x.tm = "COALESCE(t.done,t.created)"
		x.raw = `json_object('id',t.id,'target',t.target,'created',t.created,'done',t.done,'attempts',t.attempts,'result',t.result,'message',json_extract(t.payload,'$.message'))`
		x.protected = `t.done IS NULL OR t.lease>strftime('%s','now') OR EXISTS(SELECT 1 FROM email_recipients r WHERE r.task_id=t.id AND (r.done IS NULL OR r.lease>strftime('%s','now')))`
	default:
		return x, false
	}
	return x, s.has(x.db, x.table)
}
func (s *Service) serverPending(ctx context.Context) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM tasks WHERE done IS NULL AND event_id LIKE 'native:%'").Scan(&n)
	return n > 0, err
}
func where(x source, sc Scope, cursor int64, protect bool) (string, []any) {
	q := "t.rowid>? AND t.rowid<=? AND (" + x.condition + ")"
	a := []any{cursor, sc.Upper}
	if len(sc.IDs) == 0 || protect {
		q += " AND " + x.tm + "<?"
		a = append(a, sc.Before)
	}
	if len(sc.IDs) > 0 {
		q += " AND t.rowid IN (" + strings.TrimSuffix(strings.Repeat("?,", len(sc.IDs)), ",") + ")"
		for _, id := range sc.IDs {
			a = append(a, id)
		}
	}
	if sc.Node != "" {
		q += " AND " + x.node + "=?"
		a = append(a, sc.Node)
	}
	if protect {
		q += " AND NOT (" + x.protected + ")"
	}
	return q, a
}
func (s *Service) scope(ctx context.Context, f Filter) ([]Scope, error) {
	if len(f.Records) > 0 {
		return s.selectedScope(ctx, f)
	}
	names := []string{}
	switch f.Category {
	case "all":
		names = []string{"events", "security", "migrated_events", "migrated_security", "website", "server", "notifications"}
	case "events":
		names = []string{"events", "migrated_events"}
	case "security":
		names = []string{"security", "migrated_security"}
	case "website", "server", "notifications":
		names = []string{f.Category}
	default:
		return nil, userError("请选择有效的历史类别")
	}
	scopes := []Scope{}
	for _, n := range names {
		if x, ok := s.source(n); ok {
			var upper sql.NullInt64
			if err := x.db.QueryRowContext(ctx, "SELECT max(rowid) FROM "+x.table).Scan(&upper); err != nil {
				return nil, err
			}
			scopes = append(scopes, Scope{Source: n, Node: f.Node, Before: f.Before, Upper: upper.Int64})
		}
	}
	return scopes, nil
}
func (s *Service) count(ctx context.Context, sc Scope) (Counts, error) {
	x, ok := s.source(sc.Source)
	if !ok {
		return Counts{}, userError("历史数据表不可用")
	}
	allScope := sc
	if len(sc.IDs) > 0 {
		allScope.Before = 1 << 62
	}
	q, a := where(x, allScope, 0, false)
	var all, eligible int64
	if err := x.db.QueryRowContext(ctx, "SELECT count(*) FROM "+x.table+" t WHERE "+q, a...).Scan(&all); err != nil {
		return Counts{}, err
	}
	q, a = where(x, sc, 0, true)
	if sc.Source == "server" {
		pending, err := s.serverPending(ctx)
		if err != nil {
			return Counts{}, err
		}
		if pending {
			return Counts{0, all}, nil
		}
	}
	if err := x.db.QueryRowContext(ctx, "SELECT count(*) FROM "+x.table+" t WHERE "+q, a...).Scan(&eligible); err != nil {
		return Counts{}, err
	}
	return Counts{eligible, all - eligible}, nil
}
func (s *Service) Preview(ctx context.Context, owner string, f Filter) (common.Map, error) {
	if len(f.Records) > 0 {
		f.Before = time.Now().Unix() - 86400
	}
	if f.Before <= 0 || f.Before > time.Now().Unix()-86400 {
		return nil, userError("截止时间须早于最近 24 小时")
	}
	scopes, err := s.scope(ctx, f)
	if err != nil {
		return nil, err
	}
	sum := Counts{}
	for _, sc := range scopes {
		n, e := s.count(ctx, sc)
		if e != nil {
			return nil, e
		}
		sum.Eligible += n.Eligible
		sum.Protected += n.Protected
	}
	id := common.ID()
	_, err = s.DB.ExecContext(ctx, "INSERT INTO retention_previews VALUES(?,?,?,?,?,?)", id, owner, time.Now().Unix(), s.Revision(), string(common.JSON(scopes)), string(common.JSON(sum)))
	return common.Map{"id": id, "expires": time.Now().Unix() + 600, "counts": sum, "filter": f}, err
}
func (s *Service) Create(ctx context.Context, owner, kind, preview, exportJob string) (*Job, error) {
	if kind != "cleanup" && kind != "export" {
		return nil, userError("任务类型无效")
	}
	var raw, revision string
	var created int64
	if err := s.DB.QueryRowContext(ctx, "SELECT created,revision,scope FROM retention_previews WHERE id=? AND owner=?", preview, owner).Scan(&created, &revision, &raw); err != nil {
		return nil, userError("预览不存在或不属于当前账号")
	}
	if time.Now().Unix()-created > 600 || revision != s.Revision() {
		return nil, userError("预览已过期或保留设置已变化，请重新预览")
	}
	if exportJob != "" {
		var n int
		if err := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM retention_jobs WHERE id=? AND owner=? AND kind='export' AND status='complete' AND preview=? AND updated>?", exportJob, owner, preview, time.Now().Unix()-86400).Scan(&n); err != nil {
			return nil, err
		}
		if n != 1 {
			return nil, userError("导出尚未成功，请先完成本次预览的导出")
		}
	}
	tx, err := persist.BeginWrite(ctx, s.DB)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	existing, findErr := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM retention_jobs WHERE owner=? AND kind=? AND preview=?", owner, kind, preview))
	if findErr == nil {
		if existing.Status == "failed" {
			if _, err := tx.ExecContext(ctx, "UPDATE retention_jobs SET status='pending',message='',updated=? WHERE id=?", time.Now().Unix(), existing.ID); err != nil {
				return nil, err
			}
			existing.Status = "pending"
			existing.Message = ""
			return existing, tx.Commit()
		}
		return existing, nil
	}
	if findErr != sql.ErrNoRows {
		return nil, findErr
	}
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM retention_jobs WHERE status IN ('pending','running')").Scan(&active); err != nil {
		return nil, err
	}
	if active > 0 {
		return nil, userError("已有清理或导出任务正在执行，请稍后重试")
	}
	var scopes []Scope
	if err = json.Unmarshal([]byte(raw), &scopes); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	j := &Job{ID: common.ID(), Owner: owner, Kind: kind, Created: now, Updated: now, Status: "pending", Scope: scopes, Preview: preview, ExportJob: exportJob}
	_, err = tx.ExecContext(ctx, "INSERT INTO retention_jobs(id,owner,kind,created,updated,status,scope,preview,export_job) VALUES(?,?,?,?,?,?,?,?,?)", j.ID, owner, kind, now, now, j.Status, raw, preview, exportJob)
	if err != nil {
		return nil, err
	}
	return j, tx.Commit()
}
func scanJob(row interface{ Scan(...any) error }) (*Job, error) {
	var j Job
	var scope string
	e := row.Scan(&j.ID, &j.Owner, &j.Kind, &j.Created, &j.Updated, &j.Status, &scope, &j.Source, &j.Cursor, &j.Processed, &j.Skipped, &j.Message, &j.Preview, &j.ExportJob)
	if e == nil {
		e = json.Unmarshal([]byte(scope), &j.Scope)
	}
	return &j, e
}

const jobColumns = "id,owner,kind,created,updated,status,scope,source,cursor,processed,skipped,message,preview,export_job"

func (s *Service) Job(ctx context.Context, owner, id string) (*Job, error) {
	return scanJob(s.DB.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM retention_jobs WHERE id=? AND owner=?", id, owner))
}
func (s *Service) Jobs(ctx context.Context, owner string, page, size int) (common.Map, error) {
	var total int
	if e := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM retention_jobs WHERE (owner=? OR owner='system')", owner).Scan(&total); e != nil {
		return nil, e
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+jobColumns+" FROM retention_jobs WHERE (owner=? OR owner='system') ORDER BY created DESC,id DESC LIMIT ? OFFSET ?", owner, size, (page-1)*size)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		j, e := scanJob(rows)
		if e != nil {
			return nil, e
		}
		v, _ := common.Decode(common.JSON(j))
		items = append(items, v)
	}
	return common.Map{"items": items, "total": total}, rows.Err()
}
func (s *Service) Status(ctx context.Context) (common.Map, error) {
	items := []common.Map{}
	for _, name := range Categories {
		scopes, e := s.scope(ctx, Filter{Category: name, Before: time.Now().Unix() + 1})
		if e != nil {
			return nil, e
		}
		var count int64
		var oldest int64
		for _, sc := range scopes {
			x, _ := s.source(sc.Source)
			var n int64
			var tm sql.NullInt64
			if e = x.db.QueryRowContext(ctx, "SELECT count(*),CAST(min("+x.tm+") AS INTEGER) FROM "+x.table+" t WHERE "+x.condition).Scan(&n, &tm); e != nil {
				return nil, e
			}
			count += n
			if tm.Valid && (oldest == 0 || tm.Int64 < oldest) {
				oldest = tm.Int64
			}
		}
		items = append(items, common.Map{"category": name, "count": count, "oldest": oldest})
	}
	files := []common.Map{}
	root := common.S(s.Config()["data_dir"])
	for _, name := range []string{"events-v1.sqlite3", "metrics-v1.sqlite3"} {
		entry := common.Map{"name": name, "bytes": nil, "wal_bytes": nil}
		if info, e := os.Stat(filepath.Join(root, name)); e == nil {
			entry["bytes"] = info.Size()
		}
		if info, e := os.Stat(filepath.Join(root, name+"-wal")); e == nil {
			entry["wal_bytes"] = info.Size()
		}
		files = append(files, entry)
	}
	latest, e := s.Jobs(ctx, "system", 1, 1)
	if e != nil {
		return nil, e
	}
	return common.Map{"retention": Days(s.Config()), "revision": s.Revision(), "items": items, "files": files, "automatic": latest}, nil
}
func (s *Service) acquire(ctx context.Context) (bool, error) {
	now := time.Now().Unix()
	res, e := s.DB.ExecContext(ctx, `INSERT INTO retention_lock VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires WHERE retention_lock.expires<? OR retention_lock.owner=?`, s.owner, now+30, now, s.owner)
	if e != nil {
		return false, e
	}
	n, e := res.RowsAffected()
	return n == 1, e
}
func (s *Service) Tick(ctx context.Context) error {
	ok, e := s.acquire(ctx)
	if e != nil || !ok {
		return e
	}
	defer s.DB.ExecContext(context.WithoutCancel(ctx), "UPDATE retention_lock SET expires=0 WHERE id=1 AND owner=?", s.owner)
	j, e := scanJob(s.DB.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM retention_jobs WHERE status IN ('pending','running') ORDER BY created,id LIMIT 1"))
	if e == sql.ErrNoRows {
		j, e = s.autoJob(ctx)
	}
	if e != nil {
		return e
	}
	if j == nil {
		return s.expire(ctx)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if e = s.step(ctx, j); e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			_, saveErr := s.DB.ExecContext(ctx, "UPDATE retention_jobs SET status='failed',message=?,updated=? WHERE id=?", Message(e), time.Now().Unix(), j.ID)
			if saveErr != nil {
				return saveErr
			}
			return e
		}
		if j.Status == "complete" {
			break
		}
	}
	return s.expire(ctx)
}
func (s *Service) autoJob(ctx context.Context) (*Job, error) {
	var last sql.NullInt64
	if e := s.DB.QueryRowContext(ctx, "SELECT max(created) FROM retention_jobs WHERE owner='system'").Scan(&last); e != nil {
		return nil, e
	}
	if last.Valid && time.Now().Unix()-last.Int64 < 3600 {
		return nil, nil
	}
	scopes := []Scope{}
	d := Days(s.Config())
	keys := map[string]string{"events": "sqlite_events_days", "security": "security_events_days", "website": "website_incidents_days", "server": "server_alerts_days", "notifications": "delivery_records_days"}
	for _, name := range Categories {
		x, e := s.scope(ctx, Filter{Category: name, Before: time.Now().Unix() - int64(common.I(d[keys[name]]))*86400})
		if e != nil {
			return nil, e
		}
		scopes = append(scopes, x...)
	}
	for _, extra := range []struct{ name, key string }{{"notification_orphans", "delivery_records_days"}, {"server_batches", "server_alerts_days"}} {
		if x, ok := s.source(extra.name); ok {
			var upper sql.NullInt64
			if e := x.db.QueryRowContext(ctx, "SELECT max(rowid) FROM "+x.table).Scan(&upper); e != nil {
				return nil, e
			}
			scopes = append(scopes, Scope{Source: extra.name, Before: time.Now().Unix() - int64(common.I(d[extra.key]))*86400, Upper: upper.Int64})
		}
	}
	now := time.Now().Unix()
	j := &Job{ID: common.ID(), Owner: "system", Kind: "cleanup", Created: now, Updated: now, Status: "pending", Scope: scopes}
	_, e := s.DB.ExecContext(ctx, "INSERT INTO retention_jobs(id,owner,kind,created,updated,status,scope) VALUES(?,?,?,?,?,?,?)", j.ID, j.Owner, j.Kind, now, now, j.Status, string(common.JSON(scopes)))
	return j, e
}

type record struct {
	ID   int64   `json:"id"`
	Node string  `json:"node"`
	Time float64 `json:"time"`
	Raw  string  `json:"raw"`
}

func safeLine(sc Scope, r record) string {
	v, _ := common.Decode([]byte(r.Raw))
	raw := common.M(v)
	out := common.Map{"source": sc.Source, "record_id": r.ID, "node": r.Node, "time": r.Time}
	for _, key := range []string{"id", "site", "event_id", "operation", "path", "old_path", "reason", "risk", "time", "kind", "phase", "message", "started", "ended", "created", "done", "target", "attempts"} {
		if value, ok := raw[key]; ok {
			out[key] = value
		}
	}
	if scan := common.M(raw["scan"]); len(scan) > 0 {
		out["scan"] = common.Map{"status": scan["status"], "reason": scan["reason"]}
	}
	return string(common.JSON(out))
}
func (s *Service) step(ctx context.Context, j *Job) error {
	if j.Source >= len(j.Scope) {
		if j.Kind == "export" {
			done, e := s.finishExport(ctx, j.ID)
			if e != nil {
				return e
			}
			if !done {
				return nil
			}
		}
		j.Status = "complete"
		_, e := s.DB.ExecContext(ctx, "UPDATE retention_jobs SET status='complete',updated=? WHERE id=?", time.Now().Unix(), j.ID)
		return e
	}
	sc := j.Scope[j.Source]
	x, ok := s.source(sc.Source)
	if !ok {
		return userError("任务所需历史表不可用")
	}
	q, a := where(x, sc, j.Cursor, false)
	rows, e := x.db.QueryContext(ctx, "SELECT t.rowid,"+x.node+","+x.tm+","+x.raw+" FROM "+x.table+" t WHERE "+q+" ORDER BY t.rowid LIMIT 500", a...)
	if e != nil {
		return e
	}
	records := []record{}
	rawBytes := 0
	for rows.Next() {
		var r record
		if e = rows.Scan(&r.ID, &r.Node, &r.Time, &r.Raw); e != nil {
			break
		}
		if rawBytes+len(r.Raw) > 4<<20 && len(records) > 0 {
			break
		}
		rawBytes += len(r.Raw)
		records = append(records, r)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	// Journal the metrics batch before committing the other database. A restart
	// replays the same IDs and counts already absent rows as completed, without
	// restoring any snapshot or losing progress across the two WAL databases.
	journaled := false
	if x.db != s.DB && j.Kind == "cleanup" {
		var raw string
		readErr := s.DB.QueryRowContext(ctx, "SELECT records FROM retention_batches WHERE job=? AND source=? AND cursor=?", j.ID, j.Source, j.Cursor).Scan(&raw)
		if readErr == nil {
			if e = json.Unmarshal([]byte(raw), &records); e != nil {
				return e
			}
			journaled = true
		} else if readErr != sql.ErrNoRows {
			return readErr
		}
		if !journaled && len(records) > 0 {
			if _, e = s.DB.ExecContext(ctx, "INSERT INTO retention_batches VALUES(?,?,?,?)", j.ID, j.Source, j.Cursor, string(common.JSON(records))); e != nil {
				return e
			}
			journaled = true
		}
	}
	if len(records) == 0 {
		j.Source++
		j.Cursor = 0
		_, e = s.DB.ExecContext(ctx, "UPDATE retention_jobs SET source=?,cursor=0,status='running',updated=? WHERE id=?", j.Source, time.Now().Unix(), j.ID)
		return e
	}
	tx, e := persist.BeginWrite(ctx, x.db)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	done, skipped := int64(0), int64(0)
	protectedServer := false
	if sc.Source == "server" || sc.Source == "server_batches" {
		protectedServer, e = s.serverPending(ctx)
		if e != nil {
			return e
		}
	}
	// Export reads only eligible records and writes bounded chunks in a single event DB transaction.
	lines := map[int64]string{}
	for _, r := range records {
		if expected := sc.Fingerprints[fmt.Sprint(r.ID)]; expected != "" && expected != common.Hash(common.JSON(r)) {
			skipped++
			continue
		}
		var protected bool
		e = tx.QueryRowContext(ctx, "SELECT ("+x.protected+") FROM "+x.table+" t WHERE t.rowid=?", r.ID).Scan(&protected)
		if e == sql.ErrNoRows {
			if journaled {
				done++
			} else {
				skipped++
			}
			continue
		}
		if e != nil {
			return e
		}
		if protected || protectedServer || r.Time >= float64(sc.Before) {
			skipped++
			continue
		}
		if j.Kind == "export" {
			lines[r.ID] = safeLine(sc, r)
			done++
			continue
		}
		if sc.Source == "server_batches" {
			if _, e = tx.ExecContext(ctx, "DELETE FROM alert_members WHERE batch IN(SELECT id FROM alert_batches WHERE rowid=?)", r.ID); e != nil {
				return e
			}
		}
		if sc.Source == "website" {
			if _, e = tx.ExecContext(ctx, "DELETE FROM website_incident_origins WHERE id IN (SELECT id FROM website_incidents WHERE rowid=?)", r.ID); e != nil {
				return e
			}
		}
		if sc.Source == "notifications" {
			if _, e = tx.ExecContext(ctx, "DELETE FROM delivery_records WHERE task_id=?", r.ID); e != nil {
				return e
			}
		}
		if sc.Source == "server" {
			if _, e = tx.ExecContext(ctx, "DELETE FROM alert_members WHERE event IN(SELECT id FROM health_events WHERE rowid=?)", r.ID); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, "DELETE FROM alert_outbox WHERE id IN(SELECT id FROM health_events WHERE rowid=?) AND done IS NOT NULL", r.ID); e != nil {
				return e
			}
		}
		if sc.Source == "events" || sc.Source == "security" {
			if _, e = tx.ExecContext(ctx, "DELETE FROM migrated_logs WHERE node=? AND json_extract(payload,'$.event_id')=(SELECT id FROM events WHERE rowid=?)", r.Node, r.ID); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM "+x.table+" WHERE rowid=?", r.ID); e != nil {
			return e
		}
		done++
	}
	if x.db != s.DB {
		if e = tx.Commit(); e != nil {
			return e
		}
		tx, e = persist.BeginWrite(ctx, s.DB)
		if e != nil {
			return e
		}
		defer tx.Rollback()
	}
	for id, line := range lines {
		if _, e = tx.ExecContext(ctx, "INSERT OR IGNORE INTO retention_exports VALUES(?,?,?,?)", j.ID, j.Source, id, line); e != nil {
			return e
		}
	}
	if journaled {
		if _, e = tx.ExecContext(ctx, "DELETE FROM retention_batches WHERE job=?", j.ID); e != nil {
			return e
		}
	}
	next := records[len(records)-1].ID
	_, e = tx.ExecContext(ctx, "UPDATE retention_jobs SET cursor=?,processed=processed+?,skipped=skipped+?,status='running',updated=? WHERE id=?", next, done, skipped, time.Now().Unix(), j.ID)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	j.Cursor = next
	j.Processed += done
	j.Skipped += skipped
	j.Status = "running"
	return nil
}

// Finalize JSONL in bounded, restartable chunks. Truncate to the committed
// byte offset before replaying a chunk after a crash.
func (s *Service) finishExport(ctx context.Context, id string) (bool, error) {
	if e := os.MkdirAll(s.Directory, 0700); e != nil {
		return false, e
	}
	if e := os.Chmod(s.Directory, 0700); e != nil {
		return false, e
	}
	var source int = -1
	var rowID, offset int64
	e := s.DB.QueryRowContext(ctx, "SELECT source,rowid_value,bytes FROM retention_export_progress WHERE job=?", id).Scan(&source, &rowID, &offset)
	if e != nil && e != sql.ErrNoRows {
		return false, e
	}
	target := filepath.Join(s.Directory, id+".jsonl")
	tmp := target + ".tmp"
	if _, e = os.Stat(target); e == nil {
		return true, nil
	}
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return false, e
	}
	defer f.Close()
	if e = f.Truncate(offset); e != nil {
		return false, e
	}
	if _, e = f.Seek(offset, io.SeekStart); e != nil {
		return false, e
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT source,rowid_value,line FROM retention_exports WHERE job=? AND (source>? OR (source=? AND rowid_value>?)) ORDER BY source,rowid_value LIMIT 500", id, source, source, rowID)
	if e != nil {
		return false, e
	}
	n := 0
	for rows.Next() {
		var line string
		if e = rows.Scan(&source, &rowID, &line); e != nil {
			break
		}
		var written int
		written, e = io.WriteString(f, line+"\n")
		if e != nil {
			break
		}
		offset += int64(written)
		n++
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return false, e
	}
	if e = f.Sync(); e != nil {
		return false, e
	}
	if n == 0 {
		if e = f.Close(); e != nil {
			return false, e
		}
		return true, os.Rename(tmp, target)
	}
	_, e = s.DB.ExecContext(ctx, "INSERT INTO retention_export_progress VALUES(?,?,?,?) ON CONFLICT(job) DO UPDATE SET source=excluded.source,rowid_value=excluded.rowid_value,bytes=excluded.bytes", id, source, rowID, offset)
	return false, e
}
func (s *Service) Download(ctx context.Context, owner, id string) (string, error) {
	j, e := s.Job(ctx, owner, id)
	if e != nil || j.Kind != "export" || j.Status != "complete" || time.Now().Unix()-j.Updated >= 86400 {
		return "", userError("导出文件不存在、未完成或已过期")
	}
	return filepath.Join(s.Directory, j.ID+".jsonl"), nil
}
func (s *Service) expire(ctx context.Context) error {
	// Bounded removal; metadata remains for audit. Do not delete an active export.
	rows, e := s.DB.QueryContext(ctx, "SELECT id FROM retention_jobs WHERE kind='export' AND status NOT IN ('pending','running') AND export_expired=0 AND updated<? LIMIT 20", time.Now().Unix()-86400)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			break
		}
		ids = append(ids, id)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = os.Remove(filepath.Join(s.Directory, id+".jsonl")); e != nil && !os.IsNotExist(e) {
			return e
		}
		if e = os.Remove(filepath.Join(s.Directory, id+".jsonl.tmp")); e != nil && !os.IsNotExist(e) {
			return e
		}
		if _, e = s.DB.ExecContext(ctx, "DELETE FROM retention_export_progress WHERE job=?", id); e != nil {
			return e
		}
		res, e := s.DB.ExecContext(ctx, "DELETE FROM retention_exports WHERE rowid IN(SELECT rowid FROM retention_exports WHERE job=? LIMIT 500)", id)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n == 0 {
			if _, e = s.DB.ExecContext(ctx, "UPDATE retention_jobs SET export_expired=1 WHERE id=?", id); e != nil {
				return e
			}
		}
	}
	_, e = s.DB.ExecContext(ctx, "DELETE FROM retention_previews WHERE id IN(SELECT id FROM retention_previews WHERE created<? AND id NOT IN(SELECT preview FROM retention_jobs WHERE status IN ('pending','running')) LIMIT 500)", time.Now().Unix()-86400)
	if e != nil {
		return e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(ctx, "DELETE FROM retention_batches WHERE job IN(SELECT id FROM retention_jobs WHERE status NOT IN ('pending','running') AND (kind<>'export' OR export_expired=1) AND updated<? LIMIT 500)", time.Now().Unix()-365*86400)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "DELETE FROM retention_jobs WHERE id IN(SELECT id FROM retention_jobs WHERE status NOT IN ('pending','running') AND (kind<>'export' OR export_expired=1) AND updated<? LIMIT 500)", time.Now().Unix()-365*86400)
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Service) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if e := s.Tick(ctx); e != nil && ctx.Err() == nil {
			fmt.Println("history_cleanup_error=" + common.SecretFree(e))
		}
		if !common.Sleep(ctx, time.Second) {
			return
		}
	}
}

type publicError string

func (e publicError) Error() string  { return string(e) }
func userError(message string) error { return publicError(message) }
func Message(err error) string {
	var known publicError
	if errors.As(err, &known) {
		return known.Error()
	}
	if errors.Is(err, syscall.ENOSPC) || strings.Contains(strings.ToLower(err.Error()), "disk full") {
		return "磁盘空间不足，已完成部分保留，请释放空间后重新预览"
	}
	if errors.Is(err, os.ErrPermission) {
		return "备份或导出目录权限不足，请检查服务器目录权限"
	}
	if strings.Contains(strings.ToLower(err.Error()), "locked") || strings.Contains(strings.ToLower(err.Error()), "busy") {
		return "数据库繁忙，请稍后重试；已完成部分保留"
	}
	return "历史数据或导出存储操作失败，请检查服务器日志和磁盘；已完成部分保留"
}
func ValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
