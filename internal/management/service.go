package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/deploy"
	"webscan/internal/persist"
	"webscan/internal/recordops"
)

const jobSchema = `CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,request_key TEXT UNIQUE,kind TEXT,node TEXT,status TEXT,created INTEGER,updated INTEGER,revision TEXT,message TEXT);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT,job TEXT,time INTEGER,message TEXT);
CREATE INDEX IF NOT EXISTS logs_job ON logs(job,id);
CREATE TABLE IF NOT EXISTS config_backups(id TEXT PRIMARY KEY,time INTEGER,revision TEXT,source TEXT,path TEXT);
CREATE TABLE IF NOT EXISTS watchdog_state(id TEXT PRIMARY KEY,phase TEXT,since INTEGER);
CREATE TABLE IF NOT EXISTS watchdog_outbox(id TEXT PRIMARY KEY,message TEXT,created INTEGER,done INTEGER);`

type Service struct {
	Operations   *recordops.Service
	decryptSlot  chan struct{}
	ConfigPath   string
	StateDir     string
	DB           *sql.DB
	mu           sync.Mutex
	running      bool
	watchdogBeat atomic.Int64
	execute      func(context.Context, string, string, string) error
}
type Job struct {
	CanDelete    bool   `json:"can_delete"`
	DeleteReason string `json:"delete_reason"`
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Node         string `json:"node"`
	Status       string `json:"status"`
	Created      int64  `json:"created"`
	Updated      int64  `json:"updated"`
	Revision     string `json:"revision"`
	Message      string `json:"message"`
}

func Open(configPath, state string) (*Service, error) {
	if info, e := os.Lstat(configPath); e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, userError("配置必须是权限 0600 的普通文件")
	}
	p, e := filepath.Abs(configPath)
	if e != nil {
		return nil, e
	}
	if _, e = config.Load(p); e != nil {
		return nil, e
	}
	state, e = filepath.Abs(state)
	if e != nil {
		return nil, e
	}
	db, e := persist.OpenDB(filepath.Join(state, "management.sqlite3"))
	if e != nil {
		return nil, e
	}
	if _, e = db.Exec(jobSchema); e != nil {
		db.Close()
		return nil, e
	}
	ops, e := recordops.New(db, filepath.Join(state, "database-backups"))
	if e != nil {
		db.Close()
		return nil, e
	}
	if _, e = db.Exec(backupSchema + removalSchema); e != nil {
		db.Close()
		return nil, e
	}
	s := &Service{ConfigPath: p, StateDir: state, DB: db, Operations: ops, decryptSlot: make(chan struct{}, 1)}
	ops.Apply = s.applyRecordOperation
	return s, nil
}
func (s *Service) lock() (func(), error) {
	if e := os.MkdirAll(s.StateDir, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(s.StateDir, "deploy.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, userError("存在正在执行的部署，请稍后重试")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func (s *Service) pending() bool {
	state, e := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
	if os.IsNotExist(e) {
		return false
	}
	if e != nil {
		return true
	}
	if common.B(state["central_uninstall_pending"]) {
		return true
	}
	u := common.M(state["single_uninstall"])
	if len(u) > 0 && !common.B(u["complete"]) {
		return true
	}
	phase := common.S(state["step"])
	return phase != "" && phase != "complete" && phase != "rolled-back" && phase != "addition-rolled-back"
}
func (s *Service) backup(raw []byte, source string) (string, error) {
	id := common.ID()
	dir := filepath.Join(s.StateDir, "config-backups")
	if e := recordops.PrivateDirectory(dir); e != nil {
		return "", e
	}
	path := filepath.Join(dir, "console-"+id+".yaml")
	if e := common.Atomic(path, raw, 0600); e != nil {
		return "", e
	}
	_, e := s.DB.Exec("INSERT INTO config_backups VALUES(?,?,?,?,?)", id, time.Now().Unix(), common.Hash(raw), source, path)
	if e != nil {
		os.Remove(path)
	}
	return id, e
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, e error) {
	code := 400
	if strings.Contains(e.Error(), "修改") || strings.Contains(e.Error(), "正在") || strings.Contains(e.Error(), "未完成") {
		code = 409
	}
	reply(w, code, common.Map{"message": userMessage(e)})
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, (2<<20)+1))
	d.UseNumber()
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return userError("请求内容格式错误")
	}
	if d.Decode(new(any)) != io.EOF {
		return userError("请求内容超限或包含多份内容")
	}
	return nil
}
func (s *Service) Handler(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/nodes/remove"):
		s.removeNodesAPI(w, r)
	case r.URL.Path == "/operations" && r.Method == "GET":
		v, e := s.Operations.List(r.Context(), operationOwner(r), requestPage(r))
		if e != nil {
			failure(w, e)
		} else {
			reply(w, 200, v)
		}
	case r.URL.Path == "/health" && r.Method == "GET":
		var phase string
		var since int64
		e := s.DB.QueryRowContext(r.Context(), "SELECT phase,since FROM watchdog_state WHERE id='central'").Scan(&phase, &since)
		if e != nil && e != sql.ErrNoRows {
			failure(w, e)
			return
		}
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		var latest Job
		e = s.DB.QueryRowContext(r.Context(), "SELECT id,kind,node,status,created,updated,revision,message FROM jobs ORDER BY created DESC,id DESC LIMIT 1").Scan(&latest.ID, &latest.Kind, &latest.Node, &latest.Status, &latest.Created, &latest.Updated, &latest.Revision, &latest.Message)
		if e != nil && e != sql.ErrNoRows {
			failure(w, e)
			return
		}
		reply(w, 200, common.Map{"available": true, "task_running": running, "pending_task": s.pending() || s.removalPending(), "operation_running": s.running, "watchdog_phase": phase, "watchdog_since": since, "watchdog_heartbeat": s.watchdogBeat.Load(), "latest_job": latest})
	case r.URL.Path == "/settings" && r.Method == "GET":
		c, e := config.Load(s.ConfigPath)
		if e != nil {
			failure(w, e)
			return
		}
		raw, e := os.ReadFile(s.ConfigPath)
		if e != nil {
			failure(w, e)
			return
		}
		state, _ := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
		for _, n := range c.Nodes {
			n["deployment"] = common.Map{"mode": deploy.ResolveNodeMode(n, state)}
		}
		deployed := common.Map{}
		for id, value := range common.M(state["nodes"]) {
			n := common.M(value)
			mode := common.S(n["deployment_mode"])
			if mode == "" && n["go_image"] != nil {
				mode = "docker"
			}
			deployed[id] = common.Map{"mode": mode, "version": n["go_release"], "phase": n["phase"]}
		}
		reply(w, 200, common.Map{"node_deployments": deployed, "revision": common.Hash(raw), "values": Redact(c.Raw), "effective_nodes": redactNodes(c.Nodes), "editable": editable, "running": state["configuration"], "pending_task": s.pending() || s.removalPending(), "operation_running": s.running})
	case r.URL.Path == "/settings/preview" && r.Method == "POST":
		var edit Edit
		if e := decode(r, &edit); e != nil {
			failure(w, e)
			return
		}
		raw, preview, e := prepare(s.ConfigPath, edit)
		if e != nil {
			failure(w, e)
			return
		}
		preview = s.pendingPreview(raw, preview)
		reply(w, 200, preview)
	case r.URL.Path == "/settings" && r.Method == "PUT":
		var edit Edit
		if e := decode(r, &edit); e != nil {
			failure(w, e)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.running || s.pending() || s.removalPending() {
			failure(w, userError("存在未完成任务，请先继续或回退"))
			return
		}
		unlock, e := s.lock()
		if e != nil {
			failure(w, e)
			return
		}
		defer unlock()
		keyPath := s.newPrivateKeyPath(edit)
		raw, preview, e := prepareWithKeyPath(s.ConfigPath, edit, keyPath)
		if e != nil {
			failure(w, e)
			return
		}
		old, e := os.ReadFile(s.ConfigPath)
		if e == nil {
			e = s.commitConfig(old, raw, edit, keyPath, "编辑前")
		}
		if e != nil {
			failure(w, e)
			return
		}
		reply(w, 200, common.Map{"revision": common.Hash(raw), "preview": preview, "saved": true})
	case r.URL.Path == "/jobs/delete":
		s.Operations.Handler(w, r, operationOwner(r), "deployment-job")
	case r.URL.Path == "/backups/delete":
		s.Operations.Handler(w, r, operationOwner(r), "deployment-backup")
	case r.URL.Path == "/backups/import":
		s.importConfigBackup(w, r)
	case r.URL.Path == "/jobs" && r.Method == "GET":
		s.jobs(w, r)
	case r.URL.Path == "/jobs" && r.Method == "POST":
		s.createJob(w, r)
	case strings.HasPrefix(r.URL.Path, "/jobs/") && r.Method == "GET":
		s.job(w, r)
	case strings.HasPrefix(r.URL.Path, "/backups/"):
		s.backupAction(w, r)
	case r.URL.Path == "/backups":
		s.configBackups(w, r)
	default:
		reply(w, 404, common.Map{"message": "管理接口不存在"})
	}
}
func redactNodes(nodes []common.Map) []common.Map {
	out := []common.Map{}
	for _, n := range nodes {
		out = append(out, Redact(n))
	}
	return out
}
func scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	e := row.Scan(&j.ID, &j.Kind, &j.Node, &j.Status, &j.Created, &j.Updated, &j.Revision, &j.Message)
	return j, e
}

const jobColumns = "id,kind,node,status,created,updated,revision,message"

func (s *Service) jobs(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.QueryContext(r.Context(), "SELECT "+jobColumns+" FROM jobs WHERE id NOT IN (SELECT id FROM job_archives) ORDER BY created DESC LIMIT 20 OFFSET ?", (requestPage(r)-1)*20)
	if e != nil {
		failure(w, e)
		return
	}
	defer rows.Close()
	items := []Job{}
	for rows.Next() {
		j, e := scanJob(rows)
		if e != nil {
			failure(w, e)
			return
		}
		j.CanDelete, j.DeleteReason = s.jobDeletable(r.Context(), j)
		items = append(items, j)
	}
	rows.Close()
	var total int
	if e = s.DB.QueryRow("SELECT count(*) FROM jobs WHERE id NOT IN (SELECT id FROM job_archives)").Scan(&total); e != nil {
		failure(w, e)
		return
	}
	reply(w, 200, common.Map{"items": items, "total": total})
}
func (s *Service) job(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/jobs/")
	j, e := scanJob(s.DB.QueryRow("SELECT "+jobColumns+" FROM jobs WHERE id=? AND id NOT IN (SELECT id FROM job_archives)", id))
	if e != nil {
		reply(w, 404, common.Map{"message": "任务不存在"})
		return
	}
	cursor := common.I(r.URL.Query().Get("cursor"))
	fmt.Sscan(r.URL.Query().Get("cursor"), &cursor)
	rows, e := s.DB.Query("SELECT id,time,message FROM logs WHERE job=? AND id>? ORDER BY id LIMIT 200", id, cursor)
	if e != nil {
		failure(w, e)
		return
	}
	defer rows.Close()
	logs := []common.Map{}
	for rows.Next() {
		var seq, tm int64
		var msg string
		rows.Scan(&seq, &tm, &msg)
		logs = append(logs, common.Map{"id": seq, "time": tm, "message": msg})
		cursor = int(seq)
	}
	reply(w, 200, common.Map{"job": j, "logs": logs, "cursor": cursor})
}

type Start struct {
	Key      string `json:"request_key"`
	Revision string `json:"revision"`
	Kind     string `json:"kind"`
	Node     string `json:"node"`
	Edit     *Edit  `json:"edit,omitempty"`
}

func (s *Service) createJob(w http.ResponseWriter, r *http.Request) {
	var input Start
	if e := decode(r, &input); e != nil {
		failure(w, e)
		return
	}
	if input.Key == "" || len(input.Key) > 128 {
		failure(w, userError("缺少有效的重复提交标识"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, e := scanJob(s.DB.QueryRow("SELECT "+jobColumns+" FROM jobs WHERE request_key=?", input.Key)); e == nil {
		reply(w, 200, j)
		return
	}
	if s.running {
		failure(w, userError("部署正在执行"))
		return
	}
	if s.removalPending() {
		failure(w, userError("存在未完成移除任务，请从任务详情继续"))
		return
	}
	if s.pending() && input.Kind != "resume" && input.Kind != "rollback" {
		failure(w, userError("存在未完成部署，请先继续或回退"))
		return
	}
	switch input.Kind {
	case "apply", "add-node", "resume", "rollback", "migrate":
	default:
		failure(w, userError("不支持此部署操作"))
		return
	}
	unlock, e := s.lock()
	if e != nil {
		failure(w, e)
		return
	}
	defer unlock()
	raw, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		failure(w, e)
		return
	}
	if common.Hash(raw) != input.Revision {
		failure(w, userError("配置已被修改，请重新预览"))
		return
	}
	next := raw
	keyPath := ""
	if input.Edit != nil {
		if input.Kind != "apply" && input.Kind != "add-node" {
			failure(w, userError("恢复或迁移任务不能同时修改配置"))
			return
		}
		keyPath = s.newPrivateKeyPath(*input.Edit)
		next, _, e = prepareWithKeyPath(s.ConfigPath, *input.Edit, keyPath)
		if e != nil {
			failure(w, e)
			return
		}
	}
	c, e := validateBytes(s.ConfigPath, next)
	if e != nil {
		failure(w, e)
		return
	}
	if input.Kind == "add-node" && (input.Node == "" || len(c.Selected(input.Node)) != 1) {
		failure(w, userError("请选择一个启用节点"))
		return
	}
	if input.Kind == "resume" || input.Kind == "rollback" {
		state, e := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
		if e != nil {
			failure(w, e)
			return
		}
		original := common.S(state["target_node"])
		if input.Node != "" && input.Node != original {
			failure(w, userError("请保持原任务节点范围"))
			return
		}
		input.Node = original
	}
	if input.Edit != nil {
		e = s.commitConfig(raw, next, *input.Edit, keyPath, "部署前")
		if e != nil {
			failure(w, e)
			return
		}
		raw = next
	}
	id := common.ID()
	now := time.Now().Unix()
	revision := common.Hash(raw)
	_, e = s.DB.Exec("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)", id, input.Key, input.Kind, input.Node, "queued", now, now, revision, "")
	if e != nil {
		failure(w, e)
		return
	}
	s.running = true
	go s.run(id, input.Kind, input.Node)
	reply(w, 202, Job{ID: id, Kind: input.Kind, Node: input.Node, Status: "queued", Created: now, Revision: revision})
}

type logWriter struct {
	s       *Service
	id      string
	secrets []string
}

func (w logWriter) Write(b []byte) (int, error) {
	text := string(b)
	for _, secret := range w.secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[已隐藏]")
		}
	}
	_, e := w.s.DB.Exec("INSERT INTO logs(job,time,message) VALUES(?,?,?)", w.id, time.Now().Unix(), text)
	return len(b), e
}
func (s *Service) run(id, kind, node string) {
	s.DB.Exec("UPDATE jobs SET status='running',updated=? WHERE id=?", time.Now().Unix(), id)
	e := s.perform(context.Background(), id, kind, node)
	status, msg := "complete", "部署及验收完成"
	if e != nil {
		status = "failed"
		msg = userMessage(e)
	}
	s.DB.Exec("UPDATE jobs SET status=?,updated=?,message=? WHERE id=?", status, time.Now().Unix(), msg, id)
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}
func (s *Service) perform(ctx context.Context, id, kind, node string) error {
	if kind == "remove-nodes" {
		return s.performRemoval(ctx, id)
	}
	var revision string
	if e := s.DB.QueryRow("SELECT revision FROM jobs WHERE id=?", id).Scan(&revision); e != nil {
		return e
	}
	raw, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		return e
	}
	if common.Hash(raw) != revision {
		return userError("配置已被修改，请重新预览")
	}
	if s.execute != nil {
		return s.execute(ctx, id, kind, node)
	}
	if kind == "migrate" {
		return s.migrate(ctx, id)
	}
	if kind == "apply" {
		return s.apply(ctx, id)
	}
	binary, e := os.Executable()
	if e != nil {
		return e
	}
	args := []string{"deploy", "--config", s.ConfigPath, "--non-interactive", "--expected-revision", revision}
	switch kind {
	case "add-node":
		args = append(args, "--add-node", "--node", node)
	case "resume":
		args = append(args, "--resume")
		if node != "" {
			args = append(args, "--node", node)
		}
	case "rollback":
		args = append(args, "--rollback")
		if node != "" {
			args = append(args, "--node", node)
		}
	}
	return s.command(ctx, id, binary, args)
}
func (s *Service) command(ctx context.Context, id, binary string, args []string) error {
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		return e
	}
	secrets := []string{}
	var collect func(any)
	collect = func(v any) {
		switch x := v.(type) {
		case common.Map:
			for k, v := range x {
				if secret(k) {
					if v := common.S(v); v != "" {
						secrets = append(secrets, v)
					}
				} else {
					collect(v)
				}
			}
		case []any:
			for _, v := range x {
				collect(v)
			}
		}
	}
	collect(c.Raw)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "WEBSCAN_MANAGEMENT_JOB="+id)
	credentials, _ := common.ReadJSON(filepath.Join(s.StateDir, "credentials.json"))
	collect(credentials)
	writer := &lineWriter{writer: logWriter{s, id, secrets}}
	cmd.Stdout, cmd.Stderr = writer, writer
	e = cmd.Run()
	writer.close()
	if e != nil {
		return userError("部署工具执行失败，请查看本任务日志中的失败阶段，并按原范围继续或回退")
	}
	return nil
}
func Run(ctx context.Context, path, state, socket string) error {
	if os.Geteuid() != 0 {
		return userError("宿主机管理服务需要 root")
	}
	for _, p := range []string{path, state, filepath.Dir(socket)} {
		if e := secureHostPath(p); e != nil {
			return e
		}
	}
	s, e := Open(path, state)
	if e != nil {
		return e
	}
	defer s.DB.Close()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	operationsDone := make(chan struct{})
	go func() { defer close(operationsDone); s.Operations.Run(ctx) }()
	defer func() { cancel(); <-operationsDone }()
	go func() { defer close(done); s.watchdog(ctx) }()
	defer func() { cancel(); <-done }()
	if _, e = s.DB.Exec("UPDATE jobs SET status='interrupted',message='管理服务曾中断，请核对后继续或回退',updated=? WHERE status IN ('queued','running')", time.Now().Unix()); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(socket), 0700); e != nil {
		return e
	}
	if info, e := os.Lstat(socket); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return userError("管理入口存在非 Socket 文件")
		}
		c, e := net.DialTimeout("unix", socket, time.Second)
		if e == nil {
			c.Close()
			return userError("管理服务已运行")
		}
		os.Remove(socket)
	}
	l, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer os.Remove(socket)
	if e = os.Chmod(socket, 0600); e != nil {
		l.Close()
		return e
	}
	server := &http.Server{Handler: http.HandlerFunc(s.Handler), ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	e = server.Serve(l)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
func PendingAt(state string) bool { s := &Service{StateDir: state}; return s.pending() }

func requestPage(r *http.Request) int {
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	return max(1, p)
}
