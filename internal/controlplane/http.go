package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	controlv3 "webscan/api/control/v3"
	"webscan/internal/deploy"
)

var controlplaneStartedAt = time.Now().UTC()

type API struct {
	Store   *Store
	Config  Config
	Metrics *Metrics
	// Original validated bootstrap snapshot, never the process lease identity.
	bootstrapConfig *Config
}
type identity struct{ Username, Role, CSRF, Hash string }

func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic("crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, code, message string) {
	reply(w, status, map[string]string{"code": code, "message": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("请求格式不正确")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("只允许一个 JSON 对象")
	}
	return nil
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	if r.URL.Path == "/healthz" {
		if r.Method != "GET" && r.Method != "HEAD" {
			failure(w, 405, "method_not_allowed", "请使用 GET")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if a.Store.DB.PingContext(ctx) != nil {
			failure(w, 503, "database_unavailable", "数据库暂时不可用")
			return
		}
		reply(w, 200, map[string]string{"status": "normal"})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v3/") {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			failure(w, 404, "not_found", "接口不存在")
		} else {
			serveConsole(w, r)
		}
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		origin := r.Header.Get("Origin")
		u, _ := url.Parse(a.Config.Central.PublicURL)
		if origin != "" && origin != u.Scheme+"://"+u.Host {
			failure(w, 403, "origin_mismatch", "请求来源不正确")
			return
		}
	}
	if r.URL.Path == "/api/v3/login" {
		a.login(w, r)
		return
	}
	id, e := a.authenticate(r)
	if e == sql.ErrNoRows {
		failure(w, 401, "authentication_required", "请重新登录")
		return
	}
	if e != nil {
		failure(w, 503, "session_unavailable", "会话服务暂时不可用，请稍后重试")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(id.CSRF)) != 1 {
			failure(w, 403, "csrf_mismatch", "请求校验失败")
			return
		}
		if id.Role == "viewer" && r.URL.Path != "/api/v3/logout" {
			failure(w, 403, "permission_denied", "当前账号只允许查看")
			return
		}
	}
	if a.configurationApplicationRoutes(w, r, id) {
		return
	}
	if r.URL.Path == "/api/v3/servers/remove" && r.Method == http.MethodPost {
		a.removeServerRecords(w, r, id)
		return
	}
	if a.webDeploymentRoutes(w, r, id) {
		return
	}
	if a.deploymentRoutes(w, r, id) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v3/servers/") {
		if strings.HasSuffix(r.URL.Path, "/metrics") {
			a.serverTrends(w, r, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v3/servers/"), "/metrics"))
			return
		}
		a.serverDetail(w, r)
		return
	}
	if a.websiteRoutes(w, r, id) {
		return
	}
	if a.websiteBackupRoutes(w, r, id) {
		return
	}
	if a.configurationRestoreRoutes(w, r, id) {
		return
	}
	if a.configurationBackupRoutes(w, r, id) {
		return
	}
	if a.healthRoutes(w, r) {
		return
	}
	if a.notificationHistoryRoutes(w, r) {
		return
	}
	if a.auditRoutes(w, r, id) {
		return
	}
	if a.settingsRoutes(w, r, id) {
		return
	}
	if a.retentionRoutes(w, r, id) {
		return
	}
	switch r.URL.Path {
	case "/api/v3/session":
		if r.Method != "GET" {
			failure(w, 405, "method_not_allowed", "请使用 GET")
			return
		}
		reply(w, 200, map[string]string{"username": id.Username, "role": id.Role, "csrf": id.CSRF})
		return
	case "/api/v3/logout":
		if r.Method != "POST" {
			failure(w, 405, "method_not_allowed", "请使用 POST")
			return
		}
		if _, e = a.Store.DB.ExecContext(r.Context(), "DELETE FROM v3_sessions WHERE token_hash=$1", id.Hash); e != nil {
			failure(w, 503, "database_unavailable", "退出失败，请重试")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "webscan_v3_session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		reply(w, 200, map[string]bool{"ok": true})
		return
	case "/api/v3/capabilities":
		if r.Method != "GET" {
			failure(w, 405, "method_not_allowed", "请使用 GET")
			return
		}
		reply(w, 200, a.capabilities(r.Context()))
		return
	case "/api/v3/openapi.yaml":
		if r.Method != "GET" {
			failure(w, 405, "method_not_allowed", "请使用 GET")
			return
		}
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(controlv3.OpenAPI)
		return
	case "/api/v3/servers":
		a.nodes(w, r, id)
		return
	case "/api/v3/events":
		a.events(w, r)
		return
	case "/api/v3/dashboard":
		if r.Method != "GET" {
			failure(w, 405, "method_not_allowed", "请使用 GET")
			return
		}
		var raw []byte
		var at time.Time
		var reason string
		e = a.Store.DB.QueryRowContext(r.Context(), "SELECT payload,updated_at,error FROM v3_dashboard WHERE id=1").Scan(&raw, &at, &reason)
		if e != nil {
			failure(w, 503, "summary_unavailable", "总览尚未生成或暂时不可用")
			return
		}
		reply(w, 200, map[string]any{"summary": json.RawMessage(raw), "updated_at": at, "stale": time.Since(at) > 30*time.Second, "error": reason, "version": deploy.Release, "started_at": controlplaneStartedAt})
		return
	case "/api/v3/metrics":
		a.metrics(w, r)
		return
	default:
		failure(w, 404, "not_found", "接口不存在")
	}
}
func (a *API) authenticate(r *http.Request) (identity, error) {
	var id identity
	cookie, e := r.Cookie("webscan_v3_session")
	if e != nil || len(cookie.Value) != 64 {
		return id, sql.ErrNoRows
	}
	id.Hash = digest([]byte(cookie.Value))
	e = a.Store.DB.QueryRowContext(r.Context(), "SELECT a.username,a.role,s.csrf FROM v3_sessions s JOIN v3_accounts a ON a.username=s.username AND a.revision=s.revision WHERE s.token_hash=$1 AND s.expires_at>clock_timestamp()", id.Hash).Scan(&id.Username, &id.Role, &id.CSRF)
	return id, e
}
func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		failure(w, 405, "method_not_allowed", "请使用 POST")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decode(w, r, &input) != nil || len(input.Username) > 128 || len(input.Password) > 72 {
		failure(w, 400, "invalid_request", "登录参数不正确")
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	key := digest([]byte(host + "\x00" + input.Username))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, e := a.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		failure(w, 503, "database_unavailable", "登录服务暂时不可用")
		return
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		failure(w, 503, "database_unavailable", "登录服务暂时不可用")
		return
	} else if held {
		failure(w, 503, "migration_pending", ErrMigrationPending.Error())
		return
	}
	var attempts int
	e = tx.QueryRowContext(ctx, `INSERT INTO v3_login_attempts VALUES($1,1,clock_timestamp()+interval '5 minutes') ON CONFLICT(key) DO UPDATE SET count=CASE WHEN v3_login_attempts.expires_at<=clock_timestamp() THEN 1 ELSE v3_login_attempts.count+1 END,expires_at=CASE WHEN v3_login_attempts.expires_at<=clock_timestamp() THEN EXCLUDED.expires_at ELSE v3_login_attempts.expires_at END RETURNING count`, key).Scan(&attempts)
	if e != nil {
		failure(w, 503, "database_unavailable", "登录服务暂时不可用")
		return
	}
	if attempts > 10 {
		if tx.Commit() != nil {
			failure(w, 503, "database_unavailable", "登录服务暂时不可用")
			return
		}
		failure(w, 429, "login_rate_limit", "尝试次数过多，请稍后重试")
		return
	}
	var hash string
	var revision int64
	e = tx.QueryRowContext(ctx, "SELECT password_hash,revision FROM v3_accounts WHERE username=$1 FOR UPDATE", input.Username).Scan(&hash, &revision)
	if e != nil && e != sql.ErrNoRows {
		failure(w, 503, "database_unavailable", "登录服务暂时不可用")
		return
	}
	if e == sql.ErrNoRows || bcrypt.CompareHashAndPassword([]byte(hash), []byte(input.Password)) != nil {
		if tx.Commit() != nil {
			failure(w, 503, "database_unavailable", "登录服务暂时不可用")
			return
		}
		failure(w, 401, "invalid_credentials", "账号或密码不正确")
		return
	}
	secret, csrf := token(), token()
	if _, e = tx.ExecContext(ctx, "DELETE FROM v3_sessions WHERE username=$1 AND (expires_at<=clock_timestamp() OR token_hash IN(SELECT token_hash FROM v3_sessions WHERE username=$1 ORDER BY created_at DESC OFFSET 99))", input.Username); e != nil {
		failure(w, 503, "database_unavailable", "登录服务暂时不可用")
		return
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '12 hours')", digest([]byte(secret)), input.Username, revision, csrf); e != nil {
		failure(w, 503, "database_unavailable", "登录服务暂时不可用")
		return
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM v3_login_attempts WHERE key=$1", key); e != nil {
		failure(w, 503, "database_unavailable", "登录服务暂时不可用")
		return
	}
	if e = tx.Commit(); e != nil {
		failure(w, 503, "database_unavailable", "登录服务暂时不可用")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "webscan_v3_session", Value: secret, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	reply(w, 200, map[string]string{"csrf": csrf})
}

func (a *API) nodes(w http.ResponseWriter, r *http.Request, id identity) {
	if r.Method == "POST" {
		if id.Role != "admin" {
			failure(w, 403, "permission_denied", "需要管理员权限")
			return
		}
		var input struct {
			Node     Node  `json:"node"`
			Expected int64 `json:"expected_version"`
		}
		if e := decode(w, r, &input); e != nil {
			failure(w, 400, "invalid_request", e.Error())
			return
		}
		if e := input.Node.Validate(); e != nil {
			failure(w, 400, "invalid_node", e.Error())
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if !identifier.MatchString(key) || input.Expected < 0 {
			failure(w, 400, "invalid_idempotency_key", "请提供 1～128 字节的有效幂等键和非负配置版本")
			return
		}
		before, e := a.configurationEditBackup()
		if e != nil {
			failure(w, 503, "before_edit_backup_failed", errConfigurationBeforeEdit.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		response, e := a.Store.saveNode(ctx, id.Username, key, input.Node, input.Expected, a.Config.Collector.Shards, before)
		if errors.Is(e, errConfigurationBeforeEdit) {
			failure(w, 503, "before_edit_backup_failed", errConfigurationBeforeEdit.Error())
			return
		}
		if errors.Is(e, ErrConfigurationBackupPermission) {
			failure(w, 403, "permission_denied", "需要管理员权限")
			return
		}
		if errors.Is(e, ErrRequestConflict) {
			failure(w, 409, "idempotency_conflict", e.Error())
			return
		}
		if errors.Is(e, ErrDeploymentBusy) {
			failure(w, 409, "deployment_pending", e.Error())
			return
		}
		if errors.Is(e, errConfigurationApplicationBusy) {
			failure(w, 409, "configuration_application_busy", errConfigurationApplicationBusy.Error())
			return
		}
		if errors.Is(e, ErrConflict) {
			failure(w, 409, "config_conflict", e.Error())
			return
		}
		if e != nil {
			failure(w, 503, "save_failed", "配置保存失败，请重试")
			return
		}
		reply(w, 200, response)
		return
	}
	if r.Method != "GET" {
		failure(w, 405, "method_not_allowed", "请使用 GET 或 POST")
		return
	}
	limit, e := pageSize(r, 50)
	if e != nil {
		failure(w, 400, "invalid_limit", e.Error())
		return
	}
	after := ""
	if v := r.URL.Query().Get("cursor"); v != "" {
		raw, e := base64.RawURLEncoding.DecodeString(v)
		if e != nil || len(raw) > 128 || !identifier.Match(raw) {
			failure(w, 400, "invalid_cursor", "分页游标不正确")
			return
		}
		after = string(raw)
	}
	state := r.URL.Query().Get("status")
	switch state {
	case "", "normal", "unreachable", "stale", "unknown", "disabled":
	default:
		failure(w, 400, "invalid_status", "采集状态不正确")
		return
	}
	items, e := a.Store.consoleNodes(r.Context(), after, r.URL.Query().Get("q"), state, limit, a.Config.Collector.IntervalSeconds)
	if e != nil {
		failure(w, 503, "query_failed", "服务器查询失败")
		return
	}
	next := ""
	if len(items) == limit {
		var last struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(items[len(items)-1], &last) != nil {
			failure(w, 503, "query_failed", "服务器查询失败")
			return
		}
		next = base64.RawURLEncoding.EncodeToString([]byte(last.ID))
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next, "limit": limit})
}
func pageSize(r *http.Request, defaultSize int) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return defaultSize, nil
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < 1 || n > 200 {
		return 0, errors.New("每页数量须为 1～200")
	}
	return n, nil
}
func timeRange(r *http.Request) (time.Time, time.Time, error) {
	end := time.Now().UTC()
	start := end.Add(-24 * time.Hour)
	var e error
	if v := r.URL.Query().Get("start"); v != "" {
		start, e = time.Parse(time.RFC3339Nano, v)
		if e != nil {
			return start, end, e
		}
	}
	if v := r.URL.Query().Get("end"); v != "" {
		end, e = time.Parse(time.RFC3339Nano, v)
	}
	if e != nil || !end.After(start) || end.Sub(start) > 31*24*time.Hour {
		return start, end, errors.New("时间范围不正确，最多 31 天")
	}
	return start, end, nil
}
func (a *API) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	limit, e := pageSize(r, 20)
	if e != nil {
		failure(w, 400, "invalid_limit", e.Error())
		return
	}
	start, end, e := timeRange(r)
	if e != nil {
		failure(w, 400, "invalid_time", "时间范围不正确")
		return
	}
	q := r.URL.Query()
	include := false
	if v := q.Get("include_probes"); v != "" {
		include, e = strconv.ParseBool(v)
		if e != nil {
			failure(w, 400, "invalid_probes", "包含探针参数不正确")
			return
		}
	}
	f := EventFilter{Node: q.Get("node"), Operation: q.Get("operation"), Keyword: q.Get("q"), IncludeProbes: include, Since: start, Until: end, Limit: limit}
	if v := q.Get("cursor"); v != "" {
		var cursor struct {
			Time   time.Time `json:"time"`
			Node   string    `json:"node"`
			ID     string    `json:"id"`
			Source string    `json:"source"`
		}
		if len(v) > 12288 {
			failure(w, 400, "invalid_cursor", "分页游标不正确")
			return
		}
		b, e := base64.RawURLEncoding.DecodeString(v)
		if e != nil || len(b) > 8192 || json.Unmarshal(b, &cursor) != nil || cursor.Time.IsZero() || !eventText(cursor.Node, 512) || !eventText(cursor.ID, 256) || (cursor.Source != "" && cursor.Source != "events" && cursor.Source != "migrated_events") {
			failure(w, 400, "invalid_cursor", "分页游标不正确")
			return
		}
		f.BeforeTime, f.BeforeNode, f.BeforeID, f.BeforeSource = cursor.Time, cursor.Node, cursor.ID, cursor.Source
	}
	if f.Operation == "probe" && !f.IncludeProbes {
		failure(w, 400, "probe_requires_opt_in", "请先开启包含链路探针")
		return
	}
	items, e := a.Store.Events(r.Context(), f)
	if e != nil {
		failure(w, 503, "query_failed", "事件查询失败")
		return
	}
	next := ""
	if len(items) == limit {
		v := items[len(items)-1]
		raw, _ := json.Marshal(map[string]any{"time": v.Received, "node": v.Node, "id": v.ID, "source": v.Source})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next, "start": start, "end": end})
}
func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	start, end, e := timeRange(r)
	if e != nil {
		failure(w, 400, "invalid_time", "时间范围不正确")
		return
	}
	if a.Metrics == nil {
		failure(w, 503, "metrics_unavailable", "指标查询暂不可用")
		return
	}
	raw, e := a.Metrics.Range(r.Context(), r.URL.Query().Get("node"), r.URL.Query().Get("metric"), start, end)
	if e != nil {
		failure(w, 503, "metrics_unavailable", "指标查询失败，请检查节点、指标名和时序库状态")
		return
	}
	reply(w, 200, raw)
}

func (s *Store) Provision(ctx context.Context, username, password string) error {
	if !identifier.MatchString(username) || len(password) < 12 || len(password) > 72 {
		return errors.New("账号格式不正确或密码不在 12～72 字节范围")
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return err
	} else if held {
		return ErrMigrationPending
	}
	r, e := tx.ExecContext(ctx, "INSERT INTO v3_accounts(username,password_hash,role) VALUES($1,$2,'admin') ON CONFLICT DO NOTHING", username, string(hash))
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (a *API) RunSummary(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		op, cancel := context.WithTimeout(ctx, 8*time.Second)
		l, e := a.Store.Acquire(op, "dashboard", a.Config.Central.Instance)
		if e == nil {
			var previous dashboardSnapshot
			var cached []byte
			if err := a.Store.DB.QueryRowContext(op, "SELECT payload FROM v3_dashboard WHERE id=1").Scan(&cached); err == nil {
				_ = json.Unmarshal(cached, &previous)
			}
			snapshot, err := a.Store.dashboardSnapshot(op, previous, a.Config.Collector.IntervalSeconds)
			raw, marshalErr := json.Marshal(snapshot)
			if marshalErr != nil {
				err = marshalErr
			}
			if err == nil {
				tx, err := a.Store.DB.BeginTx(op, nil)
				if err == nil {
					if a.Store.Fence(op, tx, l) == nil {
						_, err = tx.ExecContext(op, "INSERT INTO v3_dashboard VALUES(1,$1,clock_timestamp(),'') ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at,error=''", []byte(raw))
						if err == nil {
							_ = tx.Commit()
						}
					}
					_ = tx.Rollback()
				}
			}
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
