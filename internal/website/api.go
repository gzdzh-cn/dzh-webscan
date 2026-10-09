package website

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"webscan/internal/common"

	"golang.org/x/crypto/bcrypt"
)

func respond(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, code int, key, message, field string) {
	respond(w, code, common.Map{"code": key, "message": message, "field": field})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		apiError(w, 400, "invalid_json", "请求内容格式不正确，请检查填写的参数", "请求内容")
		return false
	}
	return true
}
func tokenHash(token string) string {
	x := sha256.Sum256([]byte(token))
	return hex.EncodeToString(x[:])
}
func (m *Monitor) Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") || (r.TLS != nil && u.Scheme != "https") {
				apiError(w, 403, "origin_rejected", "请求来源不正确，请从管理后台操作", "Origin")
				return
			}
		}
		if r.URL.Path == "/api/login" {
			m.login(w, r)
			return
		}
		cookie, e := r.Cookie("webscan_session")
		if e != nil {
			apiError(w, 401, "login_required", "请先登录网站监控后台", "")
			return
		}
		m.mu.Lock()
		sess, ok := m.sessions[tokenHash(cookie.Value)]
		if ok && time.Now().After(sess.Expires) {
			delete(m.sessions, tokenHash(cookie.Value))
			ok = false
		}
		m.mu.Unlock()
		account, accountErr := ReadAccount(m.DB)
		if accountErr != nil {
			m.dbError(w, accountErr)
			return
		}
		if !ok || sess.Revision != account.Revision {
			apiError(w, 401, "session_expired", "登录已失效，请重新登录", "")
			return
		}
		if r.Method != "GET" && subtle.ConstantTimeCompare([]byte(sess.CSRF), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
			apiError(w, 403, "csrf_invalid", "页面验证已失效，请刷新后重试", "")
			return
		}
		switch r.URL.Path {
		case "/api/session":
			if r.Method != "GET" {
				apiError(w, 405, "method_not_allowed", "此操作不支持当前请求方法", "")
				return
			}
			respond(w, 200, common.Map{"username": account.Username, "csrf_token": sess.CSRF, "nodes": m.publicNodes()})
			return
		case "/api/logout":
			if r.Method != "POST" {
				apiError(w, 405, "method_not_allowed", "请使用退出登录按钮", "")
				return
			}
			m.mu.Lock()
			delete(m.sessions, tokenHash(cookie.Value))
			m.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "webscan_session", Path: "/", MaxAge: -1, Secure: m.secureCookie(r), HttpOnly: true, SameSite: http.SameSiteStrictMode})
			respond(w, 200, common.Map{"ok": true})
			return
		case "/api/account/password":
			m.changePassword(w, r, sess.Revision)
			return
		case "/api/overview":
			m.overview(w, r)
			return
		case "/api/incidents":
			m.incidents(w, r, 0)
			return
		case "/api/websites":
			if r.Method == "GET" {
				m.list(w, r)
			} else if r.Method == "POST" {
				m.saveSite(w, r, 0)
			} else {
				apiError(w, 405, "method_not_allowed", "请使用查看或添加网站操作", "")
			}
			return
		}
		if r.URL.Path == "/api/backups" || strings.HasPrefix(r.URL.Path, "/api/backups/") {
			m.backups(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/websites/") {
			pieces := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/websites/"), "/")
			id, e := strconv.ParseInt(pieces[0], 10, 64)
			if e != nil || id <= 0 {
				apiError(w, 400, "invalid_id", "网站编号不正确", "id")
				return
			}
			if len(pieces) == 2 && pieces[1] == "incidents" {
				m.incidents(w, r, id)
				return
			}
			if len(pieces) == 2 && pieces[1] == "check" && r.Method == "POST" {
				m.checkNow(w, r, id)
				return
			}
			if len(pieces) == 1 {
				switch r.Method {
				case "GET":
					s, e := scanSite(m.DB.QueryRowContext(r.Context(), "SELECT "+columns+" FROM websites WHERE id=? AND deleted=0", id))
					if e != nil {
						m.dbError(w, e)
					} else {
						respond(w, 200, s)
					}
				case "PUT":
					m.saveSite(w, r, id)
				case "DELETE":
					m.deleteSite(w, r, id)
				default:
					apiError(w, 405, "method_not_allowed", "请求方法不正确", "")
				}
				return
			}
		}
		apiError(w, 404, "api_not_found", "接口不存在", "")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "请求方法不支持", 405)
		return
	}
	static, _ := fs.Sub(UI, "ui")
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" || name == "." {
		name = "index.html"
	}
	if _, e := fs.Stat(static, name); e != nil {
		if strings.HasPrefix(name, "assets/") || strings.Contains(path.Base(name), ".") {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-store")
	} else if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	if name == "index.html" {
		data, err := fs.ReadFile(static, name)
		if err != nil {
			http.Error(w, "页面资源不存在", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method != "HEAD" {
			w.Write(data)
		}
		return
	}
	copy := r.Clone(r.Context())
	copy.URL.Path = "/" + name
	http.FileServer(http.FS(static)).ServeHTTP(w, copy)
}
func (m *Monitor) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiError(w, 405, "method_not_allowed", "请使用登录页面提交账号密码", "")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	account, e := ReadAccount(m.DB)
	if e != nil {
		m.dbError(w, e)
		return
	}
	now := time.Now()
	m.mu.Lock()
	for k, a := range m.attempts {
		if now.After(a.Until) {
			delete(m.attempts, k)
		}
	}
	a := m.attempts[ip]
	if a.Count >= 5 || len(m.attempts) >= 4096 {
		m.mu.Unlock()
		apiError(w, 429, "login_rate_limited", "登录尝试过于频繁，请 5 分钟后重试", "")
		return
	}
	a.Count++
	a.Until = now.Add(5 * time.Minute)
	m.attempts[ip] = a
	// Bound concurrent password verification with the same mutex, avoiding CPU bursts.
	valid := len(input.Password) <= 72 && input.Username == account.Username && bcrypt.CompareHashAndPassword([]byte(account.Hash), []byte(input.Password)) == nil
	if !valid {
		m.mu.Unlock()
		apiError(w, 401, "invalid_credentials", "账号或密码不正确", "账号/密码")
		return
	}
	for k, s := range m.sessions {
		if now.After(s.Expires) {
			delete(m.sessions, k)
		}
	}
	if len(m.sessions) >= 100 {
		m.sessions = map[string]session{}
	}
	token := common.ID() + common.ID()
	csrf := common.ID() + common.ID()
	m.sessions[tokenHash(token)] = session{Revision: account.Revision, CSRF: csrf, Expires: now.Add(12 * time.Hour)}
	delete(m.attempts, ip)
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "webscan_session", Value: token, Path: "/", MaxAge: 43200, Secure: m.secureCookie(r), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	respond(w, 200, common.Map{"username": account.Username, "csrf_token": csrf, "nodes": m.publicNodes()})
}

// A plain HTTP backend may be served through a trusted HTTPS reverse proxy.
// These hints only make the cookie stricter; they never bypass Origin or CSRF.
func (m *Monitor) secureCookie(r *http.Request) bool {
	enabled, exists := m.Config["ssl_enabled"]
	if !exists || common.B(enabled) || r.TLS != nil {
		return true
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err == nil && origin.Scheme == "https" && origin.Host == r.Host {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func (m *Monitor) publicNodes() []common.Map {
	out := []common.Map{}
	for id, v := range m.Nodes {
		n := common.M(v)
		out = append(out, common.Map{"id": id, "name": n["name"]})
	}
	sort.Slice(out, func(i, j int) bool { return common.S(out[i]["id"]) < common.S(out[j]["id"]) })
	return out
}
func (m *Monitor) dbError(w http.ResponseWriter, e error) {
	if e == sql.ErrNoRows {
		apiError(w, 404, "website_not_found", "网站不存在或已删除", "id")
	} else {
		apiError(w, 500, "database_failed", "数据库操作失败，请检查主服务器日志及磁盘空间", "")
	}
}
func page(r *http.Request) (int, int) {
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if p < 1 {
		p = 1
	}
	if size != 20 && size != 50 && size != 100 {
		size = 20
	}
	return min(p, 100000), size
}
func (m *Monitor) list(w http.ResponseWriter, r *http.Request) {
	sites, e := m.sites(r.Context())
	if e != nil {
		m.dbError(w, e)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	node := r.URL.Query().Get("node")
	status := r.URL.Query().Get("status")
	filtered := []Site{}
	for _, s := range sites {
		state := s.State.Status
		if s.Paused {
			state = "paused"
		}
		if (q != "" && !strings.Contains(strings.ToLower(s.Name+" "+s.URL), q)) || (node != "" && node != s.Node) || (status != "" && status != state) {
			continue
		}
		filtered = append(filtered, s)
	}
	p, size := page(r)
	start := min((p-1)*size, len(filtered))
	respond(w, 200, common.Map{"items": filtered[start:min(start+size, len(filtered))], "total": len(filtered), "page": p, "page_size": size})
}
func (m *Monitor) overview(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		apiError(w, 405, "method_not_allowed", "请使用查看概览操作", "")
		return
	}
	sites, e := m.sites(r.Context())
	if e != nil {
		m.dbError(w, e)
		return
	}
	counts := common.Map{"total": len(sites), "normal": 0, "down": 0, "pending": 0, "paused": 0}
	for _, s := range sites {
		key := s.State.Status
		if s.Paused {
			key = "paused"
		}
		counts[key] = common.I(counts[key]) + 1
	}
	counts["scheduler_healthy"] = time.Now().Unix()-m.pulse.Load() < 10
	counts["console_url"] = m.ConsoleURL
	respond(w, 200, counts)
}
func (m *Monitor) saveSite(w http.ResponseWriter, r *http.Request, id int64) {
	var input struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Node    string `json:"node"`
		Keyword string `json:"keyword"`
		Slow    bool   `json:"slow_alert"`
		Paused  bool   `json:"paused"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || utf8.RuneCountInString(input.Name) > 100 {
		apiError(w, 400, "invalid_name", "请填写网站名称，最多 100 个字", "name")
		return
	}
	u, e := normalizeURL(input.URL)
	if e != nil {
		apiError(w, 400, "invalid_url", e.Error(), "url")
		return
	}
	if utf8.RuneCountInString(input.Keyword) > 200 {
		apiError(w, 400, "invalid_keyword", "关键词最多 200 个字", "keyword")
		return
	}
	if input.Node != "" {
		if _, ok := m.Nodes[input.Node]; !ok {
			apiError(w, 400, "invalid_node", "关联服务器不存在，请重新选择", "node")
			return
		}
	}
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	tx, e := m.DB.BeginTx(r.Context(), nil)
	if e != nil {
		m.dbError(w, e)
		return
	}
	defer tx.Rollback()
	var duplicate int
	e = tx.QueryRow("SELECT count(*) FROM websites WHERE url=? AND deleted=0 AND id<>?", u, id).Scan(&duplicate)
	if e != nil {
		m.dbError(w, e)
		return
	}
	if duplicate > 0 {
		apiError(w, 409, "duplicate_url", "这个首页地址已经添加，请编辑已有网站", "url")
		return
	}
	st := State{Status: "pending", Next: time.Now().Unix() + int64(time.Now().UnixNano()%int64(max(1, common.I(m.Config["interval_seconds"]))))}
	if id == 0 {
		var count int
		if e = tx.QueryRow("SELECT count(*) FROM websites WHERE deleted=0").Scan(&count); e != nil {
			m.dbError(w, e)
			return
		}
		if count >= 1000 {
			apiError(w, 400, "site_limit", "当前版本最多管理 1000 个网站，请先删除不再检测的网站", "")
			return
		}
		v, e := tx.Exec("INSERT INTO websites(name,url,node,keyword,slow,paused,state) VALUES(?,?,?,?,?,?,?)", input.Name, u, input.Node, input.Keyword, input.Slow, input.Paused, string(common.JSON(st)))
		if e != nil {
			m.dbError(w, e)
			return
		}
		id, e = v.LastInsertId()
		if e != nil {
			m.dbError(w, e)
			return
		}
	} else {
		old, e := scanSite(tx.QueryRow("SELECT "+columns+" FROM websites WHERE id=? AND deleted=0", id))
		if e != nil {
			m.dbError(w, e)
			return
		}
		st = old.State
		if old.URL != u || old.Keyword != input.Keyword || input.Paused {
			_, e = tx.Exec("UPDATE website_incidents SET ended=? WHERE site=? AND ended IS NULL", time.Now().Unix(), id)
			if e != nil {
				m.dbError(w, e)
				return
			}
			st = State{Status: "pending", Next: time.Now().Unix()}
			if input.Paused && old.URL == u && old.Keyword == input.Keyword {
				st.Last = old.State.Last
				st.Checks = old.State.Checks
				st.Passed = old.State.Passed
			}
		}
		if old.Slow && !input.Slow {
			if st.SlowIncident != 0 {
				_, e = tx.Exec("UPDATE website_incidents SET ended=? WHERE id=?", time.Now().Unix(), st.SlowIncident)
				if e != nil {
					m.dbError(w, e)
					return
				}
			}
			st.SlowIncident = 0
			st.SlowSince = 0
			st.Fast = 0
		}
		_, e = tx.Exec("UPDATE websites SET name=?,url=?,node=?,keyword=?,slow=?,paused=?,version=version+1,state=? WHERE id=?", input.Name, u, input.Node, input.Keyword, input.Slow, input.Paused, string(common.JSON(st)), id)
		if e != nil {
			m.dbError(w, e)
			return
		}
	}
	if e = tx.Commit(); e != nil {
		m.dbError(w, e)
		return
	}
	m.cancel(id)
	respond(w, 200, common.Map{"id": id, "message": "网站设置已保存，将自动按计划检查"})
}
func (m *Monitor) deleteSite(w http.ResponseWriter, r *http.Request, id int64) {
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	tx, e := m.DB.BeginTx(r.Context(), nil)
	if e != nil {
		m.dbError(w, e)
		return
	}
	defer tx.Rollback()
	v, e := tx.Exec("UPDATE websites SET deleted=1,version=version+1 WHERE id=? AND deleted=0", id)
	if e != nil {
		m.dbError(w, e)
		return
	}
	n, _ := v.RowsAffected()
	if n == 0 {
		m.dbError(w, sql.ErrNoRows)
		return
	}
	_, e = tx.Exec("UPDATE website_incidents SET ended=? WHERE site=? AND ended IS NULL", time.Now().Unix(), id)
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		m.dbError(w, e)
		return
	}
	m.cancel(id)
	respond(w, 200, common.Map{"ok": true})
}
func (m *Monitor) checkNow(w http.ResponseWriter, r *http.Request, id int64) {
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	s, e := scanSite(m.DB.QueryRowContext(r.Context(), "SELECT "+columns+" FROM websites WHERE id=? AND deleted=0", id))
	if e != nil {
		m.dbError(w, e)
		return
	}
	if s.Paused {
		apiError(w, 409, "website_paused", "网站已暂停，请先恢复检测", "")
		return
	}
	s.State.Next = time.Now().Unix()
	_, e = m.DB.ExecContext(r.Context(), "UPDATE websites SET state=? WHERE id=?", string(common.JSON(s.State)), id)
	if e != nil {
		m.dbError(w, e)
		return
	}
	respond(w, 202, common.Map{"message": "检查请求已加入调度，页面将自动刷新结果"})
}
func (m *Monitor) incidents(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != "GET" {
		apiError(w, 405, "method_not_allowed", "请使用查看故障历史操作", "")
		return
	}
	p, size := page(r)
	condition := ""
	args := []any{}
	if id > 0 {
		condition = " WHERE i.site=?"
		args = append(args, id)
	}
	var count int
	if e := m.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM website_incidents i"+condition, args...).Scan(&count); e != nil {
		m.dbError(w, e)
		return
	}
	args = append(args, size, (p-1)*size)
	rows, e := m.DB.QueryContext(r.Context(), "SELECT i.id,i.site,w.name,w.url,i.kind,i.started,i.ended,i.reason FROM website_incidents i JOIN websites w ON w.id=i.site"+condition+" ORDER BY i.id DESC LIMIT ? OFFSET ?", args...)
	if e != nil {
		m.dbError(w, e)
		return
	}
	defer rows.Close()
	items := []common.Map{}
	for rows.Next() {
		var iid, site, started int64
		var name, u, kind, reason string
		var ended sql.NullInt64
		if e = rows.Scan(&iid, &site, &name, &u, &kind, &started, &ended, &reason); e != nil {
			m.dbError(w, e)
			return
		}
		items = append(items, common.Map{"id": iid, "site_id": site, "name": name, "url": u, "kind": kind, "started": started, "ended": ended.Int64, "reason": reason})
	}
	if e = rows.Err(); e != nil {
		m.dbError(w, e)
		return
	}
	respond(w, 200, common.Map{"items": items, "total": count})
}
