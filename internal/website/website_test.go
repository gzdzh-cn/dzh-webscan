package website

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func testMonitor(t *testing.T) *Monitor {
	t.Helper()
	db, e := persist.OpenDB(filepath.Join(t.TempDir(), "test.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	_, e = db.Exec(`CREATE TABLE tasks(id INTEGER PRIMARY KEY,node TEXT,event_id TEXT,target TEXT,payload TEXT,created REAL,next_try REAL,priority INTEGER DEFAULT 0,done REAL,UNIQUE(node,event_id,target));`)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	m, e := New(db, common.Map{"admin_username": "admin", "password_hash": string(hash), "interval_seconds": 60, "timeout_seconds": 1, "max_concurrent": 128}, common.Map{"node": common.Map{"name": "测试节点", "host": "203.0.113.1"}}, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func insertSite(t *testing.T, m *Monitor, name string) Site {
	t.Helper()
	v, e := m.DB.Exec("INSERT INTO websites(name,url,node) VALUES(?,?,'node')", name, "https://"+name+".example.com/")
	if e != nil {
		t.Fatal(e)
	}
	id, _ := v.LastInsertId()
	s, e := scanSite(m.DB.QueryRow("SELECT "+columns+" FROM websites WHERE id=?", id))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func runResult(t *testing.T, m *Monitor, s Site, ok bool, stamp int64) {
	t.Helper()
	if e := m.apply(context.Background(), s, Result{Time: stamp, OK: ok, HTTP: 503, Reason: "检查失败", Latency: .1}); e != nil {
		t.Fatal(e)
	}
}
func stateFor(t *testing.T, m *Monitor, id int64) State {
	t.Helper()
	s, e := scanSite(m.DB.QueryRow("SELECT "+columns+" FROM websites WHERE id=?", id))
	if e != nil {
		t.Fatal(e)
	}
	return s.State
}
func TestStateRestartAndOrderedDurableOutbox(t *testing.T) {
	m := testMonitor(t)
	s := insertSite(t, m, "中文测试")
	now := time.Now().Unix() - 60
	runResult(t, m, s, false, now)
	runResult(t, m, s, false, now+1)
	if stateFor(t, m, s.ID).Status == "down" {
		t.Fatal("early outage")
	}
	reopened, e := New(m.DB, m.Config, m.Nodes, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	m = reopened
	runResult(t, m, s, false, now+2)
	if stateFor(t, m, s.ID).Status != "down" {
		t.Fatal("lost failure streak")
	}
	runResult(t, m, s, true, now+3)
	if stateFor(t, m, s.ID).Status != "down" {
		t.Fatal("early recovery")
	}
	runResult(t, m, s, true, now+4)
	if stateFor(t, m, s.ID).Status != "normal" {
		t.Fatal("no recovery")
	}
	if e = m.flush(context.Background(), now+80); e != nil {
		t.Fatal(e)
	}
	var count int
	m.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&count)
	if count != 2 {
		t.Fatal("outbox lost", count)
	}
	var duration int
	m.DB.QueryRow("SELECT ended-started FROM website_incidents").Scan(&duration)
	if duration != 2 {
		t.Fatal(duration)
	}
	runResult(t, m, s, false, now+90)
	runResult(t, m, s, false, now+91)
	runResult(t, m, s, false, now+92)
	if e = m.flush(context.Background(), now+120); e != nil {
		t.Fatal(e)
	}
	m.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&count)
	if count != 3 {
		t.Fatal("reused outbox id suppressed new incident", count)
	}
}
func TestSummaryAndStaleResult(t *testing.T) {
	m := testMonitor(t)
	now := time.Now().Unix() - 60
	for i := 0; i < 8; i++ {
		s := insertSite(t, m, fmt.Sprint(i))
		for n := 0; n < 3; n++ {
			runResult(t, m, s, false, now+int64(n))
		}
	}
	if e := m.flush(context.Background(), now+30); e != nil {
		t.Fatal(e)
	}
	var payload string
	var count int
	m.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&count)
	m.DB.QueryRow("SELECT payload FROM tasks").Scan(&payload)
	if count != 1 || !strings.Contains(payload, "共 8 个网站") {
		t.Fatal(count, payload)
	}
	s := insertSite(t, m, "stale")
	m.DB.Exec("UPDATE websites SET version=version+1 WHERE id=?", s.ID)
	runResult(t, m, s, true, now)
	if stateFor(t, m, s.ID).Checks != 0 {
		t.Fatal("stale result committed")
	}
}
func TestCertSlowAndReminder(t *testing.T) {
	m := testMonitor(t)
	s := insertSite(t, m, "cert")
	s.Slow = true
	m.DB.Exec("UPDATE websites SET slow=1 WHERE id=?", s.ID)
	now := time.Now().Unix() - 1000
	for _, dt := range []int64{0, 300} {
		if e := m.apply(context.Background(), s, Result{Time: now + dt, OK: true, Latency: 4, CertExpires: now + 86400}); e != nil {
			t.Fatal(e)
		}
	}
	st := stateFor(t, m, s.ID)
	if !st.CertWarn || st.SlowIncident == 0 {
		t.Fatal(st)
	}
	for i := int64(0); i < 2; i++ {
		if e := m.apply(context.Background(), s, Result{Time: now + 360 + i, OK: true, Latency: 1, CertExpires: now + 30*86400}); e != nil {
			t.Fatal(e)
		}
	}
	st = stateFor(t, m, s.ID)
	if st.CertWarn || st.SlowIncident != 0 {
		t.Fatal("no cert/slow recovery", st)
	}
	for i := int64(0); i < 3; i++ {
		runResult(t, m, s, false, now+400+i)
	}
	runResult(t, m, s, false, now+400+4*3600+2)
	var count int
	m.DB.QueryRow("SELECT count(*) FROM website_outbox WHERE kind='outage_reminder'").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
}
func fixtureProber(server *httptest.Server) *prober {
	return &prober{lookup: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}, dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, strings.TrimPrefix(strings.TrimPrefix(server.URL, "http://"), "https://"))
	}}
}
func TestProbeHTTPKeywordGBKRedirectAndLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/503":
			w.WriteHeader(503)
		case "/gbk":
			b, _ := simplifiedchinese.GBK.NewEncoder().Bytes([]byte("公司网站"))
			w.Header().Set("Content-Type", "text/html; charset=gbk")
			w.Write(b)
		case "/private":
			http.Redirect(w, r, "http://127.0.0.1/", 302)
		case "/loop":
			http.Redirect(w, r, "http://example.com/loop", 302)
		case "/huge":
			w.Write([]byte(strings.Repeat("x", 300*1024) + "keyword"))
		default:
			io.WriteString(w, "欢迎访问公司网站")
		}
	}))
	defer server.Close()
	p := fixtureProber(server)
	for _, tt := range []struct {
		path, keyword string
		ok            bool
		reason        string
	}{{"/", "公司", true, ""}, {"/gbk", "公司", true, ""}, {"/503", "", false, "503"}, {"/", "missing", false, "关键词"}, {"/private", "", false, "内网"}, {"/loop", "", false, "跳转"}, {"/huge", "keyword", false, "关键词"}} {
		r := p.check(context.Background(), Site{URL: "http://example.com" + tt.path, Keyword: tt.keyword}, time.Second)
		if r.OK != tt.ok || !strings.Contains(r.Reason, tt.reason) {
			t.Fatal(tt, r)
		}
	}
}
func TestProbeDNSRebindingTLSAndTimeout(t *testing.T) {
	p := newProber()
	p.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("private address dialed")
		return nil, nil
	}
	if r := p.check(context.Background(), Site{URL: "http://example.com/"}, time.Second); r.OK || !strings.Contains(r.Reason, "安全限制") {
		t.Fatal(r)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	p = fixtureProber(server)
	r := p.check(context.Background(), Site{URL: "https://example.com/"}, time.Second)
	if r.OK || !strings.Contains(r.Reason, "证书") {
		t.Fatal(r)
	}
	p.tls = &tls.Config{InsecureSkipVerify: true}
	if r = p.check(context.Background(), Site{URL: "https://example.com/"}, time.Second); !r.OK || r.CertExpires == 0 {
		t.Fatal(r)
	}
	p = newProber()
	p.lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) { <-ctx.Done(); return nil, ctx.Err() }
	if r = p.check(context.Background(), Site{URL: "http://example.com/"}, 10*time.Millisecond); r.OK || !strings.Contains(r.Reason, "超时") {
		t.Fatal(r)
	}
	for _, u := range []string{"http://169.254.169.254/", "file:///etc/passwd", "https://user:pass@example.com/", "http://[::ffff:127.0.0.1]/"} {
		if _, e := normalizeURL(u); e == nil {
			t.Fatal("unsafe URL", u)
		}
	}
}
func request(m *Monitor, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	m.Handler(w, req)
	return w
}
func TestAPIAuthenticationCRUDCSRFAndRoutes(t *testing.T) {
	m := testMonitor(t)
	w := request(m, "GET", "/api/websites", "", nil, "")
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	w = request(m, "POST", "/api/login", `{"username":"admin","password":"fixture-password"}`, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly {
		t.Fatal("insecure cookie")
	}
	var sess struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &sess)
	w = request(m, "POST", "/api/websites", `{"name":"官网","url":"https://example.com"}`, cookie, "")
	if w.Code != 403 {
		t.Fatal("csrf accepted")
	}
	w = request(m, "POST", "/api/websites", `{"name":"官网","url":"https://example.com"}`, cookie, sess.CSRF)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var value struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &value)
	w = request(m, "POST", "/api/websites", `{"name":"重复","url":"https://EXAMPLE.com/"}`, cookie, sess.CSRF)
	if w.Code != 409 {
		t.Fatal("duplicate accepted", w.Body.String())
	}
	w = request(m, "GET", "/api/websites?q=官网&page_size=20", "", cookie, sess.CSRF)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "官网") {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), "fixture-password") {
		t.Fatal("secret leaked")
	}
	id := fmt.Sprint(value.ID)
	w = request(m, "PUT", "/api/websites/"+id, `{"name":"官网","url":"https://example.com","paused":true}`, cookie, sess.CSRF)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(m, "POST", "/api/websites/"+id+"/check", "", cookie, sess.CSRF)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	w = request(m, "DELETE", "/api/websites/"+id, "", cookie, sess.CSRF)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(m, "GET", "/websites/1", "", nil, "")
	if w.Code != 200 {
		t.Fatal("SPA route refresh", w.Code)
	}
	w = request(m, "GET", "/api/missing", "", cookie, sess.CSRF)
	if w.Code != 404 || strings.Contains(w.Body.String(), "<html") {
		t.Fatal("API SPA fallback")
	}
	w = request(m, "POST", "/api/logout", "", cookie, sess.CSRF)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = request(m, "GET", "/api/session", "", cookie, sess.CSRF)
	if w.Code != 401 {
		t.Fatal("logout did not revoke")
	}
}
func TestLoginThrottle(t *testing.T) {
	m := testMonitor(t)
	for i := 0; i < 6; i++ {
		w := request(m, "POST", "/api/login", `{"username":"admin","password":"wrong"}`, nil, "")
		if i == 5 && w.Code != 429 {
			t.Fatal(w.Code)
		}
	}
}
func TestThousandTimeoutsBoundConcurrencyAndMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("capacity")
	}
	m := testMonitor(t)
	m.Config["interval_seconds"] = 60
	timeout := 1
	if value, e := strconv.Atoi(os.Getenv("WEBSCAN_CAPACITY_TIMEOUT")); e == nil && value > 0 {
		timeout = value
	}
	m.Config["timeout_seconds"] = timeout
	tx, _ := m.DB.Begin()
	for i := 0; i < 1000; i++ {
		if _, e := tx.Exec("INSERT INTO websites(name,url,state) VALUES(?,?,'{}')", fmt.Sprint(i), fmt.Sprintf("http://site%d.example.com/", i)); e != nil {
			t.Fatal(e)
		}
	}
	tx.Commit()
	var active, peak, calls atomic.Int64
	m.probe.lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	started := time.Now()
	deadline := time.Now().Add(time.Duration(20+timeout*10) * time.Second)
	for time.Now().Before(deadline) {
		var n int
		m.DB.QueryRow("SELECT count(*) FROM websites WHERE json_extract(state,'$.checks')>=1").Scan(&n)
		if n == 1000 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	var checked int
	m.DB.QueryRow("SELECT count(*) FROM websites WHERE json_extract(state,'$.checks')>=1").Scan(&checked)
	runtime.ReadMemStats(&after)
	t.Logf("1000 timeout targets: checked=%d calls=%d peak=%d heap_growth=%d KiB elapsed=%.2fs timeout=%ds", checked, calls.Load(), peak.Load(), int64(after.HeapAlloc-before.HeapAlloc)/1024, time.Since(started).Seconds(), timeout)
	if checked != 1000 || calls.Load() != 1000 || peak.Load() > 128 {
		t.Fatal("capacity bound", checked, peak.Load())
	}
	if after.HeapAlloc > before.HeapAlloc+128*1024*1024 {
		t.Fatal("memory grew beyond budget")
	}
}

func TestAdditiveSchemaAndConsistentBackup(t *testing.T) {
	m := testMonitor(t)
	s := insertSite(t, m, "backup")
	for i := int64(0); i < 3; i++ {
		runResult(t, m, s, false, time.Now().Unix()-30+i)
	}
	backup := filepath.Join(t.TempDir(), "consistent.sqlite3")
	if e := persist.BackupDB(m.DB, backup); e != nil {
		t.Fatal(e)
	}
	db, e := persist.OpenDB(backup)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var count int
	if e = db.QueryRow("SELECT count(*) FROM website_incidents").Scan(&count); e != nil || count != 1 {
		t.Fatal(e, count)
	}
	if e = db.QueryRow("SELECT count(*) FROM website_outbox").Scan(&count); e != nil || count != 1 {
		t.Fatal("lost pending message", e, count)
	}
	if _, e = db.Exec("INSERT INTO tasks(node,event_id,target,payload) VALUES('legacy','compatible','loki','{}')"); e != nil {
		t.Fatal("legacy table not compatible", e)
	}
}

func TestFifteenSecondGroupingDoesNotOvertakeRelatedOutage(t *testing.T) {
	m := testMonitor(t)
	now := time.Now().Unix() - 20
	for i := 0; i < 8; i++ {
		m.DB.Exec("INSERT INTO website_outbox(site,node,kind,message,created) VALUES(?, 'node','outage',?,?)", i, fmt.Sprintf("fault-%d", i), now+int64(i))
	}
	if e := m.flush(context.Background(), now+15); e != nil {
		t.Fatal(e)
	}
	var count int
	m.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&count)
	if count != 1 {
		t.Fatal("window did not collect later messages", count)
	}
	now += 40
	for _, row := range []struct{ kind, node, message string }{{"outage", "a", "fault-one"}, {"recovery", "b", "recovery-one"}, {"outage", "b", "fault-two"}, {"recovery", "b", "recovery-two"}} {
		if _, e := m.DB.Exec("INSERT INTO website_outbox(site,node,kind,message,created) VALUES(1,?,?,?,?)", row.node, row.kind, row.message, now); e != nil {
			t.Fatal(e)
		}
	}
	if e := m.flush(context.Background(), now+15); e != nil {
		t.Fatal(e)
	}
	rows, e := m.DB.Query("SELECT payload FROM tasks ORDER BY id")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	messages := []string{}
	for rows.Next() {
		var raw string
		rows.Scan(&raw)
		messages = append(messages, raw)
	}
	if len(messages) != 5 || !strings.Contains(messages[3], "fault-two") || !strings.Contains(messages[4], "recovery-two") {
		t.Fatal("matching recovery overtook outage", messages)
	}
}

func TestListPaginationFiltersAndExpiredSession(t *testing.T) {
	m := testMonitor(t)
	for i := 0; i < 25; i++ {
		s := insertSite(t, m, fmt.Sprintf("site%d", i))
		if i < 5 {
			m.DB.Exec("UPDATE websites SET paused=1 WHERE id=?", s.ID)
		}
	}
	token := "fixture-cookie"
	m.sessions[tokenHash(token)] = session{Revision: 1, CSRF: "fixture", Expires: time.Now().Add(time.Hour)}
	cookie := &http.Cookie{Name: "webscan_session", Value: token}
	for _, tt := range []struct {
		path        string
		size, total int
	}{{"/api/websites?page=2&page_size=20", 5, 25}, {"/api/websites?status=paused", 5, 5}, {"/api/websites?node=node", 20, 25}, {"/api/websites?q=site24", 1, 1}} {
		w := request(m, "GET", tt.path, "", cookie, "")
		var data struct {
			Items []Site `json:"items"`
			Total int    `json:"total"`
		}
		if json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data.Items) != tt.size || data.Total != tt.total {
			t.Fatal(tt, w.Body.String())
		}
	}
	m.sessions[tokenHash(token)] = session{Revision: 1, Expires: time.Now().Add(-time.Second)}
	if w := request(m, "GET", "/api/session", "", cookie, ""); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
}

func TestFailedCheckBreaksContinuousSlowWindow(t *testing.T) {
	m := testMonitor(t)
	s := insertSite(t, m, "interrupted-slow")
	s.Slow = true
	m.DB.Exec("UPDATE websites SET slow=1 WHERE id=?", s.ID)
	now := time.Now().Unix()
	for _, r := range []Result{{Time: now, OK: true, Latency: 4}, {Time: now + 299, OK: false, Reason: "超时"}, {Time: now + 301, OK: true, Latency: 4}} {
		if e := m.apply(context.Background(), s, r); e != nil {
			t.Fatal(e)
		}
	}
	if stateFor(t, m, s.ID).SlowIncident != 0 {
		t.Fatal("interrupted slow response reported as continuous")
	}
}
