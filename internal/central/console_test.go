package central

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/telemetry"
	"webscan/internal/website"
)

func TestServerListIncludesConfiguredNodesAfterRollback(t *testing.T) {
	s := consoleFixture(t)
	dir, err := os.MkdirTemp("/tmp", "webscan-list-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "manager.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/settings" {
			t.Errorf("unexpected management request %s %s", r.Method, r.URL.Path)
		}
		write(w, 200, common.Map{"effective_nodes": []any{
			common.Map{"id": "node", "name": "子服务器", "enabled": true},
			common.Map{"id": "rolled-back", "name": "回退节点", "host": "192.0.2.5", "enabled": true, "deployment": common.Map{"mode": "docker"}, "ssh": common.Map{"password": "do-not-expose"}},
			common.Map{"id": "new-node", "name": "待部署节点", "enabled": true},
			common.Map{"id": "disabled-node", "name": "停用节点", "enabled": false},
		}, "node_deployments": common.Map{"rolled-back": common.Map{"phase": "go-rolled-back"}}})
	}))
	server.Listener.Close()
	server.Listener = l
	server.Start()
	t.Cleanup(server.Close)
	s.Config["management_socket"] = socket
	list := consoleGET(t, s, "/api/servers")
	if common.I(list["total"]) != 5 || strings.Contains(string(common.JSON(list)), "do-not-expose") {
		t.Fatal(list)
	}
	rows := map[string]common.Map{}
	for _, row := range common.A(list["items"]) {
		n := common.M(row)
		rows[common.S(n["id"])] = n
	}
	if common.S(rows["rolled-back"]["deployment_state"]) != "go-rolled-back" || common.S(rows["rolled-back"]["status"]) != "unknown" || common.S(rows["new-node"]["deployment_state"]) != "pending" || common.S(rows["disabled-node"]["status"]) != "disabled" {
		t.Fatal(list)
	}
	if common.S(consoleGET(t, s, "/api/servers/rolled-back")["id"]) != "rolled-back" {
		t.Fatal("configured detail unavailable")
	}
	if common.I(consoleGET(t, s, "/api/servers?q=回退&status=unknown")["total"]) != 1 {
		t.Fatal("filter failed")
	}
	nodes, err := s.Telemetry.Nodes(context.Background())
	if err != nil || len(nodes) != 2 {
		t.Fatal("listing changed collection targets", nodes, err)
	}
	server.Close()
	if common.I(consoleGET(t, s, "/api/servers")["total"]) != 2 {
		t.Fatal("manager outage hid running nodes")
	}
}

func consoleFixture(t *testing.T) *Store {
	s := testStore(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	var e error
	s.Websites, e = website.New(s.DB, common.Map{"password_hash": string(hash), "admin_username": "admin"}, nil, &s.mu, false)
	if e != nil {
		t.Fatal(e)
	}
	s.Config["monitoring"] = common.Map{"mode": "native", "history_days": 15, "raw_hours": 48}
	s.Telemetry, e = telemetry.Open(common.S(s.Config["data_dir"]), []telemetry.Node{{ID: "central", Name: "主服务器", Active: true, Central: true}, {ID: "node", Name: "子服务器", Active: true}}, common.M(s.Config["monitoring"]))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Telemetry.DB.Close() })
	s.Websites.Extra = s.Console
	return s
}
func consoleGET(t *testing.T, s *Store, url string) common.Map {
	t.Helper()
	w := httptest.NewRecorder()
	s.Console(w, httptest.NewRequest("GET", url, nil))
	if w.Code != 200 {
		t.Fatal(url, w.Code, w.Body.String())
	}
	v, e := common.Decode(w.Body.Bytes())
	if e != nil {
		t.Fatal(e)
	}
	return common.M(v)
}
func TestNativePersistenceAcceptanceAndNoLoki(t *testing.T) {
	s := consoleFixture(t)
	ctx := context.Background()
	e := fixture()
	s.Ingest(ctx, "node", []any{e})
	var loki int
	s.DB.QueryRow("SELECT count(*) FROM tasks WHERE target='loki'").Scan(&loki)
	if loki != 0 {
		t.Fatal(loki)
	}
	done, err := s.deliveryDone(ctx, "node", common.S(e["event_id"]), "loki")
	if err != nil || !done {
		t.Fatal(done, err)
	}
	if got := consoleGET(t, s, "/api/events"); common.I(got["total"]) != 1 {
		t.Fatal(got)
	}
	raw := string(common.JSON(e))
	s.DB.Exec("INSERT INTO migrated_logs VALUES(?,?,?,?,?)", "imported-duplicate", "node", "modify", common.Now(), raw)
	if got := consoleGET(t, s, "/api/events"); common.I(got["total"]) != 1 {
		t.Fatal("migration duplicated event", got)
	}
}
func TestAlertsPagingFilterAndRecoveryMetadata(t *testing.T) {
	s := consoleFixture(t)
	now := time.Now().Unix()
	for i := 0; i < 1100; i++ {
		id := fmt.Sprint(i)
		s.Telemetry.DB.Exec("INSERT INTO health_events VALUES(?,?,?,?,?,?,?)", id, "node", "cpu", "resolved", now+int64(i), "已恢复", `{"phase":"normal","since":1}`)
	}
	got := consoleGET(t, s, "/api/alerts?history=true&node=node&page=55&page_size=20")
	if common.I(got["total"]) != 1100 || len(common.A(got["items"])) != 20 {
		t.Fatal(got)
	}
	item := common.M(common.A(got["items"])[0])
	if item["phase"] != "resolved" || common.F(item["time"]) == 0 {
		t.Fatal(item)
	}
	s.DB.Exec("INSERT INTO websites(id,name,url,node) VALUES(1,'官网','https://example.com/','node')")
	s.DB.Exec("INSERT INTO website_incidents VALUES(1,1,'availability',?,NULL,'timeout')", now)
	got = consoleGET(t, s, "/api/alerts?node=node&source=website")
	if common.I(got["total"]) != 1 {
		t.Fatal(got)
	}
	s.DB.Exec("UPDATE websites SET paused=1 WHERE id=1")
	got = consoleGET(t, s, "/api/alerts?node=node&source=website")
	if common.I(got["total"]) != 0 {
		t.Fatal("paused site is still current incident", got)
	}
}
func TestConsoleRequiresLoginAndCSRF(t *testing.T) {
	s := consoleFixture(t)
	for _, path := range []string{"/api/events", "/api/settings", "/api/notifications/stats", "/api/servers"} {
		w := httptest.NewRecorder()
		s.Websites.Handler(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatal(path, w.Code)
		}
	}
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"fixture-password"}`))
	w := httptest.NewRecorder()
	s.Websites.Handler(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie")
	}
	req = httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{}`))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w = httptest.NewRecorder()
	s.Websites.Handler(w, req)
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code, w.Body.String())
	}
	got := consoleGET(t, s, "/api/notifications/stats")
	if got["items"] == nil {
		t.Fatal(got)
	}
}

func TestEventsExcludeProbesBeforeCountAndPagination(t *testing.T) {
	s := consoleFixture(t)
	for _, op := range []string{"probe", "health", "modify"} {
		e := fixture()
		e["event_id"] = op
		e["operation"] = op
		if _, err := s.Ingest(context.Background(), "node", []any{e}); err != nil {
			t.Fatal(err)
		}
	}
	s.DB.Exec("INSERT INTO migrated_logs VALUES('old-probe','node','probe',?,?)", common.Now(), `{"operation":"probe","event_id":"another-probe"}`)
	if got := consoleGET(t, s, "/api/events?page_size=1"); common.I(got["total"]) != 2 || len(common.A(got["items"])) != 1 {
		t.Fatal(got)
	}
	if got := consoleGET(t, s, "/api/events?include_probes=true"); common.I(got["total"]) != 4 {
		t.Fatal(got)
	}
	w := httptest.NewRecorder()
	s.Console(w, httptest.NewRequest("GET", "/api/events?operation=probe", nil))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
func TestDashboardHasThirteenComponentsAndPausedSites(t *testing.T) {
	s := consoleFixture(t)
	s.Config["email"] = common.Map{"enabled": false}
	s.DB.Exec(`INSERT INTO websites(name,url,paused,state) VALUES('paused','https://example.com',1,'{"status":"down"}')`)
	got := consoleGET(t, s, "/api/dashboard")
	cards := common.A(got["components"])
	if len(cards) != 13 || common.I(got["website_paused"]) != 1 || common.I(got["website_down"]) != 0 {
		t.Fatal(got)
	}
	for _, value := range cards {
		c := common.M(value)
		if c["id"] == "email" && c["status"] != "disabled" {
			t.Fatal(c)
		}
	}
	raw := string(common.JSON(got))
	if strings.Contains(raw, "fixture-token") {
		t.Fatal("token exposed")
	}
}
func TestRetentionAPIRequiresSessionCSRFAndConfirmation(t *testing.T) {
	s := consoleFixture(t)
	request := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		s.Websites.Handler(w, r)
		return w
	}
	if w := request("GET", "/api/retention/status", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	login := request("POST", "/api/login", `{"username":"admin","password":"fixture-password"}`, "", nil)
	v, _ := common.Decode(login.Body.Bytes())
	csrf := common.S(common.M(v)["csrf_token"])
	cookies := login.Result().Cookies()
	if login.Code != 200 || len(cookies) == 0 {
		t.Fatal(login.Code, login.Body.String())
	}
	if w := request("POST", "/api/retention/preview", `{"category":"events","before":1}`, "", cookies[0]); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("POST", "/api/retention/cleanup", `{"preview":"missing","confirm":false}`, csrf, cookies[0]); w.Code != 400 || !strings.Contains(w.Body.String(), "确认清理") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("GET", "/api/retention/status", "", "", cookies[0]); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}
