package controlplane

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"webscan/internal/website"
)

func TestConsoleV3EntryAssetsAndLegacyIsolation(t *testing.T) {
	a := &API{}
	for _, target := range []string{"/", "/login", "/servers", "/servers/node-a", "/events", "/alerts", "/settings", "/settings?tab=storage", "/settings?tab=audit", "/backups", "/backups?tab=deployment", "/config-backups", "/websites", "/websites/1", "/deployments", "/deployments/job-a", "/v3.html"} {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Webscan v3") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(target, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("missing frame policy")
		}
		raw, _ := fs.ReadFile(website.UI, "ui/index.html")
		if w.Body.String() == string(raw) {
			t.Fatal("served v2 entry from v3 API")
		}
		if target == "/" {
			refs := regexp.MustCompile(`(?:src|href)="(/assets/[^"\s]+)"`).FindAllStringSubmatch(w.Body.String(), -1)
			if len(refs) == 0 {
				t.Fatal("no embedded v3 assets")
			}
			for _, ref := range refs {
				asset := httptest.NewRecorder()
				a.ServeHTTP(asset, httptest.NewRequest("GET", ref[1], nil))
				if asset.Code != 200 || !strings.Contains(asset.Header().Get("Cache-Control"), "immutable") {
					t.Fatal("missing asset", ref[1], asset.Code)
				}
			}
		}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("HEAD", "/servers/node-a", nil))
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "" {
		t.Fatal("invalid HEAD")
	}
	for _, target := range []string{"/index.html", "/api/session", "/api/unknown", "/assets/missing.js", "/assets/../v3.html", "/servers/node-a/other", "/unknown", "/websites/0", "/websites/01", "/websites/no-id", "/websites/1/other", "/.git/config"} {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", target, nil))
		if w.Code != 404 {
			t.Fatal(target, w.Code)
		}
	}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("POST", "/servers", nil))
	if w.Code != 405 {
		t.Fatal("static POST accepted")
	}
}

func TestConsoleServerDetailAuthSafeFieldsAndMissingEvidence(t *testing.T) {
	s := testStore(t)
	in := deploymentFixture(t, s)
	job := createDeployment(t, s, in, "detail-fixture")
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET config='{"secret":"private-node-config"}'`)
	if err := s.Provision(context.Background(), "admin", "isolated-password-123"); err != nil {
		t.Fatal(err)
	}
	a := &API{Store: s}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "/api/v3/servers/node-a", nil))
	if w.Code != 401 {
		t.Fatal("anonymous detail", w.Code)
	}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("POST", "/api/v3/login", strings.NewReader(`{"username":"admin","password":"isolated-password-123"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var login map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	call := func(method, target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", login["csrf"])
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	w = call("GET", "/api/v3/servers/node-a")
	var result struct {
		Node   Node            `json:"node"`
		Status json.RawMessage `json:"status"`
		Latest *DeploymentJob  `json:"latest_deployment"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || string(result.Status) != "null" || result.Latest == nil || result.Latest.ID != job.ID {
		t.Fatal("missing evidence fabricated", w.Code, w.Body.String())
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_status(node,sampled_at,metrics,info,error,events_error) VALUES('node-a',1720000000000,'{"cpu_percent":0,"memory_percent":51.2,"secret":"private-metric"}','{"agent_mode":"native","agent_version":"v3.0.0-local-test","secret":"private-info"}','事件采集失败','事件采集失败')`)
	w = call("GET", "/api/v3/servers/node-a")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, secret := range []string{"private-node-config", "private-metric", "private-info", in.Credential, credentialFixture().Password, `"plan":`} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("private field exposed", secret)
		}
	}
	if !strings.Contains(w.Body.String(), `"cpu_percent":0`) || !strings.Contains(w.Body.String(), `"disk_percent":null`) || !strings.Contains(w.Body.String(), "事件采集失败") || !strings.Contains(w.Body.String(), "v3.0.0-local-test") {
		t.Fatal("missing status distinction", w.Body.String())
	}
	for _, target := range []string{"/api/v3/servers/missing", "/api/v3/servers/node-a/other"} {
		if w := call("GET", target); w.Code != 404 {
			t.Fatal(target, w.Code)
		}
	}
	if w := call("POST", "/api/v3/servers/node-a"); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("unexpected detail write", w.Code)
	}
}
