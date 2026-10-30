package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeploymentAPIAuthLogCursorAndNoSecretDisclosure(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	j := createDeployment(t, s, in, "one")
	if err := s.Provision(ctx, "admin", "isolated-password-123"); err != nil {
		t.Fatal(err)
	}
	api := &API{Store: s}
	api.Config.Central.PublicURL = "https://monitor.example.test"
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("GET", "/api/v3/deployments", nil))
	if w.Code != 401 {
		t.Fatal("anonymous history", w.Code)
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("POST", "/api/v3/login", strings.NewReader(`{"username":"admin","password":"isolated-password-123"}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var login map[string]string
	json.Unmarshal(w.Body.Bytes(), &login)
	call := func(method, path string, csrf bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://monitor.example.test"+path, nil)
		r.AddCookie(cookie)
		r.Header.Set("Idempotency-Key", "api-test-request")
		if csrf {
			r.Header.Set("X-CSRF-Token", login["csrf"])
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/v3/deployments", "/api/v3/deployments/" + j.ID, "/api/v3/deployments/" + j.ID + "/logs?after=0&limit=1"} {
		w = call("GET", path, false)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
		for _, secret := range []string{in.Credential, "192.0.2.1", credentialFixture().Password, "lease_owner", "plan\"", "epoch"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("private value exposed", secret)
			}
		}
	}
	w = call("GET", "/api/v3/deployments/"+j.ID+"/logs?after=1", false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"items":[]`) || !strings.Contains(w.Body.String(), `"next_cursor":1`) {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/v3/deployments?cursor=bad", "/api/v3/deployments/" + j.ID + "/logs?after=-1", "/api/v3/deployments/" + j.ID + "/logs?limit=201"} {
		if w = call("GET", path, false); w.Code != 400 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	if w = call("GET", "/api/v3/deployments/missing", false); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w = call("POST", "/api/v3/deployments", false); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	if w = call("POST", "/api/v3/deployments", true); w.Code != 503 || !strings.Contains(w.Body.String(), "executor_unavailable") {
		t.Fatal("unavailable executor accepted action", w.Code, w.Body.String())
	}
	if tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("phantom task created")
	}
	if _, err := s.DB.Exec("UPDATE v3_accounts SET role='viewer'"); err != nil {
		t.Fatal(err)
	}
	if w = call("POST", "/api/v3/deployments", true); w.Code != 403 {
		t.Fatal("viewer write", w.Code)
	}
	if w = call("GET", "/api/v3/deployments", false); w.Code != 200 {
		t.Fatal("viewer read", w.Code)
	}
}
