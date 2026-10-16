package central

import (
	"crypto/tls"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"webscan/internal/common"
	"webscan/internal/telemetry"
)

func reloadFixture(t *testing.T) *Store {
	s := testStore(t)
	s.Config["alert_token"] = "manager-token"
	s.Config["runtime_path"] = filepath.Join(t.TempDir(), "runtime.json")
	s.Config["monitoring"] = common.Map{"mode": "native", "nodes": []any{common.Map{"id": "node", "host": "127.0.0.1", "url": "http://127.0.0.1:19100/metrics", "active": true}}}
	s.Config["https"] = common.Map{"port": 0, "sources_auto": true, "allowed_sources": []string{"127.0.0.1/32"}}
	var e error
	s.Telemetry, e = telemetry.Open(t.TempDir(), nil, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Telemetry.DB.Close() })
	return s
}
func reloadRequest(s *Store, path, token string, in common.Map, public bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(string(common.JSON(in))))
	r.Header.Set("Authorization", "Bearer "+token)
	r.RemoteAddr = "127.0.0.1:1234"
	if public {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	s.Handler(w, r)
	return w
}
func addReloadNode(c common.Map) common.Map {
	c = common.Clone(c)
	common.M(c["nodes"])["new"] = common.Map{"host": "192.0.2.2", "name": "新节点", "token": "new-token"}
	c["active_nodes"] = []string{"node", "new"}
	m := common.M(c["monitoring"])
	m["nodes"] = append(common.A(m["nodes"]), common.Map{"id": "new", "host": "192.0.2.2", "url": "http://192.0.2.2:19100/metrics", "active": true})
	common.M(c["https"])["allowed_sources"] = []string{"127.0.0.1/32", "192.0.2.2/32"}
	return c
}
func TestNodeRegistryAuthScopeAndIdempotency(t *testing.T) {
	s := reloadFixture(t)
	old := s.Snapshot()
	next := addReloadNode(old)
	common.AtomicJSON(configPathFrom(old), next)
	input := common.Map{"node": "new", "expected_revision": runtimeRevision(old), "revision": runtimeRevision(next)}
	for _, path := range []string{"/reload-nodes", "/node-capabilities"} {
		for _, token := range []string{"wrong", "fixture-token"} {
			if w := reloadRequest(s, path, token, input, false); w.Code != 401 {
				t.Fatal("non-manager accepted", path, w.Code)
			}
		}
		if w := reloadRequest(s, path, "manager-token", input, true); w.Code != 404 {
			t.Fatal("public interface exposed", w.Code)
		}
	}
	if w := reloadRequest(s, "/reload-nodes", "manager-token", input, false); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := reloadRequest(s, "/reload-nodes", "manager-token", input, false); w.Code != 200 {
		t.Fatal("lost response retry not idempotent", w.Code)
	}
	if common.S(common.M(common.M(s.Snapshot()["nodes"])["new"])["token"]) != "new-token" {
		t.Fatal("registry not published")
	}
	for _, mutate := range []func(common.Map){func(c common.Map) { c["port"] = 9999 }, func(c common.Map) { common.M(common.M(c["nodes"])["node"])["token"] = "stolen" }, func(c common.Map) { common.M(c["https"])["allowed_sources"] = []string{"0.0.0.0/0"} }, func(c common.Map) { common.M(c["monitoring"])["client_key"] = "/tmp/other" }, func(c common.Map) { common.M(common.A(common.M(c["monitoring"])["nodes"])[1])["central"] = true }} {
		old = s.Snapshot()
		bad := common.Clone(old)
		mutate(bad)
		common.AtomicJSON(configPathFrom(old), bad)
		input = common.Map{"node": "new", "expected_revision": runtimeRevision(old), "revision": runtimeRevision(bad)}
		if w := reloadRequest(s, "/reload-nodes", "manager-token", input, false); w.Code != 400 {
			t.Fatal("scope change accepted", w.Code, w.Body.String())
		}
		if runtimeRevision(s.Snapshot()) != runtimeRevision(old) {
			t.Fatal("failed reload changed snapshot")
		}
	}
}
func TestNodeReloadConflictUnavailableAndConcurrentEvents(t *testing.T) {
	s := reloadFixture(t)
	old := s.Snapshot()
	next := addReloadNode(old)
	common.AtomicJSON(configPathFrom(old), next)
	in := common.Map{"node": "new", "expected_revision": "stale", "revision": runtimeRevision(next)}
	if w := reloadRequest(s, "/reload-nodes", "manager-token", in, false); w.Code != 409 {
		t.Fatal(w.Code)
	}
	in["expected_revision"] = runtimeRevision(old)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := reloadRequest(s, "/events", "fixture-token", nil, false)
			if w.Code == 401 {
				t.Error("old identity lost")
			}
		}()
	}
	if w := reloadRequest(s, "/reload-nodes", "manager-token", in, false); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	wg.Wait()
	before := s.Snapshot()
	next = common.Clone(before)
	common.M(common.M(next["nodes"])["new"])["name"] = "变更"
	common.AtomicJSON(configPathFrom(before), next)
	s.Telemetry.DB.Close()
	if w := reloadRequest(s, "/reload-nodes", "manager-token", common.Map{"node": "new", "expected_revision": runtimeRevision(before), "revision": runtimeRevision(next)}, false); w.Code != 503 {
		t.Fatal(w.Code, w.Body.String())
	}
	if runtimeRevision(before) != runtimeRevision(s.Snapshot()) {
		t.Fatal("failed DB apply replaced snapshot")
	}
}
