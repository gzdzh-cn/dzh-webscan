package management

import (
	"context"
	"gopkg.in/yaml.v3"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"webscan/internal/common"
)

func TestRemovalStagesPreserveConfigurationOnFailureAndContinueOnce(t *testing.T) {
	s := managerFixture(t)
	raw, _ := os.ReadFile(s.ConfigPath)
	var values common.Map
	yaml.Unmarshal(raw, &values)
	root := filepath.Join(t.TempDir(), "runtime")
	common.M(values["central"])["managed_runtime_dir"] = root
	b, _ := yaml.Marshal(values)
	common.Atomic(s.ConfigPath, b, 0600)
	os.MkdirAll(root, 0700)
	calls := []string{}
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer isolated" {
			w.WriteHeader(401)
			return
		}
		reply(w, 200, common.Map{"websites": []any{common.Map{"name": "fixture", "url": "https://example.com"}}})
	}))
	defer center.Close()
	_, port, _ := net.SplitHostPort(center.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	common.AtomicJSON(filepath.Join(root, "runtime.json"), common.Map{"port": p, "alert_token": "isolated"})
	fail := true
	s.execute = func(_ context.Context, _ string, kind, node string) error {
		calls = append(calls, node)
		if fail {
			return userError("隔离 SSH 故障")
		}
		return nil
	}
	nodes := common.A(values["nodes"])
	ids := []string{}
	for _, v := range nodes {
		ids = append(ids, common.S(common.M(v)["id"]))
	}
	before := revision(t, s)
	code, preview := request(t, s, "POST", "/nodes/remove/preview", common.Map{"ids": ids, "revision": before})
	if code != 200 {
		t.Fatal(code, preview)
	}
	code, start := request(t, s, "POST", "/nodes/remove", common.Map{"ids": ids, "revision": before, "token": preview["token"], "confirm": true, "request_key": "remove-test"})
	if code != 202 {
		t.Fatal(code, start)
	}
	id := common.S(start["id"])
	wait := func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()
			if !running {
				return
			}
			time.Sleep(time.Millisecond * 10)
		}
		t.Fatal("task timeout")
	}
	wait()
	if revision(t, s) != before || len(calls) != 1 {
		t.Fatal("failed uninstall mutated config or continued batch")
	}
	fail = false
	code, _ = request(t, s, "POST", "/nodes/remove/continue", common.Map{"job": id})
	if code != 202 {
		t.Fatal(code)
	}
	wait()
	if len(calls) != len(ids)+1 {
		t.Fatal("repeated completed node", calls)
	}
	after, _ := os.ReadFile(s.ConfigPath)
	yaml.Unmarshal(after, &values)
	if len(common.A(values["nodes"])) != 0 || len(common.SS(common.M(values["deployment"])["node_order"])) != 0 {
		t.Fatal("node order/config not removed")
	}
	var complete bool
	s.DB.QueryRow("SELECT complete FROM node_removals WHERE job=?", id).Scan(&complete)
	if !complete {
		t.Fatal("not complete")
	}
	code, replay := request(t, s, "POST", "/nodes/remove", common.Map{"ids": ids, "revision": before, "token": preview["token"], "confirm": true, "request_key": "remove-test"})
	if code != 200 || common.S(replay["id"]) != id {
		t.Fatal("idempotence")
	}
}

func TestRemovalRejectsUnappliedHostChange(t *testing.T) {
	s := managerFixture(t)
	raw, _ := os.ReadFile(s.ConfigPath)
	var values common.Map
	yaml.Unmarshal(raw, &values)
	node := common.M(common.A(values["nodes"])[0])
	id := common.S(node["id"])
	oldHost := node["host"]
	node["host"] = "198.51.100.99"
	root := filepath.Join(t.TempDir(), "runtime")
	common.M(values["central"])["managed_runtime_dir"] = root
	b, _ := yaml.Marshal(values)
	common.Atomic(s.ConfigPath, b, 0600)
	os.MkdirAll(root, 0700)
	common.AtomicJSON(filepath.Join(root, "runtime.json"), common.Map{"nodes": common.Map{id: common.Map{"host": oldHost}}, "monitoring": common.Map{"mode": "native"}})
	if _, e := s.centerNodeRequest(context.Background(), id, false); e == nil {
		t.Fatal("unapplied host allowed removal")
	}
}
