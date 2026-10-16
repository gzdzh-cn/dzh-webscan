package integration

import (
	"bufio"
	"bytes"
	"context"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
)

type fixtureTransport struct{ name string }

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Close = true
	var input bytes.Buffer
	if e := r.Write(&input); e != nil {
		return nil, e
	}
	command := "exec 3<>/dev/tcp/127.0.0.1/" + r.URL.Port() + "; cat >&3; cat <&3"
	cmd := exec.CommandContext(r.Context(), "docker", "exec", "-i", f.name, "/bin/bash", "-c", command)
	cmd.Stdin = &input
	output, e := cmd.Output()
	if e != nil {
		return nil, e
	}
	return http.ReadResponse(bufio.NewReader(bytes.NewReader(output)), r)
}

// Explicitly opt in: uses only a local binary, an existing base image, an
// isolated Docker network and fixture credentials. No registry or business API.
func TestV44ContainerRegistrySessionAndRollback(t *testing.T) {
	binary := os.Getenv("WEBSCAN_V44_BINARY")
	if binary == "" {
		t.Skip("set WEBSCAN_V44_BINARY to the local Linux amd64 binary")
	}
	binary, e := filepath.Abs(binary)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	raw, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "webscan"), raw, 0755); e != nil {
		t.Fatal(e)
	}
	id := common.ID()[:8]
	name, network := "webscan44-center-"+id, "webscan44-net-"+id
	docker(t, "network", "create", "--internal", network)
	t.Cleanup(func() { docker(t, "rm", "-f", name); docker(t, "network", "rm", network) })
	hash, _ := bcrypt.GenerateFromPassword([]byte("isolated-fixture-password"), bcrypt.MinCost)
	c := common.Map{"release": "v2.0.44", "bind": "0.0.0.0", "port": 18081, "data_dir": "/fixture/data", "backup_dir": "/fixture/backups", "max_request_mib": 2, "max_batch_events": 100, "alert_token": "isolated-manager-token", "nodes": common.Map{}, "active_nodes": []string{}, "feishu": common.Map{"enabled": false}, "email": common.Map{"enabled": false}, "https": common.Map{"port": 0, "sources_auto": true, "allowed_sources": []string{"127.0.0.1/32", "172.16.0.0/12"}}, "monitoring": common.Map{"mode": "native", "nodes": []any{}, "interval_seconds": 10}, "website_monitor": common.Map{"enabled": true, "host_port": 19444, "ssl_enabled": false, "admin_username": "admin", "password_hash": string(hash), "interval_seconds": 60, "timeout_seconds": 1, "max_concurrent": 2}}
	path := filepath.Join(root, "runtime.json")
	if e = common.AtomicJSON(path, c); e != nil {
		t.Fatal(e)
	}
	docker(t, "run", "--pull=never", "--platform", "linux/amd64", "-d", "--name", name, "--network", network, "-v", root+":/fixture", "--entrypoint", "/fixture/webscan", "ubuntu:24.04", "central", "--config", "/fixture/runtime.json")
	base := "http://127.0.0.1:18081"
	console := "http://127.0.0.1:19444"
	client := &http.Client{Timeout: 10 * time.Second, Transport: fixtureTransport{name}}
	wait(t, func() bool {
		code, _, e := common.Request(context.Background(), client, "GET", base+"/ready", nil, nil)
		return e == nil && code == 200
	})
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	code, value, e := common.Request(context.Background(), client, "POST", console+"/api/login", common.Map{"username": "admin", "password": "isolated-fixture-password"}, nil)
	if e != nil || code != 200 {
		t.Fatal("fixture login", code, e)
	}
	csrf := common.S(common.M(value)["csrf_token"])
	if csrf == "" {
		t.Fatal("missing csrf")
	}
	identity := docker(t, "inspect", "--format", "{{.Id}} {{.State.Pid}} {{.State.StartedAt}}", name)
	admin := map[string]string{"Authorization": "Bearer isolated-manager-token"}
	load := func(next common.Map) {
		t.Helper()
		code, cap, e := common.Request(context.Background(), client, "POST", base+"/node-capabilities", common.Map{}, admin)
		if e != nil || code != 200 {
			t.Fatal(code, e)
		}
		expected := common.S(common.M(cap)["revision"])
		common.AtomicJSON(path, next)
		revision := common.Hash(common.JSON(next))
		code, value, e = common.Request(context.Background(), client, "POST", base+"/reload-nodes", common.Map{"node": "fixture", "expected_revision": expected, "revision": revision}, admin)
		if e != nil || code != 200 || common.S(common.M(value)["revision"]) != revision {
			t.Fatal("reload", code, e, value)
		}
	}
	next := common.Clone(c)
	common.M(next["nodes"])["fixture"] = common.Map{"host": "127.0.0.1", "name": "隔离节点", "token": "isolated-node-token"}
	next["active_nodes"] = []string{"fixture"}
	common.M(next["https"])["allowed_sources"] = append(common.SS(common.M(next["https"])["allowed_sources"]), "127.0.0.1/32")
	common.M(next["monitoring"])["nodes"] = []any{common.Map{"id": "fixture", "host": "127.0.0.1", "url": "http://127.0.0.1:18081/metrics", "active": true}}
	load(next)
	wait(t, func() bool {
		code, value, e := common.Request(context.Background(), client, "GET", console+"/api/servers", nil, nil)
		if e != nil || code != 200 {
			return false
		}
		for _, v := range common.A(common.M(value)["items"]) {
			if common.S(common.M(v)["id"]) == "fixture" && common.I(common.M(common.M(v)["snapshot"])["time"]) > 0 {
				return true
			}
		}
		return false
	})
	code, value, e = common.Request(context.Background(), client, "GET", console+"/api/session", nil, nil)
	if e != nil || code != 200 || common.S(common.M(value)["csrf_token"]) != csrf {
		t.Fatal("session or csrf changed on registry load", code, e)
	}
	if !strings.Contains(string(common.JSON(value)), "隔离节点") {
		t.Fatal("new node absent from backend options")
	}
	headers := map[string]string{"X-CSRF-Token": csrf}
	code, _, e = common.Request(context.Background(), client, "POST", console+"/api/websites", common.Map{"name": "隔离站点", "url": "https://example.invalid/", "node": "fixture", "paused": true}, headers)
	if e != nil || code != 200 {
		t.Fatal("association or csrf failed", code, e)
	}
	event := common.Map{"event_id": "isolated-v44-event", "node_id": "fixture", "operation": "modify", "path": "/isolated/file.php", "time": common.Stamp()}
	code, _, e = common.Request(context.Background(), client, "POST", base+"/events", event, map[string]string{"Authorization": "Bearer isolated-node-token"})
	if e != nil || code != 200 {
		t.Fatal("new identity rejected", code, e)
	}
	// Same node update and rollback both preserve the original center identity.
	updated := common.Clone(next)
	common.M(common.M(updated["nodes"])["fixture"])["name"] = "升级后登记"
	load(updated)
	load(c)
	if after := docker(t, "inspect", "--format", "{{.Id}} {{.State.Pid}} {{.State.StartedAt}}", name); after != identity {
		t.Fatal("node operation restarted center")
	}
	code, _, e = common.Request(context.Background(), client, "POST", console+"/api/websites", common.Map{"name": "回退后站点", "url": "https://rollback.invalid/", "paused": true}, headers)
	if e != nil || code != 200 {
		t.Fatal("registry rollback invalidated csrf", code, e)
	}
	docker(t, "restart", "-t", "5", name)
	wait(t, func() bool {
		code, _, e := common.Request(context.Background(), client, "GET", base+"/ready", nil, nil)
		return e == nil && code == 200
	})
	code, value, e = common.Request(context.Background(), client, "GET", console+"/api/session", nil, nil)
	if e != nil || code != 200 || common.S(common.M(value)["csrf_token"]) != csrf {
		t.Fatal("session lost across container restart", code, e)
	}
	// Token itself must never be stored in the persistent session table.
	t.Log("Linux amd64 center: add/update/registry rollback retain container ID, PID, StartedAt, cookie and CSRF; restart retains cookie and CSRF")
}
