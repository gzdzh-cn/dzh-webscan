package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"gopkg.in/yaml.v3"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
	"webscan/internal/deploy"
)

func docker(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if e != nil {
		t.Fatalf("docker %s: %s", args[0], b)
	}
	return strings.TrimSpace(string(b))
}
func wait(t *testing.T, fn func() bool) {
	t.Helper()
	until := time.Now().Add(90 * time.Second)
	for time.Now().Before(until) {
		if fn() {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("integration condition timed out")
}
func TestVersionedImagesTLSVectorYaraRestartAndHotRules(t *testing.T) {
	version := os.Getenv("WEBSCAN_IMAGE_VERSION")
	if version == "" {
		t.Skip("set WEBSCAN_IMAGE_VERSION after local build")
	}
	centralVersion := os.Getenv("WEBSCAN_CENTRAL_IMAGE_VERSION")
	if centralVersion == "" {
		centralVersion = version
	}
	t.Logf("receiver version=%s, agent version=%s", centralVersion, version)
	vector := os.Getenv("WEBSCAN_VECTOR_IMAGE")
	if vector == "" {
		t.Skip("set WEBSCAN_VECTOR_IMAGE to the fixed official Vector image")
	}
	root := t.TempDir()
	for _, dir := range []string{"central", "central-data", "agent", "agent-data", "logs", "sites", "probe", "vector"} {
		os.MkdirAll(filepath.Join(root, dir), 0755)
	}
	uuid := common.ID()[:8]
	network := "webscan-ci-" + uuid
	cn, an, vn := "webscan-ci-central-"+uuid, "webscan-ci-agent-"+uuid, "webscan-ci-vector-"+uuid
	volumes := map[string]string{}
	for _, name := range []string{"central-data", "agent-data", "logs", "sites", "probe", "vector"} {
		volumes[name] = "webscan-ci-" + uuid + "-" + name
		docker(t, "volume", "create", volumes[name])
	}
	docker(t, "network", "create", network)
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", an, vn, cn).Run()
		exec.Command("docker", "network", "rm", network).Run()
		for _, volume := range volumes {
			exec.Command("docker", "volume", "rm", volume).Run()
		}
	})
	var sinkDown atomic.Bool
	var feishuSuccess, lokiSuccess atomic.Int32
	var feishuBusinessFailure atomic.Bool
	var noticesMu sync.Mutex
	var notices []string
	sinkDown.Store(true)
	sink := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sinkDown.Load() {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/loki/api/v1/push" {
			lokiSuccess.Add(1)
			w.WriteHeader(204)
		} else {
			if feishuBusinessFailure.Load() {
				w.Write([]byte(`{"code":19001}`))
				return
			}
			raw, _ := io.ReadAll(r.Body)
			v, _ := common.Decode(raw)
			noticesMu.Lock()
			notices = append(notices, common.S(common.M(common.M(v)["content"])["text"]))
			noticesMu.Unlock()
			feishuSuccess.Add(1)
			w.Write([]byte(`{"code":0}`))
		}
	}))
	listener, e := net.Listen("tcp", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	sink.Listener = listener
	sink.Start()
	defer sink.Close()
	sinkURL := "http://host.docker.internal:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(314), Subject: pkix.Name{CommonName: "Webscan isolated tests"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"central"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(filepath.Join(root, "central", "ca.crt"), ca, 0644)
	os.WriteFile(filepath.Join(root, "agent", "ca.crt"), ca, 0644)
	os.WriteFile(filepath.Join(root, "central", "server.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
	c := common.Map{"data_dir": "/data", "bind": "0.0.0.0", "port": 18081, "https": common.Map{"bind": "0.0.0.0", "port": 19443, "cert_file": "/config/ca.crt", "key_file": "/config/server.key", "allowed_sources": []string{"0.0.0.0/0"}}, "max_request_mib": 2, "max_batch_events": 100, "nodes": common.Map{"fixture": common.Map{"host": "127.0.0.1", "name": "isolated fixture", "token": "isolated-token"}}, "active_nodes": []string{"fixture"}, "loki_url": sinkURL, "feishu": common.Map{"enabled": true, "webhook_url": sinkURL, "notifications": common.Map{"file_changes": true, "scan_matches": true, "scan_errors": true}, "rate_limit": common.Map{"max_per_second": 100, "max_per_minute": 1000}, "retry": common.Map{"initial_delay_seconds": 1, "max_delay_seconds": 2}}, "retention": common.Map{"sqlite_events_days": 90, "delivery_records_days": 90}}
	c["alert_token"] = "isolated-deployment-admin"
	common.AtomicJSON(filepath.Join(root, "central", "runtime.json"), c)
	docker(t, "run", "-d", "--name", cn, "--network", network, "--network-alias", "central", "--read-only", "--tmpfs", "/tmp:size=16m", "-p", "127.0.0.1::18081", "-p", "127.0.0.1::19443", "-v", filepath.Join(root, "central")+":/config:ro", "-v", volumes["central-data"]+":/data", "webscan-central:"+centralVersion, "central", "--config", "/config/runtime.json")
	port := docker(t, "port", cn, "18081/tcp")
	ready := "http://" + port + "/ready"
	client, _ := common.HTTPClient(filepath.Join(root, "central", "ca.crt"), 3*time.Second)
	wait(t, func() bool {
		_, v, e := common.Request(context.Background(), client, "GET", ready, nil, nil)
		return e == nil && common.B(common.M(v)["ready"])
	})
	tlsAddress := docker(t, "port", cn, "19443/tcp")
	event := common.Map{"event_id": "legacy-fixture", "node_id": "fixture", "operation": "modify", "path": "/sites/中文.php", "time": common.Stamp(), "scan": common.Map{"status": "pending"}}
	if _, _, e = common.Request(context.Background(), client, "POST", "https://"+tlsAddress+"/webscan/v1/events", event, map[string]string{"Authorization": "Bearer isolated-token"}); e != nil {
		t.Fatal(e)
	}
	inspect := func(container, path string) common.Map {
		v, e := common.Decode([]byte(docker(t, "exec", container, "/usr/local/bin/webscan", "tool", "--action", "inspect-db", "--input", path)))
		if e != nil {
			t.Fatal(e)
		}
		return common.M(v)
	}
	wait(t, func() bool { return common.I(inspect(cn, "/data/events-v1.sqlite3")["attempted_deliveries"]) > 0 })
	docker(t, "restart", "-t", "10", cn)
	sinkDown.Store(false)
	wait(t, func() bool {
		return common.I(inspect(cn, "/data/events-v1.sqlite3")["pending_deliveries"]) == 0 && feishuSuccess.Load() > 0 && lokiSuccess.Load() > 0
	})

	schema, _ := assets.Files.ReadFile("schema.yaml")
	var raw common.Map
	yaml.Unmarshal(schema, &raw)
	defaults := common.M(raw["node_defaults"])
	monitor := common.Clone(common.M(defaults["monitor"]))
	monitor["roots"] = []string{"/sites"}
	monitor["critical_paths"] = []string{}
	monitor["exclude_paths"] = []string{}
	ac := common.Map{"node_id": "fixture", "monitor": monitor, "scan": defaults["scan"], "transport": defaults["transport"], "data_dir": "/data", "log_dir": "/logs", "probe_directory": "/probe", "metrics_file": "/data/textfile/agent.prom", "yara_rules": "/config/php-webshell.yar", "public_url": "https://central:19443", "central_ca_file": "/config/ca.crt", "token": "isolated-token", "retention_days": 7, "probe_seconds": 30}
	common.AtomicJSON(filepath.Join(root, "agent", "runtime.json"), ac)
	yara, _ := assets.Files.ReadFile("php-webshell.yar")
	os.WriteFile(filepath.Join(root, "agent", "php-webshell.yar"), yara, 0644)
	// Use the production generator with merged json.Number defaults, rather
	// than a separately written fixture that could miss deployment errors.
	vc := deploy.VectorConfig(&deploy.Config{Raw: common.Map{"central": common.Map{"public_url": "https://central:19443"}}}, common.Map{"id": "fixture", "transport": common.Clone(common.M(defaults["transport"]))}, common.Map{"nodes": common.Map{"fixture": common.Map{"token": "isolated-token"}}})
	vc["data_dir"] = "/vector"
	common.M(common.M(vc["sources"])["events"])["include"] = []string{"/logs/events-*.jsonl"}
	common.M(common.M(common.M(vc["sinks"])["central"])["tls"])["ca_file"] = "/config/ca.crt"
	vb := deploy.YAML(vc)
	os.WriteFile(filepath.Join(root, "agent", "vector.yaml"), vb, 0644)
	docker(t, "run", "-d", "--name", an, "--network", network, "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_READ_SEARCH", "--memory", "256m", "--cpus", "1", "--tmpfs", "/tmp:size=16m", "-e", "GOMEMLIMIT=64MiB", "-v", filepath.Join(root, "agent")+":/config:ro", "-v", volumes["agent-data"]+":/data", "-v", volumes["logs"]+":/logs", "-v", volumes["sites"]+":/sites:ro", "-v", volumes["probe"]+":/probe", "webscan-agent:"+version, "agent", "--config", "/config/runtime.json")
	readStatus := func() (common.Map, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b, err := exec.CommandContext(ctx, "docker", "exec", an, "cat", "/data/rules-status.json").Output()
		if err != nil {
			return nil, err
		}
		v, err := common.Decode(b)
		return common.M(v), err
	}
	currentStart := func() float64 {
		stamp, err := time.Parse(time.RFC3339Nano, docker(t, "inspect", "--format", "{{.State.StartedAt}}", an))
		if err != nil {
			t.Fatal(err)
		}
		return float64(stamp.UnixNano()) / 1e9
	}
	started := currentStart()
	readyStatus := func() bool {
		v, e := readStatus()
		ready, present := v["collector_ready"]
		return e == nil && common.S(v["state"]) == "applied" && common.F(v["time"]) >= started && (!present || common.B(ready))
	}
	wait(t, readyStatus)
	// New-node staging: build the local baseline before any HTTP sink exists.
	// A real PHP event must stay durable across an agent restart while Vector
	// is held, then reach the receiver and drain once transmission is enabled.
	beforeHeld := common.I(inspect(cn, "/data/events-v1.sqlite3")["events"])
	docker(t, "run", "--rm", "--network", "none", "-v", volumes["sites"]+":/sites", "--entrypoint", "sh", "webscan-agent:"+version, "-c", "printf '%s' '<?php /* staged addition */' > /sites/上线前留存.php")
	wait(t, func() bool {
		b, err := exec.Command("docker", "exec", an, "sh", "-c", "cat /logs/events-*.jsonl").Output()
		return err == nil && strings.Contains(string(b), "/sites/上线前留存.php") && common.I(inspect(an, "/data/agent.sqlite3")["pending_events"]) > 0
	})
	if common.I(inspect(cn, "/data/events-v1.sqlite3")["events"]) != beforeHeld {
		t.Fatal("held node sent an event before registration")
	}
	docker(t, "restart", "-t", "10", an)
	started = currentStart()
	wait(t, readyStatus)
	if common.I(inspect(an, "/data/agent.sqlite3")["pending_events"]) == 0 {
		t.Fatal("held events disappeared on restart")
	}
	docker(t, "run", "-d", "--name", vn, "--network", network, "--read-only", "-v", filepath.Join(root, "agent")+":/config:ro", "-v", volumes["logs"]+":/logs:ro", "-v", volumes["sites"]+":/sites", "-v", volumes["vector"]+":/vector", vector, "--config", "/config/vector.yaml")
	wait(t, func() bool {
		return common.I(inspect(cn, "/data/events-v1.sqlite3")["events"]) > beforeHeld && common.I(inspect(an, "/data/agent.sqlite3")["pending_events"]) == 0
	})
	t.Log("staged node: baseline ready, PHP event durable through restart, Vector enabled and queue drained")
	identity := docker(t, "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", an)
	docker(t, "exec", vn, "sh", "-c", `mkdir -p /sites/site/runtime/cache; touch /sites/site/fixture.php; chown 65534:65534 /sites/site/fixture.php; chmod 600 /sites/site/fixture.php; printf '%s' '<?php /* eval( base64_decode( never executed */' > /sites/site/fixture.php`)
	wait(t, func() bool { return common.I(inspect(cn, "/data/events-v1.sqlite3")["matched_scans"]) > 0 })

	common.M(ac["monitor"])["exclude_paths"] = []string{"/sites/*/**/runtime/**/cache"}
	common.AtomicJSON(filepath.Join(root, "agent", "runtime.json"), ac)
	wait(t, func() bool {
		v, e := readStatus()
		p, _ := common.NewPolicy(common.M(ac["monitor"]))
		return e == nil && common.S(v["state"]) == "applied" && common.S(v["version"]) == p.Version(yara)
	})
	if docker(t, "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", an) != identity {
		t.Fatal("hot rules restarted container")
	}
	v, _ := readStatus()
	versionBefore := common.S(v["version"])
	common.M(ac["monitor"])["exclude_paths"] = []string{"/sites"}
	common.AtomicJSON(filepath.Join(root, "agent", "runtime.json"), ac)
	wait(t, func() bool {
		v, e := readStatus()
		return e == nil && common.S(v["state"]) == "rejected" && common.S(v["version"]) == versionBefore
	})
	common.M(ac["monitor"])["exclude_paths"] = []string{}
	common.AtomicJSON(filepath.Join(root, "agent", "runtime.json"), ac)
	wait(t, func() bool { v, e := readStatus(); return e == nil && common.S(v["state"]) == "applied" })
	wait(t, func() bool { return common.I(inspect(an, "/data/agent.sqlite3")["pending_events"]) == 0 })

	// Post-deployment notifications precede a real PHP change, even with normal
	// file notifications disabled. A failed business response is never success.
	common.M(common.M(c["feishu"])["notifications"])["file_changes"] = false
	common.AtomicJSON(filepath.Join(root, "central", "runtime.json"), c)
	docker(t, "restart", "-t", "10", cn)
	port = docker(t, "port", cn, "18081/tcp")
	ready = "http://" + port + "/ready"
	wait(t, func() bool {
		_, _, err := common.Request(context.Background(), client, "GET", ready, nil, nil)
		return err == nil
	})
	admin := map[string]string{"Authorization": "Bearer isolated-deployment-admin"}
	call := func(path string, payload common.Map) common.Map {
		_, value, err := common.Request(context.Background(), client, "POST", "http://"+port+path, payload, admin)
		if err != nil {
			t.Fatal("deployment API", err)
		}
		return common.M(value)
	}
	mainNotice := common.Map{"id": "deployment:integration-main", "message": "主服务器监控部署完成"}
	_, capabilities, capErr := common.Request(context.Background(), client, "GET", ready, nil, nil)
	if capErr != nil {
		t.Fatal(capErr)
	}
	if common.B(common.M(capabilities)["deployment_acceptance"]) {
		quietDir := "/sites/.webscan-deploy-test-fedcba9876543210fedcba9876543210"
		quietDest := "/sites/.webscan-deploy-test-fedcba9876543210fedcba9876543211"
		quietPath, quietMoved := quietDir+"/fixture.php", quietDest+"/fixture.php"
		content := "<?php /* owned detector fixture; eval( base64_decode( never executed */"
		hash := common.Hash([]byte(content))
		expected := []any{}
		for _, item := range []struct{ op, path, status string }{{"create", quietPath, ""}, {"scan", quietPath, "matched"}, {"move", quietMoved, ""}, {"scan", quietMoved, "matched"}, {"delete", quietMoved, ""}} {
			expected = append(expected, common.Map{"operation": item.op, "path": item.path, "sha256": hash, "scan": common.Map{"status": item.status}})
		}
		if !common.B(call("/deployment-acceptance", common.Map{"node": "fixture", "events": expected})["registered"]) {
			t.Fatal("acceptance not registered")
		}
		// Registered expectations must also survive a receiver restart.
		docker(t, "restart", "-t", "10", cn)
		port = docker(t, "port", cn, "18081/tcp")
		ready = "http://" + port + "/ready"
		wait(t, func() bool {
			_, _, err := common.Request(context.Background(), client, "GET", ready, nil, nil)
			return err == nil
		})
		matchedBefore := common.I(inspect(cn, "/data/events-v1.sqlite3")["matched_scans"])
		docker(t, "exec", vn, "sh", "-c", "mkdir -p "+quietDir+" "+quietDest+"; printf '%s' '"+content+"' > "+quietPath)
		wait(t, func() bool { return common.I(inspect(cn, "/data/events-v1.sqlite3")["matched_scans"]) > matchedBefore })
		matchedBefore = common.I(inspect(cn, "/data/events-v1.sqlite3")["matched_scans"])
		docker(t, "exec", vn, "sh", "-c", "mv "+quietPath+" "+quietMoved)
		wait(t, func() bool { return common.I(inspect(cn, "/data/events-v1.sqlite3")["matched_scans"]) > matchedBefore })
		docker(t, "exec", vn, "sh", "-c", "rm -f "+quietMoved+"; rmdir "+quietDir+" "+quietDest)
		wait(t, func() bool {
			return common.I(inspect(cn, "/data/events-v1.sqlite3")["pending_deliveries"]) == 0 && common.I(inspect(an, "/data/agent.sqlite3")["pending_events"]) == 0
		})
		noticesMu.Lock()
		for _, message := range notices {
			if strings.Contains(message, quietDir) || strings.Contains(message, quietDest) {
				noticesMu.Unlock()
				t.Fatal("registered acceptance produced standalone alert", message)
			}
		}
		noticesMu.Unlock()
		t.Log("actual acceptance YARA/create/move/delete retained records and Loki delivery without standalone Feishu alerts; registration survives receiver restart")
	}
	nodeNotice := common.Map{"id": "deployment:integration-node", "message": "子服务器监控部署完成"}
	feishuBusinessFailure.Store(true)
	attempted := common.I(inspect(cn, "/data/events-v1.sqlite3")["attempted_deliveries"])
	if common.B(call("/deployment-notices", mainNotice)["done"]) {
		t.Fatal("business failure immediately passed")
	}
	wait(t, func() bool {
		return common.I(inspect(cn, "/data/events-v1.sqlite3")["attempted_deliveries"]) > attempted
	})
	if common.B(call("/deployment-notices", mainNotice)["done"]) {
		t.Fatal("business failure passed")
	}
	docker(t, "restart", "-t", "10", cn)
	port = docker(t, "port", cn, "18081/tcp")
	ready = "http://" + port + "/ready"
	feishuBusinessFailure.Store(false)
	wait(t, func() bool {
		_, _, err := common.Request(context.Background(), client, "GET", ready, nil, nil)
		return err == nil
	})
	wait(t, func() bool { return common.B(call("/deployment-notices", mainNotice)["done"]) })
	wait(t, func() bool { return common.B(call("/deployment-notices", nodeNotice)["done"]) })
	fixtureDir := "/sites/.webscan-deploy-test-0123456789abcdef0123456789abcdef"
	fixturePath := fixtureDir + "/fixture.php"
	baseline := "<?php /* deploy baseline */"
	modified := "<?php /* deploy modified */"
	registration := common.Map{"id": "deployment:integration-php", "node": "fixture", "path": fixturePath, "sha256": common.Hash([]byte(modified))}
	call("/deployment-tests", registration)
	docker(t, "exec", vn, "sh", "-c", "mkdir -p "+fixtureDir+"; printf '%s' '"+baseline+"' > "+fixturePath)
	wait(t, func() bool {
		b, err := exec.Command("docker", "exec", an, "sh", "-c", "cat /logs/events-*.jsonl").Output()
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(b), "\n") {
			v, _ := common.Decode([]byte(line))
			event := common.M(v)
			if common.S(event["operation"]) == "create" && common.S(event["path"]) == fixturePath && common.S(event["sha256"]) == common.Hash([]byte(baseline)) {
				return true
			}
		}
		return false
	})
	docker(t, "exec", vn, "sh", "-c", "printf '%s' '"+modified+"' > "+fixturePath)
	var modifyID string
	wait(t, func() bool {
		v := call("/deployment-tests", registration)
		modifyID = common.S(v["event_id"])
		return common.B(v["done"]) && modifyID != ""
	})
	docker(t, "restart", "-t", "10", cn)
	port = docker(t, "port", cn, "18081/tcp")
	ready = "http://" + port + "/ready"
	wait(t, func() bool {
		_, _, err := common.Request(context.Background(), client, "GET", ready, nil, nil)
		return err == nil
	})
	if v := call("/deployment-tests", registration); !common.B(v["done"]) || common.S(v["event_id"]) != modifyID {
		t.Fatal("PHP receipt not durable", v)
	}
	call("/deployment-notices", mainNotice)
	call("/deployment-notices", nodeNotice)
	docker(t, "exec", vn, "sh", "-c", "rm -f "+fixturePath+"; rmdir "+fixtureDir)
	wait(t, func() bool {
		return common.I(inspect(cn, "/data/events-v1.sqlite3")["pending_deliveries"]) == 0 && common.I(inspect(an, "/data/agent.sqlite3")["pending_events"]) == 0
	})
	noticesMu.Lock()
	deploymentMessages := []string{}
	for _, message := range notices {
		if strings.Contains(message, "监控部署完成") || strings.Contains(message, "部署后的 PHP 修改测试成功") {
			deploymentMessages = append(deploymentMessages, message)
		}
	}
	noticesMu.Unlock()
	if len(deploymentMessages) != 3 || !strings.Contains(deploymentMessages[0], "主服务器") || !strings.Contains(deploymentMessages[1], "子服务器") || !strings.Contains(deploymentMessages[2], "部署后的 PHP 修改测试成功") {
		t.Fatal("notification ordering or dedup failed", deploymentMessages)
	}
	t.Log("Deployment main/node notices, real PHP modification, business-code retry/restart, registration/receipt dedup and delivery drain verified")

	t.Logf("TLS, persistent retry/restart, Vector, YARA, receipts and same-container rules verified; Feishu=%d Loki=%d", feishuSuccess.Load(), lokiSuccess.Load())
}
