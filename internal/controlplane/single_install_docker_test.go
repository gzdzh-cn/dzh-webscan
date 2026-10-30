package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/nodepki"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

// This exercises the actual CLI, Docker, PostgreSQL, VictoriaMetrics and the
// installed central process. Only systemd is a shim: it cannot prove boot
// behavior or replace independent-machine acceptance.
func TestSingleInstallDisposableDockerStack(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_SINGLE_STACK") != "1" {
		t.Skip("explicit disposable Docker stack required")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Fatal("requires isolated Linux amd64 root runner")
	}
	parent := os.Getenv("WEBSCAN_V3_TEST_SINGLE_ROOT")
	volumeRoot := strings.HasPrefix(parent, "/var/lib/docker/volumes/webscan-v3-single-test-") && strings.HasSuffix(parent, "/_data")
	bindRoot := os.Getenv("WEBSCAN_V3_TEST_SINGLE_BIND") == "1" && strings.HasPrefix(parent, "/host_mnt/Users/") && strings.HasPrefix(filepath.Base(parent), "webscan-v3-single-test.")
	if !volumeRoot && !bindRoot {
		t.Fatal("test root must be an explicitly named disposable volume")
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	port := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	s := singleInstallSpec{Format: 3, Root: filepath.Join(parent, "installation"), Instance: "single-acceptance", Username: "admin", PublicURL: "https://single.example.test", APIPort: port(), PostgresPort: port(), MetricsPort: port(),
		RuntimeImage:  os.Getenv("WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE"),
		PostgresImage: os.Getenv("WEBSCAN_V3_TEST_SINGLE_PG_IMAGE"),
		MetricsImage:  os.Getenv("WEBSCAN_V3_TEST_SINGLE_VM_IMAGE")}
	binary := os.Getenv("WEBSCAN_V3_TEST_SINGLE_BINARY")
	artifacts := filepath.Join(parent, "release-artifacts")
	if err := os.Mkdir(artifacts, 0700); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"webscan": binary, "agent-native.tar.gz": "/evidence/agent-native.tar.gz"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(artifacts, name), b, 0700); err != nil {
			t.Fatal(err)
		}
	}
	signing := filepath.Join(parent, "test-signing")
	signed := filepath.Join(parent, "signed-release")
	if err := ReleaseCommand(context.Background(), ReleaseOptions{Action: "init-key", Output: signing}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := ReleaseCommand(context.Background(), ReleaseOptions{Action: "sign", Output: signed, KeyFile: filepath.Join(signing, "signing.key"), Release: "v3.0.0-local-test", Helper: filepath.Join(artifacts, "webscan"), NativeBundle: filepath.Join(artifacts, "agent-native.tar.gz"), AgentImage: os.Getenv("WEBSCAN_V3_TEST_SINGLE_AGENT_IMAGE")}, io.Discard); err != nil {
		t.Fatal(err)
	}
	s.ReleaseTrust = &DeploymentTrustConfig{VaultKeyFile: filepath.Join(s.Root, "vault.key"), PublicKeyFile: filepath.Join(signing, "signing.pub"), ManifestFile: filepath.Join(signed, "release.json"), SignatureFile: filepath.Join(signed, "release.sig"), HelperFile: filepath.Join(artifacts, "webscan"), NativeBundleFile: filepath.Join(artifacts, "agent-native.tar.gz")}
	s.RulesFile = filepath.Join(parent, "rules.yar")
	if err := os.WriteFile(s.RulesFile, []byte("rule isolated_acceptance { condition: false }"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	source := filepath.Join(parent, "request.json")
	os.WriteFile(source, raw, 0600)
	password := filepath.Join(parent, "password")
	os.WriteFile(password, []byte("isolated-first-password-123"), 0600)
	shim := filepath.Join(parent, "shim")
	os.Mkdir(shim, 0700)
	block := filepath.Join(parent, "block-start")
	os.WriteFile(block, []byte("deliberate crash boundary"), 0600)
	executorPID := filepath.Join(parent, "executor.pid")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
case "$1" in
show) echo 252;;
daemon-reload|is-enabled|is-active) exit 0;;
enable)
  case "$3" in
    *-pki.timer) exit 0;;
    *-executor.service)
      if test -f '%s' && kill -0 "$(cat '%s')" 2>/dev/null; then exit 0; fi
      '%s' control-v3 --config '%s' --action run --role executor > '%s' 2>&1 &
      echo "$!" > '%s'
      exit 0;;
  esac
  test ! -e '%s'
  exec docker compose --project-name '%s' --file '%s' up -d --no-recreate --pull never;;
*) exit 23;;
esac
`, executorPID, executorPID, binary, filepath.Join(s.Root, "executor.yaml"), filepath.Join(parent, "executor.log"), executorPID, block, singleProject(s.Root), filepath.Join(s.Root, "compose.yaml"))
	if err := os.WriteFile(filepath.Join(shim, "systemctl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if binary == "" {
		t.Fatal("missing freshly built CLI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	call := func(action string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, binary, "control-v3", "--action", action, "--source", source, "--password-file", password)
		cmd.Env = append(os.Environ(), "PATH="+shim+":"+os.Getenv("PATH"))
		return cmd.CombinedOutput()
	}
	preview, err := call("preview-single-install")
	if err != nil {
		t.Fatalf("preview: %v %s", err, preview)
	}
	if _, err := os.Lstat(s.Root); !os.IsNotExist(err) {
		t.Fatal("preview changed disk")
	}
	progress, err := call("install-single")
	if err == nil || !bytes.Contains(progress, []byte(`"step":5`)) || !bytes.Contains(progress, []byte(`"state":"failed"`)) {
		t.Fatalf("expected controlled service-activation failure: %v %s", err, progress)
	}
	for _, value := range []string{"isolated-first-password-123", "postgres://", "BEGIN PRIVATE KEY"} {
		if bytes.Contains(progress, []byte(value)) {
			t.Fatal("private data in progress")
		}
	}
	var j singleInstallJournal
	raw, _ = os.ReadFile(filepath.Join(s.Root, "journal.json"))
	if json.Unmarshal(raw, &j) != nil || j.Step != 4 {
		t.Fatal("failed boundary did not retain completed DB/account stages")
	}
	c, err := LoadConfig(filepath.Join(s.Root, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	if _, err := store.DB.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES('admin','installer-acceptance','preserve-marker','{}')`); err != nil {
		t.Fatal(err)
	}
	dsn, _ := os.ReadFile(c.Database.DSNFile)
	ids := func() map[string]string {
		result := map[string]string{}
		for _, service := range []string{"postgres", "metrics", "central"} {
			cmd := exec.CommandContext(ctx, "docker", "compose", "--project-name", singleProject(s.Root), "--file", filepath.Join(s.Root, "compose.yaml"), "ps", "--all", "--quiet", service)
			raw, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			result[service] = strings.TrimSpace(string(raw))
		}
		return result
	}
	before := ids()
	if before["postgres"] == "" || before["metrics"] == "" || before["central"] != "" {
		t.Fatal("unexpected pre-activation services", before)
	}
	os.Remove(block)
	progress, err = call("resume-single-install")
	if err != nil {
		// Repeat the failed idempotent stage with test-only command diagnostics;
		// never expose child output or private request/configuration files.
		i := newSingleInstaller()
		run := i.run
		i.run = func(op context.Context, name string, args ...string) ([]byte, error) {
			if name == "systemctl" {
				name = filepath.Join(shim, "systemctl")
			}
			result, e := run(op, name, args...)
			t.Logf("installer diagnostic command=%s success=%t", filepath.Base(name), e == nil)
			if len(args) > 0 && args[0] == "inspect" {
				var objects []struct {
					Image  string
					Config struct{ Image string }
				}
				if json.Unmarshal(result, &objects) == nil {
					for _, o := range objects {
						t.Logf("container image=%s reference=%s", o.Image, o.Config.Image)
					}
				}
			}
			if len(args) > 0 && args[0] == "image" {
				t.Logf("selected immutable image identity=%s", strings.TrimSpace(string(result)))
			}
			return result, e
		}
		t.Logf("installer diagnostic stage error=%v", i.start(ctx, s))
		t.Fatalf("resume actual stack: %v %s", err, progress)
	}
	after := ids()
	if after["postgres"] != before["postgres"] || after["metrics"] != before["metrics"] || after["central"] == "" {
		t.Fatal("resume recreated infrastructure", before, after)
	}
	loginReq, _ := http.NewRequestWithContext(ctx, "POST", "http://"+c.Central.Listen+"/api/v3/login", strings.NewReader(`{"username":"admin","password":"isolated-first-password-123"}`))
	loginReq.Header.Set("X-Forwarded-Proto", "https")
	loginReq.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	response, err := client.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || len(response.Cookies()) != 1 {
		t.Fatal("fresh actual center login failed", response.StatusCode)
	}
	cookie := response.Cookies()[0]
	verifyInstalledSettingsAPI(t, ctx, c, store, client, cookie)
	centralProcess := func() string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Pid}}/{{.State.StartedAt}}/{{.RestartCount}}", after["central"])
		raw, err := cmd.Output()
		if err != nil || len(bytes.TrimSpace(raw)) == 0 {
			t.Fatal("cannot capture installed center process", err)
		}
		return strings.TrimSpace(string(raw))
	}
	processBefore := centralProcess()
	verifyInstalledSinglePKIRotation(t, ctx, s, store)
	progress, err = call("resume-single-install")
	if err != nil {
		t.Fatalf("completed verification: %v %s", err, progress)
	}
	if repeated := ids(); repeated["central"] != after["central"] || repeated["postgres"] != after["postgres"] || repeated["metrics"] != after["metrics"] {
		t.Fatal("completed resume recreated services")
	}
	if centralProcess() != processBefore {
		t.Fatal("renewal or verification restarted the center process")
	}
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://"+c.Central.Listen+"/api/v3/session", nil)
	request.AddCookie(cookie)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("resume invalidated login")
	}
	var retained int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_audit WHERE kind='installer-acceptance'`).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("resume lost committed data", err)
	}
	newDSN, _ := os.ReadFile(c.Database.DSNFile)
	if !bytes.Equal(dsn, newDSN) {
		t.Fatal("resume changed database credential")
	}
	t.Log("actual CLI + PostgreSQL + VictoriaMetrics + central login/resume and unchanged center PID/start/restart count PASS; systemd explicitly simulated")
	verifyInstalledSingleWebUpgrade(t, ctx, s, binary, client, cookie, executorPID, after)
}

func verifyInstalledSinglePKIRotation(t *testing.T, ctx context.Context, s singleInstallSpec, store *Store) {
	t.Helper()
	c := s.configuration()
	caRaw, err := os.ReadFile(filepath.Join(s.Root, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(s.Root, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.ParseAuthority(caRaw, key, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := authority.Issue(nodepki.Node, "node-a", []string{"agent.test"}, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(leaf.Certificate, leaf.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caRaw)
	trust, err := nodepki.NewReceiverTrust(c.Collector.CAFile, c.Collector.RevocationFile, filepath.Join(filepath.Dir(s.Root), "remote-trust"), now)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(filepath.Dir(s.Root), "pki-node.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created REAL NOT NULL,accepted REAL)`); err != nil {
		t.Fatal(err)
	}
	source, err := pull.New(db, "node-a", "v3.0.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	var remoteSHA atomic.Value
	remoteSHA.Store("")
	g := pull.NewServerWithTrustUpdater(source, []string{"spiffe://webscan/collector/" + s.Instance}, func(ctx context.Context, cert *x509.Certificate, raw []byte) (*agentv1.UpdateTrustResponse, error) {
		r, err := trust.Publish(ctx, cert, raw, time.Now())
		if err != nil {
			return nil, err
		}
		remoteSHA.Store(r.SHA256)
		return &agentv1.UpdateTrustResponse{NodeId: "node-a", CrlSha256: r.SHA256, CrlNumber: r.Number, NextUpdateUnix: r.NextUpdate.Unix()}, nil
	}, func(cert *x509.Certificate) error {
		return trust.Verify(cert, nodepki.Collector, s.Instance, time.Now())
	})
	defer g.Stop()
	var seen atomic.Value
	seen.Store("")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			seen.Store(r.TLS.PeerCertificates[0].SerialNumber.Text(16))
		}
		g.ServeHTTP(w, r)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer func() {
		g.Stop()
		server.CloseClientConnections()
		server.Close()
	}()
	n := nodeFixture("node-a")
	n.Endpoint = server.Listener.Addr().String()
	n.ServerName = "agent.test"
	if err := store.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	insert := func(id string) {
		t.Helper()
		if _, err := db.Exec("INSERT INTO events VALUES(?,?,?,NULL)", id, string(eventFixture(id, "modify").Json), float64(time.Now().Unix())); err != nil {
			t.Fatal(err)
		}
	}
	confirmed := func(id string) bool {
		var b bool
		err := db.QueryRowContext(ctx, "SELECT accepted IS NOT NULL FROM events WHERE id=?", id).Scan(&b)
		return err == nil && b
	}
	wait := func(label string, f func() bool) {
		t.Helper()
		op, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		for !f() {
			select {
			case <-op.Done():
				t.Fatal(label, op.Err())
			case <-time.After(30 * time.Millisecond):
			}
		}
	}
	insert("single-pki-before")
	wait("installed collector failed original event", func() bool { return confirmed("single-pki-before") })
	_, old, err := nodepki.ReadIdentity(c.Collector.CAFile, c.Collector.IdentityFile, nodepki.Collector, s.Instance, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if seen.Load().(string) != old.Serial {
		t.Fatal("installed collector used wrong identity")
	}
	// A trusted shortened leaf makes renewal due at wall-clock time, without
	// changing a host clock or weakening any production renewal threshold.
	short, err := authority.Issue(nodepki.Collector, s.Instance, nil, time.Now().UTC().Truncate(time.Second), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(short.Key)
	if err := singleReplacePrivate(ctx, c.Collector.IdentityFile, append(append([]byte{}, short.Certificate...), short.Key...), false); err != nil {
		t.Fatal(err)
	}
	maintenance := func() singlePKIReceipt {
		t.Helper()
		cmd := exec.CommandContext(ctx, filepath.Join(s.Root, "webscan"), "control-v3", "--action", "maintain-single-pki", "--source", filepath.Join(s.Root, "install.json"))
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("installed maintenance command: %v %s", err, raw)
		}
		var r singlePKIReceipt
		if json.Unmarshal(raw, &r) != nil || r.State != "healthy" || r.NodeRenewals == nil || r.NodeRenewals.State != "healthy" {
			t.Fatal("bad maintenance receipt")
		}
		return r
	}
	receipt := maintenance()
	if !receipt.Identity.Changed || receipt.Identity.CertificateSHA256 == old.CertificateSHA256 {
		t.Fatal("installed maintenance did not renew")
	}
	wait("installed collector did not reconnect after renewal", func() bool { return seen.Load().(string) == receipt.Identity.Serial })
	// Revoke the original collector leaf through its managed authority, then
	// run the same installed command to publish the new CRL to the container.
	var output bytes.Buffer
	if err := nodepki.Command(ctx, nodepki.Options{Action: "revoke", Authority: filepath.Join(s.Root, "authority"), Certificate: filepath.Join(s.Root, "collector.crt")}, &output); err != nil {
		t.Fatal(err)
	}
	latest := maintenance()
	if latest.Identity.Changed || latest.CRLSHA256 == receipt.CRLSHA256 {
		t.Fatal("CRL refresh changed current key or failed to publish")
	}
	wait("installed center did not distribute signed CRL to independent remote state", func() bool { return remoteSHA.Load().(string) == latest.CRLSHA256 })
	insert("single-pki-after")
	wait("renewed installed collector lost confirmation", func() bool { return confirmed("single-pki-after") })
	var count int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_events WHERE id IN ('single-pki-before','single-pki-after')`).Scan(&count); err != nil || count != 2 {
		t.Fatal("installed rotation lost or duplicated events", count, err)
	}
	t.Log("installed CLI maintenance + readonly mount + actual central gRPC reauthentication, automatic signed CRL distribution and two event receipts PASS")
}

// The installed API must use the very same Vault as the real host worker. This
// exercises HTTP, container mounts and transactional backups, not just a Store.
func verifyInstalledSettingsAPI(t *testing.T, ctx context.Context, c Config, store *Store, client *http.Client, cookie *http.Cookie) {
	t.Helper()
	call := func(method, path string, input, output any, csrf, key string) {
		t.Helper()
		var body io.Reader
		if input != nil {
			raw, e := json.Marshal(input)
			if e != nil {
				t.Fatal(e)
			}
			body = bytes.NewReader(raw)
		}
		r, e := http.NewRequestWithContext(ctx, method, "http://"+c.Central.Listen+"/api/v3/"+path, body)
		if e != nil {
			t.Fatal(e)
		}
		r.AddCookie(cookie)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("installed API %s %s status=%d", method, path, resp.StatusCode)
		}
		if output != nil {
			if e = json.NewDecoder(resp.Body).Decode(output); e != nil {
				t.Fatal(e)
			}
		}
	}
	var session struct {
		CSRF string `json:"csrf"`
	}
	call("GET", "session", nil, &session, "", "")
	if session.CSRF == "" {
		t.Fatal("missing installed CSRF")
	}
	var caps struct{ Settings, Deployments featureAvailability }
	deadline := time.Now().Add(20 * time.Second)
	for {
		call("GET", "capabilities", nil, &caps, "", "")
		if caps.Settings.Available && caps.Deployments.Available {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("installed shared Vault/host worker unavailable: settings=%v deployment=%v", caps.Settings, caps.Deployments)
		}
		time.Sleep(time.Second)
	}
	var view settingsEditorView
	call("GET", "settings", nil, &view, "", "")
	backups := tableCount(t, store, "v3_configuration_backups")
	for _, action := range []string{"save", "apply"} {
		edit := settingsEdit{}
		if action == "save" {
			edit.Values = map[string]json.RawMessage{"website_monitor.interval_seconds": json.RawMessage(`42`)}
		}
		in := settingsEditorRequest{Action: action, ExpectedGeneration: view.State.Generation, ExpectedRuntime: view.State.RuntimeVersion, Edit: edit}
		var preview settingsEditorPreview
		call("POST", "settings/preview", in, &preview, session.CSRF, "")
		if tableCount(t, store, "v3_configuration_backups") != backups {
			t.Fatal("preview wrote backup")
		}
		in.Preview = preview.Token
		call("POST", "settings/confirm", in, nil, session.CSRF, "installed-settings-"+action)
		backups++
		if tableCount(t, store, "v3_configuration_backups") != backups {
			t.Fatal("missing transactional before-edit backup")
		}
		call("GET", "settings", nil, &view, "", "")
	}
	if view.State.Pending || view.RuntimeValues["website_monitor.interval_seconds"] != float64(42) {
		t.Fatal("installed settings not applied")
	}
	t.Log("installed container HTTP settings read/preview/save/apply + shared Vault and two transactional backups PASS")
}

// Apply the generated upgrade overlay to this test-owned installation. This
// validates a real container replacement and persisted state, with systemd
// activation simulated explicitly as above. No production updater is invoked.
func verifyInstalledSingleWebUpgrade(t *testing.T, ctx context.Context, s singleInstallSpec, binary string, client *http.Client, cookie *http.Cookie, executorPID string, beforeIDs map[string]string, override ...singleWebUpgradeSpec) {
	t.Helper()
	originals := map[string][]byte{}
	for _, name := range []string{"install.json", "compose.yaml", "config.yaml", "executor.yaml", "vault.key"} {
		raw, e := os.ReadFile(filepath.Join(s.Root, name))
		if e != nil {
			t.Fatal(e)
		}
		originals[name] = raw
	}
	host, e := LoadConfig(filepath.Join(s.Root, "executor.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(filepath.Dir(s.Root), "upgrade-overlay-"+token()[:12])
	spec := singleWebUpgradeSpec{Format: 1, APIConfig: filepath.Join(s.Root, "config.yaml"), ExecutorConfig: filepath.Join(s.Root, "executor.yaml"), ComposeFile: filepath.Join(s.Root, "compose.yaml"), Project: singleProject(s.Root), RuntimeImage: s.RuntimeImage, RulesFile: host.Executor.RulesFile, Trust: host.DeploymentTrust}
	if len(override) > 0 {
		spec.Trust = override[0].Trust
		spec.ComposeFile = override[0].ComposeFile
	}
	files, e := singleWebUpgradeFiles(ctx, spec, output)
	if e != nil {
		t.Fatal(e)
	}
	if e = publishTrustFiles(ctx, output, files); e != nil {
		t.Fatal(e)
	}
	command := exec.CommandContext(ctx, binary, "control-v3", "--config", filepath.Join(output, "config.yaml"), "--action", "migrate-db")
	if _, e = command.CombinedOutput(); e != nil {
		t.Fatalf("upgrade migration failed: %v", e)
	}
	command = exec.CommandContext(ctx, "docker", "compose", "--project-name", spec.Project, "--file", filepath.Join(output, "compose.yaml"), "up", "-d", "--no-deps", "--pull", "never", "central")
	if _, e = command.CombinedOutput(); e != nil {
		t.Fatalf("upgrade activation failed: %v", e)
	}
	pidRaw, e := os.ReadFile(executorPID)
	if e != nil {
		t.Fatal(e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(pidRaw)))
	if e != nil || pid <= 1 {
		t.Fatal("invalid test worker PID")
	}
	old, e := os.FindProcess(pid)
	if e != nil {
		t.Fatal(e)
	}
	_ = old.Signal(syscall.SIGTERM)
	log, e := os.OpenFile(filepath.Join(filepath.Dir(s.Root), "upgrade-executor.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	worker := exec.CommandContext(ctx, binary, "control-v3", "--config", filepath.Join(output, "executor.yaml"), "--action", "run", "--role", "executor")
	worker.Stdout, worker.Stderr = log, log
	if e = worker.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = worker.Process.Signal(syscall.SIGTERM); _ = worker.Wait() }()
	for _, service := range []string{"postgres", "metrics", "central"} {
		cmd := exec.CommandContext(ctx, "docker", "compose", "--project-name", spec.Project, "--file", filepath.Join(output, "compose.yaml"), "ps", "--all", "--quiet", service)
		raw, e := cmd.Output()
		if e != nil {
			t.Fatal(e)
		}
		id := strings.TrimSpace(string(raw))
		if id == "" || service != "central" && id != beforeIDs[service] || service == "central" && id == beforeIDs[service] {
			t.Fatal("upgrade infrastructure/replacement identity violation", service)
		}
	}
	if e = singleWait(ctx, func(op context.Context) error {
		return singleHTTPHealth(op, "http://"+s.configuration().Central.Listen+"/healthz")
	}); e != nil {
		t.Fatal(e)
	}
	c, e := LoadConfig(filepath.Join(output, "config.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	store, e := Open(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer store.DB.Close()
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://"+c.Central.Listen+"/api/v3/settings", nil)
	request.AddCookie(cookie)
	resp, e := client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	var view settingsEditorView
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&view) != nil || view.RuntimeValues["website_monitor.interval_seconds"] != float64(42) {
		t.Fatal("upgrade lost session, applied setting or Vault draft proof")
	}
	if tableCount(t, store, "v3_configuration_backups") != 2 {
		t.Fatal("upgrade lost encrypted backups")
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+c.Central.Listen+"/api/v3/capabilities", nil)
		req.AddCookie(cookie)
		r, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		var caps struct{ Deployments featureAvailability }
		e = json.NewDecoder(r.Body).Decode(&caps)
		r.Body.Close()
		if e == nil && r.StatusCode == 200 && caps.Deployments.Available {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upgraded host worker not ready", caps.Deployments.Reason)
		}
		time.Sleep(time.Second)
	}
	for name, raw := range originals {
		after, e := os.ReadFile(filepath.Join(s.Root, name))
		if e != nil || !bytes.Equal(after, raw) {
			t.Fatal("upgrade rewrote immutable source or Vault", name)
		}
	}
	t.Log("actual upgrade overlay applied: central replaced, PostgreSQL/metrics unchanged, original installation and Vault unchanged, login/settings/encrypted backups retained PASS; same-source test image, systemd simulated")
}

// Reuse only a previously verified disposable test installation, never a
// production path. This avoids relying on macOS ownership changes while PG
// performs its very first initdb; the upgrade still replaces the actual image.
func TestSingleUpgradeExistingDisposableDockerStack(t *testing.T) {
	parent := os.Getenv("WEBSCAN_V3_TEST_SINGLE_EXISTING")
	if parent == "" {
		t.Skip("explicit retained disposable stack required")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || !strings.HasPrefix(parent, "/host_mnt/Users/") || !strings.HasPrefix(filepath.Base(parent), "webscan-v3-single-test.") {
		t.Fatal("refusing non-test installation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	var manifest singleInstallManifest
	raw, e := os.ReadFile(filepath.Join(parent, "installation", "install.json"))
	if e != nil || json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("missing prior installation")
	}
	s := manifest.Spec
	if s.Root != filepath.Join(parent, "installation") {
		t.Fatal("source root mismatch")
	}
	oldBinary, e := os.ReadFile(filepath.Join(s.Root, "webscan"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = readSingleInstallation(s, digest(oldBinary)); e != nil {
		t.Fatal("unverified retained installation", e)
	}
	// Reproduce the old pilot's explicit program mount in a separate source
	// Compose. Earlier local image indexes need not survive a tag rebuild;
	// the retained, immutable old executable is the actual baseline here.
	var oldCompose map[string]any
	b, e := os.ReadFile(filepath.Join(s.Root, "compose.yaml"))
	if e != nil || yaml.Unmarshal(b, &oldCompose) != nil {
		t.Fatal("missing retained Compose")
	}
	central := oldCompose["services"].(map[string]any)["central"].(map[string]any)
	central["image"] = os.Getenv("WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE")
	central["volumes"] = append(central["volumes"].([]any), map[string]any{"type": "bind", "source": filepath.Join(s.Root, "webscan"), "target": "/usr/local/bin/webscan", "read_only": true, "bind": map[string]any{"create_host_path": false}})
	oldSource := filepath.Join(parent, "retained-start-"+token()[:12]+".yaml")
	b, e = yaml.Marshal(oldCompose)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(oldSource, b, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, "docker", "compose", "--project-name", singleProject(s.Root), "--file", oldSource, "up", "-d", "--no-recreate", "--pull", "never")
	if _, e = cmd.CombinedOutput(); e != nil {
		t.Fatal("cannot revive isolated stack", e)
	}
	if e = singleWait(ctx, func(op context.Context) error {
		return singleHTTPHealth(op, "http://"+s.configuration().Central.Listen+"/healthz")
	}); e != nil {
		t.Fatal(e)
	}
	ids := map[string]string{}
	for _, service := range []string{"postgres", "metrics", "central"} {
		b, e := exec.CommandContext(ctx, "docker", "compose", "--project-name", singleProject(s.Root), "--file", oldSource, "ps", "--all", "--quiet", service).Output()
		if e != nil {
			t.Fatal(e)
		}
		ids[service] = strings.TrimSpace(string(b))
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+s.configuration().Central.Listen+"/api/v3/login", strings.NewReader(`{"username":"admin","password":"isolated-first-password-123"}`))
	req.Header.Set("X-Forwarded-Proto", "https")
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	resp, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || len(resp.Cookies()) != 1 {
		t.Fatal("retained login failed", resp.StatusCode)
	}
	workerLog, e := os.OpenFile(filepath.Join(parent, "retained-worker.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer workerLog.Close()
	worker := exec.CommandContext(ctx, filepath.Join(s.Root, "webscan"), "control-v3", "--config", filepath.Join(s.Root, "executor.yaml"), "--action", "run", "--role", "executor")
	worker.Stdout, worker.Stderr = workerLog, workerLog
	if e = worker.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = worker.Process.Signal(syscall.SIGTERM); _ = worker.Wait() }()
	pidfile := filepath.Join(parent, "retained-worker.pid")
	os.WriteFile(pidfile, []byte(strconv.Itoa(worker.Process.Pid)), 0600)
	binary := os.Getenv("WEBSCAN_V3_TEST_SINGLE_BINARY")
	artifacts := filepath.Join(parent, "upgrade-artifacts-"+token()[:12])
	if e = os.Mkdir(artifacts, 0700); e != nil {
		t.Fatal(e)
	}
	for name, source := range map[string]string{"webscan": binary, "agent-native.tar.gz": "/evidence/agent-native.tar.gz"} {
		b, e := os.ReadFile(source)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(artifacts, name), b, 0700); e != nil {
			t.Fatal(e)
		}
	}
	signed := filepath.Join(parent, "upgrade-signed-"+token()[:12])
	if e = ReleaseCommand(ctx, ReleaseOptions{Action: "sign", Output: signed, KeyFile: filepath.Join(parent, "test-signing", "signing.key"), Release: "v3.0.0-local-test", Helper: filepath.Join(artifacts, "webscan"), NativeBundle: filepath.Join(artifacts, "agent-native.tar.gz"), AgentImage: os.Getenv("WEBSCAN_V3_TEST_SINGLE_AGENT_IMAGE")}, io.Discard); e != nil {
		t.Fatal(e)
	}
	trust := *s.ReleaseTrust
	trust.VaultKeyFile = filepath.Join(s.Root, "vault.key")
	trust.PublicKeyFile = filepath.Join(parent, "test-signing", "signing.pub")
	trust.ManifestFile = filepath.Join(signed, "release.json")
	trust.SignatureFile = filepath.Join(signed, "release.sig")
	trust.HelperFile = filepath.Join(artifacts, "webscan")
	trust.NativeBundleFile = filepath.Join(artifacts, "agent-native.tar.gz")
	s.RuntimeImage = os.Getenv("WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE")
	verifyInstalledSingleWebUpgrade(t, ctx, s, binary, client, resp.Cookies()[0], pidfile, ids, singleWebUpgradeSpec{Trust: trust, ComposeFile: oldSource})
}
