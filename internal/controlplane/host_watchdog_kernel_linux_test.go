//go:build linux

package controlplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	"webscan/internal/nodepki"
	"webscan/internal/notify"
	"webscan/internal/persist"
)

func hostWatchdogKernelGuard(t *testing.T) {
	t.Helper()
	if os.Getenv("WEBSCAN_V3_HOST_WATCHDOG_KERNEL") != "1" {
		t.Skip("requires explicitly enabled dedicated networkless watchdog kernel guest")
	}
	marker, e := os.ReadFile("/v3-tests/kernel-guest")
	pid, pe := os.Readlink("/proc/1/exe")
	interfaces, ne := os.ReadDir("/sys/class/net")
	if os.Geteuid() != 0 || e != nil || string(marker) != "webscan-v3-networkless-kernel-guest\n" || pe != nil || pid != "/usr/lib/systemd/systemd" || ne != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("refusing non-isolated watchdog kernel environment")
	}
}
func hostWatchdogKernelCommand(t *testing.T, ctx context.Context, name string, args ...string) []byte {
	t.Helper()
	raw, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		t.Fatalf("controlled watchdog kernel command %s failed: %v\n%s", name, e, raw)
	}
	return raw
}
func hostWatchdogKernelPort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().String()
}
func hostWatchdogKernelWait(t *testing.T, ctx context.Context, limit time.Duration, check func() bool, label string) {
	t.Helper()
	until := time.Now().Add(limit)
	for ctx.Err() == nil && time.Now().Before(until) {
		if check() {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("watchdog kernel condition not met:", label)
}

// The actual helper, PostgreSQL container and VictoriaMetrics binary are
// supplied by the networkless guest runner. This suite never contacts a
// production server and never changes the host machine's systemd or Docker.
func TestHostWatchdogKernelIndependentActualServices(t *testing.T) {
	hostWatchdogKernelGuard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	pgContainer := os.Getenv("WEBSCAN_V3_WATCHDOG_PG_CONTAINER")
	if pgContainer == "" {
		pgContainer = "webscan-watchdog-kernel-postgres"
	}
	if !identifier.MatchString(pgContainer) {
		t.Fatal("invalid test PG identity")
	}
	label := hostWatchdogKernelCommand(t, ctx, "docker", "inspect", "--format", "{{index .Config.Labels \"io.webscan.test\"}}", pgContainer)
	if strings.TrimSpace(string(label)) != "watchdog-kernel" {
		t.Fatal("refusing unowned PostgreSQL container")
	}
	vmBinary := os.Getenv("WEBSCAN_V3_TEST_VM_EXECUTABLE")
	if vmBinary != "/v3-tests/victoria-metrics-prod" {
		t.Fatal("explicit immutable VM executable required")
	}
	s, f := newSavedConfigurationStore(t)
	c := f.c
	localWrite(t, c.Database.DSNFile, environmentDSN(t, s))
	c.Executor.Mode = "external"
	binary, err := os.ReadFile("/v3-tests/webscan")
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, f.f.helper, binary)
	if err = os.Chmod(f.f.helper, 0700); err != nil {
		t.Fatal(err)
	}
	f.f.signed = filepath.Join(f.f.root, "actual-release")
	f.f.sign.Output = f.f.signed
	c.DeploymentTrust = f.f.config()
	var receipt bytes.Buffer
	if err = ReleaseCommand(ctx, f.f.sign, &receipt); err != nil {
		t.Fatal(err)
	}
	ca, err := f.authority.Export()
	if err != nil {
		t.Fatal(err)
	}
	server, err := f.authority.Issue(nodepki.Node, "watchdog-api", []string{"127.0.0.1"}, f.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, c.Central.CertFile, server.Certificate)
	localWrite(t, c.Central.KeyFile, server.Key)
	c.Central.Listen = hostWatchdogKernelPort(t)
	vmAddress := hostWatchdogKernelPort(t)
	c.Metrics.QueryURL, c.Metrics.WriteURL = "http://"+vmAddress, "http://"+vmAddress
	runRoot := "/run/webscan-watchdog-" + token()[:12]
	if err = os.Mkdir(runRoot, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(runRoot) })
	c.HostWatchdog = HostWatchdogConfig{Enabled: true, Socket: filepath.Join(runRoot, "control.sock"), StateDirectory: f.f.root + "-watchdog-state", SpecFile: filepath.Join(f.f.root, "watchdog.json")}
	if err = os.Mkdir(c.HostWatchdog.StateDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(c.HostWatchdog.StateDirectory) })
	for _, dir := range []string{"postgres-data", "metrics-data"} {
		if err = os.Mkdir(filepath.Join(f.f.root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	configFile := filepath.Join(f.f.root, "watchdog-control.yaml")
	configRaw, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, configFile, configRaw)
	installFile := filepath.Join(f.f.root, "install.json")
	installation := []byte(`{"format":4,"instance":"synthetic-watchdog-kernel"}`)
	localWrite(t, installFile, installation)
	spec := HostWatchdogSpec{Format: 1, Instance: c.Central.Instance, InstallationFile: installFile, InstallationSHA256: digest(installation), HostConfigFile: configFile, HostConfigSHA256: digest(configRaw), HelperFile: f.f.helper, HelperSHA256: digest(binary), StateDirectory: c.HostWatchdog.StateDirectory, Socket: c.HostWatchdog.Socket, APIURL: "https://" + c.Central.Listen, MetricsURL: "http://" + vmAddress}
	generated, err := prepareHostWatchdogFiles(ctx, c, spec)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, c.HostWatchdog.SpecFile, generated["watchdog.json"])
	// The synthetic CA is scoped to these test services, never installed into the
	// guest system trust store or used to bypass ordinary certificate checking.
	caFile := filepath.Join(f.f.root, "watchdog-test-ca.pem")
	localWrite(t, caFile, ca.CA)
	smtpPort, smtpCount := hostWatchdogKernelSMTP(t, server.Certificate, server.Key)
	var feishuCount atomic.Int32
	var loseFeishu atomic.Bool
	feishu := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 65536))
		feishuCount.Add(1)
		if loseFeishu.Swap(false) {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer feishu.Close()
	raw := common.JSON(common.Map{"email": common.Map{"enabled": true, "max_per_minute": 20, "timeout_seconds": 5, "retry": common.Map{"initial_delay_seconds": 1, "max_delay_seconds": 10}, "smtp_host": "127.0.0.1", "smtp_port": smtpPort, "tls_mode": "tls", "username": "synthetic", "password": "synthetic-only", "from_address": "synthetic@example.test", "recipients": []string{"synthetic@example.test"}, "notifications": common.Map{"health_failures": true, "health_recoveries": true}}, "feishu": common.Map{"enabled": true, "webhook_url": feishu.URL, "rate_limit": common.Map{"max_per_minute": 20, "max_per_second": 10000}, "notifications": common.Map{"health_failures": true, "health_recoveries": true}}})
	var channelConfig common.Map
	if json.Unmarshal(raw, &channelConfig) != nil || notify.Validate(common.M(channelConfig["email"])) != nil {
		t.Fatal("synthetic actual SMTP settings invalid before service startup")
	}
	if _, err = s.DB.ExecContext(ctx, `UPDATE v3_settings SET payload=$1`, raw); err != nil {
		t.Fatal(err)
	}
	if err = s.BindCluster(ctx, c); err != nil {
		t.Fatal(err)
	}
	suffix := token()[:10]
	watchdogUnit := "webscan-watchdog-kernel-" + suffix + ".service"
	apiUnit := "webscan-watchdog-api-" + suffix + ".service"
	vmUnit := "webscan-watchdog-vm-" + suffix + ".service"
	units := map[string][]byte{watchdogUnit: generated["watchdog.service"], apiUnit: []byte("[Unit]\nDescription=Isolated actual Webscan API\n[Service]\nType=simple\nExecStart=" + f.f.helper + " control-v3 --action run --role api --config " + configFile + "\n"), vmUnit: []byte("[Unit]\nDescription=Isolated actual VictoriaMetrics\n[Service]\nType=simple\nExecStart=" + vmBinary + " -storageDataPath=" + filepath.Join(f.f.root, "metrics-data") + " -httpListenAddr=" + vmAddress + "\n")}
	for name, unit := range units {
		unit = append(unit, []byte("\n[Service]\nEnvironment=SSL_CERT_FILE="+caFile+"\nEnvironment=SSL_CERT_DIR=/v3-tests/no-system-ca\n")...)
		localWrite(t, filepath.Join("/etc/systemd/system", name), unit)
	}
	t.Cleanup(func() {
		for name := range units {
			_ = exec.Command("systemctl", "stop", name).Run()
			os.Remove(filepath.Join("/etc/systemd/system", name))
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("docker", "start", pgContainer).Run()
	})
	hostWatchdogKernelCommand(t, ctx, "systemctl", "daemon-reload")
	for _, name := range []string{vmUnit, watchdogUnit, apiUnit} {
		hostWatchdogKernelCommand(t, ctx, "systemctl", "start", name)
	}
	client, err := newHostQuotaClient(c)
	if err != nil {
		t.Fatal(err)
	}
	read := func() HostWatchdogStatus {
		status, e := client.Snapshot(ctx)
		if e != nil {
			return HostWatchdogStatus{}
		}
		return status
	}
	normal := func(component string) bool {
		for _, check := range read().Checks {
			if check.Component == component {
				return check.State == "normal"
			}
		}
		return false
	}
	hostWatchdogKernelWait(t, ctx, time.Minute, func() bool { return normal("api") && normal("postgres") && normal("metrics") }, "actual API, PG and VM health")
	status := read()
	if status.Environment.OS != "linux" || status.Environment.BootID == "" || status.Environment.MemoryBytes == nil || len(status.Environment.Storage) != 3 {
		t.Fatal("host evidence unavailable", status.Environment)
	}
	// Root clients authenticate over the real Unix socket. A deliberately granted
	// filesystem connection by a different UID is still rejected by SO_PEERCRED.
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	peerRoot := "/usr/local/lib/webscan-peer-" + token()[:12]
	if e := os.Mkdir(peerRoot, 0755); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(peerRoot) })
	hostWatchdogKernelCommand(t, ctx, "chmod", "0755", peerRoot)
	peerBinary := filepath.Join(peerRoot, "peer-test")
	peerRaw, e := os.ReadFile(testBinary)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(peerBinary, peerRaw, 0755); e != nil {
		t.Fatal(e)
	}
	// The helper installs a private umask; WriteFile permissions alone are
	// filtered by that process-wide umask. Explicitly grant traversal and
	// execution only for this networkless peer-credential test.
	hostWatchdogKernelCommand(t, ctx, "chmod", "0755", peerBinary)
	peerStat, peerErr := os.Stat(peerBinary)
	var peerMount unix.Statfs_t
	peerMountErr := unix.Statfs(peerBinary, &peerMount)
	if peerErr != nil || peerMountErr != nil {
		t.Fatal("peer executable evidence unavailable", peerErr, peerMountErr)
	}
	t.Logf("peer executable mode=%#o mountflags=%#x", peerStat.Mode().Perm(), peerMount.Flags)
	if peerStat.Mode().Perm() != 0755 || peerMount.Flags&unix.ST_NOEXEC != 0 {
		t.Fatal("peer executable fixture cannot execute")
	}
	hostWatchdogKernelCommand(t, ctx, "chmod", "0755", runRoot)
	hostWatchdogKernelCommand(t, ctx, "chmod", "0666", c.HostWatchdog.Socket)
	denied := exec.CommandContext(ctx, "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", peerBinary, "-test.run=^TestHostWatchdogKernelDeniedPeer$", "-test.v")
	denied.Env = append(os.Environ(), "WEBSCAN_WATCHDOG_DENIED_SOCKET="+c.HostWatchdog.Socket)
	if output, e := denied.CombinedOutput(); e != nil {
		t.Fatalf("real peer rejection: %v\n%s", e, output)
	}
	hostWatchdogKernelCommand(t, ctx, "chmod", "0600", c.HostWatchdog.Socket)
	hostWatchdogKernelCommand(t, ctx, "chmod", "0700", runRoot)
	// Distinct OS processes share one durable local limit, independently of PG
	// notifier workers and their process-local connection pools.
	var quotaWG sync.WaitGroup
	var grants atomic.Int32
	for i := 0; i < 5; i++ {
		quotaWG.Add(1)
		go func() {
			defer quotaWG.Done()
			cmd := exec.CommandContext(ctx, testBinary, "-test.run=^TestHostWatchdogKernelQuotaProcess$", "-test.v")
			cmd.Env = append(os.Environ(), "WEBSCAN_WATCHDOG_QUOTA_CONFIG="+configFile)
			out, e := cmd.CombinedOutput()
			if e != nil {
				t.Errorf("quota child failed %v: %s", e, out)
				return
			}
			grants.Add(int32(bytes.Count(out, []byte("WATCHDOG_QUOTA_GRANTED"))))
		}()
	}
	quotaWG.Wait()
	if grants.Load() != 20 {
		t.Fatal("multi-process shared quota", grants.Load())
	}
	// Real prepared PG transactions freeze local sending. No timer may unfreeze
	// an unresolved transaction; committed/aborted snapshots are independently read.
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	prep, e := client.PrepareSettings(ctx, tx, 1, 2)
	if e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if _, e = client.Reserve(ctx, "email", token(), 1); !errors.Is(e, ErrHostSettingsFrozen) {
		tx.Rollback()
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, `UPDATE v3_settings SET version=2`); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	hostWatchdogKernelWait(t, ctx, 20*time.Second, func() bool {
		r, e := client.ResolveSettings(ctx, prep.ID)
		return e == nil && r.State == "committed" && r.RuntimeVersion == 2
	}, "real committed config activation")
	tx, e = s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	prep, e = client.PrepareSettings(ctx, tx, 2, 3)
	if e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	tx.Rollback()
	if r, e := client.ResolveSettings(ctx, prep.ID); e != nil || r.State != "aborted" {
		t.Fatal(r, e)
	}
	tx, e = s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	lost := *client
	lost.http = &http.Client{Timeout: 4 * time.Second, Transport: hostWatchdogLostReply{client.http.Transport}}
	if _, e = lost.PrepareSettings(ctx, tx, 2, 3); e == nil {
		tx.Rollback()
		t.Fatal("lost preparation response was not injected")
	}
	tx.Rollback()
	hostWatchdogKernelWait(t, ctx, 20*time.Second, func() bool { return !read().Frozen }, "response loss rollback resolved without TTL")
	initialPID := strings.TrimSpace(string(hostWatchdogKernelCommand(t, ctx, "systemctl", "show", "--property", "MainPID", "--value", watchdogUnit)))
	if initialPID == "0" {
		t.Fatal("independent watchdog not running")
	}
	hostWatchdogKernelCommand(t, ctx, "systemctl", "stop", apiUnit)
	// Verify the real 180-second startup grace before allowing an incident.
	time.Sleep(35 * time.Second)
	db, err := persist.OpenReadOnly(filepath.Join(c.HostWatchdog.StateDirectory, "watchdog.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer func() {
		if !t.Failed() {
			return
		}
		rows, e := db.Query(`SELECT component,phase,channel,state,count(*) FROM outbox GROUP BY component,phase,channel,state ORDER BY component,phase,channel,state`)
		if e != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var component, phase, channel, state string
			var count int
			if rows.Scan(&component, &phase, &channel, &state, &count) == nil {
				t.Logf("watchdog aggregate component=%s phase=%s channel=%s state=%s count=%d", component, phase, channel, state, count)
			}
		}
	}()
	var notices int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM outbox`).Scan(&notices); err != nil || notices != 0 {
		t.Fatal("startup grace generated an alert", notices, err)
	}
	terminal := func(component, phase string) bool {
		var count int
		return db.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE component=? AND phase=? AND state='accepted'`, component, phase).Scan(&count) == nil && count == 2
	}
	hostWatchdogKernelWait(t, ctx, 4*time.Minute, func() bool { return terminal("api", "firing") }, "actual API process stopped; host independently alerts")
	hostWatchdogKernelCommand(t, ctx, "systemctl", "start", apiUnit)
	hostWatchdogKernelWait(t, ctx, time.Minute, func() bool { return terminal("api", "resolved") }, "two actual healthy API observations")
	hostWatchdogKernelCommand(t, ctx, "systemctl", "stop", vmUnit)
	hostWatchdogKernelWait(t, ctx, time.Minute, func() bool { return terminal("metrics", "firing") }, "actual VM process failure")
	hostWatchdogKernelCommand(t, ctx, "systemctl", "start", vmUnit)
	hostWatchdogKernelWait(t, ctx, time.Minute, func() bool { return terminal("metrics", "resolved") }, "actual VM process restored")
	hostWatchdogKernelCommand(t, ctx, "docker", "stop", "--time", "3", pgContainer)
	hostWatchdogKernelWait(t, ctx, time.Minute, func() bool { return terminal("postgres", "firing") }, "actual PG outage; sealed cache and local quota survive")
	if got := strings.TrimSpace(string(hostWatchdogKernelCommand(t, ctx, "systemctl", "show", "--property", "MainPID", "--value", watchdogUnit))); got != initialPID {
		t.Fatal("PG/API/VM outage restarted independent watchdog")
	}
	if smtpCount.Load() < 3 || feishuCount.Load() < 3 {
		t.Fatal("real loopback channels were not used", smtpCount.Load(), feishuCount.Load())
	}
	hostWatchdogKernelCommand(t, ctx, "docker", "start", pgContainer)
	hostWatchdogKernelWait(t, ctx, time.Minute, func() bool { return terminal("postgres", "resolved") }, "actual PG recovery")
	if err = SyncHostWatchdogHistory(ctx, s, client); err != nil {
		t.Fatal(err)
	}
	var imports int
	if err = s.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_host_notification_imports`).Scan(&imports); err != nil || imports < 8 {
		t.Fatal("actual schema43 history not imported", imports, err)
	}
	hostWatchdogKernelWait(t, ctx, time.Minute, func() bool { return read().Pending == 0 }, "all previous host notices reached terminal state")
	// Accepted request with response loss is terminal unknown and never resent.
	loseFeishu.Store(true)
	id := token()
	localDB, err := persist.OpenDB(filepath.Join(c.HostWatchdog.StateDirectory, "watchdog.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = localDB.ExecContext(ctx, `INSERT INTO outbox(id,component,phase,created_at,channel,recipient,version) VALUES(?,'api','firing',?,'feishu','',2)`, id, time.Now().Unix())
	localDB.Close()
	if err != nil {
		t.Fatal(err)
	}
	hostWatchdogKernelWait(t, ctx, 30*time.Second, func() bool {
		var state string
		return db.QueryRowContext(ctx, `SELECT state FROM outbox WHERE id=?`, id).Scan(&state) == nil && state == "unknown"
	}, "actual notification response lost becomes unknown")
	before := feishuCount.Load()
	time.Sleep(12 * time.Second)
	if feishuCount.Load() != before {
		t.Fatal("unknown host notification retried")
	}
	snapshot := filepath.Join(f.f.root, "watchdog-snapshot.sqlite3")
	if _, err = BackupHostWatchdog(ctx, c, snapshot); err != nil {
		t.Fatal(err)
	}
	// A disaster-restore staging cache has no leases or trusted liveness and is
	// frozen even while its old encrypted settings and quota remain available.
	restore := c
	restore.HostWatchdog.StateDirectory = f.f.root + "-restored-watchdog"
	restore.HostWatchdog.Socket = filepath.Join(runRoot, "restored.sock")
	restore.HostWatchdog.SpecFile = filepath.Join(f.f.root, "restored-watchdog.json")
	spec.StateDirectory, spec.Socket = restore.HostWatchdog.StateDirectory, restore.HostWatchdog.Socket
	spec.KeyID = f.v.active
	spec.Proof, _ = hostSpecMAC(f.v, spec)
	encoded, _ := json.Marshal(spec)
	localWrite(t, restore.HostWatchdog.SpecFile, encoded)
	t.Cleanup(func() { os.RemoveAll(restore.HostWatchdog.StateDirectory) })
	if err = RestoreHostWatchdog(ctx, restore, snapshot); err != nil {
		t.Fatal(err)
	}
	restored, err := openHostWatchdogStore(spec, f.v)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.db.Close()
	view, err := restored.publicSnapshot(ctx)
	if err != nil || !view.Frozen || !view.ObservedAt.IsZero() {
		t.Fatal("restored cache retained liveness or sending", view, err)
	}
	t.Log("HOST_WATCHDOG_KERNEL_VERIFIED: actual independent systemd/Unix peer authentication, signed helper API, PostgreSQL and VictoriaMetrics outages, real SMTP/Feishu local transport, grace/debounce, transaction freeze/commit/rollback/lost response, multi-process quota, schema43 terminal history and WAL snapshot/frozen restore")
}

type hostWatchdogLostReply struct{ http.RoundTripper }

func (r hostWatchdogLostReply) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := r.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return nil, io.ErrUnexpectedEOF
}
func TestHostWatchdogKernelQuotaProcess(t *testing.T) {
	path := os.Getenv("WEBSCAN_WATCHDOG_QUOTA_CONFIG")
	if path == "" {
		t.Skip("watchdog quota process child only")
	}
	hostWatchdogKernelGuard(t)
	c, e := LoadConfig(path)
	if e != nil {
		t.Fatal(e)
	}
	client, e := newHostQuotaClient(c)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10; i++ {
		out, e := client.Reserve(context.Background(), "email", token(), 1)
		if e != nil {
			t.Fatal(e)
		}
		if out.New {
			fmt.Println("WATCHDOG_QUOTA_GRANTED")
		}
	}
}
func TestHostWatchdogKernelDeniedPeer(t *testing.T) {
	socket := os.Getenv("WEBSCAN_WATCHDOG_DENIED_SOCKET")
	if socket == "" {
		t.Skip("watchdog denied peer child only")
	}
	if os.Getenv("WEBSCAN_V3_HOST_WATCHDOG_KERNEL") != "1" || os.Geteuid() != 65534 || !strings.HasPrefix(socket, "/run/webscan-watchdog-") {
		t.Fatal("refusing invalid peer child")
	}
	conn, e := net.DialTimeout("unix", socket, time.Second)
	if e != nil {
		t.Fatal("test did not reach actual listener", e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write([]byte("POST /v1/status HTTP/1.1\r\nHost: host\r\nContent-Length: 2\r\n\r\n{}"))
	raw := make([]byte, 128)
	n, e := conn.Read(raw)
	if n > 0 || e == nil {
		t.Fatal("different UID received application response")
	}
}
func hostWatchdogKernelSMTP(t *testing.T, certificate, key []byte) (int, *atomic.Int32) {
	t.Helper()
	pair, e := tls.X509KeyPair(certificate, key)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if e != nil {
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				write := func(s string) bool { _, e := conn.Write([]byte(s + "\r\n")); return e == nil }
				if !write("220 isolated watchdog SMTP") {
					return
				}
				for {
					line, e := reader.ReadString('\n')
					if e != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if !write("250-isolated\r\n250 AUTH PLAIN") {
							return
						}
					case strings.HasPrefix(line, "AUTH"):
						if !write("235 accepted") {
							return
						}
					case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
						if !write("250 accepted") {
							return
						}
					case strings.HasPrefix(line, "DATA"):
						if !write("354 continue") {
							return
						}
						if _, e := textproto.NewReader(reader).ReadDotBytes(); e != nil {
							return
						}
						count.Add(1)
						if !write("250 accepted") {
							return
						}
					default:
						write("221 closing")
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); workers.Wait() })
	return listener.Addr().(*net.TCPAddr).Port, count
}
