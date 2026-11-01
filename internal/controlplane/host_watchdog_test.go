package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/persist"
)

type watchdogFixture struct {
	store *hostWatchdogStore
	vault *Vault
	key   string
	spec  HostWatchdogSpec
}

func newWatchdogFixture(t *testing.T) watchdogFixture {
	t.Helper()
	v, key := testVault(t)
	root := privateTestDir(t)
	socketRoot, e := os.MkdirTemp("/tmp", "webscan-wd-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(socketRoot) })
	socketRoot, e = filepath.EvalSymlinks(socketRoot)
	if e != nil {
		t.Fatal(e)
	}
	spec := HostWatchdogSpec{Format: 1, Instance: "synthetic-watchdog", InstallationFile: filepath.Join(root, "install.json"), InstallationSHA256: strings.Repeat("a", 64), HostConfigFile: filepath.Join(root, "control.yaml"), HostConfigSHA256: strings.Repeat("d", 64), HelperFile: filepath.Join(root, "webscan"), HelperSHA256: strings.Repeat("b", 64), StateDirectory: filepath.Join(root, "state"), Socket: filepath.Join(socketRoot, "control.sock"), APIURL: "http://127.0.0.1:19445", MetricsURL: "http://127.0.0.1:18428"}
	s, err := openHostWatchdogStore(spec, v)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	return watchdogFixture{s, v, key, spec}
}
func watchdogSettings() []byte {
	return []byte(`{"email":{"enabled":true,"max_per_minute":20,"recipients":["synthetic@example.test"],"password":"PRIVATE_SYNTHETIC_TOKEN","notifications":{"health_failures":true,"health_recoveries":true}},"feishu":{"enabled":true,"rate_limit":{"max_per_second":1,"max_per_minute":20},"notifications":{"health_failures":true,"health_recoveries":true}}}`)
}
func (f watchdogFixture) activate(t *testing.T, raw []byte) {
	t.Helper()
	tx, err := persist.BeginWrite(context.Background(), f.store.db)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = f.store.activateTx(context.Background(), tx, hostPGSettings{Identity: strings.Repeat("c", 64), Version: 1, Raw: raw}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func (f watchdogFixture) client(t *testing.T, pg *sql.DB) *HostQuotaClient {
	t.Helper()
	service := &hostWatchdogService{store: f.store, pg: pg}
	server := httptest.NewServer(service)
	t.Cleanup(server.Close)
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &HostQuotaClient{spec: f.spec, vault: f.vault, http: &http.Client{Transport: transport, Timeout: 4 * time.Second}}
}
func TestHostWatchdogQuotaConcurrentReplayAndFailClosed(t *testing.T) {
	f := newWatchdogFixture(t)
	f.activate(t, watchdogSettings())
	ctx := context.Background()
	var granted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := f.store.reserve(ctx, hostQuotaInput{"email", token(), 1})
			if err != nil {
				t.Error(err)
			}
			if out.New {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()
	if granted.Load() != 20 {
		t.Fatalf("grants=%d", granted.Load())
	}
	f2 := newWatchdogFixture(t)
	f2.activate(t, watchdogSettings())
	key := token()
	first, err := f2.store.reserve(ctx, hostQuotaInput{"email", key, 1})
	if err != nil || !first.New {
		t.Fatal(first, err)
	}
	again, err := f2.store.reserve(ctx, hostQuotaInput{"email", key, 1})
	if err != nil || again.New || again.ID != first.ID {
		t.Fatal(again, err)
	}
	if _, err = f2.store.reserve(ctx, hostQuotaInput{"email", token(), 2}); !errors.Is(err, ErrHostSettingsFrozen) {
		t.Fatal(err)
	}
	if _, err = f2.store.db.Exec(`UPDATE host_state SET frozen=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = f2.store.reserve(ctx, hostQuotaInput{"email", token(), 1}); !errors.Is(err, ErrHostSettingsFrozen) {
		t.Fatal(err)
	}
	if _, err = f2.store.db.Exec(`UPDATE host_state SET frozen=0,last_clock=?`, float64(time.Now().Add(time.Minute).Unix())); err != nil {
		t.Fatal(err)
	}
	if _, err = f2.store.reserve(ctx, hostQuotaInput{"email", token(), 1}); !errors.Is(err, ErrHostQuota) {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(f2.spec.StateDirectory, "watchdog.sqlite3"))
	if err != nil || strings.Contains(string(raw), "PRIVATE_SYNTHETIC_TOKEN") {
		t.Fatal("SQLite plaintext secret", err)
	}
}
func TestHostWatchdogRPCAuthenticationAndProjection(t *testing.T) {
	f := newWatchdogFixture(t)
	f.activate(t, watchdogSettings())
	client := f.client(t, nil)
	ctx := context.Background()
	first, err := client.Reserve(ctx, "email", token(), 1)
	if err != nil || !first.New {
		t.Fatal(first, err)
	}
	if err = client.call(ctx, "/v1/status", common.Map{"unexpected": "PRIVATE"}, &HostWatchdogStatus{}); err == nil {
		t.Fatal("unknown input accepted")
	}
	status, err := client.Snapshot(ctx)
	if err != nil || status.RuntimeVersion != 1 || !status.ObservedAt.IsZero() {
		t.Fatal(status, err)
	}
	v, _ := testVault(t)
	client.vault = v
	if _, err = client.Snapshot(ctx); err == nil {
		t.Fatal("wrong HMAC accepted")
	}
	spec := f.spec
	spec.KeyID = f.vault.active
	spec.Proof, _ = hostSpecMAC(f.vault, spec)
	file := filepath.Join(privateTestDir(t), "watchdog.json")
	raw, _ := json.Marshal(spec)
	localWrite(t, file, raw)
	if _, err = loadHostSpec(file, f.vault); err != nil {
		t.Fatal(err)
	}
	spec.APIURL = "http://192.0.2.1:80"
	raw, _ = json.Marshal(spec)
	localWrite(t, file, raw)
	if _, err = loadHostSpec(file, f.vault); err == nil {
		t.Fatal("arbitrary target accepted")
	}
}

type watchdogMockSender struct {
	calls  int
	failed bool
}

func (s *watchdogMockSender) Send(_ context.Context, n *Notification) error {
	s.calls++
	if common.S(common.M(n.Settings["email"])["password"]) != "PRIVATE_SYNTHETIC_TOKEN" {
		return errors.New("missing confirmed synthetic config")
	}
	if s.failed {
		return errors.New("synthetic ambiguous receipt")
	}
	return nil
}
func TestHostWatchdogTransitionUnknownNeverResent(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "unknown"}[failed], func(t *testing.T) {
			f := newWatchdogFixture(t)
			raw := watchdogSettings()
			var root common.Map
			json.Unmarshal(raw, &root)
			root["feishu"] = common.Map{"enabled": false}
			raw = common.JSON(root)
			f.activate(t, raw)
			ctx := context.Background()
			for i := 0; i < 3; i++ {
				if err := f.store.transition(ctx, HostWatchdogCheck{Component: "api", State: "abnormal"}); err != nil {
					t.Fatal(err)
				}
			}
			sender := &watchdogMockSender{failed: failed}
			service := hostWatchdogService{store: f.store, sender: sender}
			if err := service.sendOne(ctx); err != nil {
				t.Fatal(err)
			}
			if err := service.sendOne(ctx); err != nil {
				t.Fatal(err)
			}
			if sender.calls != 1 {
				t.Fatal(sender.calls)
			}
			records, err := f.store.history(ctx)
			if err != nil || len(records) != 1 || records[0].State != map[bool]string{true: "unknown", false: "accepted"}[failed] {
				t.Fatal(records, err)
			}
			status, err := f.store.status(ctx)
			if err != nil || status.Pending != 0 {
				t.Fatal(status, err)
			}
			for i := 0; i < 2; i++ {
				if err = f.store.transition(ctx, HostWatchdogCheck{Component: "api", State: "normal"}); err != nil {
					t.Fatal(err)
				}
			}
			var queued int
			if f.store.db.QueryRow(`SELECT count(*) FROM outbox WHERE state='queued'`).Scan(&queued) != nil || queued != 1 {
				t.Fatal("recovery not queued", queued)
			}
		})
	}
}
func TestHostWatchdogInterruptedSendBecomesUnknown(t *testing.T) {
	f := newWatchdogFixture(t)
	f.activate(t, watchdogSettings())
	now := time.Now().Unix()
	id, attempt := token(), token()
	_, err := f.store.db.Exec(`INSERT INTO outbox(id,component,phase,created_at,channel,recipient,state,version) VALUES(?,'api','firing',?,'email','synthetic@example.test','sending',1)`, id, now)
	if err == nil {
		_, err = f.store.db.Exec(`INSERT INTO attempts(id,outbox,state,created_at) VALUES(?,?,'sending',?)`, attempt, id, now)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.store.db.Close()
	reopened, err := openHostWatchdogStore(f.spec, f.vault)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.db.Close()
	records, err := reopened.history(context.Background())
	if err != nil || len(records) != 1 || records[0].State != "unknown" {
		t.Fatal(records, err)
	}
}
func TestHostWatchdogSettingsCommitRollbackAndUncertainty(t *testing.T) {
	pg := testStore(t)
	if _, e := pg.DB.Exec(`INSERT INTO v3_cluster(id,payload) VALUES(1,'{"instance":"synthetic"}')`); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if _, err := pg.DB.Exec(`UPDATE v3_settings SET payload=$1::jsonb`, watchdogSettings()); err != nil {
		t.Fatal(err)
	}
	f := newWatchdogFixture(t)
	if err := f.store.initializeSettings(ctx, pg.DB); err != nil {
		t.Fatal(err)
	}
	client := f.client(t, pg.DB)
	tx, err := pg.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	prep, err := client.PrepareSettings(ctx, tx, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Reserve(ctx, "email", token(), 1); !errors.Is(err, ErrHostSettingsFrozen) {
		t.Fatal(err)
	}
	waiting, err := client.ResolveSettings(ctx, prep.ID)
	if err != nil || waiting.State != "frozen" {
		t.Fatal(waiting, err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v3_settings SET version=2,payload=jsonb_set(payload,'{email,max_per_minute}','10')`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	resolved, err := client.ResolveSettings(ctx, prep.ID)
	if err != nil || resolved.State != "committed" || resolved.RuntimeVersion != 2 {
		t.Fatal(resolved, err)
	}
	tx, err = pg.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	prep, err = client.PrepareSettings(ctx, tx, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	resolved, err = client.ResolveSettings(ctx, prep.ID)
	if err != nil || resolved.State != "aborted" || resolved.RuntimeVersion != 2 {
		t.Fatal(resolved, err)
	}
	tx, err = pg.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	prep, err = client.PrepareSettings(ctx, tx, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v3_settings SET version=4`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = client.ResolveSettings(ctx, prep.ID); !errors.Is(err, ErrHostSettingsFrozen) {
		t.Fatal("mismatched committed version unfroze", err)
	}
}
func TestHostWatchdogHistoryImportsIdempotently(t *testing.T) {
	pg := testStore(t)
	f := newWatchdogFixture(t)
	f.activate(t, watchdogSettings())
	ctx := context.Background()
	now := time.Now().Unix()
	id, attempt := token(), token()
	_, err := f.store.db.Exec(`INSERT INTO outbox(id,component,phase,created_at,channel,recipient,state,version) VALUES(?,'api','firing',?,'email','synthetic@example.test','unknown',1)`, id, now)
	if err == nil {
		_, err = f.store.db.Exec(`INSERT INTO attempts(id,outbox,state,created_at,finished_at) VALUES(?,?,'unknown',?,?)`, attempt, id, now, now)
	}
	if err != nil {
		t.Fatal(err)
	}
	client := f.client(t, pg.DB)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := SyncHostWatchdogHistory(ctx, pg, client); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var attempts, notices, mappings int
	if err = pg.DB.QueryRow(`SELECT (SELECT count(*) FROM v3_notification_attempts),(SELECT count(*) FROM v3_notifications),(SELECT count(*) FROM v3_host_notification_imports)`).Scan(&attempts, &notices, &mappings); err != nil || attempts != 1 || notices != 1 || mappings != 1 {
		t.Fatal(attempts, notices, mappings, err)
	}
	var notification int64
	if err = pg.DB.QueryRow(`SELECT notification FROM v3_host_notification_imports WHERE local_id=$1`, id).Scan(&notification); err != nil {
		t.Fatal(err)
	}
	detail, err := pg.NotificationDetail(ctx, string(commonJSONInt(notification)))
	if err != nil || detail.Outcome.Code != "unknown" || detail.Notification.Source != "server_health" {
		t.Fatal(detail, err)
	}
	if n, err := pg.claimNotification(ctx, "email", "synthetic-history-test"); err != nil || n != nil {
		t.Fatal("imported terminal notice was sent again", n, err)
	}
}
func TestHostWatchdogConsistentBackupAndFrozenRestore(t *testing.T) {
	f := newWatchdogFixture(t)
	f.activate(t, watchdogSettings())
	ctx := context.Background()
	cfg := Config{HostWatchdog: HostWatchdogConfig{Enabled: true, StateDirectory: f.spec.StateDirectory, Socket: f.spec.Socket}}
	snapshot := filepath.Join(privateTestDir(t), "snapshot.sqlite3")
	if _, err := f.store.reserve(ctx, hostQuotaInput{"email", token(), 1}); err != nil {
		t.Fatal(err)
	}
	result, err := BackupHostWatchdog(ctx, cfg, snapshot)
	if err != nil || result.SHA256 == "" || result.Size < 1 {
		t.Fatal(result, err)
	}
	// Snapshot and live DB remain independent while WAL writes continue.
	if _, err = f.store.reserve(ctx, hostQuotaInput{"email", token(), 1}); err != nil {
		t.Fatal(err)
	}
	backup, err := persist.OpenReadOnly(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = backup.QueryRow(`SELECT count(*) FROM quota`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	backup.Close()
	spec := f.spec
	spec.StateDirectory = filepath.Join(privateTestDir(t), "restored")
	spec.Socket = filepath.Join(filepath.Dir(f.spec.Socket), "restore.sock")
	spec.KeyID = f.vault.active
	spec.Proof, _ = hostSpecMAC(f.vault, spec)
	raw, _ := json.Marshal(spec)
	specFile := filepath.Join(privateTestDir(t), "watchdog.json")
	localWrite(t, specFile, raw)
	cfg.HostWatchdog.StateDirectory, cfg.HostWatchdog.Socket, cfg.HostWatchdog.SpecFile = spec.StateDirectory, spec.Socket, specFile
	cfg.DeploymentTrust.VaultKeyFile = f.key
	if err = RestoreHostWatchdog(ctx, cfg, snapshot); err != nil {
		t.Fatal(err)
	}
	restored, err := openHostWatchdogStore(spec, f.vault)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.db.Close()
	status, err := restored.status(ctx)
	if err != nil || !status.Frozen || status.Reason != "restored_requires_reconciliation" {
		t.Fatal(status, err)
	}
	if _, err = restored.reserve(ctx, hostQuotaInput{"email", token(), 1}); !errors.Is(err, ErrHostSettingsFrozen) {
		t.Fatal(err)
	}
	if err = RestoreHostWatchdog(ctx, cfg, snapshot); err == nil {
		t.Fatal("existing state overwritten")
	}
}

func TestHostWatchdogMaintenanceIsFiniteAndComponentSpecific(t *testing.T) {
	f := newWatchdogFixture(t)
	f.activate(t, watchdogSettings())
	ctx := context.Background()
	client := f.client(t, nil)
	operation := token()
	if err := client.BeginMaintenance(ctx, operation, "api", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := client.BeginMaintenance(ctx, operation, "all", time.Minute); err == nil {
		t.Fatal("global suppression accepted")
	}
	if err := client.BeginMaintenance(ctx, operation, "api", time.Hour); err == nil {
		t.Fatal("unbounded suppression accepted")
	}
	for i := 0; i < 3; i++ {
		for _, component := range []string{"api", "postgres"} {
			if err := f.store.transition(ctx, HostWatchdogCheck{Component: component, State: "abnormal"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	var api, pg int
	if err := f.store.db.QueryRow(`SELECT sum(component='api'),sum(component='postgres') FROM outbox`).Scan(&api, &pg); err != nil || api != 0 || pg != 2 {
		t.Fatal(api, pg, err)
	}
	if err := f.store.recordSnapshot(ctx, []HostWatchdogCheck{{Component: "api", State: "abnormal", Reason: "health_endpoint_unavailable"}}, HostWatchdogEnvironment{}); err != nil {
		t.Fatal(err)
	}
	status, err := client.Snapshot(ctx)
	if err != nil || len(status.Checks) != 1 || status.Checks[0].State != "abnormal" {
		t.Fatal(status, err)
	}
	if err = client.EndMaintenance(ctx, operation, "api"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err = f.store.transition(ctx, HostWatchdogCheck{Component: "api", State: "abnormal"}); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.store.db.QueryRow(`SELECT count(*) FROM outbox WHERE component='api'`).Scan(&api); err != nil || api != 2 {
		t.Fatal(api, err)
	}
}
func TestHostWatchdogConsumedResponseNeverTriggersSend(t *testing.T) {
	f := newWatchdogFixture(t)
	f.activate(t, watchdogSettings())
	ctx := context.Background()
	id := token()
	now := time.Now().Unix()
	if _, err := f.store.db.Exec(`INSERT INTO outbox(id,component,phase,created_at,channel,recipient,state,version) VALUES(?,'api','firing',?,'email','synthetic@example.test','queued',1)`, id, now); err != nil {
		t.Fatal(err)
	}
	if grant, err := f.store.reserve(ctx, hostQuotaInput{"email", "watchdog:" + id, 1}); err != nil || !grant.New {
		t.Fatal(grant, err)
	}
	sender := &watchdogMockSender{}
	service := hostWatchdogService{store: f.store, sender: sender}
	if err := service.sendOne(ctx); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 0 {
		t.Fatal("replayed consumed reservation sent", sender.calls)
	}
	records, err := f.store.history(ctx)
	if err != nil || len(records) != 1 || records[0].State != "unknown" {
		t.Fatal(records, err)
	}
}
func TestHostWatchdogDisabledQueueDoesNotBlockOtherChannel(t *testing.T) {
	f := newWatchdogFixture(t)
	raw := watchdogSettings()
	var root common.Map
	json.Unmarshal(raw, &root)
	root["feishu"] = common.Map{"enabled": false}
	f.activate(t, common.JSON(root))
	ctx := context.Background()
	now := time.Now().Unix()
	for _, channel := range []string{"feishu", "email"} {
		if _, err := f.store.db.Exec(`INSERT INTO outbox(id,component,phase,created_at,channel,recipient,state,version) VALUES(?,'api','firing',?,?,'synthetic@example.test','queued',1)`, token(), now, channel); err != nil {
			t.Fatal(err)
		}
		now++
	}
	sender := &watchdogMockSender{}
	service := hostWatchdogService{store: f.store, sender: sender}
	if err := service.sendOne(ctx); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 1 {
		t.Fatal(sender.calls)
	}
}
