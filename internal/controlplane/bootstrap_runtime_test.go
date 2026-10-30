package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/common"
)

func dropBootstrapRuntimeForTest(t *testing.T, s *Store) {
	t.Helper()
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE IF EXISTS v3_deployment_recoveries;DROP TABLE IF EXISTS v3_deployment_installations;DROP TABLE IF EXISTS v3_node_provisioning;DROP TABLE v3_configuration_application_registrations;DROP TABLE v3_configuration_application_nodes;DROP TABLE v3_configuration_application_targets;DROP TABLE v3_configuration_operation_gate;DELETE FROM v3_schema WHERE version>=25`)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_bootstrap_processes;DROP TABLE v3_bootstrap_handoffs;DELETE FROM v3_schema WHERE version>=24`)
}

type bootstrapServeTest struct {
	cancel context.CancelFunc
	done   chan error
	waited bool
}

func startBootstrapServeForTest(t *testing.T, s *Store, c Config, role string, activation int64) *bootstrapServeTest {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	run := &bootstrapServeTest{cancel: cancel, done: make(chan error, 1)}
	go func() { run.done <- Serve(ctx, c, role) }()
	t.Cleanup(func() {
		cancel()
		if !run.waited {
			select {
			case err := <-run.done:
				run.waited = true
				if err != nil && !errors.Is(err, errBootstrapRestart) {
					t.Error("server cleanup", err)
				}
			case <-time.After(15 * time.Second):
				t.Error("server did not stop")
			}
		}
	})
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		var count int
		err := s.DB.QueryRow(`SELECT count(*) FROM v3_bootstrap_processes WHERE member=$1 AND role=$2 AND activation=$3 AND NOT ended`, c.Central.Instance, role, activation).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			return run
		}
		select {
		case err := <-run.done:
			run.waited = true
			t.Fatal("server stopped before role readiness", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("server readiness timeout")
	return run
}
func waitBootstrapRestartForTest(t *testing.T, run *bootstrapServeTest) {
	t.Helper()
	select {
	case err := <-run.done:
		run.waited = true
		if !errors.Is(err, errBootstrapRestart) {
			t.Fatal("expected restart handoff", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("old process did not exit")
	}
}

func bootstrapApplicationFixture(t *testing.T, change bool, configure ...func(*Config)) (*Store, configurationLocalFixture, privateConfigurationApplication) {
	t.Helper()
	return bootstrapApplicationFixtureDocument(t, change, nil, configure...)
}

func bootstrapApplicationFixtureDocument(t *testing.T, change bool, edit func(*Store, configurationLocalFixture, *configurationDocument), configure ...func(*Config)) (*Store, configurationLocalFixture, privateConfigurationApplication) {
	t.Helper()
	s, f := newSavedConfigurationStore(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.c.Central.Listen = l.Addr().String()
	_ = l.Close()
	for _, edit := range configure {
		edit(&f.c)
	}
	localWrite(t, f.c.Database.DSNFile, environmentDSN(t, s))
	doc := f.document(t)
	if change {
		common.M(doc.Bootstrap["collector"])["concurrency"] = 32
	}
	if edit != nil {
		edit(s, f, &doc)
	}
	// A custom document explicitly tests replacement of credential references;
	// the ordinary fixture retains the default keep-current restore policy.
	stage, revision := savedRestoreFromDocumentOptions(t, s, f, doc, configurationRestoreOptions{UseBackupCredentials: edit != nil})
	raw, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "bootstrap-save", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	raw, err = s.queueConfigurationApplication(context.Background(), f.v, f.c, "admin", "bootstrap-queue", stage.ID, revision.Generation)
	_ = applicationReceipt(t, raw, err)
	// Only preceding journal phases are synthetic. Actual Serve, listener,
	// process receipts, startup configuration and restarts are exercised below.
	for i := 0; i < 2; i++ {
		j := claimApplicationForTest(t, s, f, "bootstrap-setup")
		if i > 0 {
			j, err = s.armConfigurationApplication(context.Background(), f.v, j)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err = s.checkpointConfigurationApplication(context.Background(), f.v, j, applicationComplete(j)); err != nil {
			t.Fatal(err)
		}
	}
	j := claimApplicationForTest(t, s, f, "bootstrap-controller")
	j, err = s.armConfigurationApplication(context.Background(), f.v, j)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, j
}
func bootstrapHTTPClient(t *testing.T, f configurationLocalFixture) *http.Client {
	t.Helper()
	ca, err := os.ReadFile(f.c.Collector.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("bad fixture CA")
	}
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "monitor.example.test", MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}
func waitBootstrapConfirmed(t *testing.T, r configurationBootstrapRuntime, j privateConfigurationApplication) configurationApplicationCheckpoint {
	t.Helper()
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		p, err := r.InspectConfigurationPhase(context.Background(), j)
		if err != nil {
			t.Fatal("inspect handoff", err)
		}
		if p.State == "complete" {
			return p
		}
		if p.State != "pending" {
			t.Fatal("unexpected handoff state", p.State)
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("handoff not confirmed")
	return configurationApplicationCheckpoint{}
}

func TestBootstrapRuntimeActualServeRestartAndSessionPreservation(t *testing.T) {
	s, f, j := bootstrapApplicationFixture(t, true)
	ctx := context.Background()
	first := startBootstrapServeForTest(t, s, f.c, "api", 0)
	client := bootstrapHTTPClient(t, f)
	response, err := client.Get("https://" + f.c.Central.Listen + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("listener not serving")
	}
	if response.ProtoMajor != 2 {
		t.Fatal("TLS listener lost HTTP/2", response.Proto)
	}
	secret := token()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'admin',1,'bootstrap-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(secret)))
	r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
	if p, err := r.InspectConfigurationPhase(ctx, j); err != nil || p.State != "absent" {
		t.Fatal("pre-inspection", err)
	}
	if tableCount(t, s, "v3_bootstrap_handoffs") != 0 {
		t.Fatal("inspection approved restart")
	}
	p, err := r.ApplyConfigurationPhase(ctx, j)
	if err != nil || p.State != "pending" {
		t.Fatal("approve handoff", err)
	}
	if p.matches(j) {
		t.Fatal("restart request marked complete")
	}
	if d, err := bootstrapStateForTest(s, f.v, f.c); err != nil || !d.Pending {
		t.Fatal("approval prematurely marked applied", err)
	}
	waitBootstrapRestartForTest(t, first)
	var activation int64
	if err = s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&activation); err != nil {
		t.Fatal(err)
	}
	_ = startBootstrapServeForTest(t, s, f.c, "api", activation)
	p = waitBootstrapConfirmed(t, r, j)
	effective, actual, _, err := s.resolveBootstrap(ctx, f.c)
	if err != nil || effective.Collector.Concurrency != 32 || actual != activation {
		t.Fatal("new process did not load approved configuration", err)
	}
	if d, err := bootstrapStateForTest(s, f.v, effective); err != nil || d.Pending {
		t.Fatal("fresh process did not confirm generation", err)
	}
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, j, p); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://"+f.c.Central.Listen+"/api/v3/session", nil)
	req.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: secret})
	response, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || !json.Valid(raw) {
		t.Fatal("session lost across actual server restart", response.StatusCode)
	}
	req, _ = http.NewRequest("POST", "https://"+f.c.Central.Listen+"/api/v3/logout", nil)
	req.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: secret})
	req.Header.Set("X-CSRF-Token", "bootstrap-csrf")
	response, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || tableCount(t, s, "v3_sessions") != 0 {
		t.Fatal("persisted session CSRF/logout failed", response.StatusCode)
	}
	if tableCount(t, s, "v3_notifications") != 0 || tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("bootstrap created unrelated work")
	}
}

func TestBootstrapRuntimeActualRollbackAfterConfirmedOrPendingRestart(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "confirmed"}[confirmed], func(t *testing.T) {
			s, f, j := bootstrapApplicationFixture(t, true)
			ctx := context.Background()
			old := startBootstrapServeForTest(t, s, f.c, "api", 0)
			r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
			if p, err := r.ApplyConfigurationPhase(ctx, j); err != nil || p.State != "pending" {
				t.Fatal(err)
			}
			waitBootstrapRestartForTest(t, old)
			var forward int64
			if err := s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&forward); err != nil {
				t.Fatal(err)
			}
			var running *bootstrapServeTest
			if confirmed {
				running = startBootstrapServeForTest(t, s, f.c, "api", forward)
				_ = waitBootstrapConfirmed(t, r, j)
			}
			mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('recovery-admin','not-login','admin')`)
			if err := s.failConfigurationApplication(ctx, f.v, j, "interrupted"); err != nil {
				t.Fatal(err)
			}
			mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer',revision=revision+1 WHERE username='admin'`)
			if _, err := s.controlConfigurationApplication(ctx, f.v, "recovery-admin", "bootstrap-rollback", j.ID, "rollback"); err != nil {
				t.Fatal(err)
			}
			j = claimApplicationForTest(t, s, f, "rollback-settings")
			settings := configurationSettingsRuntime{s, f.v, f.c}
			p, err := settings.ApplyConfigurationPhase(ctx, j)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.checkpointConfigurationApplication(ctx, f.v, j, p); err != nil {
				t.Fatal(err)
			}
			j = claimApplicationForTest(t, s, f, "rollback-bootstrap")
			if p, err = r.ApplyConfigurationPhase(ctx, j); err != nil || p.State != "pending" {
				t.Fatal("rollback approval", err)
			}
			if running != nil {
				waitBootstrapRestartForTest(t, running)
			}
			var rollback int64
			if err = s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&rollback); err != nil {
				t.Fatal(err)
			}
			if rollback <= forward {
				t.Fatal("rollback reused old activation")
			}
			_ = startBootstrapServeForTest(t, s, f.c, "api", rollback)
			_ = waitBootstrapConfirmed(t, r, j)
			effective, _, _, err := s.resolveBootstrap(ctx, f.c)
			if err != nil || effective.Collector.Concurrency != f.c.Collector.Concurrency {
				t.Fatal("rollback did not restore original runtime", err)
			}
			d, err := bootstrapStateForTest(s, f.v, effective)
			if err != nil || !d.Pending || common.I(common.M(d.Desired["collector"])["concurrency"]) != 32 {
				t.Fatal("rollback lost pending desired configuration", err)
			}
		})
	}
}

func TestBootstrapRuntimeNoChangeDoesNotRestartActualServer(t *testing.T) {
	s, f, j := bootstrapApplicationFixture(t, false)
	server := startBootstrapServeForTest(t, s, f.c, "api", 0)
	r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
	if p, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil || !p.matches(j) {
		t.Fatal("no-change phase", err)
	}
	if tableCount(t, s, "v3_bootstrap_handoffs") != 0 {
		t.Fatal("no change created restart override")
	}
	select {
	case err := <-server.done:
		server.waited = true
		t.Fatal("unchanged bootstrap stopped server", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestBootstrapRuntimeSchema23UpgradeRequiresBackup(t *testing.T) {
	s := testStore(t)
	dropBootstrapRuntimeForTest(t, s)
	if err := s.Migrate(context.Background()); err == nil {
		t.Fatal("upgraded without backup")
	}
	bad := filepath.Join(privateTestDir(t), "not-directory")
	localWrite(t, bad, []byte("file"))
	if err := s.Upgrade(context.Background(), bad); err == nil {
		t.Fatal("backup failure ignored")
	}
	if version, err := currentSchema(context.Background(), s.DB); err != nil || version != 23 {
		t.Fatal("failed backup changed schema", version, err)
	}
	if err := s.Upgrade(context.Background(), privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	var exists sql.NullString
	if err := s.DB.QueryRow(`SELECT to_regclass(current_schema()||'.v3_bootstrap_handoffs')::text`).Scan(&exists); err != nil || !exists.Valid {
		t.Fatal("no handoff schema", err)
	}
}

func TestBootstrapRuntimeReadinessWaitsForEveryComponent(t *testing.T) {
	ctx, ready := withStartupReadiness(context.Background(), "all", true)
	for _, component := range []string{"api", "collector", "notify-email", "notify-feishu", "website-notifications", "server-health", "websites"} {
		runtimeReady(ctx, component)
		select {
		case <-ready:
			t.Fatal("readiness omitted executor")
		default:
		}
	}
	runtimeReady(ctx, "executor")
	select {
	case <-ready:
	default:
		t.Fatal("ready roles not signalled")
	}
	runtimeReady(ctx, "executor")
}

func TestBootstrapRuntimeActualAllRoleInitializationAndRestart(t *testing.T) {
	s, f, j := bootstrapApplicationFixture(t, true, func(c *Config) {
		c.Executor.Enabled = false
		c.Collector.Shards = 1
	})
	old := startBootstrapServeForTest(t, s, f.c, "all", 0)
	r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
	if p, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil || p.State != "pending" {
		t.Fatal("all-role handoff", err)
	}
	waitBootstrapRestartForTest(t, old)
	var revision int64
	if err := s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	_ = startBootstrapServeForTest(t, s, f.c, "all", revision)
	_ = waitBootstrapConfirmed(t, r, j)
	for _, table := range []string{"v3_notifications", "v3_website_outbox", "v3_deployment_jobs", "v3_nodes", "v3_websites"} {
		if tableCount(t, s, table) != 0 {
			t.Fatal("empty role fixture created business work", table)
		}
	}
}

func TestBootstrapRuntimeRejectsDriftOrLostAuthority(t *testing.T) {
	for _, kind := range []string{"generation", "desired", "draft-proof", "source-proof", "archive-pin", "account", "lease", "hold", "member", "rewritten-member-hint", "wrong-phase", "migration"} {
		t.Run(kind, func(t *testing.T) {
			s, f, j := bootstrapApplicationFixture(t, true)
			r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
			switch kind {
			case "generation":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_drafts SET generation=generation+1`)
			case "desired":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_drafts SET payload='{}'`)
			case "draft-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_drafts SET proof='forged'`)
			case "source-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET proof='forged'`)
			case "archive-pin":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins`)
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "lease":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second'`)
			case "hold":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET recovery_hold=true`)
			case "member":
				r.launch.Central.Instance = "different-member"
			case "rewritten-member-hint":
				r.launch.Central.Instance = "different-member"
				r.bootstrap.Central.Instance = "different-member"
				j.member = "different-member"
			case "wrong-phase":
				j.step = 3
			case "migration":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('events',$1)`, token())
			}
			if _, err := r.InspectConfigurationPhase(context.Background(), j); err == nil {
				t.Fatal("bad inspection accepted", kind)
			}
			if _, err := r.ApplyConfigurationPhase(context.Background(), j); err == nil {
				t.Fatal("bad approval accepted", kind)
			}
			if tableCount(t, s, "v3_bootstrap_handoffs") != 0 {
				t.Fatal("invalid authority approved restart")
			}
		})
	}
}

func TestBootstrapRuntimeRejectsCorruptHandoffAndLaunchDrift(t *testing.T) {
	for _, kind := range []string{"ciphertext", "confirmation", "approval-time", "launch", "key", "process-proof", "process-ended", "missing-confirmed-handoff"} {
		t.Run(kind, func(t *testing.T) {
			s, f, j := bootstrapApplicationFixture(t, true)
			old := startBootstrapServeForTest(t, s, f.c, "api", 0)
			r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
			if _, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			waitBootstrapRestartForTest(t, old)
			switch kind {
			case "ciphertext":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_handoffs SET ciphertext=set_byte(ciphertext,0,get_byte(ciphertext,0)#1)`)
			case "confirmation":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_handoffs SET confirmation='forged'`)
			case "approval-time":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_handoffs SET created_at=created_at-interval '1 hour'`)
			case "launch":
				f.c.Collector.Concurrency++
			case "key":
				if err := os.Remove(f.c.DeploymentTrust.VaultKeyFile); err != nil {
					t.Fatal(err)
				}
			case "process-proof", "process-ended", "missing-confirmed-handoff":
				var revision int64
				if err := s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&revision); err != nil {
					t.Fatal(err)
				}
				running := startBootstrapServeForTest(t, s, f.c, "api", revision)
				if kind == "process-proof" || kind == "process-ended" {
					if kind == "process-proof" {
						mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_processes SET proof='forged' WHERE NOT ended`)
					} else {
						mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_processes SET ended=true WHERE NOT ended`)
					}
					if _, err := r.InspectConfigurationPhase(context.Background(), j); err == nil {
						t.Fatal("forged process confirmed activation")
					}
					// A deliberately corrupted receipt also prevents signed shutdown.
					running.cancel()
					select {
					case <-running.done:
						running.waited = true
					case <-time.After(10 * time.Second):
						t.Fatal("corrupt process did not stop")
					}
					return
				}
				_ = waitBootstrapConfirmed(t, r, j)
				running.cancel()
				select {
				case err := <-running.done:
					running.waited = true
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("confirmed process did not stop")
				}
				mustHistoryExec(t, s.DB, `DELETE FROM v3_bootstrap_handoffs`)
			}
			if _, _, _, err := s.resolveBootstrap(context.Background(), f.c); err == nil {
				t.Fatal("invalid startup silently loaded", kind)
			}
		})
	}
}

func TestBootstrapRuntimeApprovalAndConfirmationFailuresAreAtomic(t *testing.T) {
	for _, target := range []string{"v3_bootstrap_handoffs", "v3_audit", "v3_bootstrap_drafts"} {
		t.Run(target, func(t *testing.T) {
			s, f, j := bootstrapApplicationFixture(t, true)
			old := startBootstrapServeForTest(t, s, f.c, "api", 0)
			r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
			if target != "v3_bootstrap_drafts" {
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic-bootstrap-failure';END$$;CREATE TRIGGER fail_bootstrap BEFORE INSERT ON `+target+` FOR EACH ROW EXECUTE FUNCTION fail_bootstrap()`)
				if _, err := r.ApplyConfigurationPhase(context.Background(), j); err == nil {
					t.Fatal("approval failure ignored")
				}
				if tableCount(t, s, "v3_bootstrap_handoffs") != 0 {
					t.Fatal("partial handoff committed")
				}
				mustHistoryExec(t, s.DB, `DROP TRIGGER fail_bootstrap ON `+target+`;DROP FUNCTION fail_bootstrap()`)
			}
			if p, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil || p.State != "pending" {
				t.Fatal("approval retry", err)
			}
			waitBootstrapRestartForTest(t, old)
			var revision int64
			if err := s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&revision); err != nil {
				t.Fatal(err)
			}
			_ = startBootstrapServeForTest(t, s, f.c, "api", revision)
			mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic-bootstrap-failure';END$$;CREATE TRIGGER fail_bootstrap BEFORE INSERT OR UPDATE ON `+target+` FOR EACH ROW EXECUTE FUNCTION fail_bootstrap()`)
			if _, err := r.InspectConfigurationPhase(context.Background(), j); err == nil {
				t.Fatal("confirmation failure ignored")
			}
			var confirmed bool
			if err := s.DB.QueryRow(`SELECT confirmation<>'' FROM v3_bootstrap_handoffs`).Scan(&confirmed); err != nil || confirmed {
				t.Fatal("partial confirmation committed", err)
			}
			if d, err := bootstrapStateForTest(s, f.v, f.c); err != nil || !d.Pending {
				t.Fatal("failed confirmation advanced marker", err)
			}
			mustHistoryExec(t, s.DB, `DROP TRIGGER fail_bootstrap ON `+target)
			_ = waitBootstrapConfirmed(t, r, j)
		})
	}
}

// Declaring unused phases is confined to this runner test. Only the real
// bootstrap adapter is executed; it is not a full application implementation.
type bootstrapRunnerTestRuntime struct{ configurationBootstrapRuntime }

func (bootstrapRunnerTestRuntime) SupportsConfigurationPhase(string) bool { return true }

func TestBootstrapRuntimeRunnerPendingTakeoverDoesNotLoseRecovery(t *testing.T) {
	s, f, j := bootstrapApplicationFixture(t, true)
	old := startBootstrapServeForTest(t, s, f.c, "api", 0)
	r := bootstrapRunnerTestRuntime{configurationBootstrapRuntime{s, f.v, f.c, f.c}}
	if err := s.executeConfigurationApplication(context.Background(), f.v, j, r); !errors.Is(err, errBootstrapHandoff) {
		t.Fatal("runner did not preserve pending handoff", err)
	}
	pending := privateApplicationForTest(t, s, f.v, j.ID)
	if pending.step != j.step || pending.Status != "running" || !pending.RecoveryRequired {
		t.Fatal("pending handoff lost checkpoint or recovery responsibility")
	}
	waitBootstrapRestartForTest(t, old)
	var revision int64
	if err := s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	_ = startBootstrapServeForTest(t, s, f.c, "api", revision)
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second'`)
	next := claimApplicationForTest(t, s, f, "new-bootstrap-owner")
	if next.epoch <= j.epoch {
		t.Fatal("takeover reused old epoch")
	}
	if _, err := r.InspectConfigurationPhase(context.Background(), j); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old owner retained authority", err)
	}
	if err := s.executeConfigurationApplication(context.Background(), f.v, next, r); err != nil {
		t.Fatal("new owner could not inspect committed handoff", err)
	}
	current := privateApplicationForTest(t, s, f.v, j.ID)
	if current.step != j.step+1 || !current.RecoveryRequired || tableCount(t, s, "v3_bootstrap_handoffs") != 1 {
		t.Fatal("takeover duplicated handoff or falsely finished application")
	}
}

func TestBootstrapRuntimeChangedListenerProbePreservesExistingProcess(t *testing.T) {
	f := newConfigurationLocalFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	before, err := configurationBootstrapValues(f.c)
	if err != nil {
		t.Fatal(err)
	}
	f.c.Central.Listen = listener.Addr().String()
	target, err := configurationBootstrapValues(f.c)
	if err != nil {
		t.Fatal(err)
	}
	p := bootstrapHandoffPayload{Before: before, Target: target, RequiredRoles: []string{"api"}}
	if err := checkBootstrapListener(p); err == nil {
		t.Fatal("occupied changed listener accepted")
	}
	if err := listener.Close(); err != nil {
		t.Fatal("probe disturbed original listener", err)
	}
	if err := checkBootstrapListener(p); err != nil {
		t.Fatal("available changed listener rejected", err)
	}
}

func TestBootstrapRuntimeLeaseExpiredDuringWriteRollsBack(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		t.Run(map[bool]string{false: "approval", true: "confirmation"}[confirm], func(t *testing.T) {
			s, f, j := bootstrapApplicationFixture(t, true)
			old := startBootstrapServeForTest(t, s, f.c, "api", 0)
			r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
			operation := "INSERT"
			if confirm {
				if _, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil {
					t.Fatal(err)
				}
				waitBootstrapRestartForTest(t, old)
				var revision int64
				if err := s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&revision); err != nil {
					t.Fatal(err)
				}
				_ = startBootstrapServeForTest(t, s, f.c, "api", revision)
				operation = "UPDATE"
			}
			mustHistoryExec(t, s.DB, `CREATE FUNCTION delay_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(0.4);RETURN NEW;END$$;CREATE TRIGGER delay_bootstrap BEFORE `+operation+` ON v3_bootstrap_handoffs FOR EACH ROW EXECUTE FUNCTION delay_bootstrap();UPDATE v3_configuration_applications SET lease_until=clock_timestamp()+interval '0.2 seconds'`)
			var err error
			if confirm {
				_, err = r.InspectConfigurationPhase(context.Background(), j)
			} else {
				_, err = r.ApplyConfigurationPhase(context.Background(), j)
			}
			if !errors.Is(err, ErrLeaseLost) {
				t.Fatal("expired write retained authority", err)
			}
			var count int
			if err := s.DB.QueryRow(`SELECT count(*) FROM v3_bootstrap_handoffs WHERE confirmation<>''`).Scan(&count); err != nil || count != 0 {
				t.Fatal("expired confirmation committed", err)
			}
			if !confirm && tableCount(t, s, "v3_bootstrap_handoffs") != 0 {
				t.Fatal("expired approval committed")
			}
			if d, err := bootstrapStateForTest(s, f.v, f.c); err != nil || !d.Pending {
				t.Fatal("expired write advanced draft", err)
			}
		})
	}
}

func TestBootstrapRuntimeDisasterRestoreRequiresFreshProcessAndExplicitRecovery(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "confirmed"}[confirmed], func(t *testing.T) {
			s, f, j := bootstrapApplicationFixture(t, true)
			old := startBootstrapServeForTest(t, s, f.c, "api", 0)
			r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
			if _, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			waitBootstrapRestartForTest(t, old)
			var revision int64
			if err := s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&revision); err != nil {
				t.Fatal(err)
			}
			running := startBootstrapServeForTest(t, s, f.c, "api", revision)
			if confirmed {
				_ = waitBootstrapConfirmed(t, r, j)
			}
			path, err := s.BackupPostgres(context.Background(), privateTestDir(t))
			if err != nil {
				t.Fatal(err)
			}
			running.cancel()
			select {
			case err := <-running.done:
				running.waited = true
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("source server did not stop")
			}
			target := emptyTestStore(t)
			if err := target.RestorePostgres(context.Background(), path); err != nil {
				t.Fatal(err)
			}
			if tableCount(t, target, "v3_bootstrap_processes") != 0 {
				t.Fatal("restore trusted archived process heartbeat")
			}
			localWrite(t, f.c.Database.DSNFile, environmentDSN(t, target))
			effective, activation, _, err := target.resolveBootstrap(context.Background(), f.c)
			if !confirmed {
				if err == nil {
					t.Fatal("pending handoff bypassed disaster recovery hold")
				}
				if _, err := target.controlConfigurationApplication(context.Background(), f.v, "admin", "explicit-bootstrap-resume", j.ID, "resume"); err != nil {
					t.Fatal("explicit resume", err)
				}
				effective, activation, _, err = target.resolveBootstrap(context.Background(), f.c)
			}
			if err != nil || activation != revision || effective.Collector.Concurrency != 32 {
				t.Fatal("authenticated restored configuration unavailable", err)
			}
			if tableCount(t, target, "v3_bootstrap_processes") != 0 {
				t.Fatal("resolution fabricated live process")
			}
		})
	}
}

func TestBootstrapRuntimeHousekeepingOnlyRemovesStaleProcesses(t *testing.T) {
	s := testStore(t)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_bootstrap_processes(instance,member,role,activation,launch_digest,runtime_digest,proof,heartbeat,ended) VALUES('old-process','member','api',0,'launch','runtime','proof',clock_timestamp()-interval '2 days',true),('fresh-process','member','api',0,'launch','runtime','proof',clock_timestamp(),false)`)
	if err := s.Housekeeping(context.Background(), "bootstrap-cleaner"); err != nil {
		t.Fatal(err)
	}
	var instance string
	if err := s.DB.QueryRow(`SELECT instance FROM v3_bootstrap_processes`).Scan(&instance); err != nil || instance != "fresh-process" {
		t.Fatal("housekeeping removed fresh role evidence", err)
	}
}

func TestBootstrapRuntimeObserverExitDoesNotClaimWorkersDrained(t *testing.T) {
	s, f := newSavedConfigurationStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	close(ready)
	done := make(chan error, 1)
	instance := runtimeInstance(f.c.Central.Instance)
	go func() { done <- s.runBootstrapProcess(ctx, f.v, f.c, f.c, 0, instance, "api", ready) }()
	until := time.Now().Add(5 * time.Second)
	for tableCount(t, s, "v3_bootstrap_processes") == 0 && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("observer did not stop")
	}
	var ended bool
	if err := s.DB.QueryRow(`SELECT ended FROM v3_bootstrap_processes WHERE instance=$1`, instance).Scan(&ended); err != nil || ended {
		t.Fatal("observer exit prematurely claimed all roles drained", err)
	}
	expected := bootstrapProcess{Instance: instance, Member: f.c.Central.Instance, Role: "api", Activation: 0}
	if err := s.endBootstrapProcess(context.Background(), f.v, expected); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT ended FROM v3_bootstrap_processes WHERE instance=$1`, instance).Scan(&ended); err != nil || !ended {
		t.Fatal("actual shutdown did not sign ended state", err)
	}
}

func TestBootstrapRuntimeActuallyUsesApprovedDatabaseCredentials(t *testing.T) {
	role := "v3_bootstrap_" + token()[:16]
	s, f, j := bootstrapApplicationFixtureDocument(t, true, func(s *Store, f configurationLocalFixture, doc *configurationDocument) {
		var schema string
		if err := s.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		// Disposable trust-authenticated local role. No production credentials
		// or database are used. A trigger observes the actual connection user.
		mustHistoryExec(t, s.DB, `CREATE ROLE "`+role+`" LOGIN`)
		t.Cleanup(func() {
			mustHistoryExec(t, s.DB, `DROP OWNED BY "`+role+`";DROP ROLE "`+role+`"`)
		})
		mustHistoryExec(t, s.DB, `CREATE TABLE bootstrap_connection_roles(username text,activation bigint);
CREATE FUNCTION remember_bootstrap_connection() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN INSERT INTO bootstrap_connection_roles VALUES(current_user,NEW.activation);RETURN NEW;END$$;
CREATE TRIGGER remember_bootstrap_connection AFTER INSERT ON v3_bootstrap_processes FOR EACH ROW EXECUTE FUNCTION remember_bootstrap_connection()`)
		mustHistoryExec(t, s.DB, `GRANT USAGE,CREATE ON SCHEMA "`+schema+`" TO "`+role+`";GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA "`+schema+`" TO "`+role+`";GRANT ALL ON ALL SEQUENCES IN SCHEMA "`+schema+`" TO "`+role+`"`)
		dsn, err := url.Parse(string(environmentDSN(t, s)))
		if err != nil {
			t.Fatal(err)
		}
		dsn.User = url.User(role)
		target := filepath.Join(f.f.root, "effective-postgres.dsn")
		localWrite(t, target, []byte(dsn.String()))
		common.M(doc.Bootstrap["database"])["dsn_file"] = target
	})
	old := startBootstrapServeForTest(t, s, f.c, "api", 0)
	r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
	if d, err := bootstrapStateForTest(s, f.v, f.c); err != nil || common.S(common.M(d.Desired["database"])["dsn_file"]) == f.c.Database.DSNFile {
		t.Fatal("fixture did not save replacement database reference", err)
	}
	if p, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil || p.State != "pending" {
		t.Fatal("credential handoff approval", err)
	}
	waitBootstrapRestartForTest(t, old)
	var revision int64
	if err := s.DB.QueryRow(`SELECT max(revision) FROM v3_bootstrap_handoffs`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	_ = startBootstrapServeForTest(t, s, f.c, "api", revision)
	_ = waitBootstrapConfirmed(t, r, j)
	var actual string
	if err := s.DB.QueryRow(`SELECT username FROM bootstrap_connection_roles WHERE activation=$1`, revision).Scan(&actual); err != nil || actual != role {
		t.Fatal("new runtime retained launch database credentials", err)
	}
}

func TestBootstrapRuntimeOldProcessCannotBypassHandoffDeadline(t *testing.T) {
	s, f, j := bootstrapApplicationFixture(t, true)
	_ = startBootstrapServeForTest(t, s, f.c, "api", 0)
	r := configurationBootstrapRuntime{s, f.v, f.c, f.c}
	if _, err := r.ApplyConfigurationPhase(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	h, err := readBootstrapHandoffTx(context.Background(), tx, f.v, f.c.Central.Instance, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Mint an authenticated old approval with the fixture authority. Mutating
	// the timestamp alone is separately rejected by AEAD authentication.
	h.Created = h.Created.Add(-11 * time.Minute)
	aead := f.v.keys[h.Key]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(h.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, nonce, body, handoffAAD(h))
	clear(body)
	if _, err := tx.Exec(`UPDATE v3_bootstrap_handoffs SET created_at=$1,nonce=$2,ciphertext=$3 WHERE revision=$4`, h.Created, nonce, sealed, h.Revision); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.InspectConfigurationPhase(context.Background(), j); !errors.Is(err, errBootstrapRuntime) {
		t.Fatal("old or absent process bypassed deadline", err)
	}
	if d, err := bootstrapStateForTest(s, f.v, f.c); err != nil || !d.Pending {
		t.Fatal("timed-out handoff advanced marker", err)
	}
}
