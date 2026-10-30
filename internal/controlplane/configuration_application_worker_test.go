package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"webscan/internal/common"
)

func workerSourceFixture(t *testing.T, restart bool, handlers ...http.Handler) (*Store, configurationLocalFixture, configurationRestoreStage, configurationRevision) {
	t.Helper()
	s, f := newSavedConfigurationStore(t)
	f.c.Executor.ApplicationsEnabled = true
	var handler http.Handler = http.HandlerFunc(environmentMetrics)
	if len(handlers) > 0 {
		handler = handlers[0]
	}
	vm := httptest.NewServer(handler)
	t.Cleanup(vm.Close)
	f.c.Metrics.QueryURL, f.c.Metrics.WriteURL = vm.URL, vm.URL
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.c.Central.Listen = listener.Addr().String()
	listener.Close()
	localWrite(t, f.c.Database.DSNFile, environmentDSN(t, s))
	doc := f.document(t)
	doc.Settings["retention"] = common.Map{"sqlite_events_days": 45}
	if restart {
		common.M(doc.Bootstrap["collector"])["concurrency"] = 32
	}
	stage, revision := savedRestoreFromDocument(t, s, f, doc)
	raw, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "worker-save", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	return s, f, stage, revision
}

func TestConfigurationApplicationWorkerConcurrentServeAndCancellation(t *testing.T) {
	for _, cancelActive := range []bool{false, true} {
		name := "concurrent-workers"
		if cancelActive {
			name = "drain-active-phase"
		}
		t.Run(name, func(t *testing.T) {
			entered, release, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var enterOnce, cancelOnce, releaseOnce sync.Once
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					enterOnce.Do(func() { close(entered) })
					select {
					case <-release:
					case <-r.Context().Done():
						cancelOnce.Do(func() { close(cancelled) })
						return
					}
				}
				environmentMetrics(w, r)
			})
			// Release a blocked HTTP fixture even if a preceding assertion fails.
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			s, f, stage, revision := workerSourceFixture(t, false, handler)
			raw, err := s.queueConfigurationApplication(context.Background(), f.v, f.c, "admin", "concurrent-worker-queue", stage.ID, revision.Generation)
			job := applicationReceipt(t, raw, err)
			first := startBootstrapServeForTest(t, s, f.c, "all", 0)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("environment probe did not start")
			}
			p := privateApplicationForTest(t, s, f.v, job.ID)
			if p.Status != "running" || p.phase() != "environment" {
				t.Fatal("unexpected blocked phase")
			}
			if cancelActive {
				first.cancel()
				select {
				case err := <-first.done:
					first.waited = true
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("worker did not drain cancelled phase")
				}
				select {
				case <-cancelled:
				case <-time.After(2 * time.Second):
					t.Fatal("probe was not cancelled")
				}
				after := privateApplicationForTest(t, s, f.v, job.ID)
				if after.Status != "running" || after.step != 0 || after.epoch != p.epoch || after.RecoveryRequired {
					t.Fatal("cancellation fabricated a checkpoint")
				}
				return
			}
			second := startBootstrapServeForTest(t, s, f.c, "executor", 0)
			var instances, claims int
			if err = s.DB.QueryRow(`SELECT count(DISTINCT instance) FROM v3_role_status WHERE role='configuration-applications'`).Scan(&instances); err != nil || instances != 2 {
				t.Fatal("missing independent owners", err, instances)
			}
			if err = s.DB.QueryRow(`SELECT count(*) FROM v3_configuration_application_logs WHERE job=$1 AND phase='environment' AND code IN('claimed','takeover')`, job.ID).Scan(&claims); err != nil || claims != 1 {
				t.Fatal("two workers claimed one active phase", err, claims)
			}
			second.cancel()
			select {
			case err := <-second.done:
				second.waited = true
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("standby did not stop")
			}
			releaseOnce.Do(func() { close(release) })
			done := waitWorkerApplication(t, s, f, job.ID, "succeeded", 30*time.Second)
			if done.RecoveryRequired {
				t.Fatal("successful application retained responsibility")
			}
			first.cancel()
		})
	}
}
func workerSavedFixture(t *testing.T, restart bool) (*Store, configurationLocalFixture, configurationApplicationJob) {
	t.Helper()
	s, f, stage, revision := workerSourceFixture(t, restart)
	raw, err := s.queueConfigurationApplication(context.Background(), f.v, f.c, "admin", "worker-queue", stage.ID, revision.Generation)
	return s, f, applicationReceipt(t, raw, err)
}
func waitWorkerApplication(t *testing.T, s *Store, f configurationLocalFixture, id, status string, budget time.Duration) privateConfigurationApplication {
	t.Helper()
	end := time.Now().Add(budget)
	for time.Now().Before(end) {
		j := privateApplicationForTest(t, s, f.v, id)
		if j.Status == status {
			return j
		}
		if j.Status == "failed" {
			t.Fatal("worker application failed", j.phase(), j.ErrorCode)
		}
		time.Sleep(100 * time.Millisecond)
	}
	j := privateApplicationForTest(t, s, f.v, id)
	t.Fatal("worker did not finish", j.Status, j.phase())
	return j
}
func TestConfigurationApplicationWorkerActualServeAllAndDefaultDisabled(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		s, f, j := workerSavedFixture(t, false)
		process := startBootstrapServeForTest(t, s, f.c, "all", 0)
		done := waitWorkerApplication(t, s, f, j.ID, "succeeded", 30*time.Second)
		if done.RecoveryRequired || done.Finished == nil {
			t.Fatal("worker did not complete real verification")
		}
		var workers int
		if err := s.DB.QueryRow(`SELECT count(*) FROM v3_role_status WHERE role='configuration-applications' AND error=''`).Scan(&workers); err != nil || workers != 1 {
			t.Fatal("missing actual worker heartbeat", err)
		}
		policy, err := s.RetentionPolicy(context.Background())
		if err != nil || policy.Policy.Events != 45 {
			t.Fatal("worker did not apply actual policy", err)
		}
		if tableCount(t, s, "v3_configuration_backup_pins") != 0 || tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
			t.Fatal("worker retained terminal pins or created unrelated work")
		}
		process.cancel()
	})
	t.Run("disabled", func(t *testing.T) {
		s, f, r, id, _ := applicationVerificationFixture(t)
		time.Sleep(1100 * time.Millisecond)
		j := privateApplicationForTest(t, s, f.v, id)
		if j.Status != "queued" || j.epoch != 0 {
			t.Fatal("default-disabled worker claimed a task")
		}
		var count int
		if err := s.DB.QueryRow(`SELECT count(*) FROM v3_role_status WHERE role='configuration-applications'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("disabled worker advertised readiness", err)
		}
		_ = r
	})
}
func TestConfigurationApplicationWorkerActualServeRestartResumesLease(t *testing.T) {
	s, f, j := workerSavedFixture(t, true)
	first := startBootstrapServeForTest(t, s, f.c, "all", 0)
	waitBootstrapRestartForTest(t, first)
	pending := privateApplicationForTest(t, s, f.v, j.ID)
	if pending.phase() != "bootstrap" || pending.Status != "running" || !pending.RecoveryRequired {
		t.Fatal("restart was falsely checkpointed")
	}
	_, activation, _, err := s.resolveBootstrap(context.Background(), f.c)
	if err != nil || activation < 1 {
		t.Fatal("handoff unavailable", err)
	}
	// No manual lease expiry or synthetic phase receipt: a new actual Serve
	// process waits for the previous process's real 45s lease to expire.
	second := startBootstrapServeForTest(t, s, f.c, "all", activation)
	done := waitWorkerApplication(t, s, f, j.ID, "succeeded", 75*time.Second)
	if done.epoch <= pending.epoch {
		t.Fatal("restart reused ownership epoch")
	}
	if tableCount(t, s, "v3_configuration_backup_pins") != 0 {
		t.Fatal("restart did not pass terminal verification")
	}
	second.cancel()
}
func TestConfigurationApplicationWorkerReadinessAndConfiguration(t *testing.T) {
	ctx, ready := withStartupReadiness(context.Background(), "executor", true, true)
	runtimeReady(ctx, "executor")
	select {
	case <-ready:
		t.Fatal("coordinator omitted from readiness")
	default:
	}
	runtimeReady(ctx, "configuration-applications")
	select {
	case <-ready:
	default:
		t.Fatal("coordinator never became ready")
	}
	c := ExecutorConfig{ApplicationsEnabled: true}
	if c.validate(DeploymentTrustConfig{}) == nil {
		t.Fatal("worker enabled without executor")
	}
	if err := (configurationApplicationWorker{}).Run(context.Background()); !errors.Is(err, errConfigurationApplication) {
		t.Fatal("invalid worker claimed work", err)
	}
}
func TestConfigurationApplicationWorkerRejectsTargetRemovingCoordinator(t *testing.T) {
	s, f, trust, p, _ := applicationPreparationEnvironmentFixture(t, "native", false)
	f.c.Executor.ApplicationsEnabled = true
	provider := configurationNodePreparer{s, f.c, trust}
	if err := provider.checkEnvironment(context.Background(), p); err == nil {
		t.Fatal("application could remove its own recovery coordinator")
	}
	if privateApplicationForTest(t, s, f.v, p.ID).RecoveryRequired {
		t.Fatal("rejected change armed recovery")
	}
}

func TestConfigurationApplicationWorkerAuthorityFailuresDoNotExecute(t *testing.T) {
	for _, kind := range []string{"migration", "account", "journal", "other-member", "recovery-hold"} {
		t.Run(kind, func(t *testing.T) {
			s, f, job := workerSavedFixture(t, false)
			executor, err := newDeploymentExecutor(context.Background(), s, f.c)
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := newConfigurationCompositeRuntime(context.Background(), s, f.v, f.c, f.c, []string{"all"}, executor.Runtime)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "migration":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('workflow',$1)`, strings.Repeat("f", 64))
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1,role='viewer' WHERE username='admin'`)
			case "journal":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET state_proof='private-corruption' WHERE id=$1`, job.ID)
			case "other-member":
				runtime.bootstrap.Central.Instance = "other-member"
				runtime.launch.Central.Instance = "other-member"
				runtime.nodes.bootstrap.Central.Instance = "other-member"
			case "recovery-hold":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET recovery_hold=true WHERE id=$1`, job.ID)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- (configurationApplicationWorker{s, runtime, "failure-worker"}).Run(ctx) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("worker failed to stop")
				}
			}()
			var reason string
			end := time.Now().Add(5 * time.Second)
			for {
				err = s.DB.QueryRow(`SELECT error FROM v3_role_status WHERE role='configuration-applications' AND instance='failure-worker'`).Scan(&reason)
				if err == nil {
					break
				}
				if !errors.Is(err, sql.ErrNoRows) || time.Now().After(end) {
					t.Fatal("missing worker fault heartbeat", err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if (kind == "migration" || kind == "account" || kind == "journal") && reason == "" {
				t.Fatal("authorization failure looked healthy")
			}
			if strings.Contains(reason, "private-") {
				t.Fatal("heartbeat leaked raw failure")
			}
			var status string
			var epoch int
			if err = s.DB.QueryRow(`SELECT status,lease_epoch FROM v3_configuration_applications WHERE id=$1`, job.ID).Scan(&status, &epoch); err != nil || status != "queued" || epoch != 0 {
				t.Fatal("ineligible worker claimed work", err, status, epoch)
			}
			if tableCount(t, s, "v3_configuration_application_logs") != 1 || tableCount(t, s, "v3_deployment_jobs") != 0 {
				t.Fatal("ineligible task executed")
			}
		})
	}
}
