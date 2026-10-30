package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func applicationFixture(t *testing.T) (*Store, configurationLocalFixture, configurationApplicationJob) {
	t.Helper()
	s, f, stage := environmentFixture(t, http.HandlerFunc(environmentMetrics))
	var generation int64
	if e := s.DB.QueryRow(`SELECT generation FROM v3_configuration_revisions WHERE stage=$1`, stage).Scan(&generation); e != nil {
		t.Fatal(e)
	}
	raw, e := s.queueConfigurationApplication(context.Background(), f.v, f.c, "admin", "queue-application", stage, generation)
	return s, f, applicationReceipt(t, raw, e)
}
func applicationReceipt(t *testing.T, raw []byte, e error) configurationApplicationJob {
	t.Helper()
	var j configurationApplicationJob
	if e != nil || json.Unmarshal(raw, &j) != nil || !validArchiveSource(j.ID) {
		t.Fatal("application receipt", e)
	}
	return j
}
func privateApplicationForTest(t *testing.T, s *Store, v *Vault, id string) privateConfigurationApplication {
	t.Helper()
	tx, e := s.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	j, e := readApplicationTx(context.Background(), tx, v, id, false)
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func claimApplicationForTest(t *testing.T, s *Store, f configurationLocalFixture, owner string) privateConfigurationApplication {
	t.Helper()
	j, e := s.claimConfigurationApplication(context.Background(), f.v, f.c.Central.Instance, owner)
	if e != nil {
		t.Fatal("claim", e)
	}
	return j
}
func applicationComplete(j privateConfigurationApplication) configurationApplicationCheckpoint {
	return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "complete", j.epoch}
}

type syntheticApplicationRuntime struct {
	partial     bool
	unsupported string
	failPhase   string
	applied     []string
	complete    bool
}

func (r *syntheticApplicationRuntime) SupportsConfigurationPhase(p string) bool {
	return p != r.unsupported && (!r.partial || p == "environment" || p == "nodes")
}
func (r *syntheticApplicationRuntime) InspectConfigurationPhase(_ context.Context, j privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	p := applicationComplete(j)
	if !r.complete {
		p.State = "absent"
	}
	return p, nil
}
func (r *syntheticApplicationRuntime) ApplyConfigurationPhase(_ context.Context, j privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	r.applied = append(r.applied, j.phase())
	if j.phase() == r.failPhase {
		return configurationApplicationCheckpoint{}, errors.New("private-remote-output-do-not-log")
	}
	return applicationComplete(j), nil
}

func TestConfigurationApplicationQueueReadOnlyIdempotencyAndGate(t *testing.T) {
	s, f, j := applicationFixture(t)
	ctx := context.Background()
	files := localTree(t, f.f.root)
	settings := settingsStateForTest(t, s)
	raw, e := s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "queue-application", j.Stage, j.Generation)
	replay := applicationReceipt(t, raw, e)
	if replay.ID != j.ID || tableCount(t, s, "v3_configuration_applications") != 1 || tableCount(t, s, "v3_configuration_application_logs") != 1 {
		t.Fatal("duplicate application")
	}
	if _, e = s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "different-request", j.Stage, j.Generation); !errors.Is(e, errConfigurationApplicationBusy) {
		t.Fatal("parallel application", e)
	}
	before := &configurationEditBackup{vault: f.v, bootstrap: f.c}
	if _, e = s.saveNode(ctx, "admin", "blocked-node-edit", nodeFixture("new-node"), 0, f.c.Collector.Shards, before); !errors.Is(e, errConfigurationApplicationBusy) {
		t.Fatal("editor bypassed application", e)
	}
	if _, e = s.inspectSavedConfigurationEnvironment(ctx, f.v, f.c, "admin", j.Stage); !errors.Is(e, errConfigurationApplicationBusy) {
		t.Fatal("ordinary gate bypassed application", e)
	}
	if !reflect.DeepEqual(files, localTree(t, f.f.root)) || !reflect.DeepEqual(settings, settingsStateForTest(t, s)) || tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("queue applied runtime")
	}
	pub, e := s.configurationApplication(ctx, f.v, "admin", j.ID)
	if e != nil || pub.Phase != "environment" || pub.Status != "queued" {
		t.Fatal(pub, e)
	}
	private := privateApplicationForTest(t, s, f.v, j.ID)
	if _, e = json.Marshal(private); e == nil {
		t.Fatal("private task serialized")
	}
	raw, _ = json.Marshal(pub)
	for _, secret := range []string{f.f.root, private.planProof, private.sourceProof, f.c.Central.Instance, "private-dsn-password"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("public task leaked private plan")
		}
	}
}

func TestConfigurationApplicationActualEnvironmentThenUnsupportedStopsSafely(t *testing.T) {
	s, f, pub := applicationFixture(t)
	j := claimApplicationForTest(t, s, f, "environment-one")
	runtime := configurationEnvironmentRuntime{s, f.v, f.c}
	if e := s.executeConfigurationApplication(context.Background(), f.v, j, runtime); e != nil {
		t.Fatal("real environment phase", e)
	}
	j = privateApplicationForTest(t, s, f.v, pub.ID)
	if j.Status != "queued" || j.step != 1 || j.RecoveryRequired {
		t.Fatal("environment switched runtime")
	}
	j = claimApplicationForTest(t, s, f, "environment-two")
	if e := s.executeConfigurationApplication(context.Background(), f.v, j, runtime); e == nil {
		t.Fatal("partial adapter reported success")
	}
	j = privateApplicationForTest(t, s, f.v, pub.ID)
	if j.Status != "failed" || j.ErrorCode != "runtime-unavailable" || j.RecoveryRequired {
		t.Fatal("unsupported phase armed recovery")
	}
	if _, e := s.controlConfigurationApplication(context.Background(), f.v, "admin", "cancel-unsupported", pub.ID, "cancel"); e != nil {
		t.Fatal(e)
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("diagnostic created deployment")
	}
}

func TestConfigurationApplicationEnvironmentFailureNeedsNoRollback(t *testing.T) {
	var reject atomic.Bool
	s, f, stage := environmentFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject.Load() {
			w.WriteHeader(503)
			return
		}
		environmentMetrics(w, r)
	}))
	raw, e := s.queueConfigurationApplication(context.Background(), f.v, f.c, "admin", "queue-failure", stage, 1)
	pub := applicationReceipt(t, raw, e)
	reject.Store(true)
	j := claimApplicationForTest(t, s, f, "failing-check")
	if e = s.executeConfigurationApplication(context.Background(), f.v, j, configurationEnvironmentRuntime{s, f.v, f.c}); e == nil {
		t.Fatal("failed dependency accepted")
	}
	j = privateApplicationForTest(t, s, f.v, pub.ID)
	if j.Status != "failed" || j.RecoveryRequired || j.step != 0 || j.ErrorCode != "environment-failed" {
		t.Fatal("preflight failure marked recoverable switch")
	}
	if _, e = s.controlConfigurationApplication(context.Background(), f.v, "admin", "resume-check", pub.ID, "resume"); e != nil {
		t.Fatal(e)
	}
	reject.Store(false)
	j = claimApplicationForTest(t, s, f, "fixed-check")
	if e = s.executeConfigurationApplication(context.Background(), f.v, j, configurationEnvironmentRuntime{s, f.v, f.c}); e != nil {
		t.Fatal(e)
	}
}

func TestConfigurationApplicationLeaseTakeoverFencesOldOwner(t *testing.T) {
	s, f, pub := applicationFixture(t)
	old := claimApplicationForTest(t, s, f, "old-process")
	if e := s.renewConfigurationApplication(context.Background(), f.v, old); e != nil {
		t.Fatal(e)
	}
	if _, e := s.claimConfigurationApplication(context.Background(), f.v, f.c.Central.Instance, "second-process"); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("live lease stolen", e)
	}
	if _, e := s.controlConfigurationApplication(context.Background(), f.v, "admin", "live-cancel", pub.ID, "cancel"); e == nil {
		t.Fatal("live worker cancelled without fencing")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, pub.ID)
	new := claimApplicationForTest(t, s, f, "new-process")
	if new.epoch <= old.epoch || new.step != old.step {
		t.Fatal("takeover lost checkpoint")
	}
	if e := s.renewConfigurationApplication(context.Background(), f.v, old); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("stale renewal accepted", e)
	}
	if _, e := s.checkpointConfigurationApplication(context.Background(), f.v, old, applicationComplete(old)); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("stale checkpoint accepted", e)
	}
	if e := s.failConfigurationApplication(context.Background(), f.v, old, "interrupted"); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("stale failure accepted", e)
	}
	if _, e := s.checkpointConfigurationApplication(context.Background(), f.v, new, applicationComplete(new)); e != nil {
		t.Fatal(e)
	}
	if s.DB.Stats().InUse != 0 {
		t.Fatal("leases leaked database transactions")
	}
}

func TestConfigurationApplicationSingleClaimAndPhaseReceiptBoundaries(t *testing.T) {
	s, f, pub := applicationFixture(t)
	var wg sync.WaitGroup
	var won atomic.Int32
	var unexpected atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := s.claimConfigurationApplication(context.Background(), f.v, f.c.Central.Instance, "racing-owner")
			if e == nil {
				won.Add(1)
			} else if !errors.Is(e, sql.ErrNoRows) {
				unexpected.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 || unexpected.Load() != 0 {
		t.Fatal("concurrent claims", won.Load(), unexpected.Load())
	}
	j := privateApplicationForTest(t, s, f.v, pub.ID)
	for _, kind := range []string{"job", "plan", "phase", "epoch", "unknown"} {
		p := applicationComplete(j)
		switch kind {
		case "job":
			p.Job = token()
		case "plan":
			p.Plan = "wrong"
		case "phase":
			p.Phase = "finalize"
		case "epoch":
			p.Epoch++
		case "unknown":
			p.State = "unknown"
		}
		if _, e := s.checkpointConfigurationApplication(context.Background(), f.v, j, p); e == nil {
			t.Fatal("unbound phase receipt accepted", kind)
		}
	}
	if current := privateApplicationForTest(t, s, f.v, pub.ID); current.step != 0 {
		t.Fatal("invalid receipt advanced phase")
	}
}

func TestConfigurationApplicationSyntheticJournalForwardAndRollback(t *testing.T) {
	// Synthetic adapters prove journal semantics only. They do not claim actual
	// nodes, center restart, settings application or end-to-end acceptance.
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "forward", true: "rollback"}[rollback], func(t *testing.T) {
			s, f, pub := applicationFixture(t)
			r := &syntheticApplicationRuntime{}
			phases := len(configurationApplicationForward)
			if rollback {
				phases = 2
				r.failPhase = "nodes"
			}
			for i := 0; i < phases; i++ {
				j := claimApplicationForTest(t, s, f, "phase-worker")
				e := s.executeConfigurationApplication(context.Background(), f.v, j, r)
				if e != nil && !(rollback && i == 1) {
					t.Fatal(e)
				}
			}
			j := privateApplicationForTest(t, s, f.v, pub.ID)
			if !rollback {
				if j.Status != "succeeded" || j.RecoveryRequired || j.Finished == nil {
					t.Fatal("journal did not finish")
				}
				return
			}
			if !j.RecoveryRequired || j.Status != "failed" {
				t.Fatal("failed switch lost recovery")
			}
			if _, e := s.controlConfigurationApplication(context.Background(), f.v, "admin", "unsafe-cancel", pub.ID, "cancel"); e == nil {
				t.Fatal("recovery responsibility discarded")
			}
			mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('recovery-admin','not-login','admin'); UPDATE v3_accounts SET revision=revision+1,role='viewer' WHERE username='admin'`)
			if _, e := s.controlConfigurationApplication(context.Background(), f.v, "recovery-admin", "wrong-resume", pub.ID, "resume"); e == nil {
				t.Fatal("different administrator continued original authority")
			}
			if _, e := s.controlConfigurationApplication(context.Background(), f.v, "recovery-admin", "request-rollback", pub.ID, "rollback"); e != nil {
				t.Fatal(e)
			}
			r.failPhase = ""
			for range configurationApplicationRollback {
				j = claimApplicationForTest(t, s, f, "rollback-worker")
				if e := s.executeConfigurationApplication(context.Background(), f.v, j, r); e != nil {
					t.Fatal(e)
				}
			}
			j = privateApplicationForTest(t, s, f.v, pub.ID)
			if j.Status != "rolled_back" || j.RecoveryRequired || j.Finished == nil || j.Controller != "recovery-admin" {
				t.Fatal("rollback journal did not finish")
			}
			var raw []byte
			if e := s.DB.QueryRow(`SELECT jsonb_agg(row_to_json(t)) FROM v3_configuration_application_logs t`).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(raw, []byte("private-remote-output")) || bytes.Contains(raw, []byte(j.planProof)) {
				t.Fatal("log leaked runtime evidence")
			}
		})
	}
}

func TestConfigurationApplicationPartialAdapterCannotArmSwitch(t *testing.T) {
	s, f, pub := applicationFixture(t)
	r := &syntheticApplicationRuntime{partial: true}
	j := claimApplicationForTest(t, s, f, "partial-check")
	if e := s.executeConfigurationApplication(context.Background(), f.v, j, r); e != nil {
		t.Fatal(e)
	}
	j = claimApplicationForTest(t, s, f, "partial-switch")
	if e := s.executeConfigurationApplication(context.Background(), f.v, j, r); e == nil {
		t.Fatal("partial adapter switched")
	}
	j = privateApplicationForTest(t, s, f.v, pub.ID)
	if j.RecoveryRequired || len(r.applied) != 1 || r.applied[0] != "environment" {
		t.Fatal("unsupported later phase armed recovery")
	}
}

func TestConfigurationApplicationPartialRollbackCannotRestoreSubset(t *testing.T) {
	s, f, pub := applicationFixture(t)
	r := &syntheticApplicationRuntime{failPhase: "nodes"}
	for i := 0; i < 2; i++ {
		j := claimApplicationForTest(t, s, f, "setup-recovery")
		e := s.executeConfigurationApplication(context.Background(), f.v, j, r)
		if (e != nil) != (i == 1) {
			t.Fatal("recovery fixture", e)
		}
	}
	if _, e := s.controlConfigurationApplication(context.Background(), f.v, "admin", "partial-rollback", pub.ID, "rollback"); e != nil {
		t.Fatal(e)
	}
	j := claimApplicationForTest(t, s, f, "partial-rollback")
	partial := &syntheticApplicationRuntime{unsupported: "restore-nodes"}
	if e := s.executeConfigurationApplication(context.Background(), f.v, j, partial); e == nil {
		t.Fatal("partial rollback started")
	}
	current := privateApplicationForTest(t, s, f.v, pub.ID)
	if len(partial.applied) != 0 || current.rollbackStep != 0 || !current.RecoveryRequired || current.Status != "failed" {
		t.Fatal("partial rollback changed responsibility")
	}
}

func TestConfigurationApplicationCorruptionAndSourceRevocation(t *testing.T) {
	for _, kind := range []string{"step", "controller", "epoch", "plan-proof", "state-proof", "source-proof", "archive-pin", "account"} {
		t.Run(kind, func(t *testing.T) {
			s, f, pub := applicationFixture(t)
			switch kind {
			case "step":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET step=2`)
			case "controller":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET controller='other-admin'`)
			case "epoch":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_epoch=100`)
			case "plan-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET plan_proof='forged'`)
			case "state-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET state_proof='forged'`)
			case "source-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET proof='forged' WHERE stage=$1`, pub.Stage)
			case "archive-pin":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins`)
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1`)
			}
			if _, e := s.claimConfigurationApplication(context.Background(), f.v, f.c.Central.Instance, "must-not-claim"); e == nil {
				t.Fatal("untrusted application claimed", kind)
			}
			var count int
			if e := s.DB.QueryRow(`SELECT count(*) FROM v3_configuration_application_logs WHERE code='claimed'`).Scan(&count); e != nil || count != 0 {
				t.Fatal("failed claim mutated journal", e)
			}
		})
	}
}

func TestConfigurationApplicationDisasterRestoreRequiresExplicitRecovery(t *testing.T) {
	s, f, pub := applicationFixture(t)
	old := claimApplicationForTest(t, s, f, "archived-owner")
	backup, e := s.BackupPostgres(context.Background(), privateTestDir(t))
	if e != nil {
		t.Fatal(e)
	}
	restored := emptyTestStore(t)
	if e = restored.RestorePostgres(context.Background(), backup); e != nil {
		t.Fatal("application backup restore", e)
	}
	j := privateApplicationForTest(t, restored, f.v, pub.ID)
	if !j.RecoveryHold || j.Status != "running" {
		t.Fatal("disaster recovery revived authority")
	}
	if _, e = restored.claimConfigurationApplication(context.Background(), f.v, f.c.Central.Instance, "automatic-restart"); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("restored task automatically claimed", e)
	}
	if e = restored.renewConfigurationApplication(context.Background(), f.v, old); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("archived lease renewed", e)
	}
	if _, e = restored.controlConfigurationApplication(context.Background(), f.v, "admin", "reauthorize-after-restore", pub.ID, "resume"); e != nil {
		t.Fatal(e)
	}
	j = claimApplicationForTest(t, restored, f, "explicit-restart")
	if j.epoch <= old.epoch || j.RecoveryHold {
		t.Fatal("restore did not advance fencing")
	}
}

func TestConfigurationApplicationSchema21UpgradeRequiresBackup(t *testing.T) {
	s := testStore(t)
	dropBootstrapRuntimeForTest(t, s)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_configuration_application_settings; DROP TABLE v3_configuration_application_logs; DROP TABLE v3_configuration_applications; DELETE FROM v3_schema WHERE version>=22`)
	if e := s.Migrate(context.Background()); e == nil {
		t.Fatal("schema 21 migrated without backup")
	}
	bad := filepath.Join(privateTestDir(t), "not-directory")
	localWrite(t, bad, []byte("file"))
	if e := s.Upgrade(context.Background(), bad); e == nil {
		t.Fatal("backup failure ignored")
	}
	if version, e := currentSchema(context.Background(), s.DB); e != nil || version != 21 {
		t.Fatal("failed migration changed schema", version, e)
	}
	if e := s.Upgrade(context.Background(), privateTestDir(t)); e != nil {
		t.Fatal(e)
	}
	if version, e := currentSchema(context.Background(), s.DB); e != nil || version != SchemaVersion {
		t.Fatal("upgrade failed", version, e)
	}
}

func TestConfigurationApplicationNetworkCancellationAndTakeover(t *testing.T) {
	for _, kind := range []string{"cancel", "takeover", "configuration-drift"} {
		t.Run(kind, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					once.Do(func() { close(started) })
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				environmentMetrics(w, r)
			})
			s, f, stage := environmentFixture(t, h)
			raw, e := s.queueConfigurationApplication(context.Background(), f.v, f.c, "admin", "queue-network", stage, 1)
			pub := applicationReceipt(t, raw, e)
			old := claimApplicationForTest(t, s, f, "network-owner")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- s.executeConfigurationApplication(ctx, f.v, old, configurationEnvironmentRuntime{s, f.v, f.c})
			}()
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("environment network not reached")
			}
			switch kind {
			case "cancel":
				cancel()
			case "takeover":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, pub.ID)
				new := claimApplicationForTest(t, s, f, "replacement-owner")
				if new.epoch <= old.epoch {
					t.Fatal("takeover did not fence")
				}
			case "configuration-drift":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
			}
			close(release)
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("interrupted network advanced task")
				}
			case <-time.After(8 * time.Second):
				t.Fatal("interrupted worker did not stop")
			}
			current := privateApplicationForTest(t, s, f.v, pub.ID)
			if current.step != 0 || current.RecoveryRequired {
				t.Fatal("interrupted diagnostic switched runtime")
			}
			if kind == "takeover" && current.owner.String != "replacement-owner" {
				t.Fatal("old worker overwrote new owner")
			}
		})
	}
}

func TestConfigurationApplicationKeyRotationAndInspectComplete(t *testing.T) {
	s, f, pub := applicationFixture(t)
	_, path := testVault(t)
	rotated, e := OpenVault(path, f.c.DeploymentTrust.VaultKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	j, e := s.claimConfigurationApplication(context.Background(), rotated, f.c.Central.Instance, "rotated-owner")
	if e != nil {
		t.Fatal(e)
	}
	r := &syntheticApplicationRuntime{complete: true}
	if e = s.executeConfigurationApplication(context.Background(), rotated, j, r); e != nil {
		t.Fatal(e)
	}
	if len(r.applied) != 0 {
		t.Fatal("completed remote phase blindly repeated")
	}
	current := privateApplicationForTest(t, s, rotated, pub.ID)
	if current.step != 1 || !strings.HasPrefix(current.stateProof, rotated.active+":") {
		t.Fatal("state signing key did not rotate")
	}
	if _, e = s.configurationApplication(context.Background(), f.v, "admin", pub.ID); e == nil {
		t.Fatal("missing signing key accepted")
	}
}
