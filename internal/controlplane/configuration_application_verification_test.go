package controlplane

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"webscan/internal/common"
)

// Empty-node full composition: real PostgreSQL, actual Serve(all), actual
// environment/phase adapters, and an explicitly synthetic VM HTTP endpoint.
// Remote adapter/preparation are fail-if-called. This does not attest remote
// installation, real VM persistence or capacity.
func applicationVerificationFixture(t *testing.T) (*Store, configurationLocalFixture, configurationCompositeRuntime, string, *atomic.Bool) {
	s, f, r, id, reject, _ := applicationVerificationOptions(t, false, "")
	return s, f, r, id, reject
}

func applicationVerificationOptions(t *testing.T, change bool, metrics string) (*Store, configurationLocalFixture, configurationCompositeRuntime, string, *atomic.Bool, *bootstrapServeTest) {
	t.Helper()
	s, f := newSavedConfigurationStore(t)
	var reject atomic.Bool
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject.Load() {
			w.WriteHeader(503)
			return
		}
		environmentMetrics(w, r)
	}))
	t.Cleanup(vm.Close)
	f.c.Metrics.QueryURL, f.c.Metrics.WriteURL = vm.URL, vm.URL
	if metrics != "" {
		f.c.Metrics.QueryURL, f.c.Metrics.WriteURL = metrics, metrics
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.c.Central.Listen = listener.Addr().String()
	listener.Close()
	localWrite(t, f.c.Database.DSNFile, environmentDSN(t, s))
	doc := f.document(t)
	doc.Settings["retention"] = common.Map{"sqlite_events_days": 45}
	if change {
		common.M(doc.Bootstrap["collector"])["concurrency"] = 32
	}
	stage, revision := savedRestoreFromDocument(t, s, f, doc)
	ctx := context.Background()
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "verification-save", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	raw, err = s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "verification-queue", stage.ID, revision.Generation)
	parent := applicationReceipt(t, raw, err)
	process := startBootstrapServeForTest(t, s, f.c, "all", 0)
	trust, err := loadDeploymentTrust(ctx, f.c.DeploymentTrust)
	if err != nil {
		t.Fatal(err)
	}
	nodes := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c, trust: trust, runtime: &fakeDeploymentRuntime{}, prepare: func(context.Context, privateConfigurationApplication, string) (DeploymentRequest, error) {
		t.Error("empty configuration unexpectedly prepared a node")
		return DeploymentRequest{}, errConfigurationApplication
	}}
	runtime := configurationCompositeRuntime{store: s, vault: f.v, launch: f.c, bootstrap: f.c, roles: []string{"all"}, nodes: nodes}
	return s, f, runtime, parent.ID, &reject, process
}
func advanceVerificationFixture(t *testing.T, s *Store, f configurationLocalFixture, r configurationCompositeRuntime, phase string) privateConfigurationApplication {
	t.Helper()
	for range 6 {
		p := claimApplicationForTest(t, s, f, "verification-worker")
		if p.phase() == phase {
			return p
		}
		if err := s.executeConfigurationApplication(context.Background(), f.v, p, r); err != nil {
			t.Fatal("actual preceding phase", p.phase(), err)
		}
	}
	t.Fatal("phase not reached", phase)
	return privateConfigurationApplication{}
}

func TestConfigurationApplicationVerificationComposedActualSingleProcessAndTerminalPins(t *testing.T) {
	s, f, r, id, _ := applicationVerificationFixture(t)
	p := advanceVerificationFixture(t, s, f, r, "verify")
	before := settingsStateForTest(t, s)
	if before.Pending || common.I(common.M(mustCommonMap(before.Runtime)["retention"])["sqlite_events_days"]) != 45 {
		t.Fatal("real settings adapter did not apply policy")
	}
	for _, phase := range []string{"verify", "finalize"} {
		if p.phase() != phase {
			t.Fatal("unexpected phase", p.phase())
		}
		if err := s.executeConfigurationApplication(context.Background(), f.v, p, r); err != nil {
			t.Fatal("composite verification", phase, err)
		}
		if phase == "verify" {
			p = claimApplicationForTest(t, s, f, "verification-final")
		}
	}
	done := privateApplicationForTest(t, s, f.v, id)
	if done.Status != "succeeded" || done.RecoveryRequired || done.Finished == nil {
		t.Fatal("composition did not finish")
	}
	var pins int
	if err := s.DB.QueryRow(`SELECT count(*) FROM v3_configuration_backup_pins WHERE reference IN($1,$2)`, "restore:"+p.Stage+":source", "restore:"+p.Stage+":before").Scan(&pins); err != nil || pins != 0 {
		t.Fatal("terminal application retained original rollback pins", pins, err)
	}
	if !sameApplicationSettings(before, settingsStateForTest(t, s)) || tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("verification created unrelated work")
	}
}

func mustCommonMap(raw []byte) common.Map { value, _ := common.Decode(raw); return common.M(value) }

func TestConfigurationApplicationVerificationRechecksBeforeAtomicCommit(t *testing.T) {
	for _, kind := range []string{"settings", "receipt", "process", "roles", "source", "dependency", "runtime-epoch"} {
		t.Run(kind, func(t *testing.T) {
			s, f, r, _, reject := applicationVerificationFixture(t)
			p := advanceVerificationFixture(t, s, f, r, "verify")
			proof, err := r.InspectConfigurationPhase(context.Background(), p)
			if err != nil || !proof.matches(p) {
				t.Fatal("inspection", err)
			}
			switch kind {
			case "settings":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{}'`)
			case "receipt":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_application_settings`)
			case "process":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_bootstrap_processes`)
			case "roles":
				r.roles = []string{"executor"}
			case "source":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET proof='forged'`)
			case "dependency":
				reject.Store(true)
			case "runtime-epoch":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_processes SET activation=activation+1`)
			}
			if err = r.checkpointConfigurationPhase(context.Background(), p, proof); err == nil {
				t.Fatal("stale inspected success was committed")
			}
			after := privateApplicationForTest(t, s, f.v, p.ID)
			if after.Status != "running" || after.step != p.step || tableCount(t, s, "v3_configuration_backup_pins") != 2 {
				t.Fatal("failed verification advanced or unprotected application")
			}
		})
	}
}

func TestConfigurationApplicationVerificationTerminalFailureKeepsAllProtection(t *testing.T) {
	for _, target := range []string{"v3_audit", "v3_configuration_backup_pins", "v3_configuration_applications", "v3_configuration_application_logs"} {
		t.Run(target, func(t *testing.T) {
			s, f, r, _, _ := applicationVerificationFixture(t)
			p := advanceVerificationFixture(t, s, f, r, "finalize")
			mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_verified_final() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic failure';END$$;CREATE TRIGGER fail_verified_final BEFORE INSERT OR UPDATE OR DELETE ON `+target+` FOR EACH ROW EXECUTE FUNCTION fail_verified_final()`)
			proof := applicationComplete(p)
			if err := r.checkpointConfigurationPhase(context.Background(), p, proof); err == nil {
				t.Fatal("injected terminal failure ignored")
			}
			after := privateApplicationForTest(t, s, f.v, p.ID)
			if after.step != p.step || after.Status != "running" || !after.RecoveryRequired || tableCount(t, s, "v3_configuration_backup_pins") != 2 {
				t.Fatal("partial terminal transaction committed")
			}
			mustHistoryExec(t, s.DB, `DROP TRIGGER fail_verified_final ON `+target)
			if err := r.checkpointConfigurationPhase(context.Background(), p, proof); err != nil {
				t.Fatal("retry", err)
			}
		})
	}
}

func TestConfigurationApplicationVerificationRollbackUsesActualRestoredSettings(t *testing.T) {
	s, f, r, id, _ := applicationVerificationFixture(t)
	p := advanceVerificationFixture(t, s, f, r, "verify")
	if err := s.failConfigurationApplication(context.Background(), f.v, p, "verification-failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.controlConfigurationApplication(context.Background(), f.v, "admin", "verification-rollback", id, "rollback"); err != nil {
		t.Fatal(err)
	}
	for _, phase := range configurationApplicationRollback {
		p = claimApplicationForTest(t, s, f, "verification-rollback-worker")
		if p.phase() != phase {
			t.Fatal("wrong rollback phase", p.phase())
		}
		if err := s.executeConfigurationApplication(context.Background(), f.v, p, r); err != nil {
			t.Fatal("real rollback phase", phase, err)
		}
	}
	done := privateApplicationForTest(t, s, f.v, id)
	d := settingsStateForTest(t, s)
	if done.Status != "rolled_back" || done.RecoveryRequired || !d.Pending || common.I(common.M(mustCommonMap(d.Desired)["retention"])["sqlite_events_days"]) != 45 || configurationJSONEqual(d.Runtime, d.Desired) {
		t.Fatal("rollback lost original policy or target draft")
	}
}

func TestConfigurationApplicationVerificationIncompleteCompositionCannotArm(t *testing.T) {
	s, f, r, _, _ := applicationVerificationFixture(t)
	p := advanceVerificationFixture(t, s, f, r, "nodes")
	r.nodes.prepare = nil
	if err := s.executeConfigurationApplication(context.Background(), f.v, p, r); !errors.Is(err, errConfigurationApplication) {
		t.Fatal("incomplete composition accepted", err)
	}
	if privateApplicationForTest(t, s, f.v, p.ID).RecoveryRequired {
		t.Fatal("incomplete composition armed recovery")
	}
}

func TestConfigurationApplicationVerificationActualRestartAndRollbackComposition(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		name := "forward"
		if rollback {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			s, f, r, id, _, process := applicationVerificationOptions(t, true, "")
			ctx := context.Background()
			p := advanceVerificationFixture(t, s, f, r, "bootstrap")
			if err := s.executeConfigurationApplication(ctx, f.v, p, r); !errors.Is(err, errBootstrapHandoff) {
				t.Fatal("restart was not durably pending", err)
			}
			waitBootstrapRestartForTest(t, process)
			effective, activation, _, err := s.resolveBootstrap(ctx, f.c)
			if err != nil {
				t.Fatal(err)
			}
			if effective.Collector.Concurrency != 32 || activation < 1 {
				t.Fatal("target startup was not resolved")
			}
			process = startBootstrapServeForTest(t, s, f.c, "all", activation)
			r.bootstrap = effective
			r.nodes.bootstrap = effective
			mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
			p = claimApplicationForTest(t, s, f, "after-real-restart")
			if err = s.executeConfigurationApplication(ctx, f.v, p, r); err != nil {
				t.Fatal("actual restart did not complete bootstrap", err)
			}
			p = claimApplicationForTest(t, s, f, "actual-settings-after-restart")
			if err = s.executeConfigurationApplication(ctx, f.v, p, r); err != nil {
				t.Fatal(err)
			}
			p = claimApplicationForTest(t, s, f, "actual-verification-after-restart")
			if proof, err := r.InspectConfigurationPhase(ctx, p); err != nil || !proof.matches(p) {
				t.Fatal("new process failed joint verification", err)
			}
			if !rollback {
				if err = s.executeConfigurationApplication(ctx, f.v, p, r); err != nil {
					t.Fatal(err)
				}
				p = claimApplicationForTest(t, s, f, "real-restart-finalize")
				if err = s.executeConfigurationApplication(ctx, f.v, p, r); err != nil {
					t.Fatal(err)
				}
				if privateApplicationForTest(t, s, f.v, id).Status != "succeeded" {
					t.Fatal("changed startup never completed")
				}
				return
			}
			if err = s.failConfigurationApplication(ctx, f.v, p, "verification-failed"); err != nil {
				t.Fatal(err)
			}
			if _, err = s.controlConfigurationApplication(ctx, f.v, "admin", "real-restart-rollback", id, "rollback"); err != nil {
				t.Fatal(err)
			}
			p = claimApplicationForTest(t, s, f, "real-restore-settings")
			if err = s.executeConfigurationApplication(ctx, f.v, p, r); err != nil {
				t.Fatal(err)
			}
			p = claimApplicationForTest(t, s, f, "real-restore-bootstrap")
			if err = s.executeConfigurationApplication(ctx, f.v, p, r); !errors.Is(err, errBootstrapHandoff) {
				t.Fatal("rollback restart was not pending", err)
			}
			waitBootstrapRestartForTest(t, process)
			original, next, _, err := s.resolveBootstrap(ctx, f.c)
			if err != nil || original.Collector.Concurrency != f.c.Collector.Concurrency || next <= activation {
				t.Fatal("original startup not restored", err)
			}
			startBootstrapServeForTest(t, s, f.c, "all", next)
			r.bootstrap = original
			r.nodes.bootstrap = original
			mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, id)
			for range 3 {
				p = claimApplicationForTest(t, s, f, "real-rollback-after-restart")
				if err = s.executeConfigurationApplication(ctx, f.v, p, r); err != nil {
					t.Fatal("actual rollback continuation", p.phase(), err)
				}
			}
			if privateApplicationForTest(t, s, f.v, id).Status != "rolled_back" || !settingsStateForTest(t, s).Pending {
				t.Fatal("rollback completion or saved draft lost")
			}
		})
	}
}

func TestConfigurationApplicationVerificationActualVictoriaMetrics(t *testing.T) {
	endpoint := os.Getenv("WEBSCAN_V3_TEST_VM")
	if endpoint == "" {
		t.Skip("set WEBSCAN_V3_TEST_VM to an isolated VictoriaMetrics instance")
	}
	s, f, r, id, _, _ := applicationVerificationOptions(t, false, endpoint)
	p := advanceVerificationFixture(t, s, f, r, "verify")
	if err := s.executeConfigurationApplication(context.Background(), f.v, p, r); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, s, f, "actual-vm-finalize")
	if err := s.executeConfigurationApplication(context.Background(), f.v, p, r); err != nil {
		t.Fatal(err)
	}
	if privateApplicationForTest(t, s, f.v, id).Status != "succeeded" {
		t.Fatal("real VM composition did not finish")
	}
}

// These node-observation fixtures synthesize collector reports only. They
// verify the combined SQL gate, not remote service or network installation.
func TestConfigurationApplicationVerificationChecksUnchangedNodesToo(t *testing.T) {
	for _, kind := range []string{"healthy", "events", "coverage", "lease", "runtime", "applied", "reported-version", "events-error"} {
		t.Run(kind, func(t *testing.T) {
			s, f, trust, p, in := applicationNodeFixture(t)
			ctx := context.Background()
			nr := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c, trust: trust, runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, s}, prepare: func(context.Context, privateConfigurationApplication, string) (DeploymentRequest, error) {
				return in, nil
			}}
			proof, err := nr.ApplyConfigurationPhase(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, proof); err != nil {
				t.Fatal(err)
			}
			p = claimApplicationForTest(t, s, f, "node-joint-verification-fixture")
			// Model an already deployed, unchanged node rather than rely on this
			// parent's child-specific deploymentReady check to catch missing evidence.
			mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_application_nodes`)
			switch kind {
			case "events":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_node_readiness WHERE kind='events'`)
			case "coverage":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_status SET metrics=jsonb_set(metrics,'{webscan_coverage_ok}','0')`)
			case "lease":
				mustHistoryExec(t, s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
			case "runtime":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1`)
			case "applied":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET applied_version=0`)
			case "reported-version":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_readiness SET reported_version=0 WHERE kind='metrics'`)
			case "events-error":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_status SET events_error='synthetic failure'`)
			}
			tx, err := s.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			p, err = lockedApplication(ctx, tx, f.v, p)
			if err != nil {
				t.Fatal(err)
			}
			_, doc, err := applicationSavedEvidenceTx(ctx, tx, f.v, p)
			if err != nil {
				t.Fatal(err)
			}
			err = (configurationVerificationRuntime{store: s, vault: f.v, launch: f.c, bootstrap: f.c, roles: []string{"all"}}).verifyNodesTx(ctx, tx, p, doc)
			if kind == "healthy" && err != nil {
				t.Fatal("valid unchanged node rejected", err)
			}
			if kind != "healthy" && err == nil {
				t.Fatal("unchanged node bypassed actual collection gate")
			}
		})
	}
}

func TestConfigurationApplicationVerificationRechecksRestoredEnabledRegistration(t *testing.T) {
	s, f, p, _ := applicationRegistrationFixture(t, true)
	ctx := context.Background()
	nr := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
	if _, err := nr.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal(err)
	}
	p = rollbackApplicationNodesForTest(t, s, f, p)
	if _, err := nr.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal(err)
	}
	inspect := func() error {
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		_, doc, err := applicationSavedEvidenceTx(ctx, tx, f.v, p)
		if err != nil {
			return err
		}
		return (configurationVerificationRuntime{store: s, vault: f.v, launch: f.c, bootstrap: f.c, roles: []string{"all"}}).verifyNodesTx(ctx, tx, p, doc)
	}
	if err := inspect(); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("rollback accepted old or absent observations", err)
	}
	n := runtimeNodeForTest(t, s, "registration-node")
	j := DeploymentJob{Node: n.ID, NodeVersion: n.Version, Plan: DeploymentPlan{Node: n, ConfigDigest: digest(n.Config), Request: DeploymentRequest{Release: "v3.0.0"}}}
	recordDeploymentReady(t, s, j)
	if err := inspect(); err != nil {
		t.Fatal("fresh restored collector proof rejected", err)
	}
}

func TestConfigurationApplicationVerificationLeaseExpiryDuringFinalCheckpoint(t *testing.T) {
	s, f, r, _, _ := applicationVerificationFixture(t)
	p := advanceVerificationFixture(t, s, f, r, "finalize")
	mustHistoryExec(t, s.DB, `CREATE FUNCTION delay_final_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(1.2);RETURN NEW;END$$;
 CREATE TRIGGER delay_final_checkpoint BEFORE INSERT ON v3_configuration_application_logs FOR EACH ROW EXECUTE FUNCTION delay_final_checkpoint();
 UPDATE v3_configuration_applications SET lease_until=clock_timestamp()+interval '1 second'`)
	if err := r.checkpointConfigurationPhase(context.Background(), p, applicationComplete(p)); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("expired terminal write committed", err)
	}
	after := privateApplicationForTest(t, s, f.v, p.ID)
	if after.step != p.step || after.Status != "running" || tableCount(t, s, "v3_configuration_backup_pins") != 2 {
		t.Fatal("expiry released protection or advanced checkpoint")
	}
}
