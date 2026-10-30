package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// Real SQL registration and application journals, with synthetic preceding
// environment/settings/bootstrap checkpoints. No SSH or remote service work.
func applicationRegistrationFixture(t *testing.T, installed bool) (*Store, configurationLocalFixture, privateConfigurationApplication, applicationRegistrationState) {
	t.Helper()
	s, f := newSavedConfigurationStore(t)
	ctx := context.Background()
	n := nodeFixture("registration-node")
	if installed {
		n.AppliedVersion = 1
		if err := s.PutNode(ctx, n, 0, 256); err != nil {
			t.Fatal(err)
		}
		mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET applied_version=1 WHERE id=$1`, n.ID)
		mustHistoryExec(t, s.DB, `UPDATE v3_node_runtime SET delivered_version=1 WHERE node=$1`, n.ID)
	} else {
		if _, err := s.SaveNode(ctx, "admin", "new-saved-node", n, 0, 256); err != nil {
			t.Fatal(err)
		}
	}
	before := registrationStateForTest(t, s, n.ID)
	n.Enabled = false
	doc, err := newConfigurationDocument(f.c, []byte(`{}`), 1, []Node{n}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	stage, revision := savedRestoreFromDocument(t, s, f, doc)
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "registration-save", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	raw, err = s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "registration-queue", stage.ID, revision.Generation)
	_ = applicationReceipt(t, raw, err)
	p := claimApplicationForTest(t, s, f, "registration-environment")
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, s, f, "registration-owner")
	p, err = s.armConfigurationApplication(ctx, f.v, p)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, p, before
}

func registrationStateForTest(t *testing.T, s *Store, node string) applicationRegistrationState {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	state, err := applicationRegistrationStateTx(context.Background(), tx, node)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestConfigurationApplicationRegistrationAtomicDisableAndRollback(t *testing.T) {
	for _, installed := range []bool{true, false} {
		name := "new-node"
		if installed {
			name = "installed"
		}
		t.Run(name, func(t *testing.T) {
			s, f, p, before := applicationRegistrationFixture(t, installed)
			ctx := context.Background()
			r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
			if proof, err := r.InspectConfigurationPhase(ctx, p); err != nil || proof.State != "absent" {
				t.Fatal("inspection", err)
			}
			if registrationStateForTest(t, s, "registration-node") != before || tableCount(t, s, "v3_configuration_application_registrations") != 0 {
				t.Fatal("inspection wrote state")
			}
			if _, err := s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err == nil {
				t.Fatal("synthetic checkpoint skipped registration")
			}
			proof, err := r.ApplyConfigurationPhase(ctx, p)
			if err != nil || !proof.matches(p) {
				t.Fatal("disable", err)
			}
			after := registrationStateForTest(t, s, "registration-node")
			active := runtimeNodeForTest(t, s, "registration-node")
			if active.Enabled || after.Runtime.Epoch <= before.Runtime.Epoch || after.Applied != before.Applied || after.Runtime.Delivered != before.Runtime.Delivered {
				t.Fatal("disable claimed a remote delivery or lost fencing")
			}
			if proof, err = r.ApplyConfigurationPhase(ctx, p); err != nil || !proof.matches(p) || registrationStateForTest(t, s, "registration-node") != after {
				t.Fatal("replay", err)
			}
			if tableCount(t, s, "v3_deployment_jobs") != 0 {
				t.Fatal("local disable created remote task")
			}
			mustHistoryExec(t, s.DB, `INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES('registration-node','after-disable',clock_timestamp(),'modify','{}')`)
			if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, proof); err != nil {
				t.Fatal(err)
			}
			p = claimApplicationForTest(t, s, f, "after-registration")
			p = rollbackApplicationNodesForTest(t, s, f, p)
			proof, err = r.ApplyConfigurationPhase(ctx, p)
			if err != nil || !proof.matches(p) {
				t.Fatal("rollback", err)
			}
			restored := registrationStateForTest(t, s, "registration-node")
			b := before.Runtime
			b.Epoch = restored.Runtime.Epoch
			if restored.Runtime != b || restored.Runtime.Epoch <= after.Runtime.Epoch || restored.Applied != before.Applied {
				t.Fatal("original registration was not restored with new fence")
			}
			if _, err = r.ApplyConfigurationPhase(ctx, p); err != nil || registrationStateForTest(t, s, "registration-node") != restored {
				t.Fatal("rollback replay", err)
			}
			if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, proof); err != nil {
				t.Fatal(err)
			}
			p = claimApplicationForTest(t, s, f, "registration-final-rollback")
			if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
				t.Fatal("terminal receipt check", err)
			}
			desired, err := scanNode(s.DB.QueryRow(`SELECT ` + nodeColumns + ` FROM v3_nodes WHERE id='registration-node'`))
			if err != nil || desired.Enabled || desired.Version <= before.Runtime.Version || tableCount(t, s, "v3_events") != 1 {
				t.Fatal("rollback lost desired draft or new event", err)
			}
		})
	}
}

func TestConfigurationApplicationRegistrationRollbackBeforeEffect(t *testing.T) {
	s, f, p, before := applicationRegistrationFixture(t, true)
	p = rollbackApplicationNodesForTest(t, s, f, p)
	r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
	proof, err := r.ApplyConfigurationPhase(context.Background(), p)
	if err != nil || !proof.matches(p) || registrationStateForTest(t, s, "registration-node") != before {
		t.Fatal("rollback changed unstarted node", err)
	}
	if tableCount(t, s, "v3_configuration_application_registrations") != 1 {
		t.Fatal("missing unchanged receipt")
	}
}

func TestConfigurationApplicationRegistrationTakeoverAndDisasterRestore(t *testing.T) {
	s, f, p, _ := applicationRegistrationFixture(t, true)
	ctx := context.Background()
	r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
	if _, err := r.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal(err)
	}
	after := registrationStateForTest(t, s, "registration-node")
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second'`)
	fresh := claimApplicationForTest(t, s, f, "registration-takeover")
	if _, err := r.ApplyConfigurationPhase(ctx, p); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old authority", err)
	}
	if proof, err := r.InspectConfigurationPhase(ctx, fresh); err != nil || !proof.matches(fresh) {
		t.Fatal("takeover receipt", err)
	}
	backup, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	r.store = restored
	if _, err = r.ApplyConfigurationPhase(ctx, fresh); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("restore reused lease", err)
	}
	if _, err = restored.controlConfigurationApplication(ctx, f.v, "admin", "registration-recovery", p.ID, "resume"); err != nil {
		t.Fatal(err)
	}
	current := claimApplicationForTest(t, restored, f, "registration-recovered")
	if proof, err := r.ApplyConfigurationPhase(ctx, current); err != nil || !proof.matches(current) || registrationStateForTest(t, restored, "registration-node") != after {
		t.Fatal("restore replayed effect", err)
	}
}

func TestConfigurationApplicationRegistrationTransactionFailureAndConcurrency(t *testing.T) {
	for _, direction := range []string{"forward", "rollback"} {
		for _, table := range []string{"v3_nodes", "v3_node_runtime", "v3_configuration_application_registrations", "v3_audit"} {
			t.Run(direction+"/"+table, func(t *testing.T) {
				s, f, p, _ := applicationRegistrationFixture(t, true)
				ctx := context.Background()
				r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
				if direction == "rollback" {
					if _, err := r.ApplyConfigurationPhase(ctx, p); err != nil {
						t.Fatal(err)
					}
					p = rollbackApplicationNodesForTest(t, s, f, p)
				}
				before := registrationStateForTest(t, s, "registration-node")
				count := tableCount(t, s, "v3_configuration_application_registrations")
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_registration() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic failure';END$$;CREATE TRIGGER fail_registration BEFORE INSERT OR UPDATE ON `+table+` FOR EACH ROW EXECUTE FUNCTION fail_registration()`)
				if _, err := r.ApplyConfigurationPhase(ctx, p); err == nil {
					t.Fatal("injected failure ignored")
				}
				if registrationStateForTest(t, s, "registration-node") != before || tableCount(t, s, "v3_configuration_application_registrations") != count {
					t.Fatal("partial registration committed")
				}
				mustHistoryExec(t, s.DB, `DROP TRIGGER fail_registration ON `+table)
				failures := make(chan error, 5)
				var wg sync.WaitGroup
				for range 5 {
					wg.Add(1)
					go func() { defer wg.Done(); _, err := r.ApplyConfigurationPhase(ctx, p); failures <- err }()
				}
				wg.Wait()
				close(failures)
				for err := range failures {
					if err != nil {
						t.Fatal("concurrent retry", err)
					}
				}
				if tableCount(t, s, "v3_configuration_application_registrations") != count+1 || registrationStateForTest(t, s, "registration-node").Runtime.Epoch != before.Runtime.Epoch+1 {
					t.Fatal("duplicate effect")
				}
			})
		}
	}
}

func TestConfigurationApplicationRegistrationRejectsDriftAndRevokedAuthority(t *testing.T) {
	for _, kind := range []string{"receipt", "snapshot", "runtime", "applied", "source", "account", "migration", "member", "expired", "missing-checkpointed"} {
		t.Run(kind, func(t *testing.T) {
			s, f, p, _ := applicationRegistrationFixture(t, true)
			ctx := context.Background()
			r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
			proof, err := r.ApplyConfigurationPhase(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "receipt":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_application_registrations SET ciphertext=decode(repeat('00',32),'hex')`)
			case "snapshot":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_configurations SET name='changed' WHERE id=(SELECT snapshot FROM v3_node_runtime WHERE node='registration-node')`)
			case "runtime":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_runtime SET delivered_version=99`)
			case "applied":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET applied_version=99`)
			case "source":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET proof='broken'`)
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "migration":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('events',$1)`, token())
			case "member":
				r.bootstrap.Central.Instance = "other-member"
			case "expired":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second'`)
			case "missing-checkpointed":
				if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, proof); err != nil {
					t.Fatal(err)
				}
				p = claimApplicationForTest(t, s, f, "registration-later-phase")
				p = rollbackApplicationNodesForTest(t, s, f, p)
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_application_registrations`)
			}
			before := registrationStateForTest(t, s, "registration-node")
			if _, err = r.ApplyConfigurationPhase(ctx, p); err == nil {
				t.Fatal("invalid evidence accepted")
			}
			if registrationStateForTest(t, s, "registration-node") != before {
				t.Fatal("rejected operation changed registration")
			}
		})
	}
}

func TestConfigurationApplicationRegistrationSchema25AndPrivateReceipt(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE IF EXISTS v3_deployment_recoveries;DROP TABLE IF EXISTS v3_deployment_installations;DROP TABLE IF EXISTS v3_node_provisioning;DROP TABLE v3_configuration_application_registrations;DELETE FROM v3_schema WHERE version>=26`)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("missing backup allowed")
	}
	bad := filepath.Join(privateTestDir(t), "file")
	localWrite(t, bad, []byte("synthetic"))
	if err := s.Upgrade(ctx, bad); err == nil {
		t.Fatal("failed backup allowed")
	}
	if version, err := currentSchema(ctx, s.DB); err != nil || version != 25 {
		t.Fatal("failed migration changed schema", err)
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(privateApplicationRegistrationReceipt{}); err == nil {
		t.Fatal("private receipt serialized")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = readApplicationRegistrationTx(ctx, tx, nil, privateConfigurationApplication{}, "missing", "nodes"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("missing receipt", err)
	}
}

func TestConfigurationApplicationRegistrationInvalidatesCollectorsWithoutResurrectingNotifications(t *testing.T) {
	s, f, p, _ := applicationRegistrationFixture(t, true)
	ctx := context.Background()
	old := runtimeNodeForTest(t, s, "registration-node")
	l, err := s.Acquire(ctx, shardResource(old.Shard), "registration-collector")
	if err != nil {
		t.Fatal(err)
	}
	if err = runtimeFenceForTest(s, old, l); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_health_rules(key,node,kind,phase,since,last,recovery,reminder,payload) VALUES('rule','registration-node','cpu','firing',1,1,0,0,'{}');
 INSERT INTO v3_health_events(id,node,kind,phase,time,message,payload) VALUES('old-health','registration-node','cpu','firing',1,'synthetic','{}');
 INSERT INTO v3_health_batches(id,node,phase,message,created) VALUES('batch','registration-node','firing','synthetic',1);
 INSERT INTO v3_health_outbox(id,node,phase,message,created,batch) VALUES('old-health','registration-node','firing','synthetic',1,'batch');
 INSERT INTO v3_health_samples(node,time,cpu) VALUES('registration-node',1,80);
 INSERT INTO v3_node_status(node,sampled_at,metrics) VALUES('registration-node',1,'{"cpu":80}')`)
	r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
	if _, err = r.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err = runtimeFenceForTest(s, old, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("disabled node accepted old collection", err)
	}
	var done bool
	var sampled sql.NullInt64
	if err = s.DB.QueryRow(`SELECT done_at IS NOT NULL FROM v3_health_outbox WHERE id='old-health'`).Scan(&done); err != nil || !done {
		t.Fatal("pending notification was not cancelled", err)
	}
	if err = s.DB.QueryRow(`SELECT sampled_at FROM v3_node_status WHERE node='registration-node'`).Scan(&sampled); err != nil || sampled.Valid || tableCount(t, s, "v3_health_samples") != 0 {
		t.Fatal("old observations survived", err)
	}
	p = rollbackApplicationNodesForTest(t, s, f, p)
	if _, err = r.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal(err)
	}
	restored := runtimeNodeForTest(t, s, "registration-node")
	if !restored.Enabled || restored.RuntimeEpoch <= old.RuntimeEpoch {
		t.Fatal("rollback did not reactivate under fresh fence")
	}
	if err = runtimeFenceForTest(s, old, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("rollback resurrected old collector", err)
	}
	if err = runtimeFenceForTest(s, restored, l); err != nil {
		t.Fatal("restored registration unusable", err)
	}
	if err = s.DB.QueryRow(`SELECT done_at IS NOT NULL FROM v3_health_outbox WHERE id='old-health'`).Scan(&done); err != nil || !done || tableCount(t, s, "v3_health_events") != 1 {
		t.Fatal("rollback resurrected cancelled work or lost history", err)
	}
}

func TestConfigurationApplicationRegistrationLeaseExpiryDuringWriteRollsBack(t *testing.T) {
	s, f, p, before := applicationRegistrationFixture(t, true)
	// Expire authority during the last write. A check only before the receipt or
	// audit would allow a completed registration under an already expired lease.
	mustHistoryExec(t, s.DB, `CREATE FUNCTION expire_registration_parent() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second';RETURN NEW;END$$;
 CREATE TRIGGER expire_registration_parent BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION expire_registration_parent()`)
	r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
	if _, err := r.ApplyConfigurationPhase(context.Background(), p); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("effect committed after lease expiry", err)
	}
	if registrationStateForTest(t, s, "registration-node") != before || tableCount(t, s, "v3_configuration_application_registrations") != 0 {
		t.Fatal("expired transaction partially committed")
	}
}

func TestConfigurationApplicationRegistrationReceiptSwapAndKeyRotation(t *testing.T) {
	s, f, p, _ := applicationRegistrationFixture(t, true)
	ctx := context.Background()
	r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c}
	if _, err := r.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal(err)
	}
	_, path := testVault(t)
	rotated, err := OpenVault(path, f.c.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	r.vault = rotated
	if proof, err := r.InspectConfigurationPhase(ctx, p); err != nil || !proof.matches(p) {
		t.Fatal("rotation lost authentic receipt", err)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`UPDATE v3_configuration_application_registrations SET phase='restore-nodes'`)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err = readApplicationRegistrationTx(ctx, tx, f.v, p, "registration-node", "restore-nodes"); !errors.Is(err, errConfigurationApplication) {
		tx.Rollback()
		t.Fatal("receipt accepted for another direction", err)
	}
	tx.Rollback()
	r.vault, err = OpenVault(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.InspectConfigurationPhase(ctx, p); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestConfigurationApplicationRegistrationMixedRemoteFailureAndReverseRecovery(t *testing.T) {
	s, f, trust, p, requests := applicationNodesWithDisabledFixture(t, []string{"node-a", "node-b", "node-c"}, map[string]bool{"node-a": true})
	ctx := context.Background()
	before := registrationStateForTest(t, s, "node-a")
	remote := &orderedApplicationNodeRuntime{fail: "node-b:activate"}
	prepared := []string{}
	r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c, trust: trust, runtime: readinessFixtureRuntime{remote, t, s}, prepare: func(_ context.Context, _ privateConfigurationApplication, node string) (DeploymentRequest, error) {
		prepared = append(prepared, node)
		for _, in := range requests {
			if in.Node == node {
				return in, nil
			}
		}
		return DeploymentRequest{}, ErrConflict
	}}
	if _, err := r.ApplyConfigurationPhase(ctx, p); err == nil {
		t.Fatal("partial failure reported complete")
	}
	if len(prepared) != 1 || prepared[0] != "node-b" || tableCount(t, s, "v3_deployment_jobs") != 1 || runtimeNodeForTest(t, s, "node-a").Enabled {
		t.Fatal("local change did not stop at remote failure")
	}
	p = rollbackApplicationNodesForTest(t, s, f, p)
	remote.fail = ""
	r.prepare = nil
	proof, err := r.ApplyConfigurationPhase(ctx, p)
	if err != nil || !proof.matches(p) {
		t.Fatal("mixed rollback", err)
	}
	after := registrationStateForTest(t, s, "node-a")
	before.Runtime.Epoch = after.Runtime.Epoch
	if before != after || !runtimeNodeForTest(t, s, "node-a").Enabled || tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("mixed rollback lost original runtime or started later node")
	}
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, proof); err != nil {
		t.Fatal(err)
	}
}
