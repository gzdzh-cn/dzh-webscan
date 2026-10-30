package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

// Source/parent persistence, release trust, credentials and readiness checks
// use real SQL. Collector observations, the environment checkpoint and remote
// deployment adapter are synthetic fixtures.
// These tests must not be reported as native/Docker installation acceptance.
func applicationNodeFixture(t *testing.T) (*Store, configurationLocalFixture, *deploymentTrust, privateConfigurationApplication, DeploymentRequest) {
	t.Helper()
	s, f, trust, parent, requests := applicationNodesFixture(t, []string{"node-a"})
	return s, f, trust, parent, requests[0]
}

func applicationNodesFixture(t *testing.T, ids []string) (*Store, configurationLocalFixture, *deploymentTrust, privateConfigurationApplication, []DeploymentRequest) {
	return applicationNodesWithDisabledFixture(t, ids, nil)
}

func applicationNodesWithDisabledFixture(t *testing.T, ids []string, disabled map[string]bool) (*Store, configurationLocalFixture, *deploymentTrust, privateConfigurationApplication, []DeploymentRequest) {
	t.Helper()
	s, f := newSavedConfigurationStore(t)
	ctx := context.Background()
	var nodes []Node
	credentials := map[string]string{}
	for _, id := range ids {
		n := nodeFixture(id)
		if err := s.PutNode(ctx, n, 0, f.c.Collector.Shards); err != nil {
			t.Fatal(err)
		}
		n.Enabled = !disabled[id]
		nodes = append(nodes, n)
		credentials[id] = addCredential(t, s, f.v, id)
	}
	trust, err := loadDeploymentTrust(ctx, f.c.DeploymentTrust)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := newConfigurationDocument(f.c, []byte(`{}`), 1, nodes, f.now)
	if err != nil {
		t.Fatal(err)
	}
	stage, revision := savedRestoreFromDocument(t, s, f, doc)
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "node-parent-save", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	raw, err = s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "node-parent-queue", stage.ID, revision.Generation)
	_ = applicationReceipt(t, raw, err)
	parent := claimApplicationForTest(t, s, f, "node-parent-environment")
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, parent, applicationComplete(parent)); err != nil {
		t.Fatal(err)
	}
	parent = claimApplicationForTest(t, s, f, "node-parent-owner")
	parent, err = s.armConfigurationApplication(ctx, f.v, parent)
	if err != nil {
		t.Fatal(err)
	}
	var requests []DeploymentRequest
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}
		identity, err := f.authority.Issue(nodepki.Node, n.ID, []string{n.ServerName}, f.now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(f.f.root, "node-child-identity-"+n.ID)
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for name, raw := range map[string][]byte{"ca.crt": identity.CA, "identity.crt": identity.Certificate, "identity.key": identity.Key} {
			localWrite(t, filepath.Join(dir, name), raw)
		}
		rules := filepath.Join(f.f.root, "child-rules-"+n.ID+".yar")
		localWrite(t, rules, []byte("rule isolated { condition: false }"))
		var version int64
		if err = s.DB.QueryRow(`SELECT version FROM v3_nodes WHERE id=$1`, n.ID).Scan(&version); err != nil {
			t.Fatal(err)
		}
		in, err := s.prepareLocalDeployment(ctx, f.c, trust, deploymentPreparationInput{Node: n.ID, Expected: version, Kind: "install", Credential: credentials[n.ID], IdentityDirectory: dir, Collectors: []string{"collector-local"}, RulesFile: rules})
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, in)
	}
	return s, f, trust, parent, requests
}

func TestConfigurationApplicationNodeQueueClaimAndFencedExecution(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	ctx := context.Background()
	j, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in); err != nil || replay.ID != j.ID || tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("parent replay duplicated child", err)
	}
	if _, err = s.ClaimDeployment(ctx, "ordinary-worker"); err != sql.ErrNoRows {
		t.Fatal("ordinary worker claimed parent child", err)
	}
	j, scoped, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "parent-child-worker")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RenewDeployment(ctx, j); !errors.Is(err, errConfigurationApplicationBusy) {
		t.Fatal("unscoped child renewed", err)
	}
	if err = s.RenewDeployment(scoped, j); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "duplicate-parent-worker"); err != sql.ErrNoRows {
		t.Fatal("same parent stole live child", err)
	}
	runner := DeploymentRunner{Store: s, Vault: f.v, Runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, s}}
	if err = runner.Execute(scoped, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	if j.Status != "succeeded" || j.RecoveryRequired || deploymentBackupPinCount(t, s, j, "rollback") != 1 {
		t.Fatal("child success lost parent rollback protection")
	}
	if parent := privateApplicationForTest(t, s, f.v, p.ID); parent.step != 1 || !parent.RecoveryRequired || parent.Status != "running" {
		t.Fatal("child independently completed parent")
	}
}

func TestConfigurationApplicationNodeParentTakeoverFencesLiveChild(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	ctx := context.Background()
	if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in); err != nil {
		t.Fatal(err)
	}
	old, oldScope, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "old-child")
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, p.ID)
	newParent := claimApplicationForTest(t, s, f, "replacement-parent")
	fresh, freshScope, err := s.claimApplicationNodeDeployment(ctx, f.v, newParent, in.Node, "fresh-child")
	if err != nil || fresh.ID != old.ID || fresh.Epoch <= old.Epoch {
		t.Fatal("parent takeover failed to fence live child", err)
	}
	if err = s.RenewDeployment(oldScope, old); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old parent capability survived takeover", err)
	}
	if err = s.CompleteDeploymentPhase(oldScope, old); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old child checkpoint survived takeover", err)
	}
	if err = s.RenewDeployment(freshScope, fresh); err != nil {
		t.Fatal("replacement child could not renew", err)
	}
	wrong := fresh
	wrong.Node = "other-node"
	if err = s.RenewDeployment(freshScope, wrong); !errors.Is(err, errConfigurationApplication) {
		t.Fatal("capability accepted another node", err)
	}
	if err = (&DeploymentRunner{Store: s, Vault: f.v, Runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, s}}).Execute(freshScope, fresh); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationApplicationNodeRejectsLinkTampering(t *testing.T) {
	for _, field := range []string{"proof", "parent_epoch", "ordinal", "plan_digest"} {
		t.Run(field, func(t *testing.T) {
			s, f, trust, p, in := applicationNodeFixture(t)
			ctx := context.Background()
			if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in); err != nil {
				t.Fatal(err)
			}
			value := map[string]string{"proof": "'broken'", "parent_epoch": "parent_epoch+1", "ordinal": "ordinal+1", "plan_digest": "repeat('b',64)"}[field]
			mustHistoryExec(t, s.DB, `UPDATE v3_configuration_application_nodes SET `+field+`=`+value)
			if _, _, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "tampered-child"); !errors.Is(err, errConfigurationApplication) {
				t.Fatal("tampered link authorized child", err)
			}
			j, err := s.Deployment(ctx, func() string {
				var id string
				if err := s.DB.QueryRow(`SELECT child FROM v3_configuration_application_nodes`).Scan(&id); err != nil {
					t.Fatal(err)
				}
				return id
			}())
			if err != nil || j.Epoch != 0 || j.Status != "queued" {
				t.Fatal("failed link check modified child", err)
			}
		})
	}
}

func rollbackApplicationNodesForTest(t *testing.T, s *Store, f configurationLocalFixture, p privateConfigurationApplication) privateConfigurationApplication {
	t.Helper()
	ctx := context.Background()
	if err := s.failConfigurationApplication(ctx, f.v, p, "deployment-failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.controlConfigurationApplication(ctx, f.v, "admin", "parent-node-rollback", p.ID, "rollback"); err != nil {
		t.Fatal(err)
	}
	// These preceding settings/bootstrap checkpoints are synthetic: the fixture
	// never applied either. Node rollback below uses the real child journal.
	for range 2 {
		p = claimApplicationForTest(t, s, f, "rollback-preceding-test-phase")
		if _, err := s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
			t.Fatal(err)
		}
	}
	return claimApplicationForTest(t, s, f, "parent-node-rollback-owner")
}

func TestConfigurationApplicationNodeSuccessfulChildRollbackKeepsNewEvents(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	ctx := context.Background()
	queued, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in)
	if err != nil {
		t.Fatal(err)
	}
	j, scoped, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "forward-child")
	if err != nil {
		t.Fatal(err)
	}
	remote := &fakeDeploymentRuntime{}
	runner := DeploymentRunner{Store: s, Vault: f.v, Runtime: readinessFixtureRuntime{remote, t, s}}
	if err = runner.Execute(scoped, j); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES($1,'after-child-switch',clock_timestamp(),'modify','{}')`, j.Node)
	p = rollbackApplicationNodesForTest(t, s, f, p)
	j, scoped, err = s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "rollback-child")
	if err != nil || j.ID != queued.ID || j.Direction != "rollback" || !j.RecoveryRequired || j.Plan.BeforeBackup != queued.Plan.BeforeBackup {
		t.Fatal("successful child was not reopened with original baseline", err)
	}
	remote.failPhase = "restore"
	if err = runner.Execute(scoped, j); err == nil {
		t.Fatal("failed restore reported success")
	}
	j = reloadDeployment(t, s, j.ID)
	if !j.RecoveryRequired || deploymentBackupPinCount(t, s, j, "rollback") != 1 {
		t.Fatal("failed rollback released recovery archive")
	}
	remote.failPhase = ""
	j, scoped, err = s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "continue-rollback-child")
	if err != nil {
		t.Fatal(err)
	}
	if err = runner.Execute(scoped, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	if j.Status != "rolled_back" || j.RecoveryRequired || deploymentBackupPinCount(t, s, j, "rollback") != 1 {
		t.Fatal("child terminal state lost parent archive protection")
	}
	var applied int64
	if err = s.DB.QueryRow(`SELECT applied_version FROM v3_nodes WHERE id=$1`, j.Node).Scan(&applied); err != nil || applied != j.Plan.Node.AppliedVersion {
		t.Fatal("rollback falsely retained new applied version", applied, err)
	}
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, s, f, "parent-rollback-final-verifier")
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	if deploymentBackupPinCount(t, s, j, "") != 0 || tableCount(t, s, "v3_events") != 1 {
		t.Fatal("parent finalization lost new events or retained its own finished pin")
	}
	if _, err = s.ClaimDeployment(ctx, "ordinary-after-parent"); err != sql.ErrNoRows {
		t.Fatal("finished linked child reappeared as independent task", err)
	}
}

func TestConfigurationApplicationNodeUnarmedRollbackDoesNotClaimRemoteRestore(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	ctx := context.Background()
	j, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in)
	if err != nil {
		t.Fatal(err)
	}
	p = rollbackApplicationNodesForTest(t, s, f, p)
	settled, _, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "unchanged-child")
	if err != nil || settled.Status != "rolled_back" || settled.RecoveryRequired || settled.Step != 0 || settled.Epoch != 1 {
		t.Fatal("unchanged service was not settled without remote work", err)
	}
	var unchanged int
	if err = s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='configuration-application-node-unchanged' AND result->>'service_changed'='false'`).Scan(&unchanged); err != nil || unchanged != 1 {
		t.Fatal("no explicit evidence of no service change", err)
	}
	if deploymentBackupPinCount(t, s, j, "deployment") != 1 {
		t.Fatal("unarmed child released parent archive prematurely")
	}
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, s, f, "unchanged-parent-final")
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	if deploymentBackupPinCount(t, s, j, "") != 0 {
		t.Fatal("final parent did not release unchanged child's pin")
	}
}

func TestConfigurationApplicationNodeParentCannotAdvanceBeforeChild(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	ctx := context.Background()
	j, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in)
	if err != nil {
		t.Fatal(err)
	}
	// A buggy partial runtime cannot use a synthetic phase receipt to advance
	// beyond its unfinished child or release the child's recovery archive.
	if _, err = s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); !errors.Is(err, errConfigurationApplication) {
		t.Fatal("parent advanced past unfinished child", err)
	}
	if got := privateApplicationForTest(t, s, f.v, p.ID); got.Status != "running" || got.phase() != "nodes" || !got.RecoveryRequired || deploymentBackupPinCount(t, s, j, "deployment") != 1 {
		t.Fatal("failed finalization changed durable protection")
	}
}

func TestConfigurationApplicationNodeSequentialAndReverseRollback(t *testing.T) {
	s, f, trust, p, requests := applicationNodesFixture(t, []string{"node-a", "node-b"})
	ctx := context.Background()
	if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, requests[1]); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("later node queued before earlier node", err)
	}
	for _, in := range requests {
		if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in); err != nil {
			t.Fatal(err)
		}
		j, scoped, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "sequential-child")
		if err != nil {
			t.Fatal(err)
		}
		if err = (&DeploymentRunner{Store: s, Vault: f.v, Runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, s}}).Execute(scoped, j); err != nil {
			t.Fatal(err)
		}
	}
	p = rollbackApplicationNodesForTest(t, s, f, p)
	if _, _, err := s.claimApplicationNodeDeployment(ctx, f.v, p, requests[0].Node, "incorrect-rollback-order"); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("earlier node rolled back before later node", err)
	}
	for i := len(requests) - 1; i >= 0; i-- {
		j, scoped, err := s.claimApplicationNodeDeployment(ctx, f.v, p, requests[i].Node, "reverse-child")
		if err != nil {
			t.Fatal(err)
		}
		if err = (&DeploymentRunner{Store: s, Vault: f.v, Runtime: &fakeDeploymentRuntime{}}).Execute(scoped, j); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, s, f, "reverse-final-parent")
	if _, err := s.checkpointConfigurationApplication(ctx, f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM v3_configuration_backup_pins WHERE reference LIKE 'job:%'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("parent retained completed child pins", count, err)
	}
}

func TestConfigurationApplicationNodeQueueAtomicity(t *testing.T) {
	for _, target := range []string{"v3_configuration_application_nodes", "v3_audit"} {
		t.Run(target, func(t *testing.T) {
			s, f, trust, p, in := applicationNodeFixture(t)
			counts := map[string]int{}
			for _, table := range []string{"v3_configuration_backups", "v3_deployment_jobs", "v3_deployment_logs", "v3_configuration_backup_pins", "v3_configuration_application_nodes", "v3_configuration_application_targets", "v3_audit"} {
				counts[table] = tableCount(t, s, table)
			}
			mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_child_link() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic link failure';END$$;CREATE TRIGGER reject_child_link BEFORE INSERT ON `+target+` FOR EACH ROW EXECUTE FUNCTION reject_child_link()`)
			if _, err := s.queueApplicationNodeDeployment(context.Background(), f.c, trust, p, in); err == nil {
				t.Fatal("link/audit failure did not stop queue")
			}
			for table, count := range counts {
				if tableCount(t, s, table) != count {
					t.Fatal("queue partially committed", table)
				}
			}
			mustHistoryExec(t, s.DB, `DROP TRIGGER reject_child_link ON `+target+`;DROP FUNCTION reject_child_link()`)
			if _, err := s.queueApplicationNodeDeployment(context.Background(), f.c, trust, p, in); err != nil {
				t.Fatal("atomic failure was not retryable", err)
			}
		})
	}
}

func TestConfigurationApplicationNodeRevokedControllerAndRecoveryHold(t *testing.T) {
	for _, scenario := range []string{"revoked-controller", "recovery-hold"} {
		t.Run(scenario, func(t *testing.T) {
			s, f, trust, p, in := applicationNodeFixture(t)
			ctx := context.Background()
			if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in); err != nil {
				t.Fatal(err)
			}
			j, scoped, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "revoked-child")
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "revoked-controller" {
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer',revision=revision+1 WHERE username='admin'`)
			} else {
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET recovery_hold=true WHERE id=$1`, p.ID)
			}
			if err = s.RenewDeployment(scoped, j); err == nil {
				t.Fatal("revoked parent renewed child")
			}
			if err = s.CompleteDeploymentPhase(scoped, j); err == nil {
				t.Fatal("revoked parent completed child phase")
			}
			if got := reloadDeployment(t, s, j.ID); got.Step != 0 || got.Epoch != j.Epoch {
				t.Fatal("revoked execution changed child")
			}
		})
	}
}

func TestConfigurationApplicationNodeConcurrentQueueCreatesOneChild(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	var wg sync.WaitGroup
	results := make(chan DeploymentJob, 4)
	failures := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, err := s.queueApplicationNodeDeployment(context.Background(), f.c, trust, p, in)
			results <- j
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	id := ""
	for j := range results {
		if id == "" {
			id = j.ID
		}
		if j.ID != id {
			t.Fatal("concurrent parent queue created multiple jobs")
		}
	}
	if tableCount(t, s, "v3_deployment_jobs") != 1 || tableCount(t, s, "v3_configuration_application_nodes") != 1 {
		t.Fatal("duplicate child journals/links")
	}
}

type canceledApplicationChildRuntime struct{ started chan struct{} }

func (r canceledApplicationChildRuntime) Inspect(ctx context.Context, _ DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	close(r.started)
	<-ctx.Done()
	return RemoteDeploymentCheckpoint{}, ctx.Err()
}
func (r canceledApplicationChildRuntime) Apply(context.Context, DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	return RemoteDeploymentCheckpoint{}, errors.New("unexpected remote apply")
}

func TestConfigurationApplicationNodeCancellationKeepsCapabilityForInterruptedCheckpoint(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	ctx := context.Background()
	if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in); err != nil {
		t.Fatal(err)
	}
	j, scoped, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "cancel-child")
	if err != nil {
		t.Fatal(err)
	}
	cancelable, cancel := context.WithCancel(scoped)
	defer cancel()
	runtime := canceledApplicationChildRuntime{make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- (&DeploymentRunner{Store: s, Vault: f.v, Runtime: runtime}).Execute(cancelable, j) }()
	select {
	case <-runtime.started:
	case <-time.After(10 * time.Second):
		t.Fatal("child did not reach isolated remote inspection")
	}
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("canceled child did not drain")
	}
	if got := reloadDeployment(t, s, j.ID); got.Status != "interrupted" || got.ErrorCode != "interrupted" || got.Step != 0 {
		t.Fatal("cancellation lost scoped authority to checkpoint interruption", got.Status)
	}
	if deploymentBackupPinCount(t, s, j, "deployment") != 1 {
		t.Fatal("cancellation released parent rollback protection")
	}
}

func TestConfigurationApplicationNodeDisasterRestoreRequiresReauthorization(t *testing.T) {
	s, f, trust, p, in := applicationNodeFixture(t)
	ctx := context.Background()
	if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in); err != nil {
		t.Fatal(err)
	}
	old, _, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "before-disaster-child")
	if err != nil {
		t.Fatal(err)
	}
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err = target.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "unapproved-restored-child"); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("archived lease authorized work after disaster restore", err)
	}
	if _, err = target.ClaimDeployment(ctx, "ordinary-restored-child"); err != sql.ErrNoRows {
		t.Fatal("restored child escaped parent gate", err)
	}
	if _, err = target.controlConfigurationApplication(ctx, f.v, "admin", "reauthorize-restored-parent", p.ID, "resume"); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, target, f, "restored-parent")
	j, scoped, err := target.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "approved-restored-child")
	if err != nil || j.ID != old.ID || j.Epoch <= old.Epoch {
		t.Fatal("restored child did not receive a new fence", err)
	}
	if err = (&DeploymentRunner{Store: target, Vault: f.v, Runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, target}}).Execute(scoped, j); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationApplicationNodeTargetManifestPinnedAcrossChildren(t *testing.T) {
	s, f, trust, p, requests := applicationNodesFixture(t, []string{"node-a", "node-b"})
	ctx := context.Background()
	if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, requests[0]); err != nil {
		t.Fatal(err)
	}
	j, scoped, err := s.claimApplicationNodeDeployment(ctx, f.v, p, requests[0].Node, "first-release-child")
	if err != nil {
		t.Fatal(err)
	}
	if err = (&DeploymentRunner{Store: s, Vault: f.v, Runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, s}}).Execute(scoped, j); err != nil {
		t.Fatal(err)
	}
	// Simulate a newer executor with another genuinely signature-verified
	// release. Its valid new bundle cannot change this in-progress target.
	other := *trust
	manifest := trust.release.manifest
	manifest.Release = "v3.0.1"
	other.release = signedRelease(t, manifest)
	newRequest, err := s.prepareLocalDeployment(ctx, f.c, &other, deploymentPreparationInput{Node: "node-b", Expected: requests[1].Expected, Kind: "install", Credential: requests[1].Credential, IdentityDirectory: filepath.Join(f.f.root, "node-child-identity-node-b"), Collectors: []string{"collector-local"}, RulesFile: filepath.Join(f.f.root, "child-rules-node-b.yar")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.queueApplicationNodeDeployment(ctx, f.c, &other, p, newRequest); !errors.Is(err, ErrRequestConflict) {
		t.Fatal("parent silently mixed target releases", err)
	}
	if tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("rejected new release created a child")
	}
	if _, err = s.queueApplicationNodeDeployment(ctx, f.c, trust, p, requests[1]); err != nil {
		t.Fatal("original pinned release could not continue", err)
	}
}

func TestConfigurationApplicationNodeTargetTamperingBlocksExistingLease(t *testing.T) {
	for _, corruption := range []string{"missing", "proof", "release"} {
		t.Run(corruption, func(t *testing.T) {
			s, f, trust, p, in := applicationNodeFixture(t)
			ctx := context.Background()
			if _, err := s.queueApplicationNodeDeployment(ctx, f.c, trust, p, in); err != nil {
				t.Fatal(err)
			}
			j, scoped, err := s.claimApplicationNodeDeployment(ctx, f.v, p, in.Node, "target-corruption-child")
			if err != nil {
				t.Fatal(err)
			}
			query := map[string]string{"missing": `DELETE FROM v3_configuration_application_targets`, "proof": `UPDATE v3_configuration_application_targets SET proof='broken'`, "release": `UPDATE v3_configuration_application_targets SET release='v3.0.1'`}[corruption]
			mustHistoryExec(t, s.DB, query)
			if err = s.RenewDeployment(scoped, j); !errors.Is(err, errConfigurationApplication) {
				t.Fatal("target corruption retained child authority", err)
			}
			if err = s.CompleteDeploymentPhase(scoped, j); !errors.Is(err, errConfigurationApplication) {
				t.Fatal("target corruption allowed checkpoint", err)
			}
		})
	}
}
