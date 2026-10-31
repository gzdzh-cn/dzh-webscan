package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func runtimeNodeForTest(t *testing.T, s *Store, id string) Node {
	t.Helper()
	n, err := scanActiveNode(s.DB.QueryRow("SELECT "+activeNodeColumns+" FROM v3_active_nodes WHERE id=$1", id))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func runtimeFenceForTest(s *Store, n Node, l Lease) error {
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return s.FenceNode(context.Background(), tx, n, l)
}

func TestNodeRuntimeSavedDraftDoesNotChangeCollection(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("registered-node")
	n.Config = []byte(`{"private":{"token":"synthetic-old-config"}}`)
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	old := runtimeNodeForTest(t, s, n.ID)
	l, err := s.Acquire(ctx, shardResource(old.Shard), "draft-collector")
	if err != nil {
		t.Fatal(err)
	}
	draft := n
	draft.Name = "new-name"
	draft.Endpoint = "192.0.2.99:19101"
	draft.ServerName = "other.example.test"
	draft.Enabled = false
	draft.Mode = "docker"
	draft.Config = []byte(`{"private":{"token":"synthetic-draft-config"}}`)
	if _, err = s.SaveNode(ctx, "admin", "save-draft", draft, 1, 256); err != nil {
		t.Fatal(err)
	}
	current := runtimeNodeForTest(t, s, n.ID)
	if current.Name != old.Name || current.Endpoint != old.Endpoint || current.ServerName != old.ServerName || current.Mode != old.Mode || !current.Enabled || current.Version != 1 || current.RuntimeEpoch != old.RuntimeEpoch || string(current.Config) != string(old.Config) {
		t.Fatal("draft replaced the runtime registration")
	}
	if err = runtimeFenceForTest(s, old, l); err != nil {
		t.Fatal("saved draft invalidated a live collector", err)
	}
	page, err := s.Nodes(ctx, "", "", 20, nil)
	if err != nil || len(page) != 1 || page[0].Version != 2 || page[0].Enabled || page[0].Configuration == nil || page[0].Configuration.RuntimeEnabled == nil || !*page[0].Configuration.RuntimeEnabled || page[0].Configuration.RegisteredVersion != 1 || page[0].Configuration.RuntimeEndpoint != old.Endpoint {
		t.Fatal("saved/runtime read model conflated", err)
	}
	fresh := nodeFixture("not-installed")
	if _, err = s.SaveNode(ctx, "admin", "save-new-node", fresh, 0, 256); err != nil {
		t.Fatal(err)
	}
	if _, err = scanActiveNode(s.DB.QueryRow("SELECT "+activeNodeColumns+" FROM v3_active_nodes WHERE id=$1", fresh.ID)); err != sql.ErrNoRows {
		t.Fatal("saving a new node authorized collection", err)
	}
	targets, err := s.nodesForShards(ctx, "", []int{old.Shard, fresh.Shard}, 200)
	if err != nil || len(targets) != 1 || targets[0].ID != old.ID || targets[0].RuntimeEpoch != old.RuntimeEpoch {
		t.Fatal("scheduler selected desired intent", err)
	}
}

func nodeRuntimeDeploymentFixture(t *testing.T) (*Store, Node, DeploymentJob) {
	t.Helper()
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	n.Config = []byte(`{"monitor":{"roots":["/srv/old"]}}`)
	n.AppliedVersion = 1
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET applied_version=1 WHERE id='node-a'`)
	old := runtimeNodeForTest(t, s, n.ID)
	draft := n
	draft.Endpoint = "192.0.2.55:19101"
	draft.Name = "new-routing"
	draft.Config = []byte(`{"monitor":{"roots":["/srv/new"]}}`)
	if _, err := s.SaveNode(ctx, "admin", "save-routing", draft, 1, 256); err != nil {
		t.Fatal(err)
	}
	v, _ := testVault(t)
	raw, err := s.AddCredential(ctx, v, "admin", "runtime-credential", n.ID, 2, credentialFixture())
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct{ ID string }
	if err = json.Unmarshal(raw, &receipt); err != nil || receipt.ID == "" {
		t.Fatal("invalid credential receipt", err)
	}
	id := receipt.ID
	in := DeploymentRequest{Node: n.ID, Kind: "upgrade", Expected: 2, Credential: id, Release: "v3.0.0", SHA256: strings.Repeat("a", 64)}
	createDeployment(t, s, in, "runtime-upgrade")
	j := claimDeployment(t, s, "runtime-executor")
	for j.Phase() != "activate" {
		if j.Phase() == "backup" {
			if err = s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
			j = reloadDeployment(t, s, j.ID)
		}
		if err = s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	return s, old, j
}

func TestNodeRuntimeActivationRollbackAndStaleCollectionEpoch(t *testing.T) {
	s, old, j := nodeRuntimeDeploymentFixture(t)
	ctx := context.Background()
	if n := runtimeNodeForTest(t, s, old.ID); n.Endpoint != old.Endpoint || n.Version != 1 {
		t.Fatal("preparation changed routing")
	}
	l, err := s.Acquire(ctx, shardResource(old.Shard), "runtime-collector")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	next := runtimeNodeForTest(t, s, old.ID)
	if next.Version != 2 || next.RuntimeEpoch <= old.RuntimeEpoch || next.Endpoint == old.Endpoint || next.AppliedVersion != 1 {
		t.Fatal("activation/applied versions conflated")
	}
	if err = runtimeFenceForTest(s, old, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old collector survived activation", err)
	}
	if err = runtimeFenceForTest(s, next, l); err != nil {
		t.Fatal(err)
	}
	if err = s.FailDeployment(ctx, j, "verification-failed"); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	if _, err = s.RecoverDeployment(ctx, "admin", "runtime-rollback", j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
		t.Fatal(err)
	}
	j = claimDeployment(t, s, "rollback-executor")
	if err = s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	restored := runtimeNodeForTest(t, s, old.ID)
	if restored.Endpoint != old.Endpoint || restored.Version != old.Version || string(restored.Config) != string(old.Config) || restored.RuntimeEpoch <= next.RuntimeEpoch {
		t.Fatal("rollback did not restore original routing with a new epoch")
	}
	for _, stale := range []Node{old, next} {
		if err = runtimeFenceForTest(s, stale, l); !errors.Is(err, ErrLeaseLost) {
			t.Fatal("rollback accepted a stale collector", err)
		}
	}
	if err = runtimeFenceForTest(s, restored, l); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	page, err := s.Nodes(ctx, "", "", 20, nil)
	if err != nil || page[0].Version != 2 || page[0].AppliedVersion != 1 || page[0].Configuration.DeliveredVersion != 1 {
		t.Fatal("rollback overwrote saved intent or falsely applied it", err)
	}
}

func TestNodeRuntimePublicationFailureIsAtomic(t *testing.T) {
	s, old, j := nodeRuntimeDeploymentFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_runtime_publish() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic publication failure';END$$;CREATE TRIGGER fail_runtime_publish BEFORE UPDATE ON v3_node_runtime FOR EACH ROW EXECUTE FUNCTION fail_runtime_publish()`)
	if err := s.CompleteDeploymentPhase(ctx, j); err == nil {
		t.Fatal("publication failure ignored")
	}
	current := reloadDeployment(t, s, j.ID)
	active := runtimeNodeForTest(t, s, j.Node)
	if current.Step != j.Step || current.LogCursor != j.LogCursor || active.RuntimeEpoch != old.RuntimeEpoch || active.Endpoint != old.Endpoint {
		t.Fatal("partial routing/checkpoint committed")
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER fail_runtime_publish ON v3_node_runtime`)
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
}

func TestNodeRuntimeMissingOrChangedBaselineStopsBeforeRemote(t *testing.T) {
	for _, kind := range []string{"missing", "changed", "generation"} {
		t.Run(kind, func(t *testing.T) {
			s, _, j := nodeRuntimeDeploymentFixture(t)
			if kind == "missing" {
				mustHistoryExec(t, s.DB, `DELETE FROM v3_node_runtime WHERE node=$1`, j.Node)
			} else if kind == "generation" {
				mustHistoryExec(t, s.DB, `UPDATE v3_node_runtime SET epoch=epoch+1 WHERE node=$1`, j.Node)
			} else {
				mustHistoryExec(t, s.DB, `UPDATE v3_node_configurations SET endpoint='192.0.2.77:19100' WHERE id=$1`, j.Plan.PreviousRuntime.Snapshot)
			}
			fake := &fakeDeploymentRuntime{}
			remote := &archiveCheckedRuntime{DeploymentRuntime: fake}
			err := (&DeploymentRunner{Store: s, Runtime: remote}).Execute(context.Background(), j)
			var failure DeploymentFailure
			if !errors.As(err, &failure) || failure.Code != "configuration-conflict" || len(remote.inspected) != 0 || len(fake.calls) != 0 {
				t.Fatal("changed baseline reached remote", err)
			}
		})
	}
}

func dropNodeRuntimeForTest(t *testing.T, s *Store) {
	t.Helper()
	dropSettingsDraftForTest(t, s)
	mustHistoryExec(t, s.DB, nodeHistoryRetirementTestDrop+`DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP VIEW v3_active_nodes;DROP TABLE v3_node_runtime;DROP TABLE v3_node_configurations;ALTER TABLE v3_nodes DROP COLUMN runtime_generation;DELETE FROM v3_schema WHERE version>=19`)
}

func TestNodeRuntimeFirstInstallRollbackAndReinstall(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	if _, err := s.SaveNode(ctx, "admin", "save-first", n, 0, 256); err != nil {
		t.Fatal(err)
	}
	v, _ := testVault(t)
	in := DeploymentRequest{Node: n.ID, Kind: "install", Expected: 1, Credential: addCredential(t, s, v, n.ID), Release: "v3.0.0", SHA256: strings.Repeat("a", 64)}
	createDeployment(t, s, in, "first-install")
	j := claimDeployment(t, s, "first-executor")
	for j.Phase() != "verify" {
		if j.Phase() == "backup" {
			if err := s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	active := runtimeNodeForTest(t, s, n.ID)
	if active.RuntimeEpoch != 1 || active.AppliedVersion != 0 {
		t.Fatal("first activation falsely applied", active)
	}
	if err := s.FailDeployment(ctx, j, "verification-failed"); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	if _, err := s.RecoverDeployment(ctx, "admin", "first-rollback", j.ID, "rollback", j.PlanDigest, j.LogCursor); err != nil {
		t.Fatal(err)
	}
	j = claimDeployment(t, s, "first-rollback-executor")
	for j.Phase() != "complete" {
		if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	if count := tableCount(t, s, "v3_node_runtime"); count != 0 {
		t.Fatal("failed first install retained authorization", count)
	}
	createDeployment(t, s, in, "reinstall")
	j = claimDeployment(t, s, "reinstall-executor")
	for j.Phase() != "verify" {
		if j.Phase() == "backup" {
			if err := s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	if n := runtimeNodeForTest(t, s, n.ID); n.RuntimeEpoch <= active.RuntimeEpoch+1 {
		t.Fatal("reinstall reused retired generation")
	}
	recordDeploymentReady(t, s, j)
	for j.Phase() != "complete" {
		if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	if n := runtimeNodeForTest(t, s, n.ID); n.AppliedVersion != 1 {
		t.Fatal("verified install did not advance applied version")
	}
}

func TestNodeRuntimeCorruptSnapshotsStopBeforeRemote(t *testing.T) {
	for _, activated := range []bool{false, true} {
		for _, original := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "staged", true: "active"}[activated], map[bool]string{false: "target", true: "original"}[original]}, "/"), func(t *testing.T) {
				s, _, j := nodeRuntimeDeploymentFixture(t)
				if activated {
					if err := s.CompleteDeploymentPhase(context.Background(), j); err != nil {
						t.Fatal(err)
					}
					j = reloadDeployment(t, s, j.ID)
				}
				id := j.Plan.TargetRuntime
				if original {
					id = j.Plan.PreviousRuntime.Snapshot
				}
				mustHistoryExec(t, s.DB, `UPDATE v3_node_configurations SET endpoint='192.0.2.88:19100' WHERE id=$1`, id)
				fake := &fakeDeploymentRuntime{}
				remote := &archiveCheckedRuntime{DeploymentRuntime: fake}
				err := (&DeploymentRunner{Store: s, Runtime: remote}).Execute(context.Background(), j)
				var failure DeploymentFailure
				if !errors.As(err, &failure) || failure.Code != "configuration-conflict" || len(remote.inspected) != 0 || len(fake.calls) != 0 {
					t.Fatal("corrupt snapshot reached remote", err)
				}
			})
		}
	}
}

func TestNodeRuntimePublisherWaitsForCollectorAndFencesOldRequests(t *testing.T) {
	s, old, j := nodeRuntimeDeploymentFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := s.Acquire(ctx, shardResource(old.Shard), "locking-collector")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := s.FenceNode(ctx, tx, old, l); err != nil {
		t.Fatal(err)
	}
	var collectorPID int
	if err := tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&collectorPID); err != nil {
		t.Fatal(err)
	}
	pid, result := make(chan int, 1), make(chan error, 1)
	go func() {
		publication, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			result <- e
			return
		}
		defer publication.Rollback()
		var p int
		if e = publication.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&p); e != nil {
			result <- e
			return
		}
		pid <- p
		if e = publishNodeRuntimeTx(ctx, publication, old.ID, j.Plan.TargetRuntime, j.NodeVersion); e == nil {
			e = publication.Commit()
		}
		result <- e
	}()
	var publisherPID int
	select {
	case publisherPID = <-pid:
	case e := <-result:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for {
		var blocked bool
		if err := s.DB.QueryRowContext(ctx, `SELECT $1=ANY(pg_blocking_pids($2))`, collectorPID, publisherPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case e := <-result:
			t.Fatal("publication bypassed collection lock", e)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal("publication lock order failed", err)
	}
	if err := runtimeFenceForTest(s, old, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale collection accepted", err)
	}
}

func TestNodeRuntimeSchema18UpgradeAndDisasterRestore(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("migration-node")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	dropNodeRuntimeForTest(t, s)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema 18 migrated without backup")
	}
	var exists bool
	if err := s.DB.QueryRow(`SELECT to_regclass(current_schema()||'.v3_node_runtime') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatal("failed migration changed registration", err)
	}
	dir := privateTestDir(t)
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	active := runtimeNodeForTest(t, s, n.ID)
	if active.Version != 1 || active.AppliedVersion != 0 || active.RuntimeEpoch != 1 {
		t.Fatal("migration invented installation evidence")
	}
	page, err := s.Nodes(ctx, "", "", 20, nil)
	if err != nil || page[0].Configuration.DeliveredVersion != 0 {
		t.Fatal("migration invented delivered version", err)
	}
	// Advance once before the archive: restore must preserve both snapshot IDs
	// and the monotonic counter, rather than rebuilding them from saved intent.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = publishNodeRuntimeTx(ctx, tx, n.ID, "migration-"+n.ID, 0); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
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
	restored := runtimeNodeForTest(t, target, n.ID)
	if restored.RuntimeEpoch != 2 || restored.AppliedVersion != 0 || restored.Endpoint != active.Endpoint {
		t.Fatal("runtime archive mismatch")
	}
	if err = target.PutNode(ctx, n, 1, 256); err != nil {
		t.Fatal(err)
	}
	if runtimeNodeForTest(t, target, n.ID).RuntimeEpoch != 3 {
		t.Fatal("disaster restore reused generation")
	}
}

func TestNodeRuntimeVerificationLocksCollectorLeaseBeforeNode(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	assertDeploymentLocksCollectorLeaseBeforeNode(t, s, j, func(ctx context.Context) error { return s.CompleteDeploymentPhase(ctx, j) })
}

func assertDeploymentLocksCollectorLeaseBeforeNode(t *testing.T, s *Store, j DeploymentJob, complete func(context.Context) error) {
	t.Helper()
	l := recordDeploymentReady(t, s, j)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lease, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Rollback()
	if _, err = lease.ExecContext(ctx, `UPDATE v3_leases SET expires_at=clock_timestamp()+interval '30 seconds' WHERE resource=$1`, l.Resource); err != nil {
		t.Fatal(err)
	}
	var leasePID int
	if err = lease.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&leasePID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- complete(ctx) }()
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE 'SELECT epoch FROM v3_leases WHERE resource=%FOR SHARE')`, leasePID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err = <-result:
			t.Fatal("verification did not wait for collector lease", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	probe, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback()
	var id string
	if err = probe.QueryRowContext(ctx, `SELECT id FROM v3_nodes WHERE id=$1 FOR UPDATE NOWAIT`, j.Node).Scan(&id); err != nil {
		t.Fatal("verification took node lock before collector lease", err)
	}
	if err = probe.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = lease.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
}
