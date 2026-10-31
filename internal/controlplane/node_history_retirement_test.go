package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Only used by synthetic downgrade fixtures, never by a production command.
// Older-schema tests must remove later triggers and tables before migration.
const nodeHistoryRetirementTestDrop = `DROP TABLE IF EXISTS v3_root_identity_issuances;
DROP FUNCTION IF EXISTS v3_root_issuance_immutable();
DROP TABLE IF EXISTS v3_root_rotations;
DELETE FROM v3_schema WHERE version=38;
ALTER TABLE v3_pki_authorities ADD COLUMN IF NOT EXISTS singleton boolean NOT NULL DEFAULT true UNIQUE CHECK(singleton);
DROP TABLE IF EXISTS v3_single_backup_runs;
DROP TABLE IF EXISTS v3_single_backup_policies;
DROP TRIGGER IF EXISTS v3_retirement_runtime_guard ON v3_node_runtime;
DROP TABLE IF EXISTS v3_node_history_retirements;
DROP FUNCTION IF EXISTS v3_retirement_runtime_guard();
DROP FUNCTION IF EXISTS v3_retirement_active_guard();
DROP FUNCTION IF EXISTS v3_retirement_immutable();
DELETE FROM v3_schema WHERE version=37;`

func nodeHistoryRetirementFixture(t *testing.T) (*Store, nodeHistoryRetirementInput) {
	t.Helper()
	s := testStore(t)
	ctx := context.Background()
	if err := s.Provision(ctx, "admin", "history-retirement-test-only"); err != nil {
		t.Fatal(err)
	}
	n := nodeFixture("node-history")
	n.AppliedVersion = 1
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET applied_version=1;UPDATE v3_node_runtime SET delivered_version=1;
 INSERT INTO v3_node_configurations SELECT 'migration-retire-old',node,version,'historic',endpoint,'old.example.test',false,mode,shard,config FROM v3_node_configurations WHERE node='node-history'`)
	return s, nodeHistoryRetirementInput{Node: n.ID, Expected: 1, Snapshots: []string{"migration-retire-old"}}
}

func confirmNodeHistoryRetirement(t *testing.T, s *Store, in nodeHistoryRetirementInput, key string) nodeHistoryRetirementInput {
	t.Helper()
	p, err := s.previewNodeHistoryRetirement(context.Background(), "admin", in)
	if err != nil {
		t.Fatal(err)
	}
	in.Confirm, in.PreviewSHA256 = true, p.PreviewSHA256
	if _, err = s.retireNodeHistory(context.Background(), "admin", key, in); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestNodeHistoryRetirementFencesRecoveryPreservesHistoryAndReplay(t *testing.T) {
	s, in := nodeHistoryRetirementFixture(t)
	ctx := context.Background()
	var original []byte
	if err := s.DB.QueryRow(`SELECT to_jsonb(c) FROM v3_node_configurations c WHERE id='migration-retire-old'`).Scan(&original); err != nil {
		t.Fatal(err)
	}
	before := runtimeNodeForTest(t, s, in.Node)
	in = confirmNodeHistoryRetirement(t, s, in, "retire-once")
	audits := tableCount(t, s, "v3_audit")
	if _, err := s.retireNodeHistory(ctx, "admin", "retire-once", in); err != nil || tableCount(t, s, "v3_audit") != audits || tableCount(t, s, "v3_node_history_retirements") != 1 {
		t.Fatal("receipt replay changed retirement history", err)
	}
	var kept []byte
	if err := s.DB.QueryRow(`SELECT to_jsonb(c) FROM v3_node_configurations c WHERE id='migration-retire-old'`).Scan(&kept); err != nil || string(kept) != string(original) {
		t.Fatal("historical config was deleted or rewritten", err)
	}
	after := runtimeNodeForTest(t, s, in.Node)
	if after.RuntimeEpoch != before.RuntimeEpoch || after.Version != before.Version || after.ServerName != before.ServerName {
		t.Fatal("retirement modified live collection")
	}
	for _, operation := range []string{"publish", "deployment", "baseline", "recover", "registration"} {
		t.Run(operation, func(t *testing.T) {
			tx, err := s.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			b := deploymentRuntimeBaseline{Snapshot: "migration-retire-old", Version: 1, Delivered: 1, Epoch: before.RuntimeEpoch, Digest: digest(original)}
			job := DeploymentJob{Node: in.Node, Plan: DeploymentPlan{TargetRuntime: "migration-retire-old"}}
			switch operation {
			case "publish":
				err = publishNodeRuntimeTx(ctx, tx, in.Node, b.Snapshot, 1)
			case "deployment":
				err = checkDeploymentRuntimeTx(ctx, tx, job)
			case "baseline":
				job.Plan.TargetRuntime, job.Plan.PreviousRuntime = "", &b
				err = checkDeploymentRuntimeTx(ctx, tx, job)
			case "recover":
				job.Kind, job.Direction = "recover", "rollback"
				job.Plan.PreviousRuntime = &b
				job.Plan.Recovery = &deploymentRecoveryPlan{From: b, Restore: b}
				err = checkRecoveryRuntimeTx(ctx, tx, job)
			case "registration":
				err = verifyApplicationRegistrationStateTx(ctx, tx, in.Node, applicationRegistrationState{Runtime: b})
			}
			if !errors.Is(err, errNodeHistoryRetired) {
				t.Fatal("retired snapshot reached a reactivation path", err)
			}
		})
	}
	if _, err := s.DB.Exec(`UPDATE v3_node_runtime SET snapshot='migration-retire-old' WHERE node=$1`, in.Node); err == nil {
		t.Fatal("database runtime fence was bypassed")
	}
	for _, q := range []string{`DELETE FROM v3_node_history_retirements`, `UPDATE v3_node_history_retirements SET username='other'`} {
		if _, err := s.DB.Exec(q); err == nil {
			t.Fatal("retirement evidence was mutable")
		}
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
	if _, err := s.retireNodeHistory(ctx, "admin", "retire-once", in); err == nil {
		t.Fatal("demoted administrator replayed retirement")
	}
}

func TestNodeHistoryRetirementRequiresFreshExplicitPreviewAndQuiescence(t *testing.T) {
	for _, scenario := range []string{"missing-confirm", "wrong-preview", "version", "saved-draft", "actor-revision", "snapshot-mutated", "active", "unknown", "other-node", "duplicate", "expired-intent", "pending-renewal", "pending-deployment"} {
		t.Run(scenario, func(t *testing.T) {
			s, in := nodeHistoryRetirementFixture(t)
			ctx := context.Background()
			p, err := s.previewNodeHistoryRetirement(ctx, "admin", in)
			if err != nil {
				t.Fatal(err)
			}
			in.Confirm, in.PreviewSHA256 = true, p.PreviewSHA256
			switch scenario {
			case "missing-confirm":
				in.Confirm = false
			case "wrong-preview":
				in.PreviewSHA256 = strings.Repeat("0", 64)
			case "version":
				in.Expected++
			case "saved-draft":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET name='unapplied'`)
			case "actor-revision":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "snapshot-mutated":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_configurations SET name='changed-history' WHERE id='migration-retire-old'`)
			case "active":
				if err := s.DB.QueryRow(`SELECT snapshot FROM v3_node_runtime WHERE node=$1`, in.Node).Scan(&in.Snapshots[0]); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				in.Snapshots = []string{"unknown"}
			case "other-node":
				in.Node = "other-node"
			case "duplicate":
				in.Snapshots = append(in.Snapshots, in.Snapshots[0])
			case "expired-intent":
				// Even a no-longer-usable authorization requires explicit cancel.
				mustHistoryExec(t, s.DB, `INSERT INTO v3_node_identity_recoveries(id,node,username,actor_revision,node_version,config_sha256,snapshot,runtime_epoch,credential,credential_proof,authority,parent_sha256,lifetime_hours,intent,expires_at,status) SELECT 'expired',node,'admin',1,1,repeat('a',64),snapshot,epoch,'unused',repeat('b',64),repeat('c',64),repeat('d',64),72,'{}',clock_timestamp()-interval '1 hour','prepared' FROM v3_node_runtime WHERE node=$1`, in.Node)
			case "pending-renewal":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_node_renewal_jobs(node,parent_sha256,request_sha256,request,snapshot,runtime_epoch,lifetime_hours) SELECT node,repeat('a',64),repeat('b',64),'x',snapshot,epoch,72 FROM v3_node_runtime WHERE node=$1`, in.Node)
			case "pending-deployment":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_deployment_preparations(id,node,username,account_revision,node_version,manifest_sha256,kind) VALUES('pending',$1,'admin',1,1,repeat('a',64),'prepare')`, in.Node)
			}
			if _, err = s.retireNodeHistory(ctx, "admin", "reject-retirement", in); err == nil || tableCount(t, s, "v3_node_history_retirements") != 0 {
				t.Fatal("unsafe or stale retirement committed", err)
			}
		})
	}
}

func TestNodeHistoryRetirementMakesOnlyExplicitRetiredNamesPrunable(t *testing.T) {
	f, certificate := namePruningPolicyFixture(t)
	ctx := context.Background()
	n := runtimeNodeForTest(t, f.s, f.in.Request.Node)
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_configurations SELECT 'retire-extra-name',node,version,name,endpoint,'unused.example.test',false,mode,shard,config FROM v3_node_configurations WHERE id=$1`, f.in.Snapshot)
	before, err := f.s.planNodeNamePruning(ctx, f.c, "admin", n.ID, n.Version, certificate)
	if err != nil || len(before.RemovableNames) != 0 {
		t.Fatal("unretired name was prunable", err)
	}
	confirmNodeHistoryRetirement(t, f.s, nodeHistoryRetirementInput{Node: n.ID, Expected: n.Version, Snapshots: []string{"retire-extra-name"}}, "retire-extra-name")
	after, err := f.s.planNodeNamePruning(ctx, f.c, "admin", n.ID, n.Version, certificate)
	if err != nil || !slices.Equal(after.RemovableNames, []string{"unused.example.test"}) || before.DependenciesSHA256 == after.DependenciesSHA256 || tableCount(t, f.s, "v3_node_configurations") != 2 {
		t.Fatal("explicit retirement did not release only its name", after, err)
	}
	// Corrupted archived bytes must not be silently ignored after retirement.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET name='corrupted' WHERE id='retire-extra-name'`)
	if _, err = f.s.planNodeNamePruning(ctx, f.c, "admin", n.ID, n.Version, certificate); err == nil {
		t.Fatal("changed tombstoned history was ignored")
	}
}

func TestNodeHistoryRetirementConcurrentIntentHasOneAuditAndSurvivesRestore(t *testing.T) {
	s, in := nodeHistoryRetirementFixture(t)
	ctx := context.Background()
	p, err := s.previewNodeHistoryRetirement(ctx, "admin", in)
	if err != nil {
		t.Fatal(err)
	}
	in.Confirm, in.PreviewSHA256 = true, p.PreviewSHA256
	start := make(chan struct{})
	var wg sync.WaitGroup
	errorsOut := make(chan error, 2)
	for _, key := range []string{"concurrent-a", "concurrent-b"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			<-start
			_, err := s.retireNodeHistory(ctx, "admin", key, in)
			errorsOut <- err
		}(key)
	}
	close(start)
	wg.Wait()
	close(errorsOut)
	success := 0
	for err := range errorsOut {
		if err == nil {
			success++
		} else if !errors.Is(err, errNodeHistoryRetired) {
			t.Fatal(err)
		}
	}
	if success != 1 || tableCount(t, s, "v3_node_history_retirements") != 1 {
		t.Fatal("retirement was applied more than once")
	}
	backup, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, backup); err != nil {
		t.Fatal("retirement archive cannot restore", err)
	}
	if tableCount(t, target, "v3_node_history_retirements") != 1 || tableCount(t, target, "v3_node_configurations") != 2 {
		t.Fatal("disaster recovery lost retirement or history")
	}
	if _, err = target.DB.Exec(`UPDATE v3_node_runtime SET snapshot='migration-retire-old' WHERE node=$1`, in.Node); err == nil {
		t.Fatal("restored tombstone no longer fences publication")
	}
	var audit int
	if err = target.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='retire-node-history'`).Scan(&audit); err != nil || audit != 1 {
		t.Fatal("retirement audit was duplicated or lost", err)
	}
}

func TestNodeHistoryRetirementMigrationRequiresBackup(t *testing.T) {
	s, _ := nodeHistoryRetirementFixture(t)
	mustHistoryExec(t, s.DB, nodeHistoryRetirementTestDrop)
	ctx := context.Background()
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("existing database migrated without backup")
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := s.DB.QueryRow(`SELECT max(version) FROM v3_schema`).Scan(&version); err != nil || version != SchemaVersion {
		t.Fatal(version, err)
	}
	if tableCount(t, s, "v3_node_history_retirements") != 0 || tableCount(t, s, "v3_node_configurations") != 2 {
		t.Fatal("migration retired or lost history")
	}
}

func TestNodeHistoryRetirementAfterNameApplicationBlocksOldTaskRecovery(t *testing.T) {
	f, job, certificate := nameChangeApplicationFixture(t)
	ctx := context.Background()
	job = advanceNameApplication(t, f, job, "verify")
	for job.Phase() != "complete" {
		recordDeploymentReady(t, f.s, job)
		if err := f.s.CompleteDeploymentPhase(ctx, job); err != nil {
			t.Fatal(err)
		}
		job = reloadDeployment(t, f.s, job.ID)
	}
	if job.Plan.PreviousRuntime == nil || job.Plan.PreviousRuntime.Snapshot == "" {
		t.Fatal("missing actual old runtime binding")
	}
	confirmNodeHistoryRetirement(t, f.s, nodeHistoryRetirementInput{Node: job.Node, Expected: job.NodeVersion, Snapshots: []string{job.Plan.PreviousRuntime.Snapshot}}, "retire-applied-source")
	plan, err := f.s.planNodeNamePruning(ctx, f.c, "admin", job.Node, job.NodeVersion, certificate)
	if err != nil || !slices.Equal(plan.RemovableNames, []string{f.job.SourceName}) || !slices.Equal(plan.Names, []string{f.job.TargetName}) {
		t.Fatal("completed name change did not release explicitly retired source", plan, err)
	}
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := checkDeploymentRuntimeTx(ctx, tx, job); !errors.Is(err, errNodeHistoryRetired) {
		t.Fatal("completed old task can reactivate retired predecessor", err)
	}
	if reloaded := reloadDeployment(t, f.s, job.ID); reloaded.Status != "succeeded" || reloaded.PlanDigest != job.PlanDigest {
		t.Fatal("retirement rewrote signed deployment history")
	}
}

func TestNodeHistoryRetirementRechecksTaskCommittedWhileWaitingForGate(t *testing.T) {
	s, in := nodeHistoryRetirementFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := s.previewNodeHistoryRetirement(ctx, "admin", in)
	if err != nil {
		t.Fatal(err)
	}
	in.Confirm, in.PreviewSHA256 = true, p.PreviewSHA256
	writer, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if err := lockDeploymentWriteRelationsTx(ctx, writer); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.retireNodeHistory(ctx, "admin", "wait-for-task", in); done <- err }()
	for {
		var waiting bool
		if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE 'SELECT generation FROM v3_configuration_operation_gate%')`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if !waitRetry(ctx, 5*time.Millisecond) {
			t.Fatal("retirement did not wait for in-flight writer")
		}
	}
	// This insert intentionally does not update either gate generation or node
	// row. A pre-lock REPEATABLE READ snapshot would silently miss it.
	if _, err := writer.ExecContext(ctx, `INSERT INTO v3_deployment_preparations(id,node,username,account_revision,node_version,manifest_sha256,kind) VALUES('committing',$1,'admin',1,1,repeat('a',64),'prepare')`, in.Node); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrDeploymentBusy) || tableCount(t, s, "v3_node_history_retirements") != 0 {
		t.Fatal("concurrent task reference was missed", err)
	}
}

func TestNodeHistoryRetirementDatabaseFenceRejectsPreexistingSnapshot(t *testing.T) {
	s, in := nodeHistoryRetirementFixture(t)
	ctx := context.Background()
	old, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Rollback()
	var epoch int64
	if err := old.QueryRowContext(ctx, `SELECT runtime_generation FROM v3_nodes WHERE id=$1`, in.Node).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	confirmNodeHistoryRetirement(t, s, in, "retire-with-old-reader")
	if _, err := old.ExecContext(ctx, `UPDATE v3_node_runtime SET snapshot='migration-retire-old' WHERE node=$1`, in.Node); err == nil {
		t.Fatal("old repeatable-read publisher missed retirement")
	}
	current := runtimeNodeForTest(t, s, in.Node)
	if current.RuntimeEpoch != epoch || current.ServerName == "old.example.test" {
		t.Fatal("retirement changed live generation or old reader reactivated history")
	}
}
