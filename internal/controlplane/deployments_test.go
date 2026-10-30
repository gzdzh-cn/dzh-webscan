package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func deploymentFixture(t *testing.T, s *Store) DeploymentRequest {
	t.Helper()
	ctx := context.Background()
	if err := s.PutNode(ctx, nodeFixture("node-a"), 0, 256); err != nil {
		t.Fatal(err)
	}
	v, _ := testVault(t)
	credential := addCredential(t, s, v, "node-a")
	return DeploymentRequest{Node: "node-a", Kind: "install", Expected: 1, Credential: credential, Release: "v3.0.0", SHA256: strings.Repeat("a", 64)}
}
func createDeployment(t *testing.T, s *Store, in DeploymentRequest, key string) DeploymentJob {
	t.Helper()
	raw, err := s.CreateDeployment(context.Background(), "admin", key, in)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	j, err := s.Deployment(context.Background(), response.ID)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func claimDeployment(t *testing.T, s *Store, owner string) DeploymentJob {
	t.Helper()
	j, err := s.ClaimDeployment(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func reloadDeployment(t *testing.T, s *Store, id string) DeploymentJob {
	t.Helper()
	j, err := s.Deployment(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func TestDeploymentReservationIdempotencyAndImmutablePlan(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	j := createDeployment(t, s, in, "install-one")
	replay := createDeployment(t, s, in, "install-one")
	if replay.ID != j.ID || tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("duplicate job")
	}
	changed := in
	changed.SHA256 = strings.Repeat("b", 64)
	if _, err := s.CreateDeployment(ctx, "admin", "install-one", changed); !errors.Is(err, ErrRequestConflict) {
		t.Fatal(err)
	}
	if _, err := s.CreateDeployment(ctx, "admin", "install-two", in); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal(err)
	}
	n := nodeFixture("node-a")
	n.Name = "edited"
	if _, err := s.SaveNode(ctx, "admin", "edit-busy", n, 1, 256); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("edited active deployment", err)
	}
	if j.Plan.Node.Name != "node-a" || j.Plan.Request.SHA256 != in.SHA256 {
		t.Fatal("wrong snapshot")
	}
	public, _ := json.Marshal(j)
	if strings.Contains(string(public), in.Credential) || strings.Contains(string(public), "192.0.2.1") {
		t.Fatal("private plan exposed", string(public))
	}
	if _, err := s.ClaimDeployment(ctx, "bad owner"); err == nil {
		t.Fatal("invalid owner")
	}
	j = claimDeployment(t, s, "one")
	if _, err := s.ClaimDeployment(ctx, "two"); err != sql.ErrNoRows {
		t.Fatal("concurrent owner", err)
	}
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	if err := s.ArmDeploymentRecovery(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err := s.FailDeployment(ctx, j, "remote-unavailable"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDeployment(ctx, "admin", "install-three", in); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("failed job released reservation", err)
	}
	if _, err := s.ClaimDeployment(ctx, "two"); err != sql.ErrNoRows {
		t.Fatal("failed job retried automatically", err)
	}
}
func TestDeploymentConcurrentCreationHasOneWinner(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.CreateDeployment(ctx, "admin", "create-"+token()[:16], in)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	won := 0
	for err := range results {
		if err == nil {
			won++
		} else if !errors.Is(err, ErrDeploymentBusy) {
			t.Fatal(err)
		}
	}
	if won != 1 || tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("reservation race", won)
	}
}
func TestDeploymentExpiredOwnerCannotCommitOrRenew(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "one")
	old := claimDeployment(t, s, "old")
	if _, err := s.DB.Exec("UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewDeployment(ctx, old); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("revived expired lease", err)
	}
	next := claimDeployment(t, s, "new")
	if next.Epoch <= old.Epoch {
		t.Fatal("no fencing generation")
	}
	if err := s.CompleteDeploymentPhase(ctx, old); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale completion", err)
	}
	if err := s.FailDeployment(ctx, old, "backup-failed"); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale failure", err)
	}
	if err := s.CompleteDeploymentPhase(ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteDeploymentPhase(ctx, next); !errors.Is(err, ErrDeploymentState) {
		t.Fatal("duplicate phase advanced", err)
	}
	if got := reloadDeployment(t, s, next.ID); got.Step != 1 {
		t.Fatal(got.Step)
	}
}

type fakeDeploymentRuntime struct {
	receipts     map[string]bool
	calls        []string
	failPhase    string
	loseResponse bool
	losePhase    string
	unknown      bool
	wrongEpoch   bool
	block        bool
}

func checkpoint(j DeploymentJob, state string) RemoteDeploymentCheckpoint {
	return RemoteDeploymentCheckpoint{Job: j.ID, PlanDigest: j.PlanDigest, Phase: j.Phase(), Epoch: j.Epoch, State: state}
}
func (f *fakeDeploymentRuntime) Inspect(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	if f.block {
		<-ctx.Done()
		return RemoteDeploymentCheckpoint{}, ctx.Err()
	}
	state := "absent"
	if f.receipts[j.Phase()] {
		state = "complete"
	}
	if f.unknown {
		state = "unknown"
	}
	proof := checkpoint(j, state)
	if f.wrongEpoch {
		proof.Epoch--
	}
	return proof, nil
}
func (f *fakeDeploymentRuntime) Apply(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	f.calls = append(f.calls, j.Phase())
	if f.failPhase == j.Phase() {
		return RemoteDeploymentCheckpoint{}, errors.New("private-key-and-password-must-never-reach-log")
	}
	if f.receipts == nil {
		f.receipts = map[string]bool{}
	}
	f.receipts[j.Phase()] = true
	if f.loseResponse && (f.losePhase == "" || f.losePhase == j.Phase()) {
		f.loseResponse = false
		return RemoteDeploymentCheckpoint{}, errors.New("connection lost after remote success")
	}
	return checkpoint(j, "complete"), nil
}
func TestDeploymentResponseLossResumeAndCompletedPhaseNotRepeated(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "one")
	j := claimDeployment(t, s, "one")
	remote := &fakeDeploymentRuntime{loseResponse: true, losePhase: "backup"}
	runner := DeploymentRunner{Store: s, Runtime: readinessFixtureRuntime{remote, t, s}}
	if err := runner.Execute(ctx, j); err == nil {
		t.Fatal("response loss ignored")
	}
	failed := reloadDeployment(t, s, j.ID)
	if failed.Status != "failed" || failed.Step != 2 {
		t.Fatal(failed.Status, failed.Step)
	}
	if _, err := s.RecoverDeployment(ctx, "admin", "resume", j.ID, "forward", failed.PlanDigest, failed.LogCursor-1); !errors.Is(err, ErrDeploymentState) {
		t.Fatal("stale recovery", err)
	}
	first, err := s.RecoverDeployment(ctx, "admin", "resume", j.ID, "forward", failed.PlanDigest, failed.LogCursor)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.RecoverDeployment(ctx, "admin", "resume", j.ID, "forward", failed.PlanDigest, failed.LogCursor)
	if err != nil || !sameJSON(first, second) {
		t.Fatal("duplicate resume", err)
	}
	next := claimDeployment(t, s, "new")
	if err = runner.Execute(ctx, next); err != nil {
		t.Fatal(err)
	}
	finished := reloadDeployment(t, s, j.ID)
	if finished.Status != "succeeded" || finished.Step != 6 {
		t.Fatal(finished.Status, finished.Step)
	}
	count := 0
	for _, phase := range remote.calls {
		if phase == "preflight" {
			count++
		}
	}
	if count != 1 {
		t.Fatal("remote success replayed", remote.calls)
	}
	var applied int64
	if err = s.DB.QueryRow("SELECT applied_version FROM v3_nodes WHERE id=$1", j.Node).Scan(&applied); err != nil || applied != 1 {
		t.Fatal(applied, err)
	}
	logs, err := s.DeploymentLogs(ctx, j.ID, 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	for i, entry := range logs {
		if entry.Cursor != int64(i+1) || strings.Contains(entry.Code, "private") {
			t.Fatal("log cursor or secret", entry)
		}
	}
	tail, err := s.DeploymentLogs(ctx, j.ID, logs[2].Cursor, 200)
	if err != nil || len(tail) != len(logs)-3 {
		t.Fatal("cursor reconnect", len(tail), err)
	}
	if _, err = s.SaveNode(ctx, "admin", "edit-after", nodeFixture("node-a"), 1, 256); err != nil {
		t.Fatal("completed job blocks edit", err)
	}
}
func TestDeploymentRollbackPreservesBusinessDataAndReservation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "one")
	j := claimDeployment(t, s, "one")
	if _, err := s.DB.Exec("INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES('node-a','new-event',clock_timestamp(),'modify','{}')"); err != nil {
		t.Fatal(err)
	}
	remote := &fakeDeploymentRuntime{failPhase: "activate"}
	runner := DeploymentRunner{Store: s, Runtime: remote}
	if err := runner.Execute(ctx, j); err == nil {
		t.Fatal("failure ignored")
	}
	failed := reloadDeployment(t, s, j.ID)
	if failed.Step != 3 {
		t.Fatal("checkpoint not persisted", failed.Step)
	}
	if _, err := s.RecoverDeployment(ctx, "admin", "rollback", j.ID, "rollback", failed.PlanDigest, failed.LogCursor); err != nil {
		t.Fatal(err)
	}
	next := claimDeployment(t, s, "rollback-owner")
	remote.failPhase = "restore"
	if err := runner.Execute(ctx, next); err == nil {
		t.Fatal("rollback failure ignored")
	}
	failed = reloadDeployment(t, s, j.ID)
	if _, err := s.RecoverDeployment(ctx, "admin", "reverse-rollback", j.ID, "forward", failed.PlanDigest, failed.LogCursor); !errors.Is(err, ErrDeploymentState) {
		t.Fatal("reversed a pending rollback", err)
	}
	if _, err := s.RecoverDeployment(ctx, "admin", "continue-rollback", j.ID, "rollback", failed.PlanDigest, failed.LogCursor); err != nil {
		t.Fatal(err)
	}
	remote.failPhase = ""
	next = claimDeployment(t, s, "rollback-owner-two")
	if err := runner.Execute(ctx, next); err != nil {
		t.Fatal(err)
	}
	if got := reloadDeployment(t, s, j.ID); got.Status != "rolled_back" || got.RollbackStep != 2 {
		t.Fatal(got.Status, got.RollbackStep)
	}
	if tableCount(t, s, "v3_events") != 1 {
		t.Fatal("rollback lost new events")
	}
	createDeployment(t, s, in, "new-after-rollback")
}
func TestDeploymentUnknownRemoteStateAndWrongEpochFailClosed(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "wrong-epoch"}[wrong], func(t *testing.T) {
			s := testStore(t)
			in := deploymentFixture(t, s)
			createDeployment(t, s, in, "one")
			j := claimDeployment(t, s, "one")
			remote := &fakeDeploymentRuntime{unknown: !wrong, wrongEpoch: wrong}
			err := (&DeploymentRunner{Store: s, Runtime: remote}).Execute(context.Background(), j)
			if err == nil || len(remote.calls) != 0 {
				t.Fatal("unverified remote action", err, remote.calls)
			}
			failed := reloadDeployment(t, s, j.ID)
			if failed.ErrorCode != "remote-state-unknown" {
				t.Fatal(failed.ErrorCode)
			}
		})
	}
}
func TestDeploymentShutdownRecordsInterruption(t *testing.T) {
	s := testStore(t)
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "one")
	j := claimDeployment(t, s, "one")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := (&DeploymentRunner{Store: s, Runtime: &fakeDeploymentRuntime{block: true}}).Execute(ctx, j); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if got := reloadDeployment(t, s, j.ID); got.Status != "interrupted" || got.Step != 0 {
		t.Fatal(got.Status, got.Step)
	}
}
func TestDeploymentDetectsChangedConfigBeforeRemoteWork(t *testing.T) {
	s := testStore(t)
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "one")
	j := claimDeployment(t, s, "one")
	if _, err := s.DB.Exec("UPDATE v3_nodes SET config='{\"changed\":true}' WHERE id='node-a'"); err != nil {
		t.Fatal(err)
	}
	remote := &fakeDeploymentRuntime{}
	if err := (&DeploymentRunner{Store: s, Runtime: remote}).Execute(context.Background(), j); err == nil || len(remote.calls) != 0 {
		t.Fatal("changed plan executed", err)
	}
	if got := reloadDeployment(t, s, j.ID); got.ErrorCode != "configuration-conflict" {
		t.Fatal(got.ErrorCode)
	}
}
func TestDeploymentSchemaTwoUpgradeAndBackupRestoreJobGraph(t *testing.T) {
	s := emptyTestStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(Schema + websiteSchema); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema two migrated without backup")
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	in := deploymentFixture(t, s)
	j := createDeployment(t, s, in, "one")
	claimDeployment(t, s, "one")
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	restored := reloadDeployment(t, target, j.ID)
	if restored.Status != "running" || restored.PlanDigest != j.PlanDigest || tableCount(t, target, "v3_credentials") != 1 || tableCount(t, target, "v3_deployment_logs") != 2 {
		t.Fatal("lost job graph")
	}
	// Restored leases are retained. They are not immediately replayed or marked
	// successful; an actual takeover must still reconcile the remote receipts.
	if _, err = target.ClaimDeployment(ctx, "restore-owner"); err != sql.ErrNoRows {
		t.Fatal("restored live lease reclaimed", err)
	}
}

func sameJSON(a, b []byte) bool {
	var left, right any
	return json.Unmarshal(a, &left) == nil && json.Unmarshal(b, &right) == nil && reflect.DeepEqual(left, right)
}

func TestDeploymentPreflightFailureDoesNotRequireRollback(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "one")
	j := claimDeployment(t, s, "one")
	remote := &fakeDeploymentRuntime{failPhase: "preflight"}
	if err := (&DeploymentRunner{Store: s, Runtime: remote}).Execute(ctx, j); err == nil {
		t.Fatal("preflight failure ignored")
	}
	failed := reloadDeployment(t, s, j.ID)
	if failed.RecoveryRequired || failed.CanRecover() || failed.FinishedAt == nil {
		t.Fatal("read-only failure requires rollback")
	}
	if _, err := s.RecoverDeployment(ctx, "admin", "resume-preflight", j.ID, "forward", failed.PlanDigest, failed.LogCursor); !errors.Is(err, ErrDeploymentState) {
		t.Fatal("replayed a released job", err)
	}
	n := nodeFixture("node-a")
	n.Name = "corrected"
	if _, err := s.SaveNode(ctx, "admin", "edit-after-preflight", n, 1, 256); err != nil {
		t.Fatal("preflight failure blocked correction", err)
	}
	in.Expected = 2
	createDeployment(t, s, in, "corrected-deployment")
}

type waitingDeploymentRuntime struct{ entered chan struct{} }

func (w waitingDeploymentRuntime) Inspect(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	close(w.entered)
	<-ctx.Done()
	return RemoteDeploymentCheckpoint{}, ctx.Err()
}
func (w waitingDeploymentRuntime) Apply(context.Context, DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	return RemoteDeploymentCheckpoint{}, errors.New("must never apply")
}
func TestDeploymentRenewalLossCancelsRemoteWithoutStaleCheckpoint(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "one")
	j := claimDeployment(t, s, "one")
	runtime := waitingDeploymentRuntime{entered: make(chan struct{})}
	parent, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (&DeploymentRunner{Store: s, Runtime: runtime}).Execute(parent, j) }()
	select {
	case <-runtime.entered:
	case <-parent.Done():
		t.Fatal("runtime did not start")
	}
	if _, err := s.DB.Exec("UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", j.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-parent.Done():
		t.Fatal("lost renewal did not stop remote work")
	}
	got := reloadDeployment(t, s, j.ID)
	if got.Status != "running" || got.Step != 0 || got.LogCursor != j.LogCursor {
		t.Fatal("stale owner committed after renewal loss")
	}
	next := claimDeployment(t, s, "two")
	if next.Epoch <= j.Epoch {
		t.Fatal("new executor not fenced")
	}
}
