package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

func deploymentAtVerification(t *testing.T, s *Store) DeploymentJob {
	t.Helper()
	in := deploymentFixture(t, s)
	createDeployment(t, s, in, "readiness-install")
	j := claimDeployment(t, s, "readiness-executor")
	for j.Phase() != "verify" {
		if j.Phase() == "backup" {
			if err := s.ArmDeploymentRecovery(context.Background(), j); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.CompleteDeploymentPhase(context.Background(), j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	return j
}

func readinessCapabilities(j DeploymentJob) *agentv1.CapabilitiesResponse {
	return &agentv1.CapabilitiesResponse{NodeId: j.Node, Version: j.Plan.Request.Release, Protocol: agentv1.ProtocolVersion, MaxEvents: agentv1.MaxEvents, MaxBytes: agentv1.MaxBytes, ConfigurationVersion: j.NodeVersion, ConfigurationSha256: j.Plan.ConfigDigest}
}

// Synthetic evidence for coordinator/SSH protocol tests. These tests exercise
// persistence and fencing, not real collector transport or an installed node.
func recordDeploymentReady(t *testing.T, s *Store, j DeploymentJob) Lease {
	t.Helper()
	n, err := scanActiveNode(s.DB.QueryRow("SELECT "+activeNodeColumns+" FROM v3_active_nodes WHERE id=$1", j.Node))
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(context.Background(), shardResource(j.Plan.Node.Shard), "readiness-collector")
	if err != nil {
		t.Fatal(err)
	}
	at, _, err := s.MetricCursor(context.Background(), n.ID)
	if err != nil {
		t.Fatal(err)
	}
	at = max(at+1, time.Now().UnixMilli())
	if err := s.CommitMetrics(context.Background(), n, l, &agentv1.MetricsBatch{NodeId: n.ID, Samples: []*agentv1.MetricsSample{{UnixMillis: at, PrometheusText: healthyDeploymentMetrics(t, n.Config, time.Now())}}}, telemetry.Baseline{}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"metrics", "events"} {
		if err := s.recordNodeReadiness(context.Background(), n, l, kind, readinessCapabilities(j), at); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

type readinessFixtureRuntime struct {
	DeploymentRuntime
	t *testing.T
	s *Store
}

func (f readinessFixtureRuntime) SupportsDeploymentPhase(phase string) bool {
	if support, ok := f.DeploymentRuntime.(DeploymentPhaseSupport); ok {
		return support.SupportsDeploymentPhase(phase)
	}
	return true
}
func (f readinessFixtureRuntime) Inspect(ctx context.Context, j DeploymentJob) (RemoteDeploymentCheckpoint, error) {
	proof, err := f.DeploymentRuntime.Inspect(ctx, j)
	if err == nil && j.Direction == "forward" && (j.Phase() == "verify" || j.Phase() == "finalize") {
		recordDeploymentReady(f.t, f.s, j)
	}
	return proof, err
}

func TestDeploymentNeedsFreshCollectorEvidenceForVerifyAndFinalize(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	ctx := context.Background()
	if err := s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("local service proof alone completed verification", err)
	}
	l := recordDeploymentReady(t, s, j)
	if _, err := s.DB.Exec("DELETE FROM v3_node_readiness WHERE kind='events'"); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("metrics alone completed verification", err)
	}
	recordDeploymentReady(t, s, j)
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	j = reloadDeployment(t, s, j.ID)
	active, err := scanActiveNode(s.DB.QueryRow("SELECT "+activeNodeColumns+" FROM v3_active_nodes WHERE id=$1", j.Node))
	if err != nil {
		t.Fatal(err)
	}
	(&Collector{Store: s}).failure(ctx, active, l, "events", "事件读取失败")
	if err := s.CompleteDeploymentPhase(ctx, j); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("failed event link completed finalization", err)
	}
	var applied int64
	if err := s.DB.QueryRow("SELECT applied_version FROM v3_nodes WHERE id=$1", j.Node).Scan(&applied); err != nil || applied != 0 {
		t.Fatal("marked applied before collector verification", applied, err)
	}
	recordDeploymentReady(t, s, j)
	if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow("SELECT applied_version FROM v3_nodes WHERE id=$1", j.Node).Scan(&applied); err != nil || applied != j.NodeVersion {
		t.Fatal("verified target was not applied", applied, err)
	}
}

func TestDeploymentRejectsMismatchedStaleAndFencedReadiness(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	changes := map[string]string{
		"old configuration":    "UPDATE v3_node_readiness SET reported_version=0 WHERE kind='metrics'",
		"wrong digest":         "UPDATE v3_node_readiness SET reported_digest=repeat('b',64) WHERE kind='metrics'",
		"wrong release":        "UPDATE v3_node_readiness SET release='v2.0.46' WHERE kind='metrics'",
		"wrong endpoint":       "UPDATE v3_node_readiness SET endpoint='192.0.2.2:19100'",
		"wrong server name":    "UPDATE v3_node_readiness SET server_name='other.example'",
		"old node version":     "UPDATE v3_node_readiness SET node_version=0",
		"old desired digest":   "UPDATE v3_node_readiness SET config_digest=repeat('c',64)",
		"wrong shard":          "UPDATE v3_node_readiness SET resource='collect/invalid'",
		"old observations":     "UPDATE v3_node_readiness SET checked_at=clock_timestamp()-interval '61 seconds'",
		"before activation":    "UPDATE v3_node_readiness SET checked_at=(SELECT created_at FROM v3_deployment_logs WHERE phase='activate' AND code='phase-complete')-interval '1 millisecond'",
		"old samples":          "UPDATE v3_node_readiness SET sampled_at=extract(epoch FROM clock_timestamp()-interval '61 seconds')*1000 WHERE kind='metrics'",
		"future samples":       "UPDATE v3_node_readiness SET sampled_at=extract(epoch FROM clock_timestamp()+interval '10 seconds')*1000 WHERE kind='metrics'",
		"old collector epoch":  "UPDATE v3_node_readiness SET epoch=epoch-1",
		"different collectors": "UPDATE v3_node_readiness SET owner='other' WHERE kind='events'",
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			recordDeploymentReady(t, s, j)
			if _, err := s.DB.Exec(change); err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteDeploymentPhase(context.Background(), j); !errors.Is(err, ErrDeploymentNotReady) {
				t.Fatal("invalid evidence completed verification", err)
			}
		})
	}
	l := recordDeploymentReady(t, s, j)
	if err := s.Release(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteDeploymentPhase(context.Background(), j); !errors.Is(err, ErrDeploymentNotReady) {
		t.Fatal("expired collector completed verification", err)
	}
	if err := s.recordNodeReadiness(context.Background(), j.Plan.Node, l, "events", nil, 0); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("fenced collector recorded new evidence", err)
	}
}

func TestReadinessFailureInvalidatesOnlyAffectedLink(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	for _, kind := range []string{"metrics", "events", "protocol"} {
		l := recordDeploymentReady(t, s, j)
		(&Collector{Store: s}).failure(context.Background(), runtimeNodeForTest(t, s, j.Node), l, kind, "链路失败")
		want := 1
		if kind == "protocol" {
			want = 0
		}
		if got := tableCount(t, s, "v3_node_readiness"); got != want {
			t.Fatal("wrong links retained after failure", kind, got)
		}
	}
}

func TestReadinessIsNotRestoredAsCurrentHealth(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	recordDeploymentReady(t, s, j)
	path, err := s.BackupPostgres(context.Background(), privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if got := tableCount(t, target, "v3_node_readiness"); got != 0 {
		t.Fatal("restored observations accepted as current health", got)
	}
	if got := tableCount(t, target, "v3_deployment_jobs"); got != 1 {
		t.Fatal("business job lost during restore", got)
	}
}

func TestRunnerReadinessWaitCanBeInterruptedAndRecovered(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	remote := &fakeDeploymentRuntime{receipts: map[string]bool{"verify": true}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := (&DeploymentRunner{Store: s, Runtime: remote}).Execute(ctx, j); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("readiness wait did not honor cancellation", err)
	}
	failed := reloadDeployment(t, s, j.ID)
	if failed.Status != "interrupted" || !failed.CanRecover() || failed.Step != 4 {
		t.Fatal("interrupted readiness lost recovery state", failed.Status, failed.Step)
	}
	if _, err := s.RecoverDeployment(context.Background(), "admin", "readiness-resume", j.ID, "forward", failed.PlanDigest, failed.LogCursor); err != nil {
		t.Fatal(err)
	}
	next := claimDeployment(t, s, "readiness-next-executor")
	if err := (&DeploymentRunner{Store: s, Runtime: readinessFixtureRuntime{remote, t, s}}).Execute(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if completed := reloadDeployment(t, s, j.ID); completed.Status != "succeeded" {
		t.Fatal("readiness did not recover", completed.Status)
	}
}

func TestSchemaThreeReadinessMigrationRequiresConsistentBackup(t *testing.T) {
	s := emptyTestStore(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(Schema + websiteSchema + deploymentSchema); err != nil {
		t.Fatal(err)
	}
	if err := putNode(ctx, s.DB, nodeFixture("node-a"), 0, 256); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema 3 upgraded without backup")
	}
	var exists bool
	if err := s.DB.QueryRow("SELECT to_regclass(current_schema()||'.v3_node_readiness') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatal("failed upgrade created readiness storage", exists, err)
	}
	dir := privateTestDir(t)
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	backup := filepath.Join(dir, files[0].Name())
	header, err := inspectPGBackup(backup)
	if err != nil || header.Version != 3 {
		t.Fatal("wrong pre-migration backup", header, err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if got := tableCount(t, target, "v3_nodes"); got != 1 {
		t.Fatal("original nodes not preserved", got)
	}
	if version, err := currentSchema(ctx, target.DB); err != nil || version != 3 {
		t.Fatal(version, err)
	}
	if version, err := currentSchema(ctx, s.DB); err != nil || version != SchemaVersion {
		t.Fatal(version, err)
	}
}

func TestDeploymentReadinessConcurrentCollectorWritesAndRenewals(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	l := recordDeploymentReady(t, s, j)
	n, err := scanActiveNode(s.DB.QueryRow("SELECT "+activeNodeColumns+" FROM v3_active_nodes WHERE id=$1", j.Node))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	at, _, err := s.MetricCursor(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsCh := make(chan error, 4)
	var wg sync.WaitGroup
	for _, kind := range []string{"metrics", "events", "renew", "complete"} {
		wg.Add(1)
		go func(kind string) {
			defer wg.Done()
			<-start
			for range 30 {
				var err error
				switch kind {
				case "metrics", "events":
					err = s.recordNodeReadiness(ctx, n, l, kind, readinessCapabilities(j), at)
				case "renew":
					_, err = s.Acquire(ctx, l.Resource, l.Owner)
				case "complete":
					err = s.CompleteDeploymentPhase(ctx, j)
					if errors.Is(err, ErrDeploymentNotReady) || errors.Is(err, ErrDeploymentState) {
						err = nil
					}
				}
				if err != nil {
					errorsCh <- err
					return
				}
			}
		}(kind)
	}
	close(start)
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error("collector/deployment lock conflict", err)
	}
	if ctx.Err() != nil {
		t.Fatal("concurrent readiness did not finish", ctx.Err())
	}
	current := reloadDeployment(t, s, j.ID)
	if current.Step != 5 {
		t.Fatal("concurrent verification did not advance exactly once", current.Step)
	}
}
