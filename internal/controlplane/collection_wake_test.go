package controlplane

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCollectionWakeBypassesStartupAndCoalescesWhileBusy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := make(chan struct{}, 1)
	entered, release, done := make(chan int, 3), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		collectionSchedule(ctx, time.Hour, time.Hour, wake, func() {
			n := int(calls.Add(1))
			entered <- n
			if n == 1 {
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
		})
	}()
	wake <- struct{}{}
	select {
	case n := <-entered:
		if n != 1 {
			t.Fatal(n)
		}
	case <-time.After(time.Second):
		t.Fatal("wake did not bypass startup jitter")
	}
	for range 1000 {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	close(release)
	select {
	case n := <-entered:
		if n != 2 {
			t.Fatal(n)
		}
	case <-time.After(time.Second):
		t.Fatal("pending wake was lost")
	}
	select {
	case <-entered:
		t.Fatal("wake backlog created repeated work")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("schedule did not stop")
	}
}

func TestCollectionScheduleWaitsFullIntervalAfterSlowWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, done := make(chan time.Time, 2), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		collectionSchedule(ctx, 0, 30*time.Millisecond, nil, func() {
			entered <- time.Now()
			if calls.Add(1) == 1 {
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first sample did not start")
	}
	// Let multiple ordinary intervals elapse while a request is in flight.
	time.Sleep(90 * time.Millisecond)
	finished := time.Now()
	close(release)
	select {
	case at := <-entered:
		if at.Sub(finished) < 25*time.Millisecond {
			t.Fatal("slow request accumulated an immediate timer", at.Sub(finished))
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary polling did not resume")
	}
	cancel()
	<-done
}

func TestClosedCollectionWakeDoesNotSpinOrCollectAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	wake := make(chan struct{})
	close(wake)
	calls := 0
	collectionSchedule(ctx, time.Hour, time.Hour, wake, func() { calls++ })
	if calls != 0 {
		t.Fatal("closed wake caused collection", calls)
	}
}

func TestWakeTargetsAreFencedAndBounded(t *testing.T) {
	n := nodeFixture("node-a")
	wake := make(chan struct{}, 1)
	running := map[string]nodeRun{n.ID: {version: n.Version, epoch: 7, runtimeEpoch: n.RuntimeEpoch, wake: wake}}
	wanted := map[string]Node{n.ID: n}
	leases := map[int]Lease{n.Shard: {Resource: shardResource(n.Shard), Epoch: 7}}
	for _, targets := range [][]collectionTarget{{{"unknown", 1}}, {{n.ID, n.Version + 1}}} {
		wakeCollectionTargets(running, wanted, leases, targets)
		if len(wake) != 0 {
			t.Fatal("unmatched target was woken")
		}
	}
	leases[n.Shard] = Lease{Resource: shardResource(n.Shard), Epoch: 8}
	wakeCollectionTargets(running, wanted, leases, []collectionTarget{{n.ID, n.Version}})
	if len(wake) != 0 {
		t.Fatal("old collector was woken")
	}
	leases[n.Shard] = Lease{Resource: shardResource(n.Shard), Epoch: 7}
	for range 100 {
		wakeCollectionTargets(running, wanted, leases, []collectionTarget{{n.ID, n.Version}})
	}
	if len(wake) != 1 {
		t.Fatal("wake was lost or unbounded", len(wake))
	}
}

func TestDeploymentCollectionLookupIgnoresUnreadyTasks(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	l := recordDeploymentReady(t, s, j)
	lookup := func(want int) {
		t.Helper()
		targets, err := s.deploymentCollectionTargets(context.Background(), map[int]Lease{j.Plan.Node.Shard: l})
		if err != nil || len(targets) != want {
			t.Fatal(targets, err)
		}
		if want == 1 && (targets[0].node != j.Node || targets[0].version != j.NodeVersion) {
			t.Fatal(targets)
		}
	}
	lookup(1)
	for _, statement := range []string{
		"UPDATE v3_deployment_jobs SET direction='rollback'",
		"UPDATE v3_deployment_jobs SET direction='forward',step=3",
		"UPDATE v3_deployment_jobs SET step=4,lease_until=clock_timestamp()-interval '1 second'",
		"UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()+interval '30 seconds',status='failed'",
	} {
		if _, err := s.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
		lookup(0)
	}
	if _, err := s.DB.Exec("UPDATE v3_deployment_jobs SET status='running'; UPDATE v3_nodes SET version=version+1"); err != nil {
		t.Fatal(err)
	}
	lookup(0)
	targets, err := s.deploymentCollectionTargets(context.Background(), nil)
	if err != nil || len(targets) != 0 {
		t.Fatal("unassigned collector got targets", targets, err)
	}
}

func TestDeploymentCollectionLookupPagesAllAssignedTargets(t *testing.T) {
	s := testStore(t)
	j := deploymentAtVerification(t, s)
	l := recordDeploymentReady(t, s, j)
	// Only lookup fixtures: these jobs must never be executed as installations.
	if _, err := s.DB.Exec(`INSERT INTO v3_nodes(id,name,endpoint,server_name,mode,shard)
SELECT 'wake-'||lpad(i::text,5,'0'),'wake fixture','127.0.0.1:19100','localhost','native',$1 FROM generate_series(1,451) i`, j.Plan.Node.Shard); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO v3_deployment_jobs(id,node,username,kind,status,node_version,credential,plan,plan_digest,step,lease_owner,lease_epoch,lease_until)
SELECT n.id,n.id,j.username,j.kind,'running',n.version,j.credential,j.plan,j.plan_digest,4,j.lease_owner,j.lease_epoch,clock_timestamp()+interval '30 seconds'
FROM v3_nodes n CROSS JOIN v3_deployment_jobs j WHERE n.id LIKE 'wake-%' AND j.id=$1`, j.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE v3_nodes SET enabled=false WHERE id='wake-00001'; UPDATE v3_nodes SET version=2 WHERE id='wake-00002'`); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_configurations SELECT 'fixture-'||id,id,version,name,endpoint,server_name,enabled,mode,shard,config FROM v3_nodes WHERE id LIKE 'wake-%';UPDATE v3_nodes SET runtime_generation=1 WHERE id LIKE 'wake-%';INSERT INTO v3_node_runtime(node,snapshot,epoch) SELECT id,'fixture-'||id,1 FROM v3_nodes WHERE id LIKE 'wake-%'`)
	targets, err := s.deploymentCollectionTargets(context.Background(), map[int]Lease{j.Plan.Node.Shard: l})
	if err != nil || len(targets) != 450 {
		t.Fatal("lookup lost a page or included ineligible node", len(targets), err)
	}
	seen := map[string]bool{}
	for _, target := range targets {
		if seen[target.node] || target.version != 1 || target.node == "wake-00001" || target.node == "wake-00002" {
			t.Fatal("invalid target", target)
		}
		seen[target.node] = true
	}
	if !seen["wake-00451"] || !seen[j.Node] {
		t.Fatal("last page or original node missing")
	}
}
