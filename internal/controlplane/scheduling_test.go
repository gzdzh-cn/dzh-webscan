package controlplane

import (
	"context"
	"errors"
	"fmt"
	"testing"

	agentv1 "webscan/sdk/agent/v1"
)

func TestBatchLeaseRenewalAndTakeover(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resources := []string{"collect/1", "collect/2", "collect/3"}
	one, err := s.AcquireMany(ctx, resources, "one")
	if err != nil || len(one) != 3 {
		t.Fatal(one, err)
	}
	two, err := s.AcquireMany(ctx, resources, "two")
	if err != nil || len(two) != 0 {
		t.Fatal(two, err)
	}
	renewed, err := s.AcquireMany(ctx, resources, "one")
	if err != nil || renewed["collect/2"].Epoch != one["collect/2"].Epoch {
		t.Fatal(renewed, err)
	}
	if err = s.Release(ctx, one["collect/2"]); err != nil {
		t.Fatal(err)
	}
	two, err = s.AcquireMany(ctx, resources, "two")
	if err != nil || len(two) != 1 || two["collect/2"].Epoch <= one["collect/2"].Epoch {
		t.Fatal(two, err)
	}
}

func TestCollectorReconcilesTenThousandRowsWithoutPerShardPaging(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	// This is a scheduler/database test, not a 10,000-agent capacity claim.
	_, err := s.DB.Exec(`INSERT INTO v3_nodes(id,name,endpoint,server_name,mode,shard)
	SELECT 'n-'||lpad(i::text,5,'0'),'node-'||i,'127.0.0.1:19100','localhost','native',i%256 FROM generate_series(1,10000) i`)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_node_configurations SELECT 'fixture-'||id,id,version,name,endpoint,server_name,enabled,mode,shard,config FROM v3_nodes;UPDATE v3_nodes SET runtime_generation=1;INSERT INTO v3_node_runtime(node,snapshot,epoch) SELECT id,'fixture-'||id,1 FROM v3_nodes`)

	var cfg Config
	cfg.Central.Instance, cfg.Collector.Shards = "one", 256
	c := &Collector{Store: s, Config: cfg}
	wanted, leases, err := c.reconcile(ctx, nil)
	if err != nil || len(wanted) != 10000 || len(leases) != 256 {
		t.Fatal(len(wanted), len(leases), err)
	}
	_, err = s.DB.Exec("INSERT INTO v3_workers VALUES('two',clock_timestamp())")
	if err != nil {
		t.Fatal(err)
	}
	wanted, leases, err = c.reconcile(ctx, leases)
	if err != nil || len(leases) != 128 || len(wanted) != 5000 {
		t.Fatal(len(wanted), len(leases), err)
	}
}

func TestNodeFencingRejectsWrongShardDisabledAndEditedNode(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	wrong, err := s.Acquire(ctx, shardResource((n.Shard+1)%256), "one")
	if err != nil {
		t.Fatal(err)
	}
	b := &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{eventFixture("one", "modify")}}
	if _, _, err = s.Ingest(ctx, n, wrong, b); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("wrong shard wrote", err)
	}
	right, err := s.Acquire(ctx, shardResource(n.Shard), "one")
	if err != nil {
		t.Fatal(err)
	}
	n.Enabled = false
	if err = s.PutNode(ctx, n, 1, 256); err != nil {
		t.Fatal(err)
	}
	n.Enabled = true
	if _, _, err = s.Ingest(ctx, n, right, b); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("disabled node wrote", err)
	}
	if err = s.PutNode(ctx, n, 2, 256); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Ingest(ctx, n, right, b); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("old version wrote", err)
	}
	n.Version = 3
	n.RuntimeEpoch = 3
	if _, _, err = s.Ingest(ctx, n, right, b); err != nil {
		t.Fatal(fmt.Errorf("current version rejected: %w", err))
	}
}
