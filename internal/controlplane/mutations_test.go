package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

func TestSaveNodeConcurrentRetriesCommitOneMutationAndAudit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	var wg sync.WaitGroup
	errCh := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := s.SaveNode(ctx, "admin", "request-one", n, 0, 256)
			if err == nil {
				var r struct {
					Version int64 `json:"version"`
				}
				if err = json.Unmarshal(raw, &r); err == nil && r.Version != 1 {
					err = errors.New("retry returned wrong version")
				}
			}
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_audit").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	n.Name = "changed"
	if _, err := s.SaveNode(ctx, "admin", "request-one", n, 0, 256); !errors.Is(err, ErrRequestConflict) {
		t.Fatal("reused key accepted", err)
	}
	if _, err := s.SaveNode(ctx, "admin", "request-two", n, 1, 256); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveNode(ctx, "admin", "request-three", n, 1, 256); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_requests").Scan(&count); err != nil || count != 2 {
		t.Fatal("failed mutation left a receipt", count, err)
	}
}

func TestPublicNodeEditPreservesPrivateConfiguration(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	n.Config = json.RawMessage(`{"ssh_key_ref":"encrypted-fixture-reference","saved_version":1}`)
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	n.Config = nil // Public JSON deliberately does not return this field.
	n.Name = "edited"
	if _, err := s.SaveNode(ctx, "admin", "public-edit", n, 1, 256); err != nil {
		t.Fatal(err)
	}
	var reference string
	if err := s.DB.QueryRow("SELECT config->>'ssh_key_ref' FROM v3_nodes WHERE id=$1", n.ID).Scan(&reference); err != nil || reference != "encrypted-fixture-reference" {
		t.Fatal("private node configuration lost", err)
	}
	items, err := s.Nodes(ctx, "", "", 20, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	var public []map[string]any
	if err = json.Unmarshal(raw, &public); err != nil {
		t.Fatal(err)
	}
	if _, ok := public[0]["config"]; ok {
		t.Fatal("private configuration returned")
	}
}

func TestClusterBindingRejectsImplicitTopologyAndShardChange(t *testing.T) {
	s := testStore(t)
	var c Config
	c.Central.Topology, c.Collector.Shards = "single", 256
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := s.BindCluster(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	c.Central.Topology = "ha"
	if err := s.BindCluster(ctx, c); err == nil {
		t.Fatal("implicit topology change accepted")
	}
	c.Central.Topology, c.Collector.Shards = "single", 128
	if err := s.BindCluster(ctx, c); err == nil {
		t.Fatal("implicit shard change accepted")
	}
}
