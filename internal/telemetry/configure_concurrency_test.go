package telemetry

import (
	"context"
	"path/filepath"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func TestConfigureWaitsForLiveMetricsWriter(t *testing.T) {
	dir := t.TempDir()
	nodes := []Node{{ID: "node", Active: true}}
	s, err := Open(dir, nodes, common.Map{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	peer, err := persist.OpenDB(filepath.Join(dir, "metrics-v1.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := persist.BeginWrite(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Rollback()
	if _, err = w.ExecContext(ctx, "INSERT INTO health_events VALUES('concurrent','node','cpu','triggered',1,'fixture','{}')"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Configure(common.Map{"maintenance_nodes": []string{"node"}}, nodes) }()
	select {
	case err := <-done:
		t.Fatalf("configuration did not wait for live writer: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err = w.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("configuration lost its WAL snapshot", err)
		}
	case <-ctx.Done():
		t.Fatal("configuration did not resume after writer commit")
	}
	if !common.Contains(common.SS(s.Settings()["maintenance_nodes"]), "node") {
		t.Fatal("new configuration was not applied")
	}
}
