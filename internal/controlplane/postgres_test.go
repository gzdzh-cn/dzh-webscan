package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	agentv1 "webscan/sdk/agent/v1"
)

func emptyTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("WEBSCAN_V3_TEST_DSN")
	if dsn == "" {
		t.Skip("set WEBSCAN_V3_TEST_DSN to an isolated PostgreSQL database")
	}
	base, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := "webscan_test_" + token()[:16]
	if _, e = base.Exec(`CREATE SCHEMA "` + name + `"`); e != nil {
		base.Close()
		t.Fatal(e)
	}
	cfg, e := pgx.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.RuntimeParams["search_path"] = name
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(12)
	s := &Store{DB: db}
	t.Cleanup(func() { db.Close(); base.Exec(`DROP SCHEMA "` + name + `" CASCADE`); base.Close() })
	return s
}

func testStore(t *testing.T) *Store {
	t.Helper()
	s := emptyTestStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func nodeFixture(id string) Node {
	return Node{ID: id, Name: id, Endpoint: "192.0.2.1:19100", ServerName: "192.0.2.1", Enabled: true, Mode: "native", Version: 1, RuntimeEpoch: 1, Shard: Shard(id, 256)}
}
func eventFixture(id, op string) *agentv1.Event {
	raw, _ := json.Marshal(map[string]any{"node_id": "node-a", "event_id": id, "operation": op, "path": "/www/index.php"})
	return &agentv1.Event{Id: id, Json: raw}
}
func TestPostgresLeaseAndTransactionalIngest(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	if e := s.PutNode(ctx, n, 0, 256); e != nil {
		t.Fatal(e)
	}
	l, e := s.Acquire(ctx, shardResource(n.Shard), "one")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Acquire(ctx, l.Resource, "two"); !errors.Is(e, ErrLeaseLost) {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"file_changes":true}},"email":{"enabled":true,"recipients":["a@example.test","b@example.test"],"notifications":{"file_changes":true}}}'`); e != nil {
		t.Fatal(e)
	}
	b := &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{eventFixture("a", "modify"), eventFixture("probe", "probe")}}
	for i := 0; i < 2; i++ {
		accepted, rejected, e := s.Ingest(ctx, n, l, b)
		if e != nil || len(accepted) != 2 || len(rejected) != 0 {
			t.Fatal(accepted, rejected, e)
		}
	}
	var count int
	if e = s.DB.QueryRow("SELECT count(*) FROM v3_events").Scan(&count); e != nil || count != 2 {
		t.Fatal(count, e)
	}
	if e = s.DB.QueryRow("SELECT count(*) FROM v3_notifications").Scan(&count); e != nil || count != 3 {
		t.Fatal(count, e)
	}
	if _, e = s.DB.Exec("UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'"); e != nil {
		t.Fatal(e)
	}
	next, e := s.Acquire(ctx, l.Resource, "two")
	if e != nil || next.Epoch <= l.Epoch {
		t.Fatal(next, e)
	}
	if _, _, e = s.Ingest(ctx, n, l, b); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("stale owner wrote", e)
	}
	filter := EventFilter{Since: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour), Limit: 20}
	events, e := s.Events(ctx, filter)
	if e != nil || len(events) != 1 {
		t.Fatal(events, e)
	}
	filter.IncludeProbes = true
	events, e = s.Events(ctx, filter)
	if e != nil || len(events) != 2 {
		t.Fatal(events, e)
	}
}
func TestPostgresOutboxFailureDoesNotConfirm(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	n := nodeFixture("node-a")
	if e := s.PutNode(ctx, n, 0, 256); e != nil {
		t.Fatal(e)
	}
	l, e := s.Acquire(ctx, shardResource(n.Shard), "one")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"file_changes":true}}}';CREATE FUNCTION reject_notification() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test failure'; END$$;CREATE TRIGGER reject_notice BEFORE INSERT ON v3_notifications FOR EACH ROW EXECUTE FUNCTION reject_notification()`); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Ingest(ctx, nodeFixture("node-a"), l, &agentv1.EventBatch{NodeId: "node-a", Events: []*agentv1.Event{eventFixture("a", "modify")}}); e == nil {
		t.Fatal("failure ignored")
	}
	for _, table := range []string{"v3_event_keys", "v3_events"} {
		var count int
		if e = s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); e != nil || count != 0 {
			t.Fatal(table, count, e)
		}
	}
}
func TestPostgresNodePaginationAndOptimisticVersion(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, id := range []string{"node-a", "node-b", "node-c"} {
		if e := s.PutNode(ctx, nodeFixture(id), 0, 256); e != nil {
			t.Fatal(e)
		}
	}
	items, e := s.Nodes(ctx, "", "", 2, nil)
	if e != nil || len(items) != 2 {
		t.Fatal(items, e)
	}
	next, e := s.Nodes(ctx, items[1].ID, "", 2, nil)
	if e != nil || len(next) != 1 || next[0].ID != "node-c" {
		t.Fatal(next, e)
	}
	items, e = s.Nodes(ctx, "", "%", 20, nil)
	if e != nil || len(items) != 0 {
		t.Fatal("wildcard not escaped", items, e)
	}
	n := nodeFixture("node-a")
	n.Name = "changed"
	if e = s.PutNode(ctx, n, 1, 256); e != nil {
		t.Fatal(e)
	}
	if e = s.PutNode(ctx, n, 1, 256); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestShardDistributionAndAssignment(t *testing.T) {
	counts := make([]int, 256)
	for i := 0; i < 10000; i++ {
		counts[Shard(fmt.Sprintf("node-%05d", i), 256)]++
	}
	for _, n := range counts {
		if n < 10 || n > 80 {
			t.Fatal("unbalanced", n)
		}
	}
	members := []string{"c", "a", "b"}
	for shard := 0; shard < 256; shard++ {
		owners := 0
		for _, m := range members {
			if assigned(shard, members, m) {
				owners++
			}
		}
		if owners != 1 {
			t.Fatal(shard, owners)
		}
	}
}
func TestBuildMetricsIdentityAndCardinality(t *testing.T) {
	raw, e := BuildMetrics("node-a", []*agentv1.MetricsSample{{UnixMillis: time.Now().UnixMilli(), PrometheusText: []byte("node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 1\nwebscan_transport_error{reason=\"arbitrary error\"} 1\n")}})
	if e != nil || !strings.Contains(string(raw), `"node_id":"node-a"`) || strings.Contains(string(raw), "arbitrary error") {
		t.Fatal(string(raw), e)
	}
}
