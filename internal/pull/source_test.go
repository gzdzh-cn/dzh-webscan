package pull

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webscan/internal/persist"
	agentv1 "webscan/sdk/agent/v1"
)

func testSource(t *testing.T) *Source {
	t.Helper()
	db, e := persist.OpenDB(filepath.Join(t.TempDir(), "agent.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Exec("CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT,created REAL,accepted REAL)"); e != nil {
		t.Fatal(e)
	}
	s, e := New(db, "node-a", "v3-dev", new(sync.Mutex))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func addEvent(t *testing.T, s *Source, id string) {
	t.Helper()
	if _, e := s.DB.Exec(`INSERT INTO events VALUES(?, ?, 1, NULL)`, id, `{"event_id":"`+id+`","node_id":"node-a","operation":"modify"}`); e != nil {
		t.Fatal(e)
	}
}
func TestConfirmationOnlyAfterReceiptAndEpoch(t *testing.T) {
	s := testSource(t)
	ctx := context.Background()
	addEvent(t, s, "a")
	addEvent(t, s, "b")
	batch, e := s.Fetch(ctx, 1, 100, 0)
	if e != nil || len(batch.Events) != 2 {
		t.Fatal(batch, e)
	}
	if _, e = s.Ack(ctx, &agentv1.AckEventsRequest{Epoch: 1, Receipt: batch.Receipt, Accepted: []string{"unserved"}}); e == nil {
		t.Fatal("forged acknowledgment accepted")
	}
	if n, e := s.Ack(ctx, &agentv1.AckEventsRequest{Epoch: 1, Receipt: batch.Receipt, Accepted: []string{"a"}}); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if _, e = s.Ack(ctx, &agentv1.AckEventsRequest{Epoch: 1, Receipt: batch.Receipt, Accepted: []string{"a"}}); e != nil {
		t.Fatal("retry is not idempotent", e)
	}
	batch2, e := s.Fetch(ctx, 2, 100, 0)
	if e != nil || len(batch2.Events) != 1 || batch2.Events[0].Id != "b" {
		t.Fatal(batch2, e)
	}
	if _, e = s.Ack(ctx, &agentv1.AckEventsRequest{Epoch: 1, Receipt: batch.Receipt, Accepted: []string{"b"}}); e == nil {
		t.Fatal("stale owner confirmed events")
	}
	restarted, e := New(s.DB, "node-a", "v3-dev", new(sync.Mutex))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restarted.Ack(ctx, &agentv1.AckEventsRequest{Epoch: 2, Receipt: batch2.Receipt, Accepted: []string{"b"}}); e != nil {
		t.Fatal("persistent receipt lost", e)
	}
	var pending int
	s.DB.QueryRow("SELECT count(*) FROM events WHERE accepted IS NULL").Scan(&pending)
	if pending != 0 {
		t.Fatal(pending)
	}
}
func TestMalformedAndRejectedDoNotBlock(t *testing.T) {
	s := testSource(t)
	ctx := context.Background()
	if _, e := s.DB.Exec(`INSERT INTO events VALUES('invalid','broken',0,NULL)`); e != nil {
		t.Fatal(e)
	}
	addEvent(t, s, "good")
	b, e := s.Fetch(ctx, 1, 100, 0)
	if e != nil || len(b.Events) != 1 || b.Events[0].Id != "good" {
		t.Fatal(b, e)
	}
	if _, e = s.Ack(ctx, &agentv1.AckEventsRequest{Epoch: 1, Receipt: b.Receipt, Rejected: []*agentv1.Rejection{{Id: "good", Code: "invalid_event"}}}); e != nil {
		t.Fatal(e)
	}
	b, e = s.Fetch(ctx, 1, 100, 0)
	if e != nil || len(b.Events) != 0 {
		t.Fatal(b, e)
	}
	var failed int
	s.DB.QueryRow("SELECT count(*) FROM delivery_failures").Scan(&failed)
	if failed != 2 {
		t.Fatal(failed)
	}
}
func TestMetricsRetentionReplayAndLimits(t *testing.T) {
	s := testSource(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	if e := s.RecordMetrics(ctx, now.Add(-2*time.Hour), []byte("node_x 1\n")); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordMetrics(ctx, now, []byte("node_x 2\n")); e != nil {
		t.Fatal(e)
	}
	b, e := s.Metrics(ctx, 0)
	if e != nil || len(b.Samples) != 1 || b.Samples[0].UnixMillis != now.UnixMilli() {
		t.Fatal(b, e)
	}
	b, e = s.Metrics(ctx, now.UnixMilli())
	if e != nil || len(b.Samples) != 0 {
		t.Fatal(b, e)
	}
	if _, e = s.Fetch(ctx, 0, 100, 0); e == nil {
		t.Fatal("zero epoch")
	}
	if _, e = s.Fetch(ctx, 1, 101, 0); e == nil {
		t.Fatal("unbounded batch")
	}
}
func TestLongPollCancellation(t *testing.T) {
	s := testSource(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, e := s.Fetch(ctx, 1, 100, 25*time.Second); e == nil {
		t.Fatal("cancellation ignored")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation too slow")
	}
}
