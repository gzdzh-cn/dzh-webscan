package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"webscan/internal/pull"
	agentv1 "webscan/sdk/agent/v1"
)

type lossClient struct {
	agentv1.AgentServiceClient
	source *pull.Source
	store  *Store
	calls  atomic.Int32
	done   chan struct{}
}

func (c *lossClient) FetchEvents(ctx context.Context, r *agentv1.FetchEventsRequest, _ ...grpc.CallOption) (*agentv1.EventBatch, error) {
	return c.source.Fetch(ctx, r.Epoch, int(r.Limit), time.Duration(r.WaitSeconds)*time.Second)
}

func (c *lossClient) AckEvents(ctx context.Context, r *agentv1.AckEventsRequest, _ ...grpc.CallOption) (*agentv1.AckEventsResponse, error) {
	// Every acknowledgement must observe an already committed event transaction.
	var count int
	if err := c.store.DB.QueryRowContext(ctx, "SELECT count(*) FROM v3_events").Scan(&count); err != nil || count != 1 {
		return nil, errors.New("acknowledged before durable commit")
	}
	if c.calls.Add(1) == 1 {
		return nil, errors.New("injected network loss before acknowledgement")
	}
	confirmed, err := c.source.Ack(ctx, r)
	if err == nil {
		close(c.done)
	}
	return &agentv1.AckEventsResponse{Confirmed: confirmed}, err
}

func TestPullPipelineReplaysAfterLostAcknowledgement(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	n := nodeFixture("node-a")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(ctx, shardResource(n.Shard), "one")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE events(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created REAL NOT NULL,accepted REAL)`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO events VALUES(?,?,1,NULL),(?,?,2,NULL)", "one", string(eventFixture("one", "modify").Json), "invalid", `{"event_id":"invalid","node_id":"other","operation":"modify"}`); err != nil {
		t.Fatal(err)
	}
	source, err := pull.New(db, n.ID, "v3-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &lossClient{source: source, store: s, done: make(chan struct{})}
	c := &Collector{Store: s}
	exited := make(chan struct{})
	go func() { defer close(exited); c.events(ctx, n, l, client) }()
	select {
	case <-client.done:
	case <-ctx.Done():
		t.Fatal("confirmation did not recover", ctx.Err())
	}
	cancel()
	<-exited
	var count int
	if err = db.QueryRow("SELECT count(*) FROM events WHERE accepted IS NOT NULL").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err = db.QueryRow("SELECT count(*) FROM delivery_failures WHERE id='invalid' AND error='identity_mismatch'").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_events").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if client.calls.Load() != 2 {
		t.Fatal("unexpected acknowledgement count", client.calls.Load())
	}
}
