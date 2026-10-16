package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"webscan/internal/common"
)

func TestLateOldScrapeCannotPublishAfterRegistryChange(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Write([]byte("node_memory_MemTotal_bytes 100\nnode_memory_MemAvailable_bytes 50\n"))
	}))
	defer server.Close()
	s, e := Open(t.TempDir(), []Node{{ID: "node", URL: server.URL, Active: true}}, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	nodes, e := s.Nodes(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- s.Collect(context.Background(), server.Client(), nodes[0], nil) }()
	<-started
	if e = s.Configure(common.Map{}, nil); e != nil {
		t.Fatal(e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM samples WHERE node='node'").Scan(&count)
	if count != 0 {
		t.Fatal("stale target published a sample")
	}
}
