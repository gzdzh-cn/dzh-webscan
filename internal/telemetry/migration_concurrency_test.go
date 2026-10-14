package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func TestHistoricalImportWaitsForLiveWriter(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir, []Node{{ID: "n", Active: true}}, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	ctx := context.Background()
	series := []any{common.Map{"metric": common.Map{"node_id": "n"}, "values": []any{[]any{float64(100), "42"}}}}
	q := HistoricalQuery{Name: "cpu_percent"}
	if e = s.ImportSeries(ctx, q, series, map[string]bool{"n": true}); e != nil {
		t.Fatal(e)
	}
	peer, e := persist.OpenDB(filepath.Join(dir, "metrics-v1.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	writer, e := persist.BeginWrite(ctx, peer)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Rollback()
	if _, e = writer.ExecContext(ctx, "INSERT INTO migrations VALUES('live-test','{}')"); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { result <- s.ImportSeries(ctx, q, series, map[string]bool{"n": true}) }()
	select {
	case e = <-result:
		t.Fatalf("import must wait before reading a stale WAL snapshot: %v", e)
	case <-time.After(50 * time.Millisecond):
	}
	if e = writer.Commit(); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("import did not resume")
	}
	var count int
	if e = s.DB.QueryRow("SELECT count(*) FROM samples WHERE node='n' AND time=100").Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
}

func TestImportProtectsIncompleteHistoricalRowsAcrossProcesses(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	settings := common.Map{"raw_hours": 1, "history_days": 15}
	s, e := Open(dir, []Node{{ID: "n", Active: true}}, settings)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	peer, e := Open(dir, nil, settings)
	if e != nil {
		t.Fatal(e)
	}
	defer peer.DB.Close()
	tm := (time.Now().Unix() - 7200) / 300 * 300
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A collector running in a separate process tries to compact between
		// individual metric requests, exactly when snapshots are incomplete.
		if e := peer.Compact(ctx); e != nil {
			t.Error(e)
		}
		value := "42"
		if strings.HasPrefix(r.URL.Query().Get("query"), "up{") {
			value = "1"
		}
		fmt.Fprintf(w, `{"status":"success","data":{"result":[{"metric":{"node_id":"n","device":"eth0","mountpoint":"/"},"values":[[%d,"%s"]]}]}}`, tm, value)
	}))
	defer server.Close()
	// Old checkpoints from the vulnerable importer must not skip repair.
	s.DB.Exec("INSERT INTO migrations VALUES(?, '{}')", fmt.Sprintf("prom:%d:%d:cpu_percent", tm, tm+30))
	if e = s.ImportPrometheus(ctx, server.Client(), server.URL, tm, tm+30, nil); e != nil {
		t.Fatal(e)
	}
	if e = peer.Compact(ctx); e != nil {
		t.Fatal(e)
	}
	var raw, source string
	if e = s.DB.QueryRow("SELECT payload,source FROM samples WHERE node='n' AND time=? AND resolution=300", tm).Scan(&raw, &source); e != nil {
		t.Fatal(e)
	}
	var p Point
	if e = json.Unmarshal([]byte(raw), &p); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"cpu_percent", "memory_total", "load1", "disk_read", "net_receive", "webscan_watches"} {
		if p.Values[key] != 42 {
			t.Fatalf("lost %s: %+v", key, p.Values)
		}
	}
	if source != "legacy" {
		t.Fatal("lost historical provenance", source)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM import_guards").Scan(&count)
	if count != 0 {
		t.Fatal("completed import retained guard")
	}
}

func TestInterruptedImportKeepsDurableGuard(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir, nil, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	if e = s.ImportPrometheus(context.Background(), server.Client(), server.URL, 100, 130, nil); e == nil {
		t.Fatal("expected failure")
	}
	s.DB.Close()
	peer, e := Open(dir, nil, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.DB.Close()
	var n int
	if e = peer.DB.QueryRow("SELECT count(*) FROM import_guards").Scan(&n); e != nil || n != 1 {
		t.Fatal(n, e)
	}
}
