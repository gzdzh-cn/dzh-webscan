package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"webscan/internal/common"
)

func TestCounterResetAndFilesystem(t *testing.T) {
	raw := `node_cpu_seconds_total{cpu="0",mode="idle"} 100
node_cpu_seconds_total{cpu="0",mode="user"} 100
node_memory_MemTotal_bytes 1000
node_memory_MemAvailable_bytes 400
node_filesystem_size_bytes{mountpoint="/",fstype="ext4"} 100
node_filesystem_avail_bytes{mountpoint="/",fstype="ext4"} 20
node_network_receive_bytes_total{device="eth0"} 1000
`
	ms, e := Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	first, b := Derive(ms, 100, Baseline{})
	if _, ok := first.Values["cpu_percent"]; ok {
		t.Fatal("invented first rate")
	}
	if first.Values["memory_percent"] != 60 || first.Values["disk_percent"] != 80 {
		t.Fatal(first)
	}
	ms[0].Value += 8
	ms[1].Value += 2
	ms[len(ms)-1].Value = 500
	next, _ := Derive(ms, 110, b)
	if next.Values["cpu_percent"] < 19.99 || next.Values["cpu_percent"] > 20.01 {
		t.Fatal(next)
	}
	if _, ok := next.Values["net_receive"]; ok {
		t.Fatal("counter reset became traffic")
	}
}
func TestDurableAlertAndRecovery(t *testing.T) {
	ctx := context.Background()
	n := Node{ID: "n", Name: "节点", Active: true}
	s, e := Open(t.TempDir(), []Node{n}, common.Map{"mode": "native", "interval_seconds": 30, "repeat_hours": 4})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for _, tm := range []int64{100, 130, 160, 190, 220} {
		if e = s.Evaluate(ctx, n, Snapshot{Time: tm, OK: false, Values: map[string]float64{}}); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e = s.DB.QueryRow("SELECT count(*) FROM health_events").Scan(&count); e != nil || count != 1 {
		t.Fatal(e, count)
	}
	for _, tm := range []int64{250, 280} {
		if e = s.Evaluate(ctx, n, Snapshot{Time: tm, OK: true, Values: map[string]float64{"webscan_agent_heartbeat_seconds": float64(tm)}}); e != nil {
			t.Fatal(e)
		}
	}
	s.DB.QueryRow("SELECT count(*) FROM health_events WHERE phase='resolved'").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
	calls := 0
	if e = s.Flush(ctx, func(context.Context, string, string, string) error { calls++; return nil }); e != nil {
		t.Fatal(e)
	}
	if calls < 2 {
		t.Fatal(calls)
	}
	calls = 0
	s.Flush(ctx, func(context.Context, string, string, string) error { calls++; return nil })
	if calls != 0 {
		t.Fatal("duplicate flush")
	}
}
func TestAggregationPreservesPeakAndGap(t *testing.T) {
	points := []Point{{Time: 300, OK: true, Values: map[string]float64{"cpu": 10}}, {Time: 330, OK: true, Values: map[string]float64{"cpu": 90}}, {Time: 600, OK: false}}
	out := Aggregate(points, 300)
	if len(out) != 2 || out[0].Values["cpu"] != 50 || out[0].Max["cpu"] != 90 || out[1].OK {
		t.Fatal(out)
	}
}
func TestPersistentRawAndCompact(t *testing.T) {
	ctx := context.Background()
	s, e := Open(t.TempDir(), nil, common.Map{"raw_hours": 1, "history_days": 15})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	now := time.Now().Unix()
	for _, i := range []int64{now - 7200, now - 7170} {
		if e = s.Save(ctx, "n", Snapshot{Time: i, OK: true, Values: map[string]float64{"cpu": 50}}, nil); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.Compact(ctx); e != nil {
		t.Fatal(e)
	}
	var raw, agg int
	s.DB.QueryRow("SELECT count(*) FROM samples WHERE resolution=0").Scan(&raw)
	s.DB.QueryRow("SELECT count(*) FROM samples WHERE resolution=300").Scan(&agg)
	if raw != 0 || agg == 0 {
		t.Fatal(raw, agg)
	}
}

func TestBatchCrashIdentityAndRetry(t *testing.T) {
	ctx := context.Background()
	s, e := Open(t.TempDir(), nil, common.Map{"mode": "native", "group_wait_seconds": 15})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	created := time.Now().Unix() - 100
	for i := 0; i < 8; i++ {
		id := fmt.Sprint("alarm-", i)
		if _, e = s.DB.Exec("INSERT INTO alert_outbox(id,node,kind,message,created) VALUES(?,?,?,?,?)", id, "node", "firing", id, created); e != nil {
			t.Fatal(e)
		}
	}
	first := ""
	e = s.Flush(ctx, func(_ context.Context, id, node, body string) error {
		first = id
		if !strings.Contains(body, "8 项") {
			t.Fatal(body)
		}
		return errors.New("interrupted")
	})
	if e == nil {
		t.Fatal("lost failure")
	}
	s.DB.Exec("INSERT INTO alert_outbox(id,node,kind,message,created) VALUES('new','node','firing','new',?)", created)
	calls := 0
	if e = s.Flush(ctx, func(_ context.Context, id, node, body string) error {
		if calls == 0 && id != first {
			t.Fatal("batch changed after interruption")
		}
		calls++
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
func TestCPUDisabledAndMissingIntervalsDoNotRecover(t *testing.T) {
	ctx := context.Background()
	n := Node{ID: "central", Active: true, Central: true}
	settings := common.Map{"mode": "native", "interval_seconds": 30, "alerts": common.Map{"cpu_enabled": true, "cpu_duration_seconds": 60, "cpu_warning_percent": 85, "cpu_recovery_percent": 80}}
	s, e := Open(t.TempDir(), []Node{n}, settings)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	for _, tm := range []int64{100, 130, 160} {
		if e = s.Evaluate(ctx, n, Snapshot{Time: tm, OK: true, Values: map[string]float64{"cpu_5m_percent": 99}}); e != nil {
			t.Fatal(e)
		}
	}
	var phase string
	s.DB.QueryRow("SELECT phase FROM health_rules WHERE kind='cpu'").Scan(&phase)
	if phase != "firing" {
		t.Fatal(phase)
	}
	s.Evaluate(ctx, n, Snapshot{Time: 190, OK: false})
	s.DB.QueryRow("SELECT phase FROM health_rules WHERE kind='cpu'").Scan(&phase)
	if phase != "firing" {
		t.Fatal("missing metrics resolved alarm")
	}
	common.M(settings["alerts"])["cpu_enabled"] = false
	s.Configure(settings, []Node{n})
	s.Evaluate(ctx, n, Snapshot{Time: 220, OK: true, Values: map[string]float64{}})
	s.DB.QueryRow("SELECT phase FROM health_rules WHERE kind='cpu'").Scan(&phase)
	if phase != "disabled" {
		t.Fatal(phase)
	}
}
func TestLongTrendBoundedAndRetainsRawTail(t *testing.T) {
	ctx := context.Background()
	s, e := Open(t.TempDir(), nil, common.Map{"raw_hours": 1, "history_days": 15})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	now := time.Now().Unix()
	s.Save(ctx, "node", Snapshot{Time: now - 10000, OK: true, Values: map[string]float64{"cpu": 20}}, nil)
	s.Save(ctx, "node", Snapshot{Time: now - 30, OK: true, Values: map[string]float64{"cpu": 90}}, nil)
	if e = s.Compact(ctx); e != nil {
		t.Fatal(e)
	}
	trend, e := s.Trend(ctx, "node", now-10*86400, now)
	if e != nil {
		t.Fatal(e)
	}
	if len(trend.Points) > 1201 {
		t.Fatal(len(trend.Points))
	}
	found, gap := false, false
	for _, p := range trend.Points {
		if p.Max["cpu"] == 90 {
			found = true
		}
		if !p.OK {
			gap = true
		}
	}
	if !found || !gap {
		t.Fatal(found, gap)
	}
}

func TestCPUWindowRejectsGaps(t *testing.T) {
	s, e := Open(t.TempDir(), nil, common.Map{"interval_seconds": 30})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	now := time.Now().Unix()
	for age := 300; age >= 30; age -= 30 {
		if e = s.Save(context.Background(), "n", Snapshot{Time: now - int64(age), OK: true, Values: map[string]float64{"cpu_percent": 90}}, nil); e != nil {
			t.Fatal(e)
		}
	}
	avg, known, e := s.cpuAverage(context.Background(), "n", now, 90)
	if e != nil || !known || avg != 90 {
		t.Fatalf("%v %v %v", avg, known, e)
	}
	s.DB.Exec("DELETE FROM samples WHERE time>? AND time<?", now-180, now-60)
	_, known, e = s.cpuAverage(context.Background(), "n", now, 90)
	if e != nil || known {
		t.Fatal("gap accepted as continuous high CPU")
	}
}

func TestFiftyHostCollectorRemainsBounded(t *testing.T) {
	var active, peak, calls atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if count <= old || peak.CompareAndSwap(old, count) {
				break
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(400 * time.Millisecond):
		}
		fmt.Fprintln(w, "node_memory_MemTotal_bytes 1000\nnode_memory_MemAvailable_bytes 500")
		calls.Add(1)
	}))
	defer endpoint.Close()
	nodes := []Node{}
	for i := 0; i < 50; i++ {
		nodes = append(nodes, Node{ID: fmt.Sprint(i), URL: endpoint.URL, Active: true, Central: true})
	}
	store, e := Open(t.TempDir(), nodes, common.Map{"mode": "native", "interval_seconds": 10, "raw_hours": 48, "history_days": 15})
	if e != nil {
		t.Fatal(e)
	}
	defer store.DB.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- store.Run(ctx, nil, nil) }()
	deadline := time.Now().Add(20 * time.Second)
	for calls.Load() < 50 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	if calls.Load() < 50 || peak.Load() > 4 {
		t.Fatalf("calls=%d peak=%d", calls.Load(), peak.Load())
	}
	t.Logf("50 hosts: collected=%d peak_concurrent=%d", calls.Load(), peak.Load())
}

func TestDisableRuleCancelsFailedBatchKeepsOtherRulesAndHistory(t *testing.T) {
	ctx := context.Background()
	n := Node{ID: "n", Active: true}
	settings := common.Map{"mode": "native", "alerts": common.Map{"cpu_enabled": true}}
	s, e := Open(t.TempDir(), []Node{n}, settings)
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	tm := time.Now().Unix() - 100
	for i := 0; i < 6; i++ {
		kind := "cpu"
		if i == 5 {
			kind = "disk:/:warning"
		}
		id := fmt.Sprint(i)
		if _, e = s.DB.Exec("INSERT INTO health_events VALUES(?,?,?,?,?,?,?)", id, n.ID, kind, "firing", tm, kind, "{}"); e != nil {
			t.Fatal(e)
		}
		if _, e = s.DB.Exec("INSERT INTO alert_outbox(id,node,kind,message,created) VALUES(?,?,?,?,?)", id, n.ID, "firing", kind, tm); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.Flush(ctx, func(context.Context, string, string, string) error { return errors.New("retry") }); e == nil {
		t.Fatal("missing delivery failure")
	}
	common.M(settings["alerts"])["cpu_enabled"] = false
	if e = s.Configure(settings, []Node{n}); e != nil {
		t.Fatal(e)
	}
	calls := 0
	if e = s.Flush(ctx, func(_ context.Context, _, _, msg string) error {
		calls++
		if strings.Contains(msg, "cpu") {
			t.Fatal("disabled notification sent", msg)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM health_events").Scan(&count)
	if calls != 1 || count != 6 {
		t.Fatal(calls, count)
	}
	n.Active = false
	if e = s.Configure(settings, []Node{n}); e != nil {
		t.Fatal(e)
	}
	// An already dispatched collector must not re-open a disabled node's alerts.
	stale := n
	stale.Active = true
	if e = s.Evaluate(ctx, stale, Snapshot{Time: tm + 300, OK: false}); e != nil {
		t.Fatal(e)
	}
	s.DB.QueryRow("SELECT count(*) FROM health_events").Scan(&count)
	if count != 6 {
		t.Fatal("stale collector reopened rule", count)
	}
}

func TestPrometheusLargeWindowsSubdivideAndNativeSamplesWin(t *testing.T) {
	ctx := context.Background()
	s, e := Open(t.TempDir(), []Node{{ID: "n", Active: true}}, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("start") == "0" && r.URL.Query().Get("end") == "120" {
			w.Write([]byte(strings.Repeat("x", (8<<20)+1)))
			return
		}
		start, _ := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
		end, _ := strconv.ParseInt(r.URL.Query().Get("end"), 10, 64)
		w.Write(common.JSON(common.Map{"status": "success", "data": common.Map{"result": []any{common.Map{"metric": common.Map{"node_id": "n"}, "values": []any{[]any{start, "20"}, []any{end, "20"}}}}}}))
	}))
	defer srv.Close()
	if e = s.Save(ctx, "n", Snapshot{Time: 60, OK: true, Values: map[string]float64{"cpu_percent": 99}}, nil); e != nil {
		t.Fatal(e)
	}
	q := HistoricalQuery{Name: "cpu_percent", Expression: "fixture"}
	if e = s.importWindow(ctx, srv.Client(), srv.URL, q, 0, 120, map[string]bool{"n": true}); e != nil {
		t.Fatal(e)
	}
	var raw string
	s.DB.QueryRow("SELECT payload FROM samples WHERE node='n' AND time=60").Scan(&raw)
	if !strings.Contains(raw, "99") || calls != 3 {
		t.Fatal(calls, raw)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM samples").Scan(&count)
	if count != 3 {
		t.Fatal(count)
	}
	if e = s.importWindow(ctx, srv.Client(), srv.URL, q, 0, 120, map[string]bool{"n": true}); e != nil {
		t.Fatal(e)
	}
	s.DB.QueryRow("SELECT count(*) FROM samples").Scan(&count)
	if count != 3 {
		t.Fatal("retry duplicates", count)
	}
}

func TestLongTrendBeforeFirstCompactionIncludesRaw(t *testing.T) {
	ctx := context.Background()
	s, e := Open(t.TempDir(), nil, common.Map{"raw_hours": 48, "history_days": 15})
	if e != nil {
		t.Fatal(e)
	}
	defer s.DB.Close()
	now := time.Now().Unix()
	if e = s.Save(ctx, "n", Snapshot{Time: now - 30, OK: true, Values: map[string]float64{"cpu_percent": 42}}, nil); e != nil {
		t.Fatal(e)
	}
	trend, e := s.Trend(ctx, "n", now-86400, now)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, p := range trend.Points {
		if p.Values["cpu_percent"] == 42 {
			found = true
		}
	}
	if !found {
		t.Fatal("long range hid fresh samples before first aggregation")
	}
}
