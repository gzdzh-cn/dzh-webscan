package management

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/telemetry"
)

func TestLokiOverflowSplitsAndKeepsAllRows(t *testing.T) {
	db, e := persist.OpenDB(t.TempDir() + "/events.sqlite3")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.Exec(`CREATE TABLE migrated_logs(id TEXT PRIMARY KEY,node TEXT,operation TEXT,time REAL,payload TEXT)`)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		values := []any{}
		if r.URL.Query().Get("start") == "0" && r.URL.Query().Get("end") == "99" {
			for i := 0; i < 1000; i++ {
				values = append(values, []any{"1", `{"operation":"modify"}`})
			}
		} else {
			values = append(values, []any{r.URL.Query().Get("start"), `{"operation":"modify","id":"x"}`})
		}
		w.Write(common.JSON(common.Map{"status": "success", "data": common.Map{"result": []any{common.Map{"stream": common.Map{"node_id": "n"}, "values": values}}}}))
	}))
	defer server.Close()
	if e = importLoki(context.Background(), dbExec{db}, server.Client(), server.URL, 0, 99, map[string]bool{"n": true}); e != nil {
		t.Fatal(e)
	}
	var count int
	db.QueryRow("SELECT count(*) FROM migrated_logs").Scan(&count)
	if calls != 3 || count != 2 {
		t.Fatalf("calls=%d rows=%d", calls, count)
	}
	if e = importLoki(context.Background(), dbExec{db}, server.Client(), server.URL, 0, 99, map[string]bool{"n": true}); e != nil {
		t.Fatal(e)
	}
	db.QueryRow("SELECT count(*) FROM migrated_logs").Scan(&count)
	if count != 2 {
		t.Fatal("retry duplicated logs")
	}
}

func TestMigrationSeedsMountsAndClearsStaleActiveState(t *testing.T) {
	store, e := telemetry.Open(t.TempDir(), nil, common.Map{})
	if e != nil {
		t.Fatal(e)
	}
	defer store.DB.Close()
	alert := func(name, mount string) any {
		return common.Map{"labels": common.Map{"node_id": "n", "alertname": name, "mountpoint": mount, "severity": "critical"}, "state": "firing", "activeAt": time.Now().Format(time.RFC3339), "annotations": common.Map{"summary": "磁盘不足"}}
	}
	if e = seedAlerts(store, []any{alert("WebscanDiskCritical", "/www"), alert("WebscanBacklogLocal", "")}); e != nil {
		t.Fatal(e)
	}
	var phase string
	if e = store.DB.QueryRow("SELECT phase FROM health_rules WHERE key=?", "n:disk:/www:critical").Scan(&phase); e != nil || phase != "firing" {
		t.Fatal(fmt.Sprint(e, phase))
	}
	if e = seedAlerts(store, nil); e != nil {
		t.Fatal(e)
	}
	store.DB.QueryRow("SELECT phase FROM health_rules WHERE key=?", "n:disk:/www:critical").Scan(&phase)
	if phase != "normal" {
		t.Fatal("stale migration state retained")
	}
}

func TestWatchdogDurableFailureRecoveryOrdering(t *testing.T) {
	db, e := persist.OpenDB(t.TempDir() + "/management.sqlite3")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(jobSchema); e != nil {
		t.Fatal(e)
	}
	s := &Service{DB: db}
	ctx := context.Background()
	for count := 1; count <= 3; count++ {
		if e = s.watchdogTransition(ctx, false, count, 0, 100); e != nil {
			t.Fatal(e)
		}
	}
	// A restarted supervisor reads the persisted phase and must not duplicate failure.
	s = &Service{DB: db}
	if e = s.watchdogTransition(ctx, false, 3, 0, 150); e != nil {
		t.Fatal(e)
	}
	if e = s.watchdogTransition(ctx, true, 0, 1, 160); e != nil {
		t.Fatal(e)
	}
	if e = s.watchdogTransition(ctx, true, 0, 2, 190); e != nil {
		t.Fatal(e)
	}
	rows, e := db.Query("SELECT id FROM watchdog_outbox ORDER BY created")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	if len(ids) != 2 || ids[0] != "watchdog:100:firing" || ids[1] != "watchdog:100:resolved" {
		t.Fatal(ids)
	}
}
