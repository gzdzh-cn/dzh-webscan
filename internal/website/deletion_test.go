package website

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestBatchSoftDeletionAndNodeDetachmentPreserveHistory(t *testing.T) {
	m := testMonitor(t)
	ctx := context.Background()
	site := insertSite(t, m, "fixture")
	m.DB.Exec("UPDATE websites SET node='node' WHERE id=?", site.ID)
	now := time.Now().Unix()
	m.DB.Exec("INSERT INTO website_incidents(id,site,kind,started,reason) VALUES(1,?,'outage',?,'fixture')", site.ID, now-100)
	if e := m.DetachNode(ctx, "node"); e != nil {
		t.Fatal(e)
	}
	var origin, node string
	m.DB.QueryRow("SELECT node FROM website_incident_origins WHERE id=1").Scan(&origin)
	m.DB.QueryRow("SELECT node FROM websites WHERE id=?", site.ID).Scan(&node)
	if origin != "node" || node != "" {
		t.Fatal("history identity lost")
	}
	s, e := scanSite(m.DB.QueryRow("SELECT "+columns+" FROM websites WHERE id=?", site.ID))
	if e != nil {
		t.Fatal(e)
	}
	op, e := m.Operations.Create(ctx, "admin", "website", "delete-fixture", []string{strconv.FormatInt(site.ID, 10)})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Operations.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	done, _ := m.Operations.Job(ctx, "admin", op.ID)
	if done.Results[0].Status != "deleted" {
		t.Fatal(done)
	}
	var deleted bool
	var version int64
	m.DB.QueryRow("SELECT deleted,version FROM websites WHERE id=?", site.ID).Scan(&deleted, &version)
	if !deleted || version <= s.Version {
		t.Fatal("not invalidated")
	}
	var n int
	m.DB.QueryRow("SELECT count(*) FROM website_incidents").Scan(&n)
	if n != 1 {
		t.Fatal("history deleted")
	}
}
