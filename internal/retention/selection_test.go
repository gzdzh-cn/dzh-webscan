package retention_test

import (
	"context"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/retention"
)

func TestSelectedDeletionFixedIdentityProtectionAndMigratedDuplicates(t *testing.T) {
	s, d, _, _ := fixture(t)
	ctx := context.Background()
	old := time.Now().Unix() - 172800
	for _, id := range []string{"chosen", "unselected", "changed", "pending"} {
		mustExec(t, d, "INSERT INTO events VALUES('n',?,'d',?,?)", id, `{"operation":"modify"}`, old)
	}
	mustExec(t, d, "INSERT INTO events VALUES('n','recent','d','{}',?)", time.Now().Unix())
	mustExec(t, d, "INSERT INTO migrated_logs(node,id,time,payload) VALUES('n','legacy',?,?)", old, `{"event_id":"chosen","operation":"modify"}`)
	mustExec(t, d, "INSERT INTO tasks(node,event_id,target,payload,created,next_try) VALUES('n','pending','email','{}',?,0)", old)
	keys := []string{}
	for _, id := range []string{"chosen", "changed", "pending", "recent"} {
		keys = append(keys, retention.RecordKey("events", "n", id))
	}
	p, e := s.Preview(ctx, "admin", retention.Filter{Category: "all", Records: keys})
	if e != nil {
		t.Fatal(e)
	}
	counts := common.M(p["counts"])
	if common.I(counts["Eligible"]) != 0 {
		t.Fatal("unexpected schema")
	}
	data := string(common.JSON(p))
	_ = data
	mustExec(t, d, "UPDATE events SET payload=? WHERE id='changed'", `{"operation":"modify","path":"new"}`)
	if _, e = s.Create(ctx, "other", "cleanup", common.S(p["id"]), ""); e == nil {
		t.Fatal("cross account")
	}
	j, e := s.Create(ctx, "admin", "cleanup", common.S(p["id"]), "")
	if e != nil {
		t.Fatal(e)
	}
	drive(t, s, j)
	if count(t, d, "events") != 4 || count(t, d, "migrated_logs") != 0 {
		t.Fatal("selection protection/duplicate", count(t, d, "events"), count(t, d, "migrated_logs"))
	}
	finished, _ := s.Job(ctx, "admin", j.ID)
	if finished.Processed != 1 || finished.Skipped != 3 {
		t.Fatal(finished)
	}
	for _, key := range []string{"bad", retention.RecordKey("sqlite_master", "n", "1")} {
		if _, e = s.Preview(ctx, "admin", retention.Filter{Category: "all", Records: []string{key}}); e == nil {
			t.Fatal("invalid scope")
		}
	}
}
