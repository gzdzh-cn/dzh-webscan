package controlplane

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestConsoleEventKeywordsAndProbePagination(t *testing.T) {
	s := testStore(t)
	// The literal wildcard characters must stay literal, in both native and
	// migrated event text. A probe containing the same text remains opt-in.
	for i, field := range []string{"path", "reason", "message"} {
		mustHistoryExec(t, s.DB, `INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES($1,$2,clock_timestamp(),'health',jsonb_build_object($3::text,$4::text))`, fmt.Sprintf("node-%d", i), fmt.Sprintf("id-%d", i), field, "风险%_literal")
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES('node-x','wildcard',clock_timestamp(),'modify','{"path":"风险ABliteral"}'),('node-a','probe',clock_timestamp(),'probe','{"reason":"风险%_literal"}')`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_imported_events(migration_source,node,id,event_id,digest,received_at,operation,security,payload) VALUES('fixture','removed-node','imported','','fixture',clock_timestamp(),'health',false,'{"message":"风险%_literal"}')`)
	f := EventFilter{Since: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour), Limit: 20, Keyword: "风险%_"}
	items, err := s.Events(context.Background(), f)
	if err != nil || len(items) != 4 {
		t.Fatal(len(items), err)
	}
	for _, item := range items {
		if item.ID == "wildcard" || item.ID == "probe" {
			t.Fatal("unexpected wildcard/probe", item)
		}
	}
	f.Node = "node-1"
	items, err = s.Events(context.Background(), f)
	if err != nil || len(items) != 1 || items[0].ID != "id-1" {
		t.Fatal(items, err)
	}
	f.Node = ""
	f.IncludeProbes = true
	f.Limit = 1
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		items, err = s.Events(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 0 {
			break
		}
		item := items[0]
		if seen[item.RecordKey] {
			t.Fatal("repeated cursor record", item)
		}
		seen[item.RecordKey] = true
		f.BeforeTime, f.BeforeNode, f.BeforeID, f.BeforeSource = item.Received, item.Node, item.ID, item.Source
	}
	if len(seen) != 5 {
		t.Fatal("clear-server/probe pagination lost rows", seen)
	}
}
