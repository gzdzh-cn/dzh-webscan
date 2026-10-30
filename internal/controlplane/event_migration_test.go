package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/central"
	"webscan/internal/common"
	agentv1 "webscan/sdk/agent/v1"
)

func legacyFilePayload(node, id string) common.Map {
	return common.Map{"node_id": node, "event_id": id, "operation": "modify", "time": "2026-10-06T00:00:00+00:00", "path": "/中文/<&>\u2028.php", "size": json.Number("9007199254740993"), "inode": json.Number("18446744073709551615"), "ratio": json.Number("1.0")}
}
func seedLegacyFile(t *testing.T, f legacyHistories, id string, p common.Map) {
	t.Helper()
	clean, hash, err := canonicalEvent(p)
	if err != nil {
		t.Fatal(err)
	}
	stored := common.Clone(clean)
	stored["server_name"] = "原服务器"
	stored["server_ip"] = "192.0.2.10"
	stored["received_time"] = "original receiver time"
	mustHistoryExec(t, f.queue, "INSERT INTO events VALUES(?,?,?,?,?)", common.S(p["node_id"]), id, hash, string(common.JSON(stored)), float64(f.at)+0.125)
}
func archiveFiles(t *testing.T, s *Store, path string) string {
	t.Helper()
	report, err := s.ArchiveSQLite(context.Background(), path, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return report.Source
}
func eventRange(at int64) EventFilter {
	return EventFilter{Since: time.Unix(at-1, 0), Until: time.Now().Add(time.Hour), Limit: 200}
}

func TestEventMigrationRealV2ReceiptsPreservePrecisionWithoutReplay(t *testing.T) {
	ctx := context.Background()
	s, n, l, _ := healthFixture(t)
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(jsonb_set(payload,'{feishu,notifications,file_changes}','true'),'{email,notifications,file_changes}','true')`)
	dir := t.TempDir()
	old, err := central.New(common.Map{"data_dir": dir, "backup_dir": t.TempDir(), "max_batch_events": 100, "active_nodes": []string{n.ID}, "nodes": common.Map{n.ID: common.Map{"host": "192.0.2.10", "name": "原服务器"}}, "monitoring": common.Map{"mode": "native"}, "feishu": common.Map{"enabled": false}, "email": common.Map{"enabled": false}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		old.DB.Close()
		if old.Telemetry != nil {
			old.Telemetry.DB.Close()
		}
	})
	p := legacyFilePayload(n.ID, "native-old")
	security := common.Clone(p)
	security["event_id"] = "security-old"
	security["operation"] = "scan"
	security["scan"] = common.Map{"status": "matched"}
	if _, err = old.Ingest(ctx, n.ID, []any{p, security}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Unix() - 172800
	mustHistoryExec(t, old.DB, "UPDATE events SET received=?", float64(at)+0.125)
	var enriched string
	if err = old.DB.QueryRow("SELECT payload FROM events WHERE id='native-old'").Scan(&enriched); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, old.DB, "INSERT INTO migrated_logs VALUES('duplicate',?,'modify',?,?)", n.ID, at, enriched)
	mustHistoryExec(t, old.DB, "INSERT INTO migrated_logs VALUES('old-log','removed-node','modify',?,?)", at, `{"operation":"modify","path":"/legacy/only.php"}`)
	mustHistoryExec(t, old.DB, "INSERT INTO migrated_logs VALUES('old-probe',?,'probe',?,?)", n.ID, at, `{"operation":"probe","event_id":"old-probe"}`)
	source := archiveFiles(t, s, filepath.Join(dir, "events-v1.sqlite3"))
	if _, err = s.MapNotificationArchive(ctx, source); err != nil {
		t.Fatal(err)
	}
	report, err := s.MapEventArchive(ctx, source)
	if err != nil || !report.Complete || report.ReadyForCutover || report.Processed != 5 || report.Imported != 4 {
		t.Fatal(report, err)
	}
	if tableCount(t, s, "v3_notifications") != 0 || tableCount(t, s, "v3_nodes") != 1 || tableCount(t, s, "v3_node_identities") != 2 {
		t.Fatal("import activated notices or historical nodes")
	}
	var size, inode string
	var atPG time.Time
	if err = s.DB.QueryRow("SELECT payload->>'size',payload->>'inode',received_at FROM v3_events WHERE id='native-old'").Scan(&size, &inode, &atPG); err != nil || size != "9007199254740993" || inode != "18446744073709551615" || atPG.UnixMicro() != at*1000000+125000 {
		t.Fatal(size, inode, atPG, err)
	}
	f := eventRange(at)
	items, err := s.Events(ctx, f)
	if err != nil || len(items) != 3 {
		t.Fatal(len(items), err)
	}
	f.IncludeProbes = true
	items, err = s.Events(ctx, f)
	if err != nil || len(items) != 4 {
		t.Fatal(len(items), err)
	}
	for _, item := range items {
		if item.RecordKey == "" || item.CanDelete || item.DeleteReason == "" {
			t.Fatal(item)
		}
	}
	backup, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"v3_events", "v3_event_keys", "v3_imported_events", "v3_node_identities", "v3_migration_domains"} {
		if tableCount(t, s, table) != tableCount(t, restored, table) {
			t.Fatal("restore lost", table)
		}
	}
	// Test-only activation, after verifying that snapshots retained the fence.
	mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=false")
	accepted, rejected, err := s.Ingest(ctx, n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: "native-old", Json: common.JSON(p)}}})
	if err != nil || len(accepted) != 1 || len(rejected) != 0 || tableCount(t, s, "v3_events") != 2 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal(accepted, rejected, err)
	}
	p["path"] = "/conflicting.php"
	fresh := legacyFilePayload(n.ID, "fresh-after-migration")
	accepted, rejected, err = s.Ingest(ctx, n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: "native-old", Json: common.JSON(p)}, {Id: "fresh-after-migration", Json: common.JSON(fresh)}}})
	if err != nil || len(accepted) != 1 || len(rejected) != 1 || rejected[0].Code != "event_id_conflict" || tableCount(t, s, "v3_notifications") != 2 || tableCount(t, s, "v3_event_rejections") != 1 {
		t.Fatal(accepted, rejected, err)
	}
	var original int
	if err = old.DB.QueryRow("SELECT count(*) FROM events").Scan(&original); err != nil || original != 2 {
		t.Fatal("modified source", original, err)
	}
}

func TestEventMigrationLegacyTakeoverAndSourceAwareAPIPagination(t *testing.T) {
	s, n, l, _ := healthFixture(t)
	ctx := context.Background()
	f := legacyHistoryFixture(t)
	p := legacyFilePayload(n.ID, "legacy-only")
	mustHistoryExec(t, f.queue, "INSERT INTO migrated_logs VALUES('legacy-key',?,'modify',?,?)", n.ID, float64(f.at)+0.125, string(common.JSON(p)))
	mustHistoryExec(t, f.queue, "INSERT INTO migrated_logs VALUES('collision',?,'modify',?,?)", n.ID, float64(f.at)+0.125, `{"operation":"modify","path":"/legacy/without-id.php"}`)
	source := archiveFiles(t, s, f.queuePath)
	if report, err := s.MapEventArchive(ctx, source); err != nil || !report.Complete || report.Imported != 2 {
		t.Fatal(report, err)
	}
	if tableCount(t, s, "v3_event_keys") != 0 {
		t.Fatal("Loki history invented native receipts")
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_migration_domains SET pending=false")
	a, r, err := s.Ingest(ctx, n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: "legacy-only", Json: common.JSON(p)}}})
	if err != nil || len(a) != 1 || len(r) != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("old observation created new notices", a, r, err)
	}
	fresh := legacyFilePayload(n.ID, "collision")
	if _, _, err = s.Ingest(ctx, n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: "collision", Json: common.JSON(fresh)}}}); err != nil {
		t.Fatal(err)
	}
	// Create a real source tie, so a cursor using only time/node/id would skip.
	mustHistoryExec(t, s.DB, "UPDATE v3_events SET received_at=to_timestamp($1)", float64(f.at)+0.125)
	if err = s.Provision(ctx, "viewer", "fixture-password-123"); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("a", 64)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,'viewer',1,'csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(secret)))
	api := &API{Store: s}
	call := func(path string, auth bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		if auth {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: secret})
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	if w := call("/api/v3/events", false); w.Code != 401 {
		t.Fatal(w.Code)
	}
	q := url.Values{"start": {time.Unix(f.at-1, 0).UTC().Format(time.RFC3339)}, "end": {time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, "limit": {"1"}}
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		w := call("/api/v3/events?"+q.Encode(), true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var page struct {
			Items []EventRecord `json:"items"`
			Next  string        `json:"next_cursor"`
		}
		if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, v := range page.Items {
			if v.RecordKey == "" || seen[v.RecordKey] || v.CanDelete || v.DeleteReason == "" {
				t.Fatal(v)
			}
			seen[v.RecordKey] = true
		}
		if page.Next == "" {
			break
		}
		q.Set("cursor", page.Next)
	}
	if len(seen) != 3 {
		t.Fatal("source tie lost a page", seen)
	}
	bad := base64.RawURLEncoding.EncodeToString(common.JSON(common.Map{"time": time.Now(), "node": n.ID, "id": "collision", "source": "unknown"}))
	if w := call("/api/v3/events?cursor="+bad, true); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := call("/api/v3/events?operation=probe", true); w.Code != 400 {
		t.Fatal(w.Code)
	}
	mustHistoryExec(t, s.DB, "DELETE FROM v3_events WHERE id='legacy-only'")
	visible, err := s.Events(ctx, eventRange(f.at))
	if err != nil || len(visible) != 2 {
		t.Fatal("deleted native history resurrected migrated display", len(visible), err)
	}
}

func TestEventMigrationResumes503NativeEvents(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := legacyHistoryFixture(t)
	for i := 1; i <= 503; i++ {
		id := fmt.Sprintf("event-%04d", i)
		seedLegacyFile(t, f, id, legacyFilePayload("removed-node", id))
	}
	source := archiveFiles(t, s, f.queuePath)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION interrupt_file_mapping() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.id='event-0501' THEN RAISE EXCEPTION 'private-payload-detail'; END IF; RETURN NEW; END$$;
 CREATE TRIGGER interrupt_file_mapping BEFORE INSERT ON v3_events FOR EACH ROW EXECUTE FUNCTION interrupt_file_mapping()`)
	partial, err := s.MapEventArchive(ctx, source)
	if err == nil || partial.Complete || partial.Processed != 500 || tableCount(t, s, "v3_events") != 500 || strings.Contains(err.Error(), "private-payload-detail") {
		t.Fatal(partial, err)
	}
	mustHistoryExec(t, s.DB, "DROP TRIGGER interrupt_file_mapping ON v3_events")
	report, err := s.MapEventArchive(ctx, source)
	if err != nil || !report.Complete || report.Imported != 503 || report.ReadyForCutover || tableCount(t, s, "v3_event_keys") != 503 {
		t.Fatal(report, err)
	}
	again, err := s.MapEventArchive(ctx, source)
	if err != nil || again.Imported != 503 || tableCount(t, s, "v3_nodes") != 0 {
		t.Fatal(again, err)
	}
}

func TestEventMigrationRejectsInvalidSourceAndLiveTarget(t *testing.T) {
	for _, which := range []string{"receipt digest", "staging digest", "node mismatch", "operation mismatch", "invalid legacy payload", "live target", "notification source"} {
		t.Run(which, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			f := legacyHistoryFixture(t)
			seedLegacyFile(t, f, "original", legacyFilePayload("old-node", "original"))
			switch which {
			case "receipt digest":
				mustHistoryExec(t, f.queue, "UPDATE events SET digest='changed'")
			case "node mismatch":
				mustHistoryExec(t, f.queue, "UPDATE events SET node='other'")
			case "operation mismatch":
				mustHistoryExec(t, f.queue, "INSERT INTO migrated_logs VALUES('m','old-node','probe',?,'{\"operation\":\"modify\"}')", f.at)
			case "invalid legacy payload":
				mustHistoryExec(t, f.queue, "INSERT INTO migrated_logs VALUES('m','old-node','modify',?,'[]')", f.at)
			case "live target":
				mustHistoryExec(t, s.DB, "INSERT INTO v3_events VALUES('live','live',clock_timestamp(),'modify',false,'{}')")
			case "notification source":
				other := legacyHistoryFixture(t)
				other.task(t, 1, "other", "feishu", common.Map{}, nil)
				otherSource := archiveFiles(t, s, other.queuePath)
				if _, err := s.MapNotificationArchive(ctx, otherSource); err != nil {
					t.Fatal(err)
				}
			}
			source := archiveFiles(t, s, f.queuePath)
			if which == "staging digest" {
				mustHistoryExec(t, s.DB, `UPDATE v3_legacy_records SET payload=jsonb_set(payload,'{node,value}','"changed"') WHERE source=$1 AND table_name='events'`, source)
			}
			if report, err := s.MapEventArchive(ctx, source); err == nil || report.Complete {
				t.Fatal(report, err)
			}
			if which == "live target" && tableCount(t, s, "v3_migration_domains") != 0 {
				t.Fatal("failed initialization fenced live target")
			}
		})
	}
}

func TestEventSchema6UpgradePreservesOldDigestAndRejectsRoundedCollision(t *testing.T) {
	s := emptyTestStore(t)
	ctx := context.Background()
	for _, schema := range []string{Schema, websiteSchema, deploymentSchema, deploymentReadinessSchema, healthSchema, migrationSchema} {
		mustHistoryExec(t, s.DB, schema)
	}
	n := nodeFixture("node-a")
	if err := putNode(ctx, s.DB, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"old-small", "old-rounded"} {
		p := legacyFilePayload(n.ID, id)
		p["size"] = 1
		p["inode"] = 1
		if id == "old-rounded" {
			p["size"] = json.Number("9007199254740993")
		}
		var old common.Map
		if err := json.Unmarshal(common.JSON(p), &old); err != nil {
			t.Fatal(err)
		}
		stored := common.JSON(old)
		mustHistoryExec(t, s.DB, "INSERT INTO v3_event_keys VALUES($1,$2,$3,clock_timestamp())", n.ID, id, digest(stored))
		mustHistoryExec(t, s.DB, "INSERT INTO v3_events VALUES($1,$2,clock_timestamp(),'modify',false,$3)", n.ID, id, stored)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("upgraded schema6 without backup")
	}
	dir := privateTestDir(t)
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(ctx, shardResource(n.Shard), "new-collector")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"old-small", "old-rounded"} {
		p := legacyFilePayload(n.ID, id)
		p["size"] = 1
		p["inode"] = 1
		if id == "old-rounded" {
			p["size"] = json.Number("9007199254740993")
		}
		a, r, err := s.Ingest(ctx, n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: id, Json: common.JSON(p)}}})
		if err != nil {
			t.Fatal(err)
		}
		if id == "old-small" && len(a) != 1 || id == "old-rounded" && (len(a) != 0 || len(r) != 1) {
			t.Fatal("legacy digest did not verify payload", id, a, r)
		}
	}
}

func TestEventMigrationByteBudgetCommitsBeforeInterruptedLargeRecord(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := legacyHistoryFixture(t)
	for i := 1; i <= 7; i++ {
		id := fmt.Sprintf("large-%d", i)
		p := legacyFilePayload("large-node", id)
		p["detail"] = strings.Repeat("x", 1500000)
		seedLegacyFile(t, f, id, p)
	}
	source := archiveFiles(t, s, f.queuePath)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION interrupt_large_mapping() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.id='large-6' THEN RAISE EXCEPTION 'private-content'; END IF; RETURN NEW; END$$;
 CREATE TRIGGER interrupt_large_mapping BEFORE INSERT ON v3_events FOR EACH ROW EXECUTE FUNCTION interrupt_large_mapping()`)
	report, err := s.MapEventArchive(ctx, source)
	if err == nil || report.Complete || report.Processed != 5 || tableCount(t, s, "v3_events") != 5 || strings.Contains(err.Error(), "private-content") {
		t.Fatal(report, err)
	}
	mustHistoryExec(t, s.DB, "DROP TRIGGER interrupt_large_mapping ON v3_events")
	report, err = s.MapEventArchive(ctx, source)
	if err != nil || !report.Complete || report.Processed != 7 || report.Imported != 7 || tableCount(t, s, "v3_event_keys") != 7 {
		t.Fatal(report, err)
	}
}

func TestEventIngestInvalidItemsDoNotBlockExactNumbersOrReplay(t *testing.T) {
	s, n, l, _ := healthFixture(t)
	ctx := context.Background()
	batch := &agentv1.EventBatch{NodeId: n.ID}
	for i, detail := range []any{common.Map{"nested": []any{"bad\x00text"}}, common.Map{"bad\x00key": true}, json.Number("1e100000"), json.Number("1e-100000"), json.Number(strings.Repeat("9", 131073))} {
		id := fmt.Sprintf("bad-%d", i)
		p := legacyFilePayload(n.ID, id)
		p["detail"] = detail
		batch.Events = append(batch.Events, &agentv1.Event{Id: id, Json: common.JSON(p)})
	}
	p := legacyFilePayload(n.ID, "valid-exact")
	batch.Events = append(batch.Events, &agentv1.Event{Id: "valid-exact", Json: common.JSON(p)})
	accepted, rejected, err := s.Ingest(ctx, n, l, batch)
	if err != nil || len(accepted) != 1 || accepted[0] != "valid-exact" || len(rejected) != 5 || tableCount(t, s, "v3_events") != 1 || tableCount(t, s, "v3_event_keys") != 1 || tableCount(t, s, "v3_event_rejections") != 5 {
		t.Fatal(accepted, rejected, err)
	}
	for _, r := range rejected {
		if r.Code != "invalid_event" {
			t.Fatal(r)
		}
	}
	var size, inode string
	if err = s.DB.QueryRow("SELECT payload->>'size',payload->>'inode' FROM v3_events WHERE id='valid-exact'").Scan(&size, &inode); err != nil || size != "9007199254740993" || inode != "18446744073709551615" {
		t.Fatal(size, inode, err)
	}
	// Receiver metadata can change during retry without changing event identity.
	p["server_name"] = "different center name"
	p["server_ip"] = "192.0.2.55"
	p["received_time"] = "different time"
	accepted, rejected, err = s.Ingest(ctx, n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{{Id: "valid-exact", Json: common.JSON(p)}}})
	if err != nil || len(accepted) != 1 || len(rejected) != 0 || tableCount(t, s, "v3_events") != 1 {
		t.Fatal(accepted, rejected, err)
	}
}
