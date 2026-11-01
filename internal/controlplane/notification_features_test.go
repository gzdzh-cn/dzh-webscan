package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/common"
	agentv1 "webscan/sdk/agent/v1"
)

func TestNotificationProducerProjectionCommitsWithEvent(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	n := nodeFixture("node-a")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(ctx, shardResource(n.Shard), "projection-collector")
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"file_changes":true}}}'`)
	e := &agentv1.Event{Id: "projection-event", Json: common.JSON(common.Map{"node_id": n.ID, "event_id": "projection-event", "operation": "modify", "path": "/srv/synthetic/index.php", "source": "website", "message": "PRIVATE arbitrary message", "token": "PRIVATE credential"})}
	batch := &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{e}}
	for i := 0; i < 2; i++ {
		accepted, rejected, err := s.Ingest(ctx, n, l, batch)
		if err != nil || len(accepted) != 1 || len(rejected) != 0 {
			t.Fatal("event not durably accepted", len(accepted), len(rejected), err)
		}
	}
	var source, body string
	var projections, notifications int
	if err := s.DB.QueryRow(`SELECT source,body FROM v3_notification_public`).Scan(&source, &body); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT (SELECT count(*) FROM v3_notification_public),(SELECT count(*) FROM v3_notifications)`).Scan(&projections, &notifications); err != nil {
		t.Fatal(err)
	}
	if source != "event" || !strings.Contains(body, "/srv/synthetic/index.php") || strings.Contains(body, "PRIVATE") || projections != 1 || notifications != 1 {
		t.Fatal("trusted provenance, public projection or deduplication lost")
	}
}

func TestNotificationProjectionFailureDoesNotAcknowledgeEvent(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	n := nodeFixture("node-a")
	if err := s.PutNode(ctx, n, 0, 256); err != nil {
		t.Fatal(err)
	}
	l, err := s.Acquire(ctx, shardResource(n.Shard), "projection-collector")
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"file_changes":true}}}';CREATE FUNCTION reject_public_projection() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated projection failure';END$$;CREATE TRIGGER reject_public_projection BEFORE INSERT ON v3_notification_public FOR EACH ROW EXECUTE FUNCTION reject_public_projection()`)
	accepted, _, err := s.Ingest(ctx, n, l, &agentv1.EventBatch{NodeId: n.ID, Events: []*agentv1.Event{eventFixture("projection-failure", "modify")}})
	if err == nil || len(accepted) != 0 {
		t.Fatal("failed transaction acknowledged event")
	}
	for _, table := range []string{"v3_event_keys", "v3_events", "v3_notifications", "v3_notification_public"} {
		if tableCount(t, s, table) != 0 {
			t.Fatal("partial transaction remained", table)
		}
	}
}

func TestNotificationFeatureUpgrade41BacksUpAndStopsOnFailure(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(node,event_id,channel,recipient,payload) VALUES('synthetic','old','feishu','','{"message":"PRIVATE historical payload"}')`)
	mustHistoryExec(t, s.DB, notificationFeaturesTestDrop)
	var before []byte
	if err := s.DB.QueryRow(`SELECT to_jsonb(n) FROM v3_notifications n`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	assertOld := func() {
		t.Helper()
		version, err := currentSchema(ctx, s.DB)
		var exists bool
		if err != nil || version != 41 {
			t.Fatal("failed migration changed version", version, err)
		}
		if err = s.DB.QueryRow(`SELECT to_regclass(current_schema()||'.v3_notification_public') IS NOT NULL`).Scan(&exists); err != nil || exists {
			t.Fatal("failed migration left new tables", err)
		}
	}
	unsafe := privateTestDir(t)
	if err := os.Chmod(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, unsafe); err == nil {
		t.Fatal("backup failure ignored")
	}
	assertOld()
	mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_schema42() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.version=42 THEN RAISE EXCEPTION 'isolated migration failure';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_schema42 BEFORE INSERT ON v3_schema FOR EACH ROW EXECUTE FUNCTION reject_schema42()`)
	backupDir := privateTestDir(t)
	if err := s.Upgrade(ctx, backupDir); err == nil {
		t.Fatal("migration failure ignored")
	}
	assertOld()
	files, err := filepath.Glob(filepath.Join(backupDir, "postgres-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatal("missing pre-upgrade snapshot", err)
	}
	header, err := inspectPGBackup(files[0])
	if err != nil || header.Version != 41 {
		t.Fatal("incorrect snapshot version", err)
	}
	prior := emptyTestStore(t)
	if err = prior.RestorePostgres(ctx, files[0]); err != nil {
		t.Fatal("pre-upgrade snapshot is not restorable", err)
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER reject_schema42 ON v3_schema`)
	if err = s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err = s.DB.QueryRow(`SELECT to_jsonb(n) FROM v3_notifications n`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	var a, b any
	if json.Unmarshal(before, &a) != nil || json.Unmarshal(after, &b) != nil || string(common.JSON(a)) != string(common.JSON(b)) {
		t.Fatal("upgrade rewrote historical delivery data")
	}
	if tableCount(t, s, "v3_notification_public") != 0 {
		t.Fatal("startup migration scanned and projected all historical payloads")
	}
}
