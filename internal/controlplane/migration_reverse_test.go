package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"gopkg.in/yaml.v3"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/persist"
)

func migrationLegacyTestBatch(session, id string, rows ...MigrationTargetReplayRow) MigrationTargetReplayBatch {
	return MigrationTargetReplayBatch{Session: session, Consumer: "legacy_business", ID: digest([]byte(id)), SHA256: digest([]byte(id + "-chain")), Phase: "changes", Rows: rows}
}

// Bind a real legacy YAML through its authenticated production import path.
// This website-only fixture has no managed agents and does not invent one.
func migrationBindLegacyYAMLFixture(t *testing.T, s *Store, id, source string, version int64, v *Vault) int64 {
	t.Helper()
	m := legacySettingsFixture(t)
	m["nodes"] = []any{}
	common.M(m["deployment"])["node_order"] = []any{}
	path := writeLegacySettings(t, m)
	raw, e := readLegacySettings(path)
	if e != nil {
		t.Fatal(e)
	}
	settings, _, e := legacySettings(raw)
	if e != nil {
		t.Fatal(e)
	}
	clear(raw)
	// Initialize the synthetic runtime with the actual import result, retaining
	// all schema/security checks in MapLegacyNodes and the reverse output.
	if _, e = s.DB.Exec(`UPDATE v3_settings SET payload=$1 WHERE id=1`, common.JSON(settings)); e != nil {
		t.Fatal(e)
	}
	report, e := s.MapLegacyNodes(context.Background(), id, version, path, source, v)
	if e != nil || !report.Complete {
		t.Fatal(report, e)
	}
	return report.SessionVersion
}

func TestMigrationReverseKnownBaselineAndActualNotificationLifecycle(t *testing.T) {
	ctx := context.Background()
	s := migrationSessionTestStore(t)
	id := digest([]byte(t.Name()))
	state, e := s.BeginMigrationSession(ctx, id, 0, []string{"central"})
	if e != nil {
		t.Fatal(e)
	}
	f := legacyHistoryFixture(t)
	f.task(t, 41, "original-file", "feishu", common.Map{"operation": "modify", "path": "/srv/owned.php"}, nil)
	path := filepath.Join(privateTestDir(t), "snapshot.sqlite3")
	if e = persist.BackupDB(f.queue, path); e != nil {
		t.Fatal(e)
	}
	rev, e := s.BindMigrationRevision(ctx, id, state.Version, MigrationRevisionInput{"central", digest([]byte("central")), path})
	if e != nil {
		t.Fatal(e)
	}
	v, _ := testVault(t)
	mapped, e := s.MapMigrationFinalDomains(ctx, id, rev.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil {
		t.Fatal(e)
	}
	sink, e := s.PrepareMigrationLegacySink(ctx, id, mapped.SessionVersion, map[string]string{"central": path}, filepath.Join(privateTestDir(t), "reverse"), v)
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	var raw []byte
	if e = s.DB.QueryRow(`SELECT to_jsonb(t) FROM v3_notifications t`).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	parsed, e := common.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	notice := common.M(parsed)
	if _, e = sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(id, "notification-baseline", migrationLegacyTestRow("v3_notifications", "BASELINE", nil, notice))); e != nil {
		t.Fatal(e)
	}
	var result string
	if e = sink.db.QueryRow(`SELECT coalesce(result,'') FROM central.tasks WHERE id=41`).Scan(&result); e != nil || result != "" {
		t.Fatal("redacted v3 response replaced original", result, e)
	}
	done := common.Clone(notice)
	done["done_at"] = time.Unix(f.at+100, 0).UTC().Format(time.RFC3339Nano)
	done["attempts"] = int64(3)
	done["result"] = "模拟投递完成"
	if _, e = sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(id, "notification-done", migrationLegacyTestRow("v3_notifications", "UPDATE", notice, done))); e != nil {
		t.Fatal(e)
	}
	var received sql.NullFloat64
	if e = sink.db.QueryRow(`SELECT done,result FROM central.tasks WHERE id=41`).Scan(&received, &result); e != nil || !received.Valid || int64(received.Float64) != f.at+100 || result != "模拟投递完成" {
		t.Fatal(received, result, e)
	}
	email := common.Map{"id": int64(9001), "node": "node-new", "event_id": "file-new", "channel": "email", "recipient": "a@example.test", "payload": common.Map{"operation": "modify", "path": "/srv/new.php"}, "created_at": time.Unix(f.at, 0).UTC().Format(time.RFC3339Nano), "next_try": time.Unix(f.at+1, 0).UTC().Format(time.RFC3339Nano), "attempts": int64(0), "done_at": nil, "result": "", "migration_task": nil, "delivery_key": "current-v3-email-key"}
	second := common.Clone(email)
	second["id"] = int64(9002)
	second["recipient"] = "b@example.test"
	attempt := common.Map{"id": int64(12001), "notification": int64(9001), "created_at": email["created_at"], "success": false, "result": "模拟失败", "migration_record": ""}
	if _, e = sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(id, "new-mail", migrationLegacyTestRow("v3_notifications", "ADD", nil, email), migrationLegacyTestRow("v3_notifications", "ADD", nil, second), migrationLegacyTestRow("v3_notification_attempts", "ADD", nil, attempt))); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = sink.db.QueryRow(`SELECT count(*) FROM central.tasks WHERE event_id='file-new'`).Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	if e = sink.db.QueryRow(`SELECT count(*) FROM central.email_recipients WHERE task_id=42`).Scan(&count); e != nil || count != 2 {
		t.Fatal(count, e)
	}
	if e = sink.db.QueryRow(`SELECT count(*) FROM central.email_attempts WHERE task_id=42 AND recipient='a@example.test'`).Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	report, e := sink.Report(ctx)
	if e != nil || len(report.Pending) > 0 {
		t.Fatal(report, e)
	}
	// v3's unknown delivery identity must not be changed to a fresh legacy key.
	retried := common.Clone(email)
	retried["attempts"] = int64(1)
	if _, e = sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(id, "mail-pending-key", migrationLegacyTestRow("v3_notifications", "UPDATE", email, retried))); e != nil {
		t.Fatal(e)
	}
	report, e = sink.Report(ctx)
	if e != nil || report.Complete || len(report.Pending) != 1 || report.Pending[0].Category != "reverse_pending_email_delivery_key_not_preserved" {
		t.Fatal(report, e)
	}
}

func TestMigrationReverseEvidenceBindsBaselineAndSealedActualBusinessOutput(t *testing.T) {
	s, id, source, sourceDB, snapshot, v := migrationFinalFixture(t)
	ctx := context.Background()
	path := snapshot()
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, path})
	if e != nil {
		t.Fatal(e)
	}
	version := migrationBindLegacyYAMLFixture(t, s, id, source, rev.SessionVersion, v)
	var sourceFile string
	if e = sourceDB.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&sourceFile); e != nil {
		t.Fatal(e)
	}
	frozen, e := s.freezeMigrationSession(ctx, id, version, migrationFreezeTestManifest(t, id, source, sourceFile), privateTestDir(t), func(context.Context, MigrationFreezeSource) (string, error) {
		return digest([]byte("synthetic-stopped")), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	mapped, e := s.MapMigrationFinalDomains(ctx, id, frozen.Version, MigrationFinalMappingInput{}, v)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DB.QueryRow(`SELECT snapshot FROM v3_migration_revisions WHERE session=$1 AND role='central' ORDER BY sequence DESC LIMIT 1`, id).Scan(&path); e != nil {
		t.Fatal(e)
	}
	sink, e := s.PrepareMigrationLegacySink(ctx, id, mapped.SessionVersion, map[string]string{"central": path}, filepath.Join(privateTestDir(t), "reverse"), v)
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	armed, e := s.ArmMigrationTargetJournal(ctx, id, mapped.SessionVersion)
	if e != nil {
		t.Fatal(e)
	}
	evidence, e := s.ProjectMigrationLegacyBaseline(ctx, id, armed.SessionVersion, "actual_legacy", sink, v)
	if e != nil || !evidence.Verified || evidence.Phase != "baseline" || len(evidence.Pending) > 0 {
		t.Fatal(evidence, e)
	}
	verify := func(evidence MigrationLegacyProjectionEvidence) (bool, error) {
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		return VerifyMigrationLegacyEvidenceTx(ctx, tx, id, "actual_legacy", evidence, sink, v)
	}
	if ok, e := verify(evidence); e != nil || !ok {
		t.Fatal(ok, e)
	}
	changed := evidence
	changed.Phase = "rollback"
	if _, e = verify(changed); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("phase substitution accepted", e)
	}
	if _, e = sink.db.Exec(`UPDATE central.websites SET name='tampered' WHERE id=2`); e != nil {
		t.Fatal(e)
	}
	if _, e = verify(evidence); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("actual business tamper accepted", e)
	}
	if _, e = sink.db.Exec(`UPDATE central.websites SET name='原网站-2' WHERE id=2`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_websites SET name='切换后新增名称',version=version+1 WHERE id=2`); e != nil {
		t.Fatal(e)
	}
	sealed, e := s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := s.ReplayMigrationTargetJournal(ctx, id, sealed.SessionVersion, "actual_legacy", sink)
	if e != nil || replay.State != "complete" {
		t.Fatal(replay, e)
	}
	rollback, e := s.VerifyMigrationLegacyRollback(ctx, id, replay.SessionVersion, "actual_legacy", sink, v)
	if e != nil || !rollback.Verified || rollback.Phase != "rollback" || rollback.OutputSHA256 == evidence.OutputSHA256 {
		t.Fatal(rollback, e)
	}
	var name string
	if e = sink.db.QueryRow(`SELECT name FROM central.websites WHERE id=2`).Scan(&name); e != nil || name != "切换后新增名称" {
		t.Fatal(name, e)
	}
	if ok, e := verify(rollback); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if _, e = verify(evidence); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("armed baseline accepted after sealing", e)
	}
}

func TestMigrationReverseSettingsRoundtripAndUnrepresentableField(t *testing.T) {
	m := legacySettingsFixture(t)
	raw, e := yaml.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	settings, _, e := legacySettings(raw)
	if e != nil {
		t.Fatal(e)
	}
	common.M(settings["website_monitor"])["interval_seconds"] = int64(111)
	common.M(settings["monitoring"])["group_wait_seconds"] = int64(45)
	common.M(settings["email"])["password"] = "new-private-synthetic-password"
	output, e := migrationLegacySettingsYAML(raw, settings)
	if e != nil {
		t.Fatal(e)
	}
	roundtrip, _, e := legacySettings(output)
	if e != nil || common.I(common.M(roundtrip["website_monitor"])["interval_seconds"]) != 111 || common.S(common.M(roundtrip["email"])["password"]) != "new-private-synthetic-password" {
		t.Fatal("settings not restored", e)
	}
	settings["collector"] = common.Map{"interval_seconds": int64(25)}
	if _, e = migrationLegacySettingsYAML(raw, settings); e == nil {
		t.Fatal("different collector/health intervals silently merged")
	}
	delete(settings, "collector")
	settings["new_v3_only_policy"] = common.Map{"enabled": true}
	if _, e = migrationLegacySettingsYAML(raw, settings); e == nil {
		t.Fatal("v3-only setting silently dropped")
	}
}
func migrationLegacyTestRow(table, op string, before, after common.Map) MigrationTargetReplayRow {
	row := MigrationTargetReplayRow{Table: table, Operation: op, Before: common.JSON(before), After: common.JSON(after)}
	if before != nil {
		row.BeforeKey = common.JSON(common.Map{"id": before["id"]})
	}
	if after != nil {
		row.AfterKey = common.JSON(common.Map{"id": after["id"]})
	}
	return row
}
func TestMigrationReverseActualSQLiteChangeReplayAndIdempotence(t *testing.T) {
	s, id, source, _, snapshot, v := migrationFinalFixture(t)
	ctx := context.Background()
	path := snapshot()
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, path})
	if e != nil {
		t.Fatal(e)
	}
	mapped, e := s.MapMigrationFinalDomains(ctx, id, rev.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(privateTestDir(t), "reversed")
	sink, e := s.PrepareMigrationLegacySink(ctx, id, mapped.SessionVersion, map[string]string{"central": path}, output)
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	var raw []byte
	if e = s.DB.QueryRow(`SELECT to_jsonb(t) FROM v3_websites t WHERE id=1`).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	parsed, e := common.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	before := common.M(parsed)
	after := common.Clone(before)
	after["name"] = "切换后新增名称"
	after["version"] = int64(4)
	row := migrationLegacyTestRow("v3_websites", "UPDATE", before, after)
	batch := migrationLegacyTestBatch(id, "update", row)
	receipt, e := sink.ApplyMigrationJournal(ctx, batch)
	if e != nil || receipt.Rows != 1 {
		t.Fatal(receipt, e)
	}
	again, e := sink.ApplyMigrationJournal(ctx, batch)
	if e != nil || again != receipt {
		t.Fatal(again, e)
	}
	var name string
	if e = sink.db.QueryRow(`SELECT name FROM central.websites WHERE id=1`).Scan(&name); e != nil || name != "切换后新增名称" {
		t.Fatal(name, e)
	}
	remove := migrationLegacyTestRow("v3_websites", "DELETE", after, nil)
	if _, e = sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(id, "delete", remove)); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = sink.db.QueryRow(`SELECT count(*) FROM central.websites WHERE id=1`).Scan(&count); e != nil || count != 0 {
		t.Fatal(count, e)
	}
	if e = sink.db.QueryRow(`SELECT count(*) FROM central.websites WHERE id=2`).Scan(&count); e != nil || count != 1 {
		t.Fatal("unrelated snapshot record lost", count, e)
	}
	report, e := sink.Report(ctx)
	if e != nil || !report.Complete || report.Rows != 2 || report.ReadyForRollback {
		t.Fatal(report, e)
	}
	if e = sink.Close(); e != nil {
		t.Fatal(e)
	}
	sink, e = OpenMigrationLegacySink(ctx, id, output)
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	if _, e = sink.ApplyMigrationJournal(ctx, batch); e != nil {
		t.Fatal("receipt lost after reopen", e)
	}
	wrong := batch
	wrong.SHA256 = digest([]byte("wrong"))
	if _, e = sink.ApplyMigrationJournal(ctx, wrong); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
}
func TestMigrationReverseUnknownSemanticsRemainExplicitlyBlocked(t *testing.T) {
	s, id, source, _, snapshot, _ := migrationFinalFixture(t)
	ctx := context.Background()
	path := snapshot()
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, path})
	if e != nil {
		t.Fatal(e)
	}
	sink, e := s.PrepareMigrationLegacySink(ctx, id, rev.SessionVersion, map[string]string{"central": path}, filepath.Join(privateTestDir(t), "reversed"))
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	rows := []MigrationTargetReplayRow{migrationLegacyTestRow("v3_nodes", "ADD", nil, common.Map{"id": "node-new", "mode": "docker"}), migrationLegacyTestRow("v3_accounts", "ADD", nil, common.Map{"id": "viewer", "role": "viewer"})}
	if _, e = sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(id, "unknown", rows...)); e != nil {
		t.Fatal(e)
	}
	report, e := sink.Report(ctx)
	if e != nil || report.Complete || len(report.Pending) != 1 || report.Pending[0].Count != 2 || report.ReadyForRollback {
		t.Fatal(report, e)
	}
	// Removing an unsupported record resolves only that record's own blocker.
	if _, e = sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(id, "unknown-delete", migrationLegacyTestRow("v3_nodes", "DELETE", common.Map{"id": "node-new", "mode": "docker"}, nil))); e != nil {
		t.Fatal(e)
	}
	report, e = sink.Report(ctx)
	if e != nil || report.Pending[0].Count != 1 || report.Complete {
		t.Fatal(report, e)
	}
}
func TestMigrationReverseBatchFailureRollsBackActualTablesAndReceipt(t *testing.T) {
	s, id, source, _, snapshot, _ := migrationFinalFixture(t)
	ctx := context.Background()
	path := snapshot()
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, path})
	if e != nil {
		t.Fatal(e)
	}
	sink, e := s.PrepareMigrationLegacySink(ctx, id, rev.SessionVersion, map[string]string{"central": path}, filepath.Join(privateTestDir(t), "reversed"))
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	if _, e = sink.db.Exec(`CREATE TRIGGER central.reverse_fail BEFORE DELETE ON websites WHEN old.id=2 BEGIN SELECT RAISE(ABORT,'synthetic');END`); e != nil {
		t.Fatal(e)
	}
	batch := migrationLegacyTestBatch(id, "fail", migrationLegacyTestRow("v3_websites", "DELETE", common.Map{"id": int64(1)}, nil), migrationLegacyTestRow("v3_websites", "DELETE", common.Map{"id": int64(2)}, nil))
	// Invalid partial business rows are refused before a destructive projection.
	if _, e = sink.ApplyMigrationJournal(ctx, batch); e == nil {
		t.Fatal("partial source data accepted")
	}
	var count int
	if e = sink.db.QueryRow(`SELECT count(*) FROM central.websites`).Scan(&count); e != nil || count != 3 {
		t.Fatal(count, e)
	}
	if e = sink.db.QueryRow(`SELECT count(*) FROM migration_receipts`).Scan(&count); e != nil || count != 0 {
		t.Fatal(count, e)
	}
}
