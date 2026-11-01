package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/management"
	"webscan/internal/persist"
)

func migrationLegacyHistoryFixture(t *testing.T) (*Store, string, string, *management.Service, func() string, *Vault) {
	t.Helper()
	ctx := context.Background()
	s := migrationSessionTestStore(t)
	var present bool
	if e := s.DB.QueryRow(`SELECT to_regclass('v3_legacy_history') IS NOT NULL`).Scan(&present); e != nil {
		t.Fatal(e)
	}
	if !present {
		if _, e := s.DB.Exec(migrationLegacyHistorySchema); e != nil {
			t.Fatal(e)
		}
	}
	id := digest([]byte(t.Name()))
	source := digest([]byte("host-history-source"))
	if _, e := s.BeginMigrationSession(ctx, id, 0, []string{"host-manager"}); e != nil {
		t.Fatal(e)
	}
	svc, e := management.Open(writeLegacySettings(t, legacySettingsFixture(t)), privateTestDir(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { svc.DB.Close() })
	root := privateTestDir(t)
	snapshot := func() string {
		path := filepath.Join(root, "host-"+token()+".sqlite3")
		if e := persist.BackupDB(svc.DB, path); e != nil {
			t.Fatal(e)
		}
		return path
	}
	v, _ := testVault(t)
	return s, id, source, svc, snapshot, v
}
func migrationHistoryVerify(t *testing.T, s *Store, id, revision string, v *Vault) (bool, error) {
	t.Helper()
	tx, e := s.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	return VerifyLegacyHistoryTx(context.Background(), tx, id, revision, v)
}

func TestMigrationLegacyHistoryActualJobsLogsArtifactsAndDelta(t *testing.T) {
	ctx := context.Background()
	s, id, source, svc, snapshot, v := migrationLegacyHistoryFixture(t)
	at := time.Now().Add(-48 * time.Hour).Unix()
	backupDir := privateTestDir(t)
	restoreDir := privateTestDir(t)
	original, e := readLegacySettings(svc.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(backupDir, "console-fixture.yaml")
	if e = os.WriteFile(file, original, 0600); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, svc.DB, `INSERT INTO jobs VALUES('job-one','PRIVATE-request-key','upgrade-node','node-202','complete',?,?,'private-revision','PRIVATE-job-message')`, at, at+1)
	mustHistoryExec(t, svc.DB, `INSERT INTO logs(job,time,message) VALUES('job-one',?,'PRIVATE-log-raw-password')`, at+1)
	mustHistoryExec(t, svc.DB, `INSERT INTO job_workflow VALUES('job-one','','PRIVATE-run-id')`)
	mustHistoryExec(t, svc.DB, `INSERT INTO job_progress VALUES('job-one',1,'install','PRIVATE-host','PRIVATE-title','success','PRIVATE-progress',?)`, at+1)
	mustHistoryExec(t, svc.DB, `INSERT INTO upgrade_jobs VALUES('job-one','PRIVATE-image','v2.0.46')`)
	mustHistoryExec(t, svc.DB, `INSERT INTO config_backups VALUES('backup-one',?,?,?,?)`, at, digest(original), "PRIVATE-source", file)
	mustHistoryExec(t, svc.DB, `INSERT INTO config_backup_details VALUES('backup-one','[]',0,'PRIVATE-backup-result')`)
	mustHistoryExec(t, svc.DB, `INSERT INTO config_backup_previews VALUES('PRIVATE-preview-token','backup-one','PRIVATE-owner','revision','digest',1,?)`, at)
	mustHistoryExec(t, svc.DB, `INSERT INTO job_archives VALUES('job-one',?)`, at+1)
	mustHistoryExec(t, svc.DB, `INSERT INTO backup_import_attempts VALUES('PRIVATE-owner',2,?)`, at)
	mustHistoryExec(t, svc.DB, `INSERT INTO watchdog_state VALUES('central','up',?)`, at)
	mustHistoryExec(t, svc.DB, `INSERT INTO watchdog_outbox VALUES('watchdog:1:resolved','PRIVATE-watchdog-message',?,1)`, at)
	path := snapshot()
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"host-manager", source, path})
	if e != nil {
		t.Fatal(e)
	}
	pending, e := s.MapMigrationLegacyHistory(ctx, id, rev.SessionVersion, rev.ID, MigrationLegacyHistoryInput{}, v)
	if e != nil || pending.Complete || pending.Records != 12 || len(pending.Pending) != 1 || pending.Pending[0].Category != "legacy_configuration_backup_file_missing" {
		t.Fatal(pending, e)
	}
	if ok, e := migrationHistoryVerify(t, s, id, rev.ID, v); e != nil || ok {
		t.Fatal(ok, e)
	}
	in := MigrationLegacyHistoryInput{ConfigurationBackupDirectories: map[string]string{"host-manager": backupDir}, RestoreVerificationDirectory: restoreDir}
	report, e := s.MapMigrationLegacyHistory(ctx, id, pending.SessionVersion, rev.ID, in, v)
	if e != nil || !report.Complete || report.Artifacts != 1 || report.RestoredArtifacts != 1 || report.ReadyForCutover {
		t.Fatal(report, e)
	}
	if ok, e := migrationHistoryVerify(t, s, id, rev.ID, v); e != nil || !ok {
		t.Fatal(ok, e)
	}
	replay, e := s.MapMigrationLegacyHistory(ctx, id, pending.SessionVersion, rev.ID, in, v)
	if e != nil || replay.SessionVersion != report.SessionVersion {
		t.Fatal("lost response retry not idempotent", replay, e)
	}
	var rowID, originalArchiveDigest string
	if e = s.DB.QueryRow(`SELECT r.id,r.archive_digest FROM v3_migration_legacy_history_rows r JOIN v3_legacy_history h USING(id) WHERE h.session=$1 LIMIT 1`, id).Scan(&rowID, &originalArchiveDigest); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_migration_legacy_history_rows SET archive_digest=$1 WHERE id=$2`, digest([]byte("forged archive metadata")), rowID)
	if _, e := migrationHistoryVerify(t, s, id, rev.ID, v); e == nil {
		t.Fatal("archive metadata tamper accepted")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_migration_legacy_history_rows SET archive_digest=$1 WHERE id=$2`, originalArchiveDigest, rowID)
	mustHistoryExec(t, s.DB, `UPDATE v3_legacy_history SET role='central' WHERE session=$1 AND table_name='jobs'`, id)
	if _, e := migrationHistoryVerify(t, s, id, rev.ID, v); e == nil {
		t.Fatal("ownership metadata tamper accepted")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_legacy_history SET role='host-manager' WHERE session=$1 AND table_name='jobs'`, id)
	files, e := os.ReadDir(restoreDir)
	if e != nil || len(files) != 1 {
		t.Fatal("actual restore missing", e)
	}
	restored, e := readTrustData(filepath.Join(restoreDir, files[0].Name(), "configuration.yaml"), true, 2<<20)
	if e != nil || digest(restored) != digest(original) {
		t.Fatal("actual backup bytes missing", e)
	}
	page, e := s.ListMigrationLegacyHistory(ctx, id, "host-manager", "", "", 200)
	if e != nil || len(page.Items) != 12 || !page.ReadOnly {
		t.Fatal(page, e)
	}
	public := string(common.JSON(page))
	for _, secret := range []string{"PRIVATE-", file, "password", "private-settings"} {
		if strings.Contains(public, secret) {
			t.Fatal("private history entered public projection")
		}
	}
	// The real message is preserved inside authenticated ciphertext, not erased.
	tx, e := s.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	owned, e := migrationLegacyHistoryLoadTx(ctx, tx, id, source, v)
	tx.Rollback()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, r := range owned {
		if strings.Contains(string(r.Envelope.Source), "PRIVATE-log-raw-password") {
			found = true
		}
	}
	if !found {
		t.Fatal("original log not retained")
	}
	var firstID string
	if e = s.DB.QueryRow(`SELECT id FROM v3_legacy_history WHERE session=$1 AND table_name='logs' AND record_key=1`, id).Scan(&firstID); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, svc.DB, `UPDATE logs SET message='PRIVATE-changed-message' WHERE id=1; INSERT INTO logs(job,time,message) VALUES('job-one',1,'PRIVATE-added-message'); DELETE FROM job_progress`)
	next, e := s.BindMigrationRevision(ctx, id, report.SessionVersion, MigrationRevisionInput{"host-manager", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	delta, e := s.MapMigrationLegacyHistory(ctx, id, next.SessionVersion, next.ID, MigrationLegacyHistoryInput{}, v)
	if e != nil || !delta.Complete || delta.Records != 12 {
		t.Fatal(delta, e)
	}
	var nextID string
	if e = s.DB.QueryRow(`SELECT id FROM v3_legacy_history WHERE session=$1 AND table_name='logs' AND record_key=1`, id).Scan(&nextID); e != nil || firstID != nextID {
		t.Fatal("history identity changed", e)
	}
	if ok, e := migrationHistoryVerify(t, s, id, next.ID, v); e != nil || !ok {
		t.Fatal(ok, e)
	}
	if _, e := migrationHistoryVerify(t, s, id, rev.ID, v); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("stale revision accepted", e)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_legacy_history SET payload='{}' WHERE id=$1`, firstID)
	if _, e = s.MapMigrationLegacyHistory(ctx, id, delta.SessionVersion, next.ID, MigrationLegacyHistoryInput{}, v); !errors.Is(e, ErrConflict) {
		t.Fatal("foreign modification overwritten", e)
	}
}

func TestMigrationLegacyHistoryPendingJobsNotificationsAndTamper(t *testing.T) {
	ctx := context.Background()
	s, id, source, svc, snapshot, v := migrationLegacyHistoryFixture(t)
	at := time.Now().Unix()
	mustHistoryExec(t, svc.DB, `INSERT INTO jobs VALUES('job-one','key','add-node','node','interrupted',?,?,'rev','PRIVATE')`, at, at)
	mustHistoryExec(t, svc.DB, `INSERT INTO watchdog_outbox VALUES('watchdog:1:firing','PRIVATE-notification',?,0)`, at)
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"host-manager", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	report, e := s.MapMigrationLegacyHistory(ctx, id, rev.SessionVersion, rev.ID, MigrationLegacyHistoryInput{}, v)
	if e != nil || report.Complete || len(report.Pending) != 2 {
		t.Fatal(report, e)
	}
	mustHistoryExec(t, svc.DB, `UPDATE jobs SET status='complete'; UPDATE watchdog_outbox SET done=1`)
	next, e := s.BindMigrationRevision(ctx, id, report.SessionVersion, MigrationRevisionInput{"host-manager", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	report, e = s.MapMigrationLegacyHistory(ctx, id, next.SessionVersion, next.ID, MigrationLegacyHistoryInput{}, v)
	if e != nil || !report.Complete {
		t.Fatal(report, e)
	}
	if ok, e := migrationHistoryVerify(t, s, id, next.ID, v); e != nil || !ok {
		t.Fatal(ok, e)
	}
	wrong, _ := testVault(t)
	if _, e := migrationHistoryVerify(t, s, id, next.ID, wrong); e == nil {
		t.Fatal("wrong Vault accepted")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_migration_legacy_history_rows SET ciphertext=decode('00','hex') WHERE id=(SELECT id FROM v3_legacy_history WHERE table_name='logs' LIMIT 1)`)
	// A changed report cannot authorize activation, even when counts look right.
	mustHistoryExec(t, s.DB, `UPDATE v3_migration_legacy_history_runs SET report=jsonb_set(report,'{complete}','true') ,rows_digest=repeat('0',64) WHERE session=$1`, id)
	if _, e := migrationHistoryVerify(t, s, id, next.ID, v); e == nil {
		t.Fatal("forged evidence accepted")
	}
}

func TestMigrationLegacyHistoryArtifactRejectsSymlinkAndDigest(t *testing.T) {
	ctx := context.Background()
	s, id, source, svc, snapshot, v := migrationLegacyHistoryFixture(t)
	dir := privateTestDir(t)
	raw, e := readLegacySettings(svc.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(privateTestDir(t), "private.yaml")
	if e = os.WriteFile(target, raw, 0600); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "console-one.yaml")
	if e = os.Symlink(target, path); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, svc.DB, `INSERT INTO config_backups VALUES('backup',1,?,'source',?)`, digest(raw), path)
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"host-manager", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	input := MigrationLegacyHistoryInput{ConfigurationBackupDirectories: map[string]string{"host-manager": dir}, RestoreVerificationDirectory: privateTestDir(t)}
	r, e := s.MapMigrationLegacyHistory(ctx, id, rev.SessionVersion, rev.ID, input, v)
	if e != nil || r.Complete || r.Pending[0].Category != "legacy_configuration_backup_file_unsafe_or_missing" {
		t.Fatal(r, e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(raw, []byte("\n# changed")...), 0600); e != nil {
		t.Fatal(e)
	}
	r, e = s.MapMigrationLegacyHistory(ctx, id, r.SessionVersion, rev.ID, input, v)
	if e != nil || r.Complete || r.Pending[0].Category != "legacy_configuration_backup_digest_mismatch" {
		t.Fatal(r, e)
	}
}

func TestMigrationLegacyHistoryFinalMappingAndActualReverseArtifacts(t *testing.T) {
	ctx := context.Background()
	s, id, source, svc, snapshot, v := migrationLegacyHistoryFixture(t)
	raw, e := readLegacySettings(svc.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	dir := privateTestDir(t)
	file := filepath.Join(dir, "console-original.yaml")
	if e = os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, svc.DB, `INSERT INTO jobs VALUES('job','key','apply','','complete',1,2,'revision','PRIVATE-original')`)
	mustHistoryExec(t, svc.DB, `INSERT INTO logs(job,time,message) VALUES('job',2,'PRIVATE-original-log')`)
	mustHistoryExec(t, svc.DB, `INSERT INTO config_backups VALUES('backup',1,?,'source',?)`, digest(raw), file)
	path := snapshot()
	rev, e := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"host-manager", source, path})
	if e != nil {
		t.Fatal(e)
	}
	initial, e := s.MapMigrationFinalDomains(ctx, id, rev.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil || initial.Complete || len(initial.Pending) != 1 || initial.Pending[0].Category != "legacy_history_requires_verified_mapping" {
		t.Fatal(initial, e)
	}
	history, e := s.MapMigrationLegacyHistory(ctx, id, initial.SessionVersion, rev.ID, MigrationLegacyHistoryInput{ConfigurationBackupDirectories: map[string]string{"host-manager": dir}, RestoreVerificationDirectory: privateTestDir(t)}, v)
	if e != nil || !history.Complete {
		t.Fatal(history, e)
	}
	final, e := s.MapMigrationFinalDomains(ctx, id, history.SessionVersion, MigrationFinalMappingInput{}, v)
	if e != nil || !final.Complete {
		t.Fatal(final, e)
	}
	sink, e := s.PrepareMigrationLegacySink(ctx, id, final.SessionVersion, map[string]string{"host-manager": path}, filepath.Join(privateTestDir(t), "reverse"), v)
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	var exported, message string
	if e = sink.db.QueryRow(`SELECT path FROM manager.config_backups WHERE id='backup'`).Scan(&exported); e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(exported, filepath.Join(sink.output, "config-backups")+string(os.PathSeparator)) {
		t.Fatal("backup still points to original deployment")
	}
	recovered, e := readTrustData(exported, true, 2<<20)
	if e != nil || digest(recovered) != digest(raw) {
		t.Fatal("actual external YAML missing", e)
	}
	if e = sink.db.QueryRow(`SELECT message FROM manager.logs WHERE id=1`).Scan(&message); e != nil || message != "PRIVATE-original-log" {
		t.Fatal("actual original log changed", e)
	}
	rows, e := s.DB.Query(`SELECT to_jsonb(h) FROM v3_legacy_history h WHERE session=$1 ORDER BY id`, id)
	if e != nil {
		t.Fatal(e)
	}
	baseline := []MigrationTargetReplayRow{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			t.Fatal(e)
		}
		parsed, e := common.Decode(b)
		if e != nil {
			t.Fatal(e)
		}
		baseline = append(baseline, migrationLegacyTestRow("v3_legacy_history", "BASELINE", nil, common.M(parsed)))
	}
	rows.Close()
	if _, e = sink.ApplyMigrationJournal(ctx, migrationLegacyTestBatch(id, "actual-history-baseline", baseline...)); e != nil {
		t.Fatal(e)
	}
	status, e := sink.Report(ctx)
	if e != nil || !status.Complete || len(status.Pending) > 0 {
		t.Fatal(status, e)
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	e = VerifyMigrationLegacyArtifactsTx(ctx, tx, id, sink, v)
	tx.Rollback()
	if e != nil {
		t.Fatal(e)
	}
	// A valid-looking replacement file and local digest cannot substitute the
	// original authenticated backup payload retained in PostgreSQL.
	altered := append(append([]byte{}, raw...), []byte("\n# forged replacement")...)
	mustHistoryExec(t, sink.db, `UPDATE migration_configuration_artifacts SET payload=?,digest=? WHERE id='backup'`, altered, digest(altered))
	if _, e = sink.Report(ctx); e != nil {
		t.Fatal(e)
	}
	tx, e = s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	e = VerifyMigrationLegacyArtifactsTx(ctx, tx, id, sink, v)
	tx.Rollback()
	if e == nil {
		t.Fatal("changed external backup accepted")
	}
}

func TestMigrationLegacyHistorySameSourceDifferentRolesRemainIndependent(t *testing.T) {
	ctx := context.Background()
	s := migrationSessionTestStore(t)
	id, source := digest([]byte(t.Name())), digest([]byte("same-id-for-both-roles"))
	state, e := s.BeginMigrationSession(ctx, id, 0, []string{"central", "host-manager"})
	if e != nil {
		t.Fatal(e)
	}
	svc, e := management.Open(writeLegacySettings(t, legacySettingsFixture(t)), privateTestDir(t))
	if e != nil {
		t.Fatal(e)
	}
	defer svc.DB.Close()
	mustHistoryExec(t, svc.DB, `INSERT INTO jobs VALUES('completed','private-key','add-node','node','complete',1,1,'rev','private-log')`)
	hostPath := filepath.Join(privateTestDir(t), "host.sqlite3")
	if e = persist.BackupDB(svc.DB, hostPath); e != nil {
		t.Fatal(e)
	}
	host, e := s.BindMigrationRevision(ctx, id, state.Version, MigrationRevisionInput{"host-manager", source, hostPath})
	if e != nil {
		t.Fatal(e)
	}
	v, _ := testVault(t)
	db, e := persist.OpenDB(filepath.Join(privateTestDir(t), "central.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	mustHistoryExec(t, db, `CREATE TABLE probes(node TEXT PRIMARY KEY,received INTEGER NOT NULL); INSERT INTO probes VALUES('old-node',1)`)
	centralPath := filepath.Join(privateTestDir(t), "central-snapshot.sqlite3")
	if e = persist.BackupDB(db, centralPath); e != nil {
		t.Fatal(e)
	}
	central, e := s.BindMigrationRevision(ctx, id, host.SessionVersion, MigrationRevisionInput{"central", source, centralPath})
	if e != nil {
		t.Fatal(e)
	}
	h, e := s.MapMigrationLegacyHistory(ctx, id, central.SessionVersion, host.ID, MigrationLegacyHistoryInput{}, v)
	if e != nil || !h.Complete || h.Records != 1 {
		t.Fatal(h, e)
	}
	c, e := s.MapMigrationLegacyHistory(ctx, id, h.SessionVersion, central.ID, MigrationLegacyHistoryInput{}, v)
	if e != nil || !c.Complete || c.Records != 1 {
		t.Fatal(c, e)
	}
	for _, revision := range []string{host.ID, central.ID} {
		if ok, e := migrationHistoryVerify(t, s, id, revision, v); e != nil || !ok {
			t.Fatal(revision, ok, e)
		}
	}
	page, e := s.ListMigrationLegacyHistory(ctx, id, "", "", "", 20)
	if e != nil || len(page.Items) != 2 {
		t.Fatal(page, e)
	}
}
