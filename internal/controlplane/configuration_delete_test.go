package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func configurationDeleteFixture(t *testing.T, count int) (*Store, *Vault, []string) {
	t.Helper()
	s, v, c := configurationBackupStoreFixture(t)
	ids := []string{}
	for i := 0; i < count; i++ {
		raw, err := s.createConfigurationBackup(context.Background(), v, c, "admin", fmt.Sprintf("delete-fixture-%d", i))
		ids = append(ids, configurationBackupReceiptID(t, raw, err))
	}
	sort.Strings(ids)
	return s, v, ids
}

func configurationDeletePreviewForTest(t *testing.T, s *Store, ids ...string) configurationDeletePreview {
	t.Helper()
	records := []string{}
	for _, id := range ids {
		records = append(records, "configuration-backup:"+id)
	}
	out, err := s.previewConfigurationDelete(context.Background(), "admin", records)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func configurationDeleteQueueForTest(t *testing.T, s *Store, p configurationDeletePreview, key string) configurationDeleteJob {
	t.Helper()
	raw, err := s.submitConfigurationDelete(context.Background(), "admin", key, p.Token, true)
	var job configurationDeleteJob
	if err != nil || json.Unmarshal(raw, &job) != nil || !validArchiveSource(job.ID) {
		t.Fatal("cannot queue delete job", err)
	}
	return job
}

func configurationDeleteLease(t *testing.T, s *Store, owner string) Lease {
	t.Helper()
	l, err := s.Acquire(context.Background(), "retention", owner)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func drainConfigurationDelete(t *testing.T, s *Store, l Lease, id string) configurationDeleteJob {
	t.Helper()
	for i := 0; i < 202; i++ {
		j, err := s.configurationDeleteBatch(context.Background(), l, id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != "queued" && j.Status != "running" {
			return j
		}
	}
	t.Fatal("delete did not finish within explicit selection limit")
	return configurationDeleteJob{}
}

func TestConfigurationDeleteExplicitPreviewProtectionAndCheckpoint(t *testing.T) {
	s, _, ids := configurationDeleteFixture(t, 5)
	ctx := context.Background()
	// No ordinary-history age rule: a newly created independent backup is
	// deletable. A missing row and preview-protected row are fixed exclusions.
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'rollback','fixed-reference')`, ids[1])
	p := configurationDeletePreviewForTest(t, s, ids[0], ids[1], ids[2], strings.Repeat("f", 64))
	if p.Eligible != 2 || p.Protected != 2 || len(p.Items) != 4 || time.Until(p.Expires) > 10*time.Minute {
		t.Fatal("wrong fixed scope", p.Eligible, p.Protected)
	}
	// Unpinning a protected item must not expand the accepted deletion scope.
	mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1`, ids[1])
	j := configurationDeleteQueueForTest(t, s, p, "delete-fixed-selection")
	if tableCount(t, s, "v3_configuration_backups") != 5 || j.Status != "queued" {
		t.Fatal("queue performed deletion")
	}
	list, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range list {
		if b.ID == ids[0] && (b.CanDelete || b.DeleteReason != "删除任务处理中") {
			t.Fatal("queued backup remained selectable")
		}
	}
	l := configurationDeleteLease(t, s, "first-cleaner")
	first, err := s.configurationDeleteBatch(ctx, l, j.ID)
	if err != nil || first.Deleted != 1 || first.Status != "running" {
		t.Fatal("first checkpoint not durable", err, first)
	}
	// New protection created after preview is checked at actual execution.
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'deployment','new-reference')`, ids[2])
	mustHistoryExec(t, s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource='retention'`)
	next := configurationDeleteLease(t, s, "replacement-cleaner")
	if _, err = s.configurationDeleteBatch(ctx, l, j.ID); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale cleaner wrote", err)
	}
	// A fresh Store represents process replacement, not a new logical task.
	finished := drainConfigurationDelete(t, &Store{DB: s.DB}, next, j.ID)
	if finished.Status != "partial" || finished.Deleted != 1 || finished.Skipped != 3 || finished.Failed != 0 || finished.Finished == nil {
		t.Fatal("wrong partial result", finished)
	}
	if tableCount(t, s, "v3_configuration_backups") != 4 || tableCount(t, s, "v3_configuration_backup_parts") != 4 || tableCount(t, s, "v3_nodes") != 1 {
		t.Fatal("scope expanded, chunks orphaned or live data changed")
	}
	raw, err := s.submitConfigurationDelete(ctx, "admin", "delete-fixed-selection", p.Token, true)
	var replay configurationDeleteJob
	if err != nil || json.Unmarshal(raw, &replay) != nil || replay.ID != j.ID || replay.Status != "queued" || tableCount(t, s, "v3_configuration_delete_jobs") != 1 {
		t.Fatal("replay created new destructive intent", err)
	}
	if err := s.Release(ctx, next); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationDeleteRejectsScopeExpansionExpiredAndOtherAccounts(t *testing.T) {
	s, _, ids := configurationDeleteFixture(t, 2)
	ctx := context.Background()
	bad := [][]string{nil, {}, {ids[0]}, {"configuration-backup:../file"}, {"configuration-backup:" + ids[0], "configuration-backup:" + ids[0]}}
	for _, records := range bad {
		if _, err := s.previewConfigurationDelete(ctx, "admin", records); !errors.Is(err, errConfigurationDeleteInput) {
			t.Fatal("invalid scope accepted", err)
		}
	}
	large := []string{}
	for i := 0; i < 201; i++ {
		large = append(large, fmt.Sprintf("configuration-backup:%064x", i))
	}
	if _, err := s.previewConfigurationDelete(ctx, "admin", large); !errors.Is(err, errConfigurationDeleteInput) {
		t.Fatal("oversized scope accepted", err)
	}
	p := configurationDeletePreviewForTest(t, s, ids[0])
	if _, err := s.submitConfigurationDelete(ctx, "admin", "no-confirm", p.Token, false); !errors.Is(err, errConfigurationDeleteInput) {
		t.Fatal("unconfirmed deletion accepted", err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('other-admin','not-a-password','admin')`)
	if _, err := s.submitConfigurationDelete(ctx, "other-admin", "other-owner", p.Token, true); !errors.Is(err, errConfigurationDeletePreview) {
		t.Fatal("another account used preview", err)
	}
	for _, user := range []string{"viewer", "operator"} {
		if _, err := s.previewConfigurationDelete(ctx, user, []string{"configuration-backup:" + ids[0]}); !errors.Is(err, ErrConfigurationBackupPermission) {
			t.Fatal("non-admin preview", err)
		}
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_delete_previews SET expires_at=clock_timestamp()-interval '1 second'`)
	if _, err := s.submitConfigurationDelete(ctx, "admin", "expired", p.Token, true); !errors.Is(err, errConfigurationDeletePreview) {
		t.Fatal("expired preview accepted", err)
	}
	p = configurationDeletePreviewForTest(t, s, ids[0])
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
	if _, err := s.submitConfigurationDelete(ctx, "admin", "changed-settings", p.Token, true); !errors.Is(err, errConfigurationDeletePreview) {
		t.Fatal("changed settings accepted", err)
	}
	if tableCount(t, s, "v3_configuration_delete_jobs") != 0 || tableCount(t, s, "v3_configuration_backups") != 2 {
		t.Fatal("rejected request changed source")
	}
}

func TestConfigurationDeleteConcurrentQueueAndOwnerVisibility(t *testing.T) {
	s, _, ids := configurationDeleteFixture(t, 1)
	ctx := context.Background()
	p := configurationDeletePreviewForTest(t, s, ids[0])
	var wg sync.WaitGroup
	responses := make(chan []byte, 2)
	errorsSeen := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := s.submitConfigurationDelete(ctx, "admin", "same-delete-key", p.Token, true)
			responses <- raw
			errorsSeen <- err
		}()
	}
	wg.Wait()
	close(responses)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	var previous string
	var job configurationDeleteJob
	for raw := range responses {
		if json.Unmarshal(raw, &job) != nil {
			t.Fatal("invalid queue receipt")
		}
		if previous != "" && previous != job.ID {
			t.Fatal("concurrent retry created another job")
		}
		previous = job.ID
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('other-admin','not-a-password','admin')`)
	if _, _, err := s.configurationDeleteJob(ctx, "other-admin", job.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("another admin read private operation", err)
	}
	if rows, err := s.configurationDeleteJobs(ctx, "other-admin", retentionCursor{}, 20); err != nil || len(rows) != 0 {
		t.Fatal("other owner task listed", err)
	}
	// Demotion revokes both receipt replay and future task execution.
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
	if _, err := s.submitConfigurationDelete(ctx, "admin", "same-delete-key", p.Token, true); !errors.Is(err, ErrConfigurationBackupPermission) {
		t.Fatal("demoted account replayed receipt", err)
	}
	finished := drainConfigurationDelete(t, s, configurationDeleteLease(t, s, "role-check"), job.ID)
	if finished.Status != "cancelled" || finished.Deleted != 0 || finished.Skipped != 1 || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("demotion did not protect remaining backups", finished)
	}
}

func TestConfigurationDeleteRecordFailureDoesNotBlockOtherSelectedBackups(t *testing.T) {
	s, _, ids := configurationDeleteFixture(t, 3)
	p := configurationDeletePreviewForTest(t, s, ids...)
	j := configurationDeleteQueueForTest(t, s, p, "partial-failure")
	// A permanent row error rolls back the parent/chunks together, is
	// sanitized, and does not stop the following independent selected item.
	mustHistoryExec(t, s.DB, fmt.Sprintf(`CREATE FUNCTION reject_one_configuration_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.id='%s' THEN RAISE EXCEPTION 'private-provider-password-do-not-expose'; END IF; RETURN OLD; END $$;CREATE TRIGGER reject_one_configuration_delete BEFORE DELETE ON v3_configuration_backups FOR EACH ROW EXECUTE FUNCTION reject_one_configuration_delete()`, ids[1]))
	finished := drainConfigurationDelete(t, s, configurationDeleteLease(t, s, "partial-cleaner"), j.ID)
	if finished.Deleted != 2 || finished.Failed != 1 || finished.Status != "partial" || tableCount(t, s, "v3_configuration_backups") != 1 || tableCount(t, s, "v3_configuration_backup_parts") != 1 {
		t.Fatal("partial failure not durable", finished)
	}
	_, items, err := s.configurationDeleteJob(context.Background(), "admin", j.ID)
	if err != nil || items[1].Status != "failed" || strings.Contains(items[1].Reason, "private-provider") {
		t.Fatal("row failure not sanitized", err)
	}
	var raw []byte
	if err := s.DB.QueryRow(`SELECT json_agg(result)::text FROM v3_audit WHERE kind LIKE 'configuration-backup-delete-%'`).Scan(&raw); err != nil || bytes.Contains(raw, []byte("private-provider")) {
		t.Fatal("audit contains driver secret", err)
	}
}

func TestConfigurationDeleteSharedWorkerAndConfigurationChange(t *testing.T) {
	s, _, ids := configurationDeleteFixture(t, 2)
	ctx := context.Background()
	p := configurationDeletePreviewForTest(t, s, ids...)
	j := configurationDeleteQueueForTest(t, s, p, "config-change-checkpoint")
	l := configurationDeleteLease(t, s, "current-cleaner")
	if _, err := s.Acquire(ctx, "retention", "other-cleaner"); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("automatic and backup cleaners did not share mutex", err)
	}
	first, err := s.configurationDeleteBatch(ctx, l, j.ID)
	if err != nil || first.Deleted != 1 {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
	finished := drainConfigurationDelete(t, s, l, j.ID)
	if finished.Status != "cancelled" || finished.Deleted != 1 || finished.Skipped != 1 || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("config change discarded checkpoint or expanded deletion", finished)
	}
	if err := s.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	// Normal runtime uses the unified scheduler, not an HTTP-side delete.
	remaining, err := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if err != nil {
		t.Fatal(err)
	}
	p = configurationDeletePreviewForTest(t, s, remaining[0].ID)
	j = configurationDeleteQueueForTest(t, s, p, "unified-worker")
	if err := s.RunRetentionRound(ctx, "unified-cleaner"); err != nil {
		t.Fatal(err)
	}
	finished, _, err = s.configurationDeleteJob(ctx, "admin", j.ID)
	if err != nil || finished.Status != "succeeded" || finished.Deleted != 1 {
		t.Fatal("runtime did not run queued delete", err, finished)
	}
}

func TestConfigurationDeleteMigrationGateAndSchema14Backup(t *testing.T) {
	s, _, ids := configurationDeleteFixture(t, 1)
	ctx := context.Background()
	dropConfigurationDeletesForTest(t, s)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema14 upgraded without backup")
	}
	bad := filepath.Join(privateTestDir(t), "file")
	if err := os.WriteFile(bad, []byte("not-a-directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, bad); err == nil {
		t.Fatal("failed backup allowed schema15")
	}
	if version, _ := currentSchema(ctx, s.DB); version != 14 {
		t.Fatal("failed upgrade changed schema")
	}
	dir := privateTestDir(t)
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 1 {
		t.Fatal("missing consistent schema14 backup")
	}
	old := emptyTestStore(t)
	if err := old.RestorePostgres(ctx, files[0]); err != nil {
		t.Fatal(err)
	}
	if version, _ := currentSchema(ctx, old.DB); version != 14 || tableCount(t, old, "v3_configuration_backups") != 1 {
		t.Fatal("schema14 backup not restorable")
	}
	if err := old.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	p := configurationDeletePreviewForTest(t, s, ids[0])
	j := configurationDeleteQueueForTest(t, s, p, "migration-pauses-delete")
	l := configurationDeleteLease(t, s, "migration-cleaner")
	mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source,pending) VALUES('settings',repeat('a',64),true)`)
	if _, err := s.configurationDeleteBatch(ctx, l, j.ID); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("migration freeze did not pause destructive work", err)
	}
	if tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("frozen task deleted backup")
	}
}

func TestConfigurationDeleteDisasterRestoreCancelsOnlyPendingWork(t *testing.T) {
	s, v, ids := configurationDeleteFixture(t, 2)
	ctx := context.Background()
	p := configurationDeletePreviewForTest(t, s, ids...)
	j := configurationDeleteQueueForTest(t, s, p, "disaster-checkpoint")
	if first, err := s.configurationDeleteBatch(ctx, configurationDeleteLease(t, s, "pre-disaster-cleaner"), j.ID); err != nil || first.Deleted != 1 {
		t.Fatal(err)
	}
	archive, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err := restored.RestorePostgres(ctx, archive); err != nil {
		t.Fatal(err)
	}
	got, items, err := restored.configurationDeleteJob(ctx, "admin", j.ID)
	if err != nil || got.Status != "cancelled" || got.Deleted != 1 || got.Skipped != 1 || len(items) != 2 {
		t.Fatal("destructive intent revived", err, got)
	}
	if readPrivateConfigurationBackup(t, restored, v, ids[1]).SettingsVersion != 5 {
		t.Fatal("remaining encrypted backup was changed")
	}
	raw, err := restored.submitConfigurationDelete(ctx, "admin", "disaster-checkpoint", p.Token, true)
	var replay configurationDeleteJob
	if err != nil || json.Unmarshal(raw, &replay) != nil || replay.ID != j.ID || tableCount(t, restored, "v3_configuration_delete_jobs") != 1 {
		t.Fatal("old request resurrected after restore", err)
	}
}

type configurationBlockingDownload struct {
	*httptest.ResponseRecorder
	started chan struct{}
	resume  chan struct{}
}

func (w *configurationBlockingDownload) Write(data []byte) (int, error) {
	close(w.started)
	<-w.resume
	return 0, errors.New("synthetic download disconnected")
}

func TestConfigurationDeleteHTTPExportRemainsPinnedUntilWriteReturns(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	created := configurationAPICall(a, "POST", "", strings.NewReader("{}"), sessions["admin"], "configuration-csrf", "export-pin-backup", true)
	id := configurationBackupReceiptID(t, created.Body.Bytes(), nil)
	p := configurationDeletePreviewForTest(t, a.Store, id)
	j := configurationDeleteQueueForTest(t, a.Store, p, "while-download-active")
	r := httptest.NewRequest("GET", "/api/v3/configuration-backups/"+id+"/export", nil)
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
	w := &configurationBlockingDownload{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	done := make(chan struct{})
	var unblock sync.Once
	resume := func() { unblock.Do(func() { close(w.resume) }) }
	t.Cleanup(resume)
	go func() { defer close(done); a.ServeHTTP(w, r) }()
	select {
	case <-w.started:
	case <-time.After(5 * time.Second):
		t.Fatal("export did not reach HTTP write")
	}
	finished := drainConfigurationDelete(t, a.Store, configurationDeleteLease(t, a.Store, "download-cleaner"), j.ID)
	if finished.Status != "partial" || finished.Skipped != 1 || tableCount(t, a.Store, "v3_configuration_backups") != 1 || tableCount(t, a.Store, "v3_configuration_backup_pins") != 1 {
		t.Fatal("HTTP transfer lost reference protection", finished)
	}
	resume()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("write failure did not terminate handler")
	}
	if tableCount(t, a.Store, "v3_configuration_backup_pins") != 0 {
		t.Fatal("failed transfer leaked pin")
	}
}

func TestConfigurationDeleteCompetingPreviewsAndAuditRollback(t *testing.T) {
	s, _, ids := configurationDeleteFixture(t, 2)
	ctx := context.Background()
	p1 := configurationDeletePreviewForTest(t, s, ids[0])
	p2 := configurationDeletePreviewForTest(t, s, ids[0])
	var wg sync.WaitGroup
	jobs := make(chan configurationDeleteJob, 2)
	errs := make(chan error, 2)
	for i, p := range []configurationDeletePreview{p1, p2} {
		wg.Add(1)
		go func(i int, p configurationDeletePreview) {
			defer wg.Done()
			raw, err := s.submitConfigurationDelete(ctx, "admin", fmt.Sprintf("competing-%d", i), p.Token, true)
			var j configurationDeleteJob
			if err == nil {
				err = json.Unmarshal(raw, &j)
			}
			jobs <- j
			errs <- err
		}(i, p)
	}
	wg.Wait()
	close(jobs)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var skipped int
	for j := range jobs {
		skipped += j.Skipped
	}
	if skipped != 1 {
		t.Fatal("overlapping previews queued two pending deletes", skipped)
	}
	var pending int
	if err := s.DB.QueryRow(`SELECT count(*) FROM v3_configuration_delete_items WHERE status='pending'`).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("pending scope", err, pending)
	}
	p := configurationDeletePreviewForTest(t, s, ids[1])
	j := configurationDeleteQueueForTest(t, s, p, "audit-atomicity")
	mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_delete_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='configuration-backup-delete-progress' THEN RAISE EXCEPTION 'synthetic-private-audit-failure'; END IF; RETURN NEW; END $$;CREATE TRIGGER reject_delete_audit BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION reject_delete_audit()`)
	l := configurationDeleteLease(t, s, "audit-cleaner")
	if _, err := s.configurationDeleteBatch(ctx, l, j.ID); err == nil {
		t.Fatal("audit failure allowed delete")
	}
	got, items, err := s.configurationDeleteJob(ctx, "admin", j.ID)
	if err != nil || got.Deleted != 0 || items[0].Status != "pending" || tableCount(t, s, "v3_configuration_backups") != 2 || tableCount(t, s, "v3_configuration_backup_parts") != 2 {
		t.Fatal("failed audit did not roll back parent,parts and checkpoint", err, got)
	}
	if err = s.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	// A backup-audit-specific failure does not starve automatic history work.
	if err = s.RunRetentionRound(ctx, "independent-cleaner"); err == nil {
		t.Fatal("retrying archive error was hidden")
	}
	var status string
	if err = s.DB.QueryRow(`SELECT status FROM v3_retention_jobs ORDER BY created_at DESC LIMIT 1`).Scan(&status); err != nil || status != "succeeded" {
		t.Fatal("archive failure starved automatic retention", err, status)
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER reject_delete_audit ON v3_audit;DROP FUNCTION reject_delete_audit()`)
	finished := drainConfigurationDelete(t, s, configurationDeleteLease(t, s, "recovered-cleaner"), j.ID)
	if finished.Status != "succeeded" || finished.Deleted != 1 {
		t.Fatal("failed audit task did not resume", finished)
	}
}

func TestConfigurationDeleteQuotaAndHousekeeping(t *testing.T) {
	s, _, ids := configurationDeleteFixture(t, 1)
	ctx := context.Background()
	p := configurationDeletePreviewForTest(t, s, ids[0])
	j := configurationDeleteQueueForTest(t, s, p, "gc-old-job")
	l := configurationDeleteLease(t, s, "gc-cleaner")
	_ = drainConfigurationDelete(t, s, l, j.ID)
	if err := s.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_delete_jobs SET finished_at=clock_timestamp()-interval '366 days' WHERE id=$1`, j.ID)
	// Unused, expired capabilities may be dropped; active jobs and used previews remain.
	unused := configurationDeletePreviewForTest(t, s, strings.Repeat("e", 64))
	active := configurationDeleteQueueForTest(t, s, unused, "gc-active-job")
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_delete_previews SET expires_at=clock_timestamp()-interval '1 second'`)
	if err := s.Housekeeping(ctx, "gc-worker"); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_configuration_delete_jobs") != 1 || tableCount(t, s, "v3_configuration_delete_previews") != 1 || tableCount(t, s, "v3_configuration_delete_items") != 1 {
		t.Fatal("GC discarded active job or retained expired finished metadata")
	}
	if got, _, err := s.configurationDeleteJob(ctx, "admin", active.ID); err != nil || got.Status != "queued" {
		t.Fatal("active job removed", err)
	}
	raw, err := s.submitConfigurationDelete(ctx, "admin", "gc-old-job", p.Token, true)
	var replay configurationDeleteJob
	if err != nil || json.Unmarshal(raw, &replay) != nil || replay.ID != j.ID || tableCount(t, s, "v3_configuration_delete_jobs") != 1 {
		t.Fatal("GC removed idempotency tombstone", err)
	}
	for i := 0; i < 100; i++ {
		configurationDeletePreviewForTest(t, s, strings.Repeat("d", 64))
	}
	if _, err := s.previewConfigurationDelete(ctx, "admin", []string{"configuration-backup:" + strings.Repeat("d", 64)}); !errors.Is(err, errConfigurationDeleteQuota) {
		t.Fatal("preview quota not enforced", err)
	}
}

func TestConfigurationDeleteAPIAuthScopeAndJobs(t *testing.T) {
	a, _, sessions := configurationAPIFixture(t)
	created := configurationAPICall(a, "POST", "", strings.NewReader(`{}`), sessions["admin"], "configuration-csrf", "api-delete-create", true)
	id := configurationBackupReceiptID(t, created.Body.Bytes(), nil)
	// Listing and deletion do not decrypt private configuration archives.
	a.Config.DeploymentTrust.VaultKeyFile = filepath.Join(privateTestDir(t), "unavailable-vault")
	body := `{"records":["configuration-backup:` + id + `"]}`
	for _, tc := range []struct {
		user, csrf, body string
		want             int
	}{
		{"", "configuration-csrf", body, 401}, {"viewer", "configuration-csrf", body, 403}, {"operator", "configuration-csrf", body, 403}, {"admin", "invalid", body, 403},
		{"admin", "configuration-csrf", `{"records":[],"table":"arbitrary"}`, 400},
	} {
		w := configurationAPICall(a, "POST", "/delete-preview", strings.NewReader(tc.body), sessions[tc.user], tc.csrf, "", true)
		if w.Code != tc.want {
			t.Fatal("auth/scope status", tc.user, w.Code, w.Body.String())
		}
	}
	w := configurationAPICall(a, "POST", "/delete-preview", strings.NewReader(body), sessions["admin"], "configuration-csrf", "", false)
	var p configurationDeletePreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Eligible != 1 {
		t.Fatal("preview", w.Code, w.Body.String())
	}
	// Even plain HTTP uses the same destructive-operation session/CSRF boundary;
	// no credential or private document is transmitted for deletion.
	input := fmt.Sprintf(`{"token":%q,"confirm":true}`, p.Token)
	w = configurationAPICall(a, "POST", "/delete", strings.NewReader(input), sessions["admin"], "configuration-csrf", "", false)
	if w.Code != 400 {
		t.Fatal("missing idempotency accepted", w.Code)
	}
	w = configurationAPICall(a, "POST", "/delete", strings.NewReader(input), sessions["admin"], "configuration-csrf", "api-delete-once", false)
	var j configurationDeleteJob
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &j) != nil || j.Status != "queued" || j.Deleted != 0 {
		t.Fatal("queue not distinguished from deletion", w.Code, w.Body.String())
	}
	for _, path := range []string{"/delete-jobs", "/delete-jobs/" + j.ID} {
		w = configurationAPICall(a, "GET", path, nil, sessions["admin"], "", "", false)
		if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(j.ID)) {
			t.Fatal("job unavailable", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/v3/configuration-backups/delete-preview", strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
	r.Header.Set("X-CSRF-Token", "configuration-csrf")
	r.Header.Set("Origin", "https://other.example.test")
	blocked := httptest.NewRecorder()
	a.ServeHTTP(blocked, r)
	if blocked.Code != 403 {
		t.Fatal("cross-origin deletion allowed", blocked.Code)
	}
	if tableCount(t, a.Store, "v3_configuration_backups") != 1 {
		t.Fatal("HTTP queue deleted data inline")
	}
}
