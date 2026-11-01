package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNotificationTestFullPostgresRestoreRevokesOnlySendingAuthority(t *testing.T) {
	f := newNotificationTestFixture(t)
	ctx := context.Background()
	mixed := f.submit(t, f.preview(t, "email"))
	first, e := f.worker.claim(ctx)
	if e != nil || first == nil {
		t.Fatal(e)
	}
	if e = f.worker.finish(ctx, first, true); e != nil {
		t.Fatal(e)
	}
	sending := f.submit(t, f.preview(t, "feishu"))
	if a, e := f.worker.claimJob(ctx, sending.ID); e != nil || a == nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_notification_test_cooldowns SET next_allowed_at='epoch' WHERE channel='email'`)
	queued := f.submit(t, f.preview(t, "email"))
	unused := f.preview(t, "email")
	if e = f.worker.heartbeat(ctx, nil); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_role_status(role,instance,heartbeat) VALUES('isolated-preserved-role','notification-backup',clock_timestamp())`)
	tx, e := f.s.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	var notification int64
	if e = tx.QueryRow(`INSERT INTO v3_notifications(node,event_id,channel,recipient,payload) VALUES('synthetic','restore-projection','email','synthetic@example.test','{"operation":"modify","path":"/srv/synthetic/index.php","message":"PRIVATE source receipt"}') RETURNING id`).Scan(&notification); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = projectNotificationTx(ctx, tx, notification, "event"); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	projections := publicMonitoringRows(t, f.s, "v3_notification_public", "notification")
	notifications := publicMonitoringRows(t, f.s, "v3_notifications", "id")
	signed := func(s *Store) string {
		t.Helper()
		var value string
		if e := s.DB.QueryRow(`SELECT jsonb_agg(jsonb_build_array(id,preview,username,account_revision,channel,runtime_version,targets,key_id,proof,expires_at) ORDER BY id)::text FROM v3_notification_test_jobs`).Scan(&value); e != nil {
			t.Fatal(e)
		}
		return value
	}
	before := signed(f.s)
	path, e := f.s.BackupPostgres(ctx, privateTestDir(t))
	if e != nil {
		t.Fatal("full backup", e)
	}
	restored := emptyTestStore(t)
	if e = restored.RestorePostgres(ctx, path); e != nil {
		t.Fatal("full restore into empty database", e)
	}
	if e = restored.Migrate(ctx); e != nil {
		t.Fatal("restored schema not current", e)
	}
	if signed(restored) != before || publicMonitoringRows(t, restored, "v3_notification_public", "notification") != projections || publicMonitoringRows(t, restored, "v3_notifications", "id") != notifications {
		t.Fatal("restore rewrote signed authorization, source payload or verified public projection")
	}
	for _, tc := range []struct {
		id, status string
		states     []string
	}{{mixed.ID, "partial", []string{"accepted", "cancelled"}}, {sending.ID, "unknown", []string{"unknown"}}, {queued.ID, "cancelled", []string{"cancelled", "cancelled"}}} {
		j, e := restored.notificationTestJob(ctx, "admin", tc.id)
		if e != nil || j.Status != tc.status || len(j.Items) != len(tc.states) {
			t.Fatal("restored wrong job state", j, e)
		}
		for i, state := range tc.states {
			if j.Items[i].State != state {
				t.Fatal("restored stale delivery authorization", j)
			}
		}
	}
	var archived, unrelated int
	if e = restored.DB.QueryRow(`SELECT count(*) FILTER(WHERE role='notification-tests'),count(*) FILTER(WHERE role='isolated-preserved-role') FROM v3_role_status`).Scan(&archived, &unrelated); e != nil || archived != 0 || unrelated != 1 {
		t.Fatal("restore retained sending heartbeat or removed unrelated evidence", archived, unrelated, e)
	}
	api := NewAPI(restored, Config{})
	api.Config.DeploymentTrust.VaultKeyFile = f.vaultPath
	if api.notificationTestAvailability(ctx).Available {
		t.Fatal("restored role status reported worker live")
	}
	if _, e = restored.submitNotificationTest(ctx, f.vault, "admin", "revoked-restored-preview", unused.Token, true); !errors.Is(e, errNotificationTestPreview) {
		t.Fatal("unused restored preview authorized external send", e)
	}
	sender := &notificationTestSender{}
	worker := &NotificationTestWorker{Store: restored, Vault: f.vault, Instance: "restored-test-worker", Sender: sender}
	for i := 0; i < 3; i++ {
		if e = worker.RunRound(ctx); e != nil {
			t.Fatal(e)
		}
	}
	if sender.count() != 0 {
		t.Fatal("restore automatically resent old notification")
	}
	detail, e := restored.NotificationDetail(ctx, fmt.Sprint(notification))
	if e != nil || detail.Notification.ContentState != "available" || !strings.Contains(detail.Body, "/srv/synthetic/index.php") || strings.Contains(detail.Body, "PRIVATE") {
		t.Fatal("public projection digest failed verification after restore", detail, e)
	}
	// No raw delivery configuration is introduced by backup quarantine or GET.
	public, _ := json.Marshal(detail)
	if strings.Contains(string(public), "PRIVATE") {
		t.Fatal("restored public detail leaked original provider fields")
	}
}

func TestNotificationTestHousekeepingRetainsActiveYoungAndMigrationProtectedJobs(t *testing.T) {
	f := newNotificationTestFixture(t)
	ctx := context.Background()
	f.worker.Sender = &notificationTestSender{}
	old := f.submit(t, f.preview(t, "email"))
	for i := 0; i < 2; i++ {
		if e := f.worker.RunRound(ctx); e != nil {
			t.Fatal(e)
		}
	}
	young := f.submit(t, f.preview(t, "feishu"))
	if e := f.worker.RunRound(ctx); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_notification_test_cooldowns SET next_allowed_at='epoch' WHERE channel='email'`)
	active := f.submit(t, f.preview(t, "email"))
	expired := f.preview(t, "email")
	mustHistoryExec(t, f.s.DB, `UPDATE v3_notification_test_jobs SET created_at=clock_timestamp()-interval '40 days',updated_at=clock_timestamp()-interval '31 days',finished_at=clock_timestamp()-interval '31 days' WHERE id=$1`, old.ID)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_notification_test_jobs SET created_at=clock_timestamp()-interval '40 days',expires_at=clock_timestamp()-interval '39 days' WHERE id=$1`, active.ID)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_notification_test_previews SET created_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1`, digest([]byte(expired.Token)))
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_migration_domains(domain,source,pending) VALUES('settings',repeat('a',64),true)`)
	if e := f.s.Housekeeping(ctx, "notification-cleaner"); e != nil {
		t.Fatal(e)
	}
	if tableCount(t, f.s, "v3_notification_test_jobs") != 3 {
		t.Fatal("housekeeping removed migration protected jobs")
	}
	var exists bool
	if e := f.s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM v3_notification_test_previews WHERE id=$1)`, digest([]byte(expired.Token))).Scan(&exists); e != nil || !exists {
		t.Fatal("housekeeping removed migration protected preview", e)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_migration_domains SET pending=false`)
	if e := f.s.Housekeeping(ctx, "notification-cleaner"); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{active.ID, young.ID} {
		if _, e := f.s.notificationTestJob(ctx, "admin", id); e != nil {
			t.Fatal("housekeeping removed active or young terminal job", e)
		}
	}
	var oldExists, deliveryExists, expiredExists bool
	if e := f.s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM v3_notification_test_jobs WHERE id=$1),EXISTS(SELECT 1 FROM v3_notification_test_deliveries WHERE job=$1),EXISTS(SELECT 1 FROM v3_notification_test_previews WHERE id=$2)`, old.ID, digest([]byte(expired.Token))).Scan(&oldExists, &deliveryExists, &expiredExists); e != nil || oldExists || deliveryExists || expiredExists {
		t.Fatal("terminal expiration or cascading delivery cleanup failed", oldExists, deliveryExists, expiredExists, e)
	}
	if tableCount(t, f.s, "v3_notification_test_jobs") != 2 {
		t.Fatal("unexpected cleanup scope")
	}
}
