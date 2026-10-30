package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

func flushWebsiteFixture(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	mustHistoryExec(t, s.DB, "UPDATE v3_website_outbox SET created=LEAST(created,floor(extract(epoch FROM clock_timestamp()))::bigint-60) WHERE done_at IS NULL")
	l, err := s.Acquire(ctx, "website-flush", "fixture-flush")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FlushWebsiteNotices(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err = s.Release(ctx, l); err != nil {
		t.Fatal(err)
	}
}
func websiteSettingsFixture(t *testing.T, s *Store) {
	t.Helper()
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"notifications":{"health_failures":true,"health_recoveries":true}},"email":{"enabled":true,"recipients":["a@example.test"],"notifications":{"health_failures":true,"health_recoveries":true}},"website_monitor":{"console_url":"https://console.example.test"}}'`)
}
func seedWebsiteNotice(t *testing.T, s *Store, site int64, kind, msg string) {
	t.Helper()
	mustHistoryExec(t, s.DB, "INSERT INTO v3_website_outbox(site,node,kind,message,created) VALUES($1,'node-a',$2,$3,floor(extract(epoch FROM clock_timestamp()))::bigint-60)", site, kind, msg)
}
func TestWebsiteOutboxBatchingOrderRollbackAndTakeover(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	websiteSettingsFixture(t, s)
	a := savedSite(t, s, "outbox-a")
	b := savedSite(t, s, "outbox-b")
	for _, v := range []struct {
		site      int64
		kind, msg string
	}{{a.ID, "outage", "故障a"}, {b.ID, "outage", "故障b"}, {a.ID, "recovery", "恢复a"}, {a.ID, "outage", "再次故障a"}} {
		seedWebsiteNotice(t, s, v.site, v.kind, v.msg)
	}
	l, err := s.Acquire(ctx, "website-flush", "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_outbox_channel() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.channel='email' THEN RAISE EXCEPTION 'fixture'; END IF; RETURN NEW; END$$;CREATE TRIGGER fail_outbox_channel BEFORE INSERT ON v3_notifications FOR EACH ROW EXECUTE FUNCTION fail_outbox_channel()`)
	if err = s.FlushWebsiteNotices(ctx, l); err == nil || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("partial admission", err)
	}
	var done int
	_ = s.DB.QueryRow("SELECT count(*) FROM v3_website_outbox WHERE done_at IS NOT NULL").Scan(&done)
	if done != 0 {
		t.Fatal(done)
	}
	mustHistoryExec(t, s.DB, "DROP TRIGGER fail_outbox_channel ON v3_notifications")
	mustHistoryExec(t, s.DB, "UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource='website-flush'")
	next, err := s.Acquire(ctx, "website-flush", "worker-b")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FlushWebsiteNotices(ctx, l); !errors.Is(err, ErrLeaseLost) {
		t.Fatal(err)
	}
	if err = s.FlushWebsiteNotices(ctx, next); err != nil {
		t.Fatal(err)
	}
	if err = s.FlushWebsiteNotices(ctx, next); err != nil || tableCount(t, s, "v3_notifications") != 8 {
		t.Fatal(err, tableCount(t, s, "v3_notifications"))
	}
	rows, err := s.DB.Query("SELECT payload->>'message',event_id FROM v3_notifications WHERE channel='feishu' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := []string{}
	for rows.Next() {
		var message, event string
		if err = rows.Scan(&message, &event); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(event, "website-v3:") {
			t.Fatal(event)
		}
		got = append(got, message)
	}
	if strings.Join(got, "|") != "故障a|故障b|恢复a|再次故障a" {
		t.Fatal(got)
	}
}
func TestWebsiteOutboxBudgetPauseSummaryAndClockOrder(t *testing.T) {
	s := testStore(t)
	websiteSettingsFixture(t, s)
	ctx := context.Background()
	for i := 0; i < 503; i++ {
		site := savedSite(t, s, fmt.Sprintf("batch-%03d", i))
		seedWebsiteNotice(t, s, site.ID, "outage", "故障")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{monitoring}','{"notifications_paused":true}')`)
	flushWebsiteFixture(t, s)
	if tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("pause ignored")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{monitoring,notifications_paused}','false')`)
	flushWebsiteFixture(t, s)
	var done int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_website_outbox WHERE done_at IS NOT NULL").Scan(&done); err != nil || done != 500 || tableCount(t, s, "v3_notifications") != 2 {
		t.Fatal(done, err)
	}
	var message string
	_ = s.DB.QueryRow("SELECT payload->>'message' FROM v3_notifications LIMIT 1").Scan(&message)
	if !strings.Contains(message, "共 500 个网站") {
		t.Fatal(message)
	}
	flushWebsiteFixture(t, s)
	if tableCount(t, s, "v3_notifications") != 8 {
		t.Fatal("remainder lost")
	}
	a := savedSite(t, s, "clock-a")
	b := savedSite(t, s, "clock-b")
	seedWebsiteNotice(t, s, a.ID, "outage", "较晚时钟的故障")
	mustHistoryExec(t, s.DB, "UPDATE v3_website_outbox SET created=floor(extract(epoch FROM clock_timestamp()))::bigint+3600 WHERE site=$1", a.ID)
	seedWebsiteNotice(t, s, a.ID, "recovery", "较早时钟的恢复")
	seedWebsiteNotice(t, s, b.ID, "outage", "其他网站")
	l, err := s.Acquire(ctx, "website-flush", "clock")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FlushWebsiteNotices(ctx, l); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_notifications") != 10 {
		t.Fatal("clock issue blocked other site or overtook failure")
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_website_outbox SET created=floor(extract(epoch FROM clock_timestamp()))::bigint-30 WHERE site=$1 AND kind='outage'", a.ID)
	if err = s.FlushWebsiteNotices(ctx, l); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.Query("SELECT payload FROM v3_notifications WHERE payload->>'message' LIKE '较%' AND channel='feishu' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := []string{}
	for rows.Next() {
		var raw []byte
		_ = rows.Scan(&raw)
		var p common.Map
		_ = json.Unmarshal(raw, &p)
		got = append(got, common.S(p["notice_kind"]))
	}
	if strings.Join(got, ",") != "outage,recovery" {
		t.Fatal(got)
	}
}

func TestWebsiteOutboxTimeWindowDisabledChannelsAndSoftDelete(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	websiteSettingsFixture(t, s)
	site := savedSite(t, s, "window-site")
	seedWebsiteNotice(t, s, site.ID, "outage", "待发送")
	mustHistoryExec(t, s.DB, "UPDATE v3_website_outbox SET created=floor(extract(epoch FROM clock_timestamp()))::bigint")
	l, err := s.Acquire(ctx, "website-flush", "window")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FlushWebsiteNotices(ctx, l); err != nil || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("ignored window", err)
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_website_outbox SET created=created-60")
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(jsonb_set(payload,'{feishu,enabled}','false'),'{email,enabled}','false')`)
	if err = s.FlushWebsiteNotices(ctx, l); err != nil || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("discarded disabled channel backlog", err)
	}
	if _, err = s.DeleteSites(ctx, "admin", "delete-before-flush", []SiteVersion{{site.ID, site.Version}}); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,enabled}','true')`)
	if err = s.FlushWebsiteNotices(ctx, l); err != nil || tableCount(t, s, "v3_notifications") != 1 {
		t.Fatal("lost notice after soft delete", err)
	}
	var channel string
	_ = s.DB.QueryRow("SELECT channel FROM v3_notifications").Scan(&channel)
	if channel != "email" {
		t.Fatal(channel)
	}
}

func TestWebsiteOutboxByteBudgetDoesNotDropRemainder(t *testing.T) {
	s := testStore(t)
	websiteSettingsFixture(t, s)
	for i := 0; i < 40; i++ {
		site := savedSite(t, s, fmt.Sprintf("bytes-%d", i))
		seedWebsiteNotice(t, s, site.ID, "outage", strings.Repeat("x", 256<<10))
	}
	flushWebsiteFixture(t, s)
	var done int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_website_outbox WHERE done_at IS NOT NULL").Scan(&done); err != nil || done != 31 {
		t.Fatal(done, err)
	}
	flushWebsiteFixture(t, s)
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_website_outbox WHERE done_at IS NOT NULL").Scan(&done); err != nil || done != 40 || tableCount(t, s, "v3_notifications") != 4 {
		t.Fatal(done, err)
	}
}

func TestWebsiteOutboxSchema7UpgradeAndRestorePreserveFrozenImport(t *testing.T) {
	ctx := context.Background()
	s := emptyTestStore(t)
	for _, schema := range []string{Schema, websiteSchema, deploymentSchema, deploymentReadinessSchema, healthSchema, migrationSchema, eventHistorySchema} {
		mustHistoryExec(t, s.DB, schema)
	}
	source := strings.Repeat("a", 64)
	mustHistoryExec(t, s.DB, "INSERT INTO v3_domain_imports(source,domain,table_name,processed,imported,complete) VALUES($1,'websites','websites',1,1,true)", source)
	mustHistoryExec(t, s.DB, "INSERT INTO v3_websites(id,name,url,migration_pending) VALUES(1,'旧映射','https://old.example.test',true)")
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema7 upgraded without backup")
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	var bound string
	var pending bool
	if err := s.DB.QueryRow("SELECT source,pending FROM v3_migration_domains WHERE domain='websites'").Scan(&bound, &pending); err != nil || bound != source || !pending {
		t.Fatal(bound, pending, err)
	}
	mustHistoryExec(t, s.DB, "INSERT INTO v3_website_outbox(site,node,kind,message,created,migration_source) VALUES(1,'','outage','原消息',$1,$2)", time.Now().Unix()-60, source)
	backup, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, restored, "v3_website_outbox") != 1 || tableCount(t, restored, "v3_migration_domains") != 1 {
		t.Fatal("lost pending data")
	}
	l, err := restored.Acquire(ctx, "website-flush", "after-restore")
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.FlushWebsiteNotices(ctx, l); err != nil || tableCount(t, restored, "v3_notifications") != 0 {
		t.Fatal(err)
	}
	if err = restored.Provision(ctx, "new-admin", "fixture-password-123"); !errors.Is(err, ErrMigrationPending) {
		t.Fatal("provision modified frozen accounts", err)
	}
}

func TestWebsiteOutboxNotifierAutomaticallyFlushesAndIsolatesChannels(t *testing.T) {
	s := testStore(t)
	websiteSettingsFixture(t, s)
	site := savedSite(t, s, "worker-outbox")
	seedWebsiteNotice(t, s, site.ID, "outage", "真实出箱链路，发送器为替身")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	done := make(chan error, 1)
	n := &Notifier{Store: s, Instance: "outbox-notifier", Sender: fakeNotificationSender{}}
	go func() { done <- n.Run(ctx) }()
	defer func() { cancel(); <-done }()
	for ctx.Err() == nil {
		var completed, retried int
		if err := s.DB.QueryRow("SELECT count(*) FILTER(WHERE channel='email' AND done_at IS NOT NULL),count(*) FILTER(WHERE channel='feishu' AND attempts>0 AND done_at IS NULL) FROM v3_notifications").Scan(&completed, &retried); err != nil {
			t.Fatal(err)
		}
		if completed == 1 && retried == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("website outbox did not reach independent senders", ctx.Err())
}

func TestWebsiteOutboxOverviewDistinguishesUnknownAndPending(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	site := savedSite(t, s, "summary-outbox")
	seedWebsiteNotice(t, s, site.ID, "outage", "等待")
	raw, err := s.WebsiteSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Outbox struct {
			Pending int    `json:"pending"`
			Oldest  *int64 `json:"oldest_wait_seconds"`
		} `json:"notification_outbox"`
		Worker struct {
			Healthy *bool `json:"healthy"`
		} `json:"notification_worker"`
	}
	if err = json.Unmarshal(raw, &v); err != nil || v.Outbox.Pending != 1 || v.Outbox.Oldest == nil || *v.Outbox.Oldest < 60 || v.Worker.Healthy != nil {
		t.Fatal(string(raw), err)
	}
	websiteSettingsFixture(t, s)
	flushWebsiteFixture(t, s)
	raw, err = s.WebsiteSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &v); err != nil || v.Outbox.Pending != 0 || v.Outbox.Oldest != nil {
		t.Fatal(string(raw), err)
	}
}

func TestWebsiteOutboxPolicyCannotChangeHalfwayThroughAdmission(t *testing.T) {
	s := testStore(t)
	websiteSettingsFixture(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	site := savedSite(t, s, "policy-outbox")
	seedWebsiteNotice(t, s, site.ID, "outage", "固定策略")
	gate, err := s.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if _, err = gate.ExecContext(ctx, "SELECT pg_advisory_lock(773376009)"); err != nil {
		t.Fatal(err)
	}
	defer gate.ExecContext(context.Background(), "SELECT pg_advisory_unlock(773376009)")
	mustHistoryExec(t, s.DB, `CREATE FUNCTION wait_website_policy() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(773376009); RETURN NEW; END$$;CREATE TRIGGER wait_website_policy BEFORE INSERT ON v3_notifications FOR EACH ROW EXECUTE FUNCTION wait_website_policy()`)
	l, err := s.Acquire(ctx, "website-flush", "policy")
	if err != nil {
		t.Fatal(err)
	}
	flushed := make(chan error, 1)
	go func() { flushed <- s.FlushWebsiteNotices(ctx, l) }()
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=773376009 AND NOT granted)").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	changed := make(chan error, 1)
	go func() {
		_, err := s.DB.ExecContext(ctx, `UPDATE v3_settings SET payload=jsonb_set(jsonb_set(payload,'{email,enabled}','false'),'{feishu,enabled}','false')`)
		changed <- err
	}()
	for {
		var waiting bool
		if err = s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE query LIKE 'UPDATE v3_settings SET payload=jsonb_set(jsonb_set%' AND wait_event_type='Lock')").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-changed:
			t.Fatal("policy changed during admission", err)
		default:
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = gate.ExecContext(ctx, "SELECT pg_advisory_unlock(773376009)"); err != nil {
		t.Fatal(err)
	}
	if err = <-flushed; err != nil {
		t.Fatal(err)
	}
	if err = <-changed; err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "v3_notifications") != 2 {
		t.Fatal("one channel lost to configuration race")
	}
}
