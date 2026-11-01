package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"webscan/internal/common"
)

type notificationTestFixture struct {
	s         *Store
	vault     *Vault
	vaultPath string
	worker    *NotificationTestWorker
}

func newNotificationTestFixture(t *testing.T) notificationTestFixture {
	t.Helper()
	s := testStore(t)
	v, path := testVault(t)
	if err := s.Provision(context.Background(), "admin", "isolated-notification-password"); err != nil {
		t.Fatal(err)
	}
	settings := common.Map{"email": common.Map{"enabled": true, "smtp_host": "smtp.example.test", "smtp_port": 465, "tls_mode": "tls", "username": "sender@example.test", "password": "PRIVATE-notification-fixture", "from_address": "sender@example.test", "recipients": []string{"one@example.test", "two@example.test"}, "timeout_seconds": 2, "max_per_minute": 600, "retry": common.Map{"initial_delay_seconds": 1, "max_delay_seconds": 10}}, "feishu": common.Map{"enabled": true, "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/isolated-test-not-a-real-token", "rate_limit": common.Map{"max_per_minute": 600, "max_per_second": 10000}}}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=1,payload=$1`, common.JSON(settings))
	return notificationTestFixture{s: s, vault: v, vaultPath: path, worker: &NotificationTestWorker{Store: s, Vault: v, Instance: "test-worker"}}
}
func (f notificationTestFixture) preview(t *testing.T, channel string) notificationTestPreview {
	t.Helper()
	p, e := f.s.previewNotificationTest(context.Background(), f.vault, "admin", "preview-"+token(), channel, 1)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func (f notificationTestFixture) submit(t *testing.T, p notificationTestPreview) notificationTestJob {
	t.Helper()
	raw, e := f.s.submitNotificationTest(context.Background(), f.vault, "admin", "confirm-"+token(), p.Token, true)
	if e != nil {
		t.Fatal(e)
	}
	var j notificationTestJob
	if json.Unmarshal(raw, &j) != nil {
		t.Fatal("invalid job")
	}
	return j
}
func (f notificationTestFixture) job(t *testing.T, id string) notificationTestJob {
	t.Helper()
	j, e := f.s.notificationTestJob(context.Background(), "admin", id)
	if e != nil {
		t.Fatal(e)
	}
	return j
}
func TestNotificationTestPreviewBindsAppliedRuntimeAndIdempotentConfirmation(t *testing.T) {
	f := newNotificationTestFixture(t)
	ctx := context.Background()
	p, e := f.s.previewNotificationTest(ctx, f.vault, "admin", "one-preview", "email", 1)
	if e != nil {
		t.Fatal(e)
	}
	repeat, e := f.s.previewNotificationTest(ctx, f.vault, "admin", "one-preview", "email", 1)
	if e != nil || repeat.Token != p.Token {
		t.Fatal("preview replay", e)
	}
	// A saved draft affects only the next configuration, not current delivery.
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_settings_drafts(id,runtime_version,runtime_digest,payload,proof) VALUES(1,1,'isolated-draft','{"email":{"enabled":false}}','isolated-draft')`)
	raw, e := f.s.submitNotificationTest(ctx, f.vault, "admin", "one-confirm", p.Token, true)
	if e != nil {
		t.Fatal("saved draft invalidated runtime preview", e)
	}
	repeated, e := f.s.submitNotificationTest(ctx, f.vault, "admin", "one-confirm", p.Token, true)
	var original, replay any
	_ = json.Unmarshal(raw, &original)
	_ = json.Unmarshal(repeated, &replay)
	if e != nil || !reflect.DeepEqual(original, replay) {
		t.Fatal("confirm replay", e)
	}
	var j notificationTestJob
	_ = json.Unmarshal(raw, &j)
	if j.Status != "queued" || len(j.Items) != 2 || j.Items[0].State != "queued" {
		t.Fatal("creation falsely completed", j)
	}
	if _, e = f.s.submitNotificationTest(ctx, f.vault, "admin", "different-confirm", p.Token, true); !errors.Is(e, errNotificationTestPreview) {
		t.Fatal("preview reusable", e)
	}
	if _, e = f.s.previewNotificationTest(ctx, f.vault, "admin", "one-preview", "feishu", 1); !errors.Is(e, ErrRequestConflict) {
		t.Fatal("idempotency conflict", e)
	}
	var audit, stored string
	if e = f.s.DB.QueryRow(`SELECT COALESCE(string_agg(result::text,''),'') FROM v3_audit`).Scan(&audit); e != nil {
		t.Fatal(e)
	}
	if e = f.s.DB.QueryRow(`SELECT row_to_json(j)::text||COALESCE((SELECT string_agg(row_to_json(p)::text,'') FROM v3_notification_test_previews p),'') FROM v3_notification_test_jobs j LIMIT 1`).Scan(&stored); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{p.Token, "PRIVATE-notification-fixture", "smtp.example.test", "open.feishu.cn"} {
		if strings.Contains(audit, secret) || strings.Contains(stored, secret) {
			t.Fatal("secret escaped into test persistence")
		}
	}
	if f.job(t, j.ID).ID != j.ID {
		t.Fatal("job missing")
	}
}
func TestNotificationTestPreviewRejectsAuthorizationChanges(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{{"runtime", `UPDATE v3_settings SET version=version+1`}, {"disabled-channel", `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,enabled}','false')`}, {"payload", `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,password}','"changed-private-value"')`}, {"account", `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`}, {"targets", `UPDATE v3_notification_test_previews SET targets='["third@example.test"]'`}, {"proof", `UPDATE v3_notification_test_previews SET proof=repeat('0',64)`}, {"expired", `UPDATE v3_notification_test_previews SET created_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '1 second'`}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNotificationTestFixture(t)
			p := f.preview(t, "email")
			mustHistoryExec(t, f.s.DB, tc.sql)
			if _, e := f.s.submitNotificationTest(context.Background(), f.vault, "admin", "changed-confirm", p.Token, true); !errors.Is(e, errNotificationTestPreview) {
				t.Fatal("changed authorization accepted", e)
			}
			if tableCount(t, f.s, "v3_notification_test_jobs") != 0 || tableCount(t, f.s, "v3_notification_test_cooldowns") != 0 {
				t.Fatal("rejected preview changed queue/cooldown")
			}
		})
	}
}
func TestNotificationTestAppliedChannelsAndTargetsAreValidated(t *testing.T) {
	for _, tc := range []struct{ name, sql string }{{"disabled", `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,enabled}','false')`}, {"invalid-address", `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,recipients}','["bad address"]')`}, {"oversized-address", `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,recipients}',jsonb_build_array(repeat('a',310)||'@example.test'))`}, {"empty", `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,recipients}','[]')`}, {"too-many", `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,recipients}',(SELECT jsonb_agg('a'||n||'@example.test') FROM generate_series(1,21) n))`}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNotificationTestFixture(t)
			mustHistoryExec(t, f.s.DB, tc.sql)
			if _, e := f.s.previewNotificationTest(context.Background(), f.vault, "admin", "bad-preview", "email", 1); !errors.Is(e, errNotificationTestInput) {
				t.Fatal("invalid targets accepted", e)
			}
		})
	}
	f := newNotificationTestFixture(t)
	p := f.preview(t, "feishu")
	if len(p.Recipients) != 1 || p.Recipients[0] != "已应用的飞书机器人" || strings.Contains(string(common.JSON(p)), "open.feishu.cn") {
		t.Fatal("webhook shown in preview")
	}
	if _, e := f.s.previewNotificationTest(context.Background(), nil, "admin", "missing-key", "email", 1); !errors.Is(e, errNotificationTestUnavailable) {
		t.Fatal("missing key accepted", e)
	}
}
func TestNotificationTestCooldownIsGlobalConcurrentAndPerChannel(t *testing.T) {
	f := newNotificationTestFixture(t)
	ctx := context.Background()
	if e := f.s.Provision(ctx, "other", "isolated-other-password"); e != nil {
		t.Fatal(e)
	}
	p := f.preview(t, "email")
	other, e := f.s.previewNotificationTest(ctx, f.vault, "other", "other-preview", "email", 1)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, rate := 0, 0
	for i, attempt := range []struct{ user, capability string }{{"admin", p.Token}, {"other", other.Token}} {
		wg.Add(1)
		go func(i int, user, capability string) {
			defer wg.Done()
			_, e := f.s.submitNotificationTest(ctx, f.vault, user, fmt.Sprintf("concurrent-confirm-%d", i), capability, true)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				success++
			} else if errors.Is(e, errNotificationTestRate) {
				rate++
			} else {
				t.Error(e)
			}
		}(i, attempt.user, attempt.capability)
	}
	wg.Wait()
	if success != 1 || rate != 1 {
		t.Fatal("cooldown not serialized", success, rate)
	}
	f.submit(t, f.preview(t, "feishu"))
}

func TestNotificationTestFailedCreationDoesNotConsumeAuthorizationOrCooldown(t *testing.T) {
	f := newNotificationTestFixture(t)
	p := f.preview(t, "email")
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_test_job() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated transaction failure';END$$;CREATE TRIGGER reject_test_job BEFORE INSERT ON v3_notification_test_jobs FOR EACH ROW EXECUTE FUNCTION reject_test_job()`)
	if _, e := f.s.submitNotificationTest(context.Background(), f.vault, "admin", "failed-confirm", p.Token, true); e == nil {
		t.Fatal("injected failure ignored")
	}
	var used bool
	if e := f.s.DB.QueryRow(`SELECT used FROM v3_notification_test_previews WHERE id=$1`, digest([]byte(p.Token))).Scan(&used); e != nil || used {
		t.Fatal("failed transaction consumed preview", e)
	}
	if tableCount(t, f.s, "v3_notification_test_cooldowns") != 0 || tableCount(t, f.s, "v3_notification_test_jobs") != 0 {
		t.Fatal("failed transaction consumed cooldown or queue")
	}
	mustHistoryExec(t, f.s.DB, `DROP TRIGGER reject_test_job ON v3_notification_test_jobs;DROP FUNCTION reject_test_job()`)
	f.submit(t, p)
}
func TestNotificationTestConcurrentIdempotentConfirmationCreatesOneJob(t *testing.T) {
	f := newNotificationTestFixture(t)
	p := f.preview(t, "email")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := []string{}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, e := f.s.submitNotificationTest(context.Background(), f.vault, "admin", "same-confirm", p.Token, true)
			if e != nil {
				t.Error(e)
				return
			}
			var j notificationTestJob
			if e = json.Unmarshal(raw, &j); e != nil {
				t.Error(e)
				return
			}
			mu.Lock()
			ids = append(ids, j.ID)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(ids) != 4 || tableCount(t, f.s, "v3_notification_test_jobs") != 1 {
		t.Fatal("duplicate confirmation created jobs", len(ids))
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Fatal("inconsistent idempotent receipt")
		}
	}
}
