package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNotificationPublicWhitelistedBusinessProjection(t *testing.T) {
	for _, tc := range []struct{ source, raw, want string }{
		{"event", `{"source":"website","operation":"modify","path":"/srv/synthetic/file.php","time":"2026-11-01T10:00:00+08:00","scan":{"status":"matched","risk":"high","result":"PRIVATE"},"message":"PRIVATE","reason":"PRIVATE","result":"PRIVATE","password":"PRIVATE"}`, "风险：高"},
		{"event", `{"operation":"health","risk":"warning","scan":{"status":"not_applicable"},"reason":"PRIVATE"}`, "风险：警告"},
		{"server_health", `{"phase":"firing","kind":"cpu","members":[{"message":"PRIVATE"},{"reason":"PRIVATE"}],"message":"PRIVATE"}`, "涉及告警：2 项"},
		{"website", `{"notice_kind":"slow","site_ids":[1,2],"message":"PRIVATE","url":"PRIVATE"}`, "涉及网站：2 个"},
		{"test", `{"source":"legacy","message":"PRIVATE","token":"PRIVATE"}`, "管理员发起"},
	} {
		p := renderNotificationPublic([]byte(tc.raw), tc.source)
		if p.Source != tc.source || p.State != "available" || !strings.Contains(p.Body, tc.want) || strings.Contains(p.Body+p.Subject+p.Summary, "PRIVATE") {
			t.Fatal("unsafe or incomplete projection", tc.source, p)
		}
	}
	for _, source := range []string{"legacy", "unknown"} {
		p := renderNotificationPublic([]byte(`{"operation":"modify","path":"PRIVATE","source":"event"}`), source)
		if p.State != "unsupported" || p.Body != "" || p.Reason == "" || strings.Contains(p.Summary, "PRIVATE") {
			t.Fatal("untrusted provenance rendered", source, p)
		}
	}
	for _, raw := range []string{"null", "[]", "broken"} {
		if p := renderNotificationPublic([]byte(raw), "event"); p.State != "unsupported" || p.Body != "" {
			t.Fatal("unsupported shape rendered", raw, p)
		}
	}
	p := renderNotificationPublic([]byte(`{"operation":"PRIVATE","scan":{"status":"PRIVATE","risk":"PRIVATE"},"kind":"PRIVATE"}`), "event")
	if strings.Contains(p.Body, "PRIVATE") {
		t.Fatal("uncontrolled enumeration exposed", p)
	}
}

func TestNotificationPublicUTF8CapsAndControlCharacters(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"operation": "modify", "path": strings.Repeat("文", 20000) + "\x00\n\u202e\t", "old_path": "a\nb\t\x00\u202ec"})
	p := renderNotificationPublic(raw, "event")
	if !p.Truncated || len(p.Subject) > 1024 || len(p.Summary) > 4096 || len(p.Body) > 32768 || !utf8.ValidString(p.Body) || !utf8.ValidString(p.Summary) {
		t.Fatal("byte cap or UTF-8 lost")
	}
	clean, _ := notificationPublicText("a\nb\t\x00\u202ec\xff", 100)
	if clean != "abc" {
		t.Fatalf("control and invalid UTF-8 retained: %q", clean)
	}
	for limit := 1; limit <= 7; limit++ {
		s, truncated := notificationPublicLimit("文文文", limit)
		if !truncated || len(s) > limit || !utf8.ValidString(s) {
			t.Fatal("split UTF-8", limit, s)
		}
	}
}

func projectedNotificationFixture(t *testing.T, s *Store, id int64, source, raw string) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_notifications(id,node,event_id,channel,recipient,payload) VALUES($1::bigint,'node-a',($1::bigint)::text,'email','a@example.test',$2::jsonb)`, id, raw); err != nil {
		t.Fatal(err)
	}
	if err = projectNotificationTx(ctx, tx, id, source); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationPublicExactDigestImmutableProjectionAndSafeFallback(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	projectedNotificationFixture(t, s, 1, "event", `{"source":"website","operation":"modify","path":"/srv/synthetic/original.php","password":"PRIVATE"}`)
	var raw []byte
	var stored, source string
	if err := s.DB.QueryRow(`SELECT n.payload::text,p.payload_sha256,p.source FROM v3_notifications n JOIN v3_notification_public p ON p.notification=n.id WHERE n.id=1`).Scan(&raw, &stored, &source); err != nil || stored != digest(raw) || source != "event" {
		t.Fatal("exact PostgreSQL digest or trusted source lost", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = projectNotificationTx(ctx, tx, 1, "test"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var body string
	if err = s.DB.QueryRow(`SELECT source,body FROM v3_notification_public WHERE notification=1`).Scan(&source, &body); err != nil || source != "event" || !strings.Contains(body, "original.php") {
		t.Fatal("repeat call overwrote immutable projection", err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_notifications SET payload='{"operation":"create","path":"PRIVATE changed payload"}' WHERE id=1`)
	out, err := s.NotificationDetail(ctx, "1")
	if err != nil || out.Body != "" || out.Notification.ContentState != "unsupported" || out.Notification.Source != "unknown" || out.Notification.ContentReason == "" {
		t.Fatal("stale projection not revoked", out, err)
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notifications(id,node,event_id,channel,payload,migration_source) VALUES(2,'node-a','old','email','{"source":"event","path":"PRIVATE"}','legacy-source'),(3,'node-a','missing','email','{"source":"event","path":"PRIVATE"}','')`)
	for id, want := range map[string]string{"2": "legacy", "3": "unknown"} {
		out, err = s.NotificationDetail(ctx, id)
		if err != nil || out.Body != "" || out.Notification.Source != want || out.Notification.ContentState != "unsupported" {
			t.Fatal("missing projection rendered arbitrary payload", out, err)
		}
	}
	if err = projectNotificationTx(ctx, nil, 1, "event"); err != ErrHistoryInput {
		t.Fatal("nil transaction accepted", err)
	}
	tx, err = s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = projectNotificationTx(ctx, tx, 1, "spoofed"); err != ErrHistoryInput {
		t.Fatal("unknown provenance accepted", err)
	}
	if err = projectNotificationTx(ctx, tx, 99, "event"); err != sql.ErrNoRows {
		t.Fatal("missing notice accepted", err)
	}
}
