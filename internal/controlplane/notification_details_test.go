package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNotificationDetailsEvidenceAndAttemptsPagination(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	projectedNotificationFixture(t, s, 1, "event", `{"operation":"modify","path":"/srv/synthetic/detail.php","message":"PRIVATE"}`)
	projectedNotificationFixture(t, s, 2, "test", `{}`)
	projectedNotificationFixture(t, s, 3, "test", `{}`)
	mustHistoryExec(t, s.DB, `UPDATE v3_notifications SET done_at=clock_timestamp(),result='PRIVATE provider result' WHERE id=3`)
	d, err := s.NotificationDetail(ctx, "1")
	if err != nil || d.Outcome.Code != "pending" || !strings.Contains(d.Body, "detail.php") {
		t.Fatal("pending detail invalid", d, err)
	}
	if d, err = s.NotificationDetail(ctx, "3"); err != nil || d.Outcome.Code != "unknown" {
		t.Fatal("historical completion invented evidence", d, err)
	}
	now := time.Now().Add(-time.Minute).UTC()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notification_attempts(id,notification,epoch,success,result,created_at) VALUES(9007199254740993,1,9007199254740995,true,'PRIVATE accepted response',$1),(9007199254740994,1,9007199254740996,false,'PRIVATE error response',$2)`, now, now.Add(time.Second))
	d, err = s.NotificationDetail(ctx, "1")
	if err != nil || d.Outcome.Code != "unknown" || !strings.Contains(d.Outcome.Message, "可能已经投递") {
		t.Fatal("false sender result treated as definite rejection", d, err)
	}
	page, err := s.NotificationAttempts(ctx, "1", notificationCursor{}, 1)
	if err != nil || len(page) != 1 || page[0].ID != "9007199254740994" || page[0].Epoch != "9007199254740996" || page[0].Outcome != "unknown" || page[0].Success {
		t.Fatal("latest attempt or decimal identity lost", page, err)
	}
	page, err = s.NotificationAttempts(ctx, "1", notificationCursor{page[0].Created, page[0].ID}, 1)
	if err != nil || len(page) != 1 || page[0].ID != "9007199254740993" || page[0].Epoch != "9007199254740995" || page[0].Outcome != "accepted" || !page[0].Success {
		t.Fatal("attempt cursor failed", page, err)
	}
	encoded, _ := json.Marshal(struct {
		Detail   NotificationDetail
		Attempts []NotificationAttempt
	}{d, page})
	if strings.Contains(string(encoded), "PRIVATE") || strings.Contains(string(encoded), "payload") || strings.Contains(string(encoded), `"result"`) {
		t.Fatal("private transport content escaped", string(encoded))
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_notification_attempts(notification,epoch,success,result) VALUES(2,1,true,'PRIVATE')`)
	if d, err = s.NotificationDetail(ctx, "2"); err != nil || d.Outcome.Code != "accepted" {
		t.Fatal("accepted evidence missing", d, err)
	}
	if _, err = s.NotificationDetail(ctx, "99"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("missing notification accepted", err)
	}
	for _, id := range []string{"", "0", "-1", "01", "+1", "9223372036854775808"} {
		if _, err = s.NotificationDetail(ctx, id); err != ErrHistoryInput {
			t.Fatal("invalid ID accepted", id, err)
		}
	}
	for _, limit := range []int{0, 101} {
		if _, err = s.NotificationAttempts(ctx, "1", notificationCursor{}, limit); err != ErrHistoryInput {
			t.Fatal("invalid attempt limit accepted", limit, err)
		}
	}
}

func TestNotificationDetailRoutesReadOnlyViewerAndSafeErrors(t *testing.T) {
	s := testStore(t)
	projectedNotificationFixture(t, s, 9007199254740993, "test", `{"message":"PRIVATE"}`)
	viewer := historyAPISession(t, s, "notification-reader", "viewer")
	api := &API{Store: s}
	call := func(path, session string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/v3/notifications/9007199254740993", "/api/v3/notifications/9007199254740993/attempts"} {
		if w := call(path, ""); w.Code != 401 {
			t.Fatal("anonymous read accepted", w.Code)
		}
		if w := call(path, viewer); w.Code != 200 || strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal("viewer detail unavailable or private", w.Code, w.Body.String())
		}
	}
	if w := call("/api/v3/notifications/stats?channel=email", viewer); w.Code != 200 {
		t.Fatal("details shadowed notification statistics", w.Code, w.Body.String())
	}
	for path, code := range map[string]int{
		"/api/v3/notifications/01":                                   400,
		"/api/v3/notifications/99":                                   404,
		"/api/v3/notifications/99/attempts":                          404,
		"/api/v3/notifications/9007199254740993/attempts?limit=101":  400,
		"/api/v3/notifications/9007199254740993/attempts?cursor=bad": 400,
		"/api/v3/notifications/9007199254740993/raw":                 404,
	} {
		if w := call(path, viewer); w.Code != code {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	if !api.notificationDetailRoutes(w, httptest.NewRequest("POST", "/api/v3/notifications/9007199254740993", nil)) || w.Code != 405 {
		t.Fatal("detail handler accepted mutation", w.Code)
	}
}
