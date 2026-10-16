package website

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func TestPersistentSessionAcrossProcessStateAndRevocation(t *testing.T) {
	m := testMonitor(t)
	login := request(m, "POST", "/api/login", `{"username":"admin","password":"fixture-password"}`, nil, "")
	if login.Code != 200 {
		t.Fatal(login.Code, login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	var csrf string
	var expires int64
	if e := m.DB.QueryRow("SELECT csrf,expires FROM website_sessions WHERE token_hash=?", tokenHash(cookie.Value)).Scan(&csrf, &expires); e != nil {
		t.Fatal(e)
	}
	var raw int
	m.DB.QueryRow("SELECT count(*) FROM website_sessions WHERE token_hash=?", cookie.Value).Scan(&raw)
	if raw != 0 {
		t.Fatal("raw cookie stored")
	}
	var seq int
	var name, path string
	m.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path)
	db, e := persist.OpenDB(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	restarted, e := New(db, m.Config, m.Nodes, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	if w := request(restarted, "GET", "/api/session", "", cookie, ""); w.Code != 200 {
		t.Fatal("login lost across restart", w.Code)
	}
	var unchanged int64
	db.QueryRow("SELECT expires FROM website_sessions").Scan(&unchanged)
	if unchanged != expires {
		t.Fatal("restart renewed expiry")
	}
	if w := request(restarted, "POST", "/api/logout", "{}", cookie, csrf); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(m, "GET", "/api/session", "", cookie, ""); w.Code != 401 {
		t.Fatal("logout not durable", w.Code)
	}
	a, _ := ReadAccount(db)
	for i := 0; i < 2; i++ {
		if ok, e := m.storeSession(context.Background(), fmt.Sprint(i), session{Revision: a.Revision, CSRF: "c", Expires: time.Now().Add(sessionLifetime)}); e != nil || !ok {
			t.Fatal(e)
		}
	}
	if e := ResetPassword(db, "new-fixture-password"); e != nil {
		t.Fatal(e)
	}
	var count int
	db.QueryRow("SELECT count(*) FROM website_sessions").Scan(&count)
	if count != 0 {
		t.Fatal("reset did not revoke all")
	}
	if ok, e := m.storeSession(context.Background(), "stale-login", session{Revision: a.Revision, CSRF: "c", Expires: time.Now().Add(sessionLifetime)}); e != nil || ok {
		t.Fatal("login race after password reset", ok, e)
	}
}
func TestSessionCapacityExpiryAndDatabaseFailure(t *testing.T) {
	m := testMonitor(t)
	a, _ := ReadAccount(m.DB)
	ctx := context.Background()
	for i := 0; i < 101; i++ {
		if ok, e := m.storeSession(ctx, fmt.Sprintf("%03d", i), session{Revision: a.Revision, CSRF: "csrf", Expires: time.Now().Add(sessionLifetime + time.Duration(i)*time.Second)}); e != nil || !ok {
			t.Fatal(e)
		}
	}
	var count int
	m.DB.QueryRow("SELECT count(*) FROM website_sessions").Scan(&count)
	if count != 100 {
		t.Fatal(count)
	}
	if _, e := m.readSession(ctx, "000"); e != sql.ErrNoRows {
		t.Fatal("oldest session retained", e)
	}
	m.DB.Exec("UPDATE website_sessions SET expires=0 WHERE token_hash='001'")
	if _, e := m.readSession(ctx, "001"); e != sql.ErrNoRows {
		t.Fatal("expired session authenticated", e)
	}
	m.DB.Close()
	w := request(m, "GET", "/api/session", "", &http.Cookie{Name: "webscan_session", Value: "fixture"}, "")
	if w.Code != 500 {
		t.Fatal("DB failure misclassified as logout", w.Code)
	}
}
func TestSessionMigrationBackupFailureStopsSchemaChange(t *testing.T) {
	m := testMonitor(t)
	insertSite(t, m, "preserved")
	m.DB.Exec("DROP TABLE website_sessions")
	blocker := filepath.Join(t.TempDir(), "not-directory")
	if e := common.Atomic(blocker, []byte("block"), 0600); e != nil {
		t.Fatal(e)
	}
	settings := common.Clone(m.Settings())
	settings["backup_dir"] = blocker
	m.settings.Store(&settings)
	if e := m.migrate(); e == nil {
		t.Fatal("migration proceeded without backup")
	}
	var count int
	m.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='website_sessions'").Scan(&count)
	if count != 0 {
		t.Fatal("schema changed")
	}
}

func TestPasswordAndSessionRevocationCommitAtomically(t *testing.T) {
	m := testMonitor(t)
	a, _ := ReadAccount(m.DB)
	m.storeSession(context.Background(), "fixture", session{Revision: a.Revision, CSRF: "c", Expires: time.Now().Add(sessionLifetime)})
	m.DB.Exec(`CREATE TRIGGER simulate_disk_failure BEFORE DELETE ON website_sessions BEGIN SELECT RAISE(ABORT,'fixture disk full'); END`)
	if _, e := replacePassword(context.Background(), m.DB, "replacement-hash", &a.Revision); e == nil {
		t.Fatal("failed revocation committed password")
	}
	current, _ := ReadAccount(m.DB)
	if current.Hash != a.Hash || current.Revision != a.Revision {
		t.Fatal("partial password commit")
	}
	if _, e := m.readSession(context.Background(), "fixture"); e != nil {
		t.Fatal("failed update revoked existing session", e)
	}
}
