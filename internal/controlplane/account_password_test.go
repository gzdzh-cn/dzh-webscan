package controlplane

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const ownPasswordOld = "synthetic-old-password"
const ownPasswordNew = "synthetic-new-password"

func TestOwnPasswordDecodeBoundsAndAmbiguity(t *testing.T) {
	valid := func(current, next, confirm string) string {
		raw, err := json.Marshal(map[string]string{"current_password": current, "new_password": next, "confirm_password": confirm})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	for _, raw := range []string{valid(ownPasswordOld, ownPasswordNew, ownPasswordNew), valid("a", strings.Repeat("x", 72), strings.Repeat("x", 72)), valid("a", strings.Repeat("密", 24), strings.Repeat("密", 24))} {
		in, err := decodeOwnPassword(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(raw)))
		if err != nil || in.New == "" {
			t.Fatal("valid password rejected", err)
		}
		if strings.Contains(fmt.Sprintf("%v %#v", in, in), "synthetic") {
			t.Fatal("password formatter leaks")
		}
	}
	invalid := []string{
		`null`, `[]`, `{}`, `{"Current_Password":"a","new_password":"long-new-password","confirm_password":"long-new-password"}`,
		`{"current_password":"a","new_password":"long-new-password","confirm_password":"long-new-password","username":"another"}`,
		`{"current_password":"a","current_password":"b","new_password":"long-new-password","confirm_password":"long-new-password"}`,
		`{"current_password":null,"new_password":"long-new-password","confirm_password":"long-new-password"}`,
		`{"current_password":"a","new_password":null,"confirm_password":"long-new-password"}`,
		`{"current_password":"a","new_password":"long-new-password","confirm_password":null}`,
		`{"current_password":"a","new_password":"long-new-password","confirm_password":12}`,
		valid("", ownPasswordNew, ownPasswordNew), valid(strings.Repeat("x", 73), ownPasswordNew, ownPasswordNew),
		valid(ownPasswordOld, strings.Repeat("x", 11), strings.Repeat("x", 11)),
		valid(ownPasswordOld, strings.Repeat("x", 73), strings.Repeat("x", 73)),
		valid(ownPasswordOld, strings.Repeat("密", 25), strings.Repeat("密", 25)),
		valid(ownPasswordOld, ownPasswordNew, "different-password"),
		valid(ownPasswordOld, ownPasswordNew, ownPasswordNew) + " {}",
		strings.Repeat(" ", 4097) + "{}",
		"{\"current_password\":\"\xff\",\"new_password\":\"long-new-password\",\"confirm_password\":\"long-new-password\"}",
	}
	for n, raw := range invalid {
		if _, err := decodeOwnPassword(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(raw))); !errors.Is(err, errOwnPasswordInput) {
			t.Fatalf("ambiguous or invalid body %d accepted", n)
		}
	}
}

type ownPasswordFixture struct {
	s     *Store
	a     *API
	id    identity
	clear string
}

func newOwnPasswordFixture(t *testing.T, role string) ownPasswordFixture {
	t.Helper()
	s := testStore(t)
	ctx := context.Background()
	if err := s.Provision(ctx, "member", ownPasswordOld); err != nil {
		t.Fatal(err)
	}
	if err := s.Provision(ctx, "other", "synthetic-other-password"); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, "UPDATE v3_accounts SET role=$1 WHERE username='member'", role)
	cleartext := token()
	id := identity{Username: "member", Role: role, Hash: digest([]byte(cleartext)), CSRF: "own-password-csrf"}
	for _, session := range []struct{ hash, user, csrf string }{{id.Hash, "member", id.CSRF}, {digest([]byte(token())), "member", "second-csrf"}, {digest([]byte(token())), "other", "other-csrf"}} {
		mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,$2,1,$3,clock_timestamp()+interval '12 hours')`, session.hash, session.user, session.csrf)
	}
	var config Config
	config.Central.PublicURL = "https://password.example.test"
	return ownPasswordFixture{s: s, a: &API{Store: s, Config: config}, id: id, clear: cleartext}
}

func ownPasswordRequest(f ownPasswordFixture, current, next, confirm string, secure bool, csrf string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(map[string]string{"current_password": current, "new_password": next, "confirm_password": confirm})
	r := httptest.NewRequest("POST", "/api/v3/account/password", strings.NewReader(string(raw)))
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: f.clear})
	r.Header.Set("X-CSRF-Token", csrf)
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	f.a.ServeHTTP(w, r)
	return w
}

func assertOwnPasswordState(t *testing.T, f ownPasswordFixture, next bool) {
	t.Helper()
	var hash string
	var revision int
	if err := f.s.DB.QueryRow("SELECT password_hash,revision FROM v3_accounts WHERE username='member'").Scan(&hash, &revision); err != nil {
		t.Fatal(err)
	}
	password, expectedRevision, sessions := ownPasswordOld, 1, 2
	if next {
		password, expectedRevision, sessions = ownPasswordNew, 2, 0
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || revision != expectedRevision {
		t.Fatal("incorrect committed account state")
	}
	var count int
	if err := f.s.DB.QueryRow("SELECT count(*) FROM v3_sessions WHERE username='member'").Scan(&count); err != nil || count != sessions {
		t.Fatal("incorrect account session state", count, err)
	}
	if err := f.s.DB.QueryRow("SELECT count(*) FROM v3_sessions WHERE username='other'").Scan(&count); err != nil || count != 1 {
		t.Fatal("other account session changed", count, err)
	}
	if err := f.s.DB.QueryRow("SELECT revision FROM v3_accounts WHERE username='other'").Scan(&count); err != nil || count != 1 {
		t.Fatal("other account revision changed", err)
	}
}

func TestOwnPasswordAPIAllRolesAndSessionRevocation(t *testing.T) {
	for _, role := range []string{"admin", "operator", "viewer"} {
		t.Run(role, func(t *testing.T) {
			f := newOwnPasswordFixture(t, role)
			w := ownPasswordRequest(f, ownPasswordOld, ownPasswordNew, ownPasswordNew, true, f.id.CSRF)
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"reauthenticate":true`) {
				t.Fatal("password change failed", w.Code, w.Body.String())
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || cookies[0].MaxAge >= 0 || !cookies[0].Secure || !cookies[0].HttpOnly {
				t.Fatal("session cookie was not revoked securely")
			}
			assertOwnPasswordState(t, f, true)
			var audit string
			if err := f.s.DB.QueryRow("SELECT result::text FROM v3_audit WHERE username='member' AND kind='account-password-change'").Scan(&audit); err != nil || !strings.Contains(audit, "sessions_revoked") || strings.Contains(audit, "synthetic") {
				t.Fatal("audit unavailable or unsafe", err)
			}
			w = ownPasswordRequest(f, ownPasswordOld, "another-password", "another-password", true, f.id.CSRF)
			if w.Code != 401 {
				t.Fatal("revoked session reused", w.Code)
			}
		})
	}
}

func TestOwnPasswordAPIGuardsAndPersistentRateLimit(t *testing.T) {
	f := newOwnPasswordFixture(t, "viewer")
	for _, tc := range []struct {
		current, next, confirm, csrf string
		secure                       bool
		status                       int
	}{
		{ownPasswordOld, ownPasswordNew, ownPasswordNew, "", true, 403},
		{ownPasswordOld, ownPasswordNew, ownPasswordNew, f.id.CSRF, false, 403},
		{ownPasswordOld, "short", "short", f.id.CSRF, true, 400},
		{ownPasswordOld, ownPasswordNew, "mismatch", f.id.CSRF, true, 400},
	} {
		w := ownPasswordRequest(f, tc.current, tc.next, tc.confirm, tc.secure, tc.csrf)
		if w.Code != tc.status {
			t.Fatal("guard failed", w.Code, w.Body.String())
		}
	}
	for attempt := 1; attempt <= 11; attempt++ {
		// Recreating an API instance must not reset the account rate limit.
		f.a = &API{Store: f.s, Config: f.a.Config}
		w := ownPasswordRequest(f, "incorrect-password", ownPasswordNew, ownPasswordNew, true, f.id.CSRF)
		expected := 400
		if attempt > 10 {
			expected = 429
		}
		if w.Code != expected {
			t.Fatal("persistent rate limit failed", attempt, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), ownPasswordNew) || strings.Contains(w.Body.String(), "incorrect-password") {
			t.Fatal("response leaked password")
		}
	}
	assertOwnPasswordState(t, f, false)
	mustHistoryExec(t, f.s.DB, "UPDATE v3_login_attempts SET expires_at=clock_timestamp()-interval '1 second'")
	w := ownPasswordRequest(f, ownPasswordOld, ownPasswordNew, ownPasswordNew, true, f.id.CSRF)
	if w.Code != 200 {
		t.Fatal("expired limit failed to reset", w.Code, w.Body.String())
	}
	assertOwnPasswordState(t, f, true)
}

func TestOwnPasswordGlobalLimitAndTrustedProxy(t *testing.T) {
	f := newOwnPasswordFixture(t, "admin")
	mustHistoryExec(t, f.s.DB, "INSERT INTO v3_login_attempts VALUES('account-password:global',60,clock_timestamp()+interval '5 minutes')")
	w := ownPasswordRequest(f, ownPasswordOld, ownPasswordNew, ownPasswordNew, true, f.id.CSRF)
	if w.Code != 429 || w.Header().Get("Retry-After") != "300" {
		t.Fatal("global limit ignored", w.Code)
	}
	assertOwnPasswordState(t, f, false)
	mustHistoryExec(t, f.s.DB, "DELETE FROM v3_login_attempts")
	for _, trusted := range []bool{false, true} {
		raw, _ := json.Marshal(map[string]string{"current_password": ownPasswordOld, "new_password": ownPasswordNew, "confirm_password": ownPasswordNew})
		r := httptest.NewRequest("POST", "/api/v3/account/password", strings.NewReader(string(raw)))
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-CSRF-Token", f.id.CSRF)
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: f.clear})
		if trusted {
			f.a.Config.Central.TrustedProxies = []string{"127.0.0.1/32"}
		}
		w = httptest.NewRecorder()
		f.a.ServeHTTP(w, r)
		expected := 403
		if trusted {
			expected = 200
		}
		if w.Code != expected {
			t.Fatal("proxy trust boundary failed", trusted, w.Code, w.Body.String())
		}
	}
	assertOwnPasswordState(t, f, true)
}

func TestOwnPasswordMigrationAndAtomicFailure(t *testing.T) {
	for _, mode := range []string{"migration", "audit-failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newOwnPasswordFixture(t, "admin")
			if mode == "migration" {
				mustHistoryExec(t, f.s.DB, "INSERT INTO v3_migration_domains(domain,source,pending) VALUES('settings',repeat('a',64),true)")
			} else {
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION own_password_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private synthetic database detail'; END $$;
CREATE TRIGGER own_password_fail_audit BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION own_password_fail_audit()`)
			}
			w := ownPasswordRequest(f, ownPasswordOld, ownPasswordNew, ownPasswordNew, true, f.id.CSRF)
			if w.Code != 503 || strings.Contains(w.Body.String(), "synthetic") {
				t.Fatal("failure not isolated", w.Code, w.Body.String())
			}
			assertOwnPasswordState(t, f, false)
		})
	}
}

func TestOwnPasswordConcurrentChangesAndStaleAuthorization(t *testing.T) {
	f := newOwnPasswordFixture(t, "admin")
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- f.s.changeOwnPasswordTx(context.Background(), f.id, ownPasswordInput{ownPasswordOld, ownPasswordNew, ownPasswordNew})
		}()
	}
	close(start)
	group.Wait()
	close(results)
	var succeeded, revoked int
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, errOwnPasswordSession) {
			revoked++
		} else {
			t.Fatal("unexpected concurrent outcome", err)
		}
	}
	if succeeded != 1 || revoked != 1 {
		t.Fatal("two old authorizations changed password", succeeded, revoked)
	}
	assertOwnPasswordState(t, f, true)

	// A reset between initial HTTP authentication and the password transaction
	// must revoke the earlier authorization even when its old password is known.
	f = newOwnPasswordFixture(t, "admin")
	if err := f.s.ResetPassword(context.Background(), "member", "synthetic-reset-password"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.changeOwnPasswordTx(context.Background(), f.id, ownPasswordInput{ownPasswordOld, ownPasswordNew, ownPasswordNew}); !errors.Is(err, errOwnPasswordSession) {
		t.Fatal("stale reset authorization accepted", err)
	}
}
