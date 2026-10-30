package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPISessionSurvivesInstanceAndKeepsCSRF(t *testing.T) {
	s := testStore(t)
	if e := s.Provision(context.Background(), "admin", "test-password-123"); e != nil {
		t.Fatal(e)
	}
	var cfg Config
	cfg.Central.PublicURL = "https://monitor.example.test"
	api := &API{Store: s, Config: cfg}
	r := httptest.NewRequest("POST", "/api/v3/login", strings.NewReader(`{"username":"admin","password":"test-password-123"}`))
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	var response map[string]string
	if e := json.Unmarshal(w.Body.Bytes(), &response); e != nil {
		t.Fatal(e)
	}
	api = &API{Store: s, Config: cfg}
	r = httptest.NewRequest("GET", "/api/v3/session", nil)
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), response["csrf"]) {
		t.Fatal(w.Code, w.Body.String())
	}
	r = httptest.NewRequest("POST", "/api/v3/logout", nil)
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing csrf", w.Code)
	}
	r = httptest.NewRequest("POST", "/api/v3/logout", nil)
	r.AddCookie(cookies[0])
	r.Header.Set("X-CSRF-Token", response["csrf"])
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	r = httptest.NewRequest("GET", "/api/v3/session", nil)
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("revoked session accepted", w.Code)
	}
}
func TestAPIDatabaseFailureIsNotAuthenticationFailure(t *testing.T) {
	s := testStore(t)
	api := &API{Store: s}
	s.DB.Close()
	r := httptest.NewRequest("GET", "/api/v3/session", nil)
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: strings.Repeat("a", 64)})
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestAPIRejectsCrossOriginLogin(t *testing.T) {
	api := &API{}
	api.Config.Central.PublicURL = "https://monitor.example.test"
	r := httptest.NewRequest("POST", "/api/v3/login", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://other.example.test")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
