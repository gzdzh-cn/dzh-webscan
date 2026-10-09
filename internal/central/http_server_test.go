package central

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"webscan/internal/common"
)

func TestHTTPIngressPreservesSourceAllowlist(t *testing.T) {
	s := testStore(t)
	s.Config["https"] = common.Map{"allowed_sources": []string{"127.0.0.1/32"}}
	for _, tc := range []struct {
		remote string
		status int
	}{{"198.51.100.7:3456", 403}, {"127.0.0.1:3456", 200}} {
		r := httptest.NewRequest("POST", "/webscan/v1/events", strings.NewReader(string(common.JSON(fixture()))))
		r.RemoteAddr = tc.remote
		r.Header.Set("Authorization", "Bearer fixture-token")
		w := httptest.NewRecorder()
		s.publicHTTPHandler(w, r)
		if w.Code != tc.status {
			t.Fatal(tc.remote, w.Code)
		}
	}
}

func TestPlainHTTPConsoleAndRestrictedEventIngress(t *testing.T) {
	base := t.TempDir()
	internalPort, publicPort, consolePort := freePort(t), freePort(t), freePort(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	config := common.Map{"data_dir": base, "bind": "127.0.0.1", "port": internalPort, "https": common.Map{"port": 0, "cert_file": "/missing.crt", "allowed_sources": []string{"127.0.0.1/32"}}, "public_http": common.Map{"bind": "127.0.0.1", "port": publicPort}, "max_request_mib": 2, "max_batch_events": 100, "nodes": common.Map{"node": common.Map{"host": "127.0.0.1", "token": "fixture-token"}}, "website_monitor": common.Map{"enabled": true, "ssl_enabled": false, "host_port": consolePort, "admin_username": "admin", "password_hash": string(hash), "interval_seconds": 60, "max_concurrent": 1, "timeout_seconds": 1}, "feishu": common.Map{"enabled": false}}
	path := filepath.Join(base, "runtime.json")
	common.AtomicJSON(path, config)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, path) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("shutdown timeout")
		}
	}()
	client, _ := common.HTTPClient("", 2*time.Second)
	internalURL := "http://127.0.0.1:" + strconv.Itoa(internalPort)
	publicURL := "http://127.0.0.1:" + strconv.Itoa(publicPort)
	consoleURL := "http://127.0.0.1:" + strconv.Itoa(consolePort)
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, _, _ := common.Request(ctx, client, "GET", consoleURL+"/api/session", nil, nil)
		if code == 401 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("HTTP startup timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code, _, err := common.Request(ctx, client, "GET", internalURL+"/ready", nil, nil); err != nil || code != 200 {
		t.Fatal(code, err)
	}
	for _, route := range []string{"/ready", "/metrics", "/alerts", "/deployment-acceptance"} {
		if code, _, _ := common.Request(ctx, client, "GET", publicURL+route, nil, nil); code != 404 {
			t.Fatal("internal route exposed", route, code)
		}
	}
	if code, _, _ := common.Request(ctx, client, "POST", publicURL+"/webscan/v1/events", fixture(), nil); code != 401 {
		t.Fatal("token required", code)
	}
	if code, _, err := common.Request(ctx, client, "POST", publicURL+"/webscan/v1/events", fixture(), map[string]string{"Authorization": "Bearer fixture-token"}); err != nil || code != 200 {
		t.Fatal(code, err)
	}
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	if code, _, err := common.Request(ctx, client, "POST", consoleURL+"/api/login", common.Map{"username": "admin", "password": "fixture-password"}, nil); err != nil || code != 200 {
		t.Fatal(code, err)
	}
	if code, _, err := common.Request(ctx, client, "GET", consoleURL+"/api/session", nil, nil); err != nil || code != 200 {
		t.Fatal("HTTP browser did not retain session", code, err)
	}
	if code, _, _ := common.Request(ctx, client, "POST", consoleURL+"/api/logout", common.Map{}, nil); code != 403 {
		t.Fatal("HTTP mode bypassed CSRF", code)
	}
	if code, _, _ := common.Request(ctx, client, "POST", consoleURL+"/api/login", common.Map{"username": "admin", "password": "fixture-password"}, map[string]string{"Origin": "https://unrelated.example"}); code != 403 {
		t.Fatal("HTTP mode bypassed Origin", code)
	}
	// HTTPS reverse proxy keeps Host; the external HTTPS Origin makes the cookie Secure.
	req, _ := http.NewRequest("POST", consoleURL+"/api/login", strings.NewReader(`{"username":"admin","password":"fixture-password"}`))
	req.Header.Set("Origin", "https://"+req.URL.Host)
	req.Header.Set("X-Forwarded-Proto", "https")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || !response.Cookies()[0].Secure {
		t.Fatal("proxy HTTPS session protection lost")
	}
	// File data was persisted; no certificate or private key was needed.
	if _, err = os.Stat(filepath.Join(base, "events-v1.sqlite3")); err != nil {
		t.Fatal(err)
	}
}
