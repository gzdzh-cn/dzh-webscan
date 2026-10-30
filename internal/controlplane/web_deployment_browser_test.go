package controlplane

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in visual fixture, isolated database schema and loopback TLS only. There
// is deliberately no deployment runner: visual error handling cannot certify
// a real Linux lifecycle, and capabilities must report that unavailability.
func TestWebDeploymentBrowserFixture(t *testing.T) {
	dir := os.Getenv("WEBSCAN_V3_BROWSER_EVIDENCE")
	if dir == "" {
		t.Skip("opt-in browser fixture")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute evidence directory required")
	}
	f := webDeployFixture(t)
	if err := f.s.ResetPassword(context.Background(), "admin", "isolated-browser-password-123"); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, "DELETE FROM v3_role_status WHERE role='executor'")
	server := httptest.NewUnstartedServer(f.api)
	if address := os.Getenv("WEBSCAN_V3_BROWSER_LISTEN"); address != "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != "127.0.0.1" {
			server.Close()
			t.Fatal("browser fixture must listen on IPv4 loopback")
		}
		server.Listener.Close()
		server.Listener, err = net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
	}
	server.StartTLS()
	defer server.Close()
	f.api.Config.Central.PublicURL = server.URL
	f.api.bootstrapConfig.Central.PublicURL = server.URL
	raw, _ := json.Marshal(map[string]any{"url": server.URL, "ssh_port": f.port, "scope": "visual UI and unavailable-executor feedback only; no real Linux lifecycle"})
	if err := os.WriteFile(filepath.Join(dir, "browser-fixture.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(20 * time.Minute)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("browser validation timed out")
		case <-tick.C:
			if _, err := os.Stat(filepath.Join(dir, "browser-done")); err == nil {
				return
			}
		}
	}
}
