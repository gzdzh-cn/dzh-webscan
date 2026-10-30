//go:build linux

package controlplane

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The outer guest guard belongs to the only caller. The container receives no
// CA key, host helper, SSH keys, configuration bundles or Docker socket.
func webKernelAPIContainer(t *testing.T, ctx context.Context, f webDeploymentFixture) (*httptest.Server, func()) {
	t.Helper()
	image, err := os.ReadFile("/v3-tests/central-image-id")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(image)), "sha256:") {
		t.Fatal("real central image required")
	}
	root := privateTestDir(t)
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := f.s.DB.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil || !strings.HasPrefix(schema, "webscan_test_") {
		t.Fatal("isolated schema required", err)
	}
	dsn, err := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if err != nil || dsn.Hostname() != "127.0.0.1" {
		t.Fatal("loopback database required")
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	dsnPath := filepath.Join(root, "postgres.dsn")
	if err := os.WriteFile(dsnPath, []byte(dsn.String()), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	target, _ := url.Parse("http://" + address)
	proxy := httputil.NewSingleHostReverseProxy(target)
	original := proxy.Director
	proxy.Director = func(r *http.Request) {
		original(r)
		r.Header.Del("Forwarded")
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	server := httptest.NewTLSServer(proxy)
	c := f.api.Config
	c.Central.Instance, c.Central.Listen, c.Central.PublicURL = "kernel-web-api", address, server.URL
	c.Central.CertFile, c.Central.KeyFile = "", ""
	c.Central.TrustedProxies = []string{"127.0.0.1/32"}
	c.Central.ExportDirectory = filepath.Join(state, "exports")
	c.Metrics.SpoolDir = filepath.Join(state, "spool")
	c.Collector.Shards = f.c.Collector.Shards
	c.Database.DSNFile = dsnPath
	if err := c.Validate(); err != nil {
		server.Close()
		t.Fatal(err)
	}
	config := filepath.Join(root, "config.yaml")
	raw, _ := yaml.Marshal(c)
	if err := os.WriteFile(config, raw, 0600); err != nil {
		server.Close()
		t.Fatal(err)
	}
	name := "webscan-kernel-api-" + token()[:12]
	args := []string{"run", "-d", "--name", name, "--network", "host", "--read-only", "--restart", "no", "--tmpfs", "/tmp:rw,nosuid,size=64m", "--mount", "type=bind,src=" + state + ",dst=" + state}
	seen := map[string]bool{}
	paths := []string{config, dsnPath, c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PublicKeyFile, c.DeploymentTrust.ManifestFile, c.DeploymentTrust.SignatureFile, c.Collector.CAFile, c.Collector.CertFile, c.Collector.KeyFile, c.Collector.RevocationFile}
	for _, path := range paths {
		if path != "" && !seen[path] {
			args = append(args, "--mount", "type=bind,src="+path+",dst="+path+",readonly")
			seen[path] = true
		}
	}
	args = append(args, strings.TrimSpace(string(image)), "control-v3", "--config", config, "--action", "run", "--role", "api")
	id, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		server.Close()
		t.Fatal("central container start", err)
	}
	idString := strings.TrimSpace(string(id))
	t.Cleanup(func() {
		if t.Failed() {
			if raw, err := exec.Command("docker", "logs", idString).CombinedOutput(); err == nil {
				t.Logf("central container diagnostic: %s", raw)
			}
		}
		exec.Command("docker", "rm", "-fv", idString).Run()
		server.Close()
	})
	for end := time.Now().Add(time.Minute); ; {
		response, err := http.Get(target.String() + "/healthz")
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(end) {
			t.Fatal("real central API not healthy")
		}
		time.Sleep(time.Second)
	}
	identity := func() string {
		t.Helper()
		raw, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.Id}}/{{.State.Pid}}/{{.State.StartedAt}}/{{.RestartCount}}", idString).Output()
		if err != nil {
			t.Fatal("central identity", err)
		}
		return strings.TrimSpace(string(raw))
	}
	before := identity()
	return server, func() {
		t.Helper()
		if identity() != before {
			t.Fatal("node operations replaced or restarted central", fmt.Sprintf("%q", idString))
		}
		t.Log("real central container ID, PID, start time and restart count unchanged")
	}
}
