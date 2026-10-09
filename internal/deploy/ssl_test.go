package deploy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/common"
)

func TestHTTPDeploymentPackagesAndProtocolSwitchScope(t *testing.T) {
	c := fixture(t)
	c.Raw["ssl"] = common.Map{"enabled": false}
	common.M(c.Raw["central"])["public_url"] = "http://192.0.2.1:19443"
	common.M(c.Raw["central"])["website_monitor"] = common.Map{"enabled": true, "host_port": 19444, "bind_address": "127.0.0.1", "extra_memory_mib": 128, "admin_username": "admin"}
	common.M(c.Raw["registry"])["prefix"] = "docker.io/gzdzh"
	dir := filepath.Join(t.TempDir(), "packages")
	if err := PrepareCompose(c, dir, []byte("include: []\n")); err != nil {
		t.Fatal(err)
	}
	runtime, err := common.ReadJSON(filepath.Join(dir, "central/config/runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	if common.I(common.M(runtime["https"])["port"]) != 0 || common.I(common.M(runtime["public_http"])["port"]) != 19443 || common.B(common.M(runtime["website_monitor"])["ssl_enabled"]) {
		t.Fatal("HTTP listeners not configured")
	}
	if _, err = os.Stat(filepath.Join(dir, "private/ca.key")); !os.IsNotExist(err) {
		t.Fatal("HTTP package generated CA", err)
	}
	for _, n := range c.Nodes {
		if strings.Contains(string(common.JSON(VectorConfig(c, n, common.Map{}))), "ca_file") {
			t.Fatal("HTTP Vector depends on certificate")
		}
		if common.S(NodeRuntime(c, n, common.Map{})["central_ca_file"]) != "" {
			t.Fatal("HTTP Agent depends on CA")
		}
	}
	if strings.Contains(string(common.JSON(Prometheus(c, []string{common.S(c.Nodes[0]["id"])}))), "tls_config") || len(ExporterWebConfig(c)) != 0 {
		t.Fatal("TLS metrics remain enabled")
	}
	if WebsiteURL(c) != "http://192.0.2.1:19444" {
		t.Fatal(WebsiteURL(c))
	}
	d := &Deploy{C: c, State: common.Map{"central_installed": true, "configuration": common.Map{"ssl": common.Map{"enabled": true}}}}
	for _, options := range []Options{{CentralOnly: true}, {Node: "node-202"}, {AddNode: true}, {ReloadRules: true}, {Check: true}} {
		d.O = options
		if d.validateSSLChange() == nil {
			t.Fatal("partial switch accepted", options)
		}
	}
	d.O = Options{Upgrade: true}
	if d.validateSSLChange() != nil {
		t.Fatal("full switch refused")
	}
	common.M(d.State["configuration"])["ssl"] = common.Map{"enabled": false}
	d.O = Options{CentralOnly: true}
	if d.validateSSLChange() != nil {
		t.Fatal("ordinary same-protocol upgrade refused")
	}
	// Plain metrics validation must work without any local pki files.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("webscan_collector_ready 1\n")) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	n := common.Map{"host": u.Hostname(), "metrics": common.Map{"port": port}}
	metrics, err := d.metrics(context.Background(), n)
	if err != nil || metrics["webscan_collector_ready"] != 1 {
		t.Fatal(metrics, err)
	}
}
