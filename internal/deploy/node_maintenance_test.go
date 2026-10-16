package deploy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/progress"
)

func maintenanceServer(t *testing.T, d *Deploy, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	port, _ := strconv.Atoi(u.Port())
	common.M(common.M(d.C.Raw["central"])["event_service"])["port"] = port
	d.HTTP = s.Client()
	return s
}

func TestMaintenanceRetriesBusyCenterAndConfirmsAlreadyWrittenFile(t *testing.T) {
	d := additionFixture(t)
	d.Journal, _ = NewJournal(filepath.Join(StateRoot, "test-run"))
	requests := 0
	maintenanceServer(t, d, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/reload-settings" || r.Header.Get("Authorization") != "Bearer test-alert" {
			t.Error("wrong management request")
		}
		requests++
		if requests == 1 {
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})
	// The desired on-disk value already exists, but that is not evidence that
	// the running center confirmed a previous reload.
	if err := d.clearNodeMaintenance(context.Background(), d.C.Selected("new-node")[0]); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatal("missing retry or skipped running-state confirmation", requests)
	}
}

func TestMaintenancePermanentRejectionIsNotRetriedAndDoesNotLeakResponse(t *testing.T) {
	d := additionFixture(t)
	requests := 0
	maintenanceServer(t, d, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(401)
		w.Write([]byte(`{"message":"private-token-must-not-leak"}`))
	})
	err := d.reloadNodeMaintenance(context.Background())
	if err == nil || requests != 1 || !strings.Contains(progress.Explain(err), "HTTP 401") || strings.Contains(progress.Explain(err), "private-token") {
		t.Fatal("permanent rejection was retried or response leaked", requests, err)
	}
}

func TestAcceptedAdditionKeepsServiceWhenMaintenanceNeedsResume(t *testing.T) {
	d := additionFixture(t)
	d.O.AddNode, d.O.Upgrade = true, false
	common.M(d.C.Raw["ssl"])["enabled"] = false
	common.M(common.M(d.C.Raw["central"])["monitoring"])["mode"] = "native"
	requests := 0
	s := maintenanceServer(t, d, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/node-capabilities":
			w.Write([]byte(`{"node_registry_reload":true,"revision":"fixture"}`))
		case "/ready":
			w.Write([]byte(`{"ready":true}`))
		case "/metrics":
			for _, k := range []string{"webscan_collector_ready", "webscan_baseline_completed", "webscan_coverage_ok", "webscan_vector_metrics_up"} {
				fmt.Fprintf(w, "%s 1\n", k)
			}
			fmt.Fprintf(w, "webscan_agent_heartbeat_seconds %g\nwebscan_local_probe_seconds %g\n", common.Now(), common.Now())
		case "/reload-settings":
			requests++
			if requests == 1 {
				w.WriteHeader(400)
				return
			}
			w.Write([]byte(`{"ok":true}`))
		default:
			t.Error("unexpected installation or rollback request", r.URL.Path)
			w.WriteHeader(500)
		}
	})
	u, _ := url.Parse(s.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	n := d.C.Selected("new-node")[0]
	n["host"] = host
	n["metrics"] = common.Map{"port": mustPort(t, port)}
	if err := d.initialize(); err != nil {
		t.Fatal(err)
	}
	st := common.M(d.State["node_addition"])
	for _, key := range []string{"registered", "local_ready", "transport_ready", "accepted"} {
		st[key] = true
	}
	node := common.Map{"phase": "go-installed", "go_run_id": d.RunID}
	common.M(d.State["nodes"])["new-node"] = node
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.deployAddition(ctx); err == nil {
		t.Fatal("missing maintenance rejection")
	}
	if d.State["step"] != "node-maintenance-pending" || node["phase"] != "go-installed" || !common.B(st["accepted"]) || common.S(common.M(d.State["last_failure"])["stage"]) != "node-maintenance" {
		t.Fatal("accepted node was rolled back or acceptance checkpoint lost")
	}
	if err := d.deployAddition(ctx); err != nil {
		t.Fatal("resume failed", err)
	}
	if d.State["step"] != "notifying" || node["phase"] != "complete" || requests != 2 {
		t.Fatal("resume did not finish original accepted node", d.State["step"], requests)
	}
}

func mustPort(t *testing.T, value string) int {
	t.Helper()
	n, e := strconv.Atoi(value)
	if e != nil {
		t.Fatal(e)
	}
	return n
}

func TestAgentLatestUsesMatchingReleaseWithoutChangingExplicitPins(t *testing.T) {
	for _, tc := range []struct{ image, release, want string }{
		{"docker.io/gzdzh/webscan-agent:latest", "v2.0.42", "docker.io/gzdzh/webscan-agent:v2.0.42"},
		{"registry.example:5000/team/webscan-agent:latest", "v2.0.42", "registry.example:5000/team/webscan-agent:v2.0.42"},
		{"docker.io/gzdzh/webscan-agent:v2.0.35", "v2.0.42", "docker.io/gzdzh/webscan-agent:v2.0.35"},
		{"docker.io/gzdzh/webscan-agent@sha256:fixture", "v2.0.42", "docker.io/gzdzh/webscan-agent@sha256:fixture"},
		{"docker.io/gzdzh/webscan-agent:latest", "development", "docker.io/gzdzh/webscan-agent:latest"},
	} {
		if got := agentImageForRelease(tc.image, tc.release); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
}
