package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

func runtimeSettingsObject(t *testing.T, raw string) configurationValues {
	t.Helper()
	var root configurationValues
	if decodeConfigurationObject([]byte(raw), &root) != nil {
		t.Fatal("invalid settings fixture")
	}
	return root
}

func TestCollectorSettingsValidatesActualCadenceAndPreservesLegacyAlertSemantics(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{{`{}`, 30}, {`{"monitoring":{"interval_seconds":300}}`, 30}, {`{"collector":{"interval_seconds":10}}`, 10}, {`{"collector":{"interval_seconds":3600}}`, 3600}} {
		got, err := collectorSettingsInterval(runtimeSettingsObject(t, tc.raw), 30)
		if err != nil || got != tc.want {
			t.Fatal(tc.raw, got, err)
		}
	}
	for _, raw := range []string{`{"collector":null}`, `{"collector":[]}`, `{"collector":{"interval_seconds":9}}`, `{"collector":{"interval_seconds":3601}}`, `{"collector":{"interval_seconds":30.5}}`, `{"collector":{"interval_seconds":"30"}}`, `{"collector":{"interval_seconds":true}}`} {
		if _, err := collectorSettingsInterval(runtimeSettingsObject(t, raw), 30); err == nil {
			t.Fatal("invalid cadence accepted", raw)
		}
	}
	if _, err := collectorSettingsInterval(configurationValues{}, 0); err == nil {
		t.Fatal("invalid bootstrap fallback accepted")
	}
}

func TestCollectorSettingsReadsAppliedPolicyAndCapturesIndependentRun(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"collector":{"interval_seconds":60}}'`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_settings_drafts(id,runtime_version,runtime_digest,payload,proof) SELECT 1,version,'fixture','{"collector":{"interval_seconds":10}}','draft-fixture' FROM v3_settings`)
	if got, err := s.effectiveCollectorInterval(ctx, 30); err != nil || got != 60 {
		t.Fatal("draft modified runtime cadence", got, err)
	}
	c := &Collector{}
	c.Config.Collector.IntervalSeconds = 30
	copy := collectorRunWithInterval(c, 60)
	if copy == c || copy.Config.Collector.IntervalSeconds != 60 || c.Config.Collector.IntervalSeconds != 30 {
		t.Fatal("node run mutated shared configuration")
	}
	// Readers and independently captured runs never update the bootstrap value.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			worker := collectorRunWithInterval(c, 120)
			if worker.Config.Collector.IntervalSeconds != 120 {
				panic("invalid captured interval")
			}
		}
	}()
	for range 1000 {
		if c.Config.Collector.IntervalSeconds != 30 || copy.Config.Collector.IntervalSeconds != 60 {
			t.Fatal("captured configuration changed")
		}
	}
	<-done
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"collector":{"interval_seconds":10}}',version=version+1`)
	if got, err := s.effectiveCollectorInterval(ctx, 30); err != nil || got != 10 {
		t.Fatal(got, err)
	}
	if _, _, err := editSettings(runtimeSettingsObject(t, `{}`), settingsEdit{Values: map[string]json.RawMessage{"collector.interval_seconds": json.RawMessage(`15`)}}); err != nil {
		t.Fatal("editor cannot preview actual collector interval", err)
	}
}

type settingsCadenceAgent struct {
	agentv1.UnimplementedAgentServiceServer
	capabilities chan time.Time
	metrics      chan time.Time
	counter      atomic.Int64
}

func (s *settingsCadenceAgent) Capabilities(context.Context, *agentv1.CapabilitiesRequest) (*agentv1.CapabilitiesResponse, error) {
	s.capabilities <- time.Now()
	return &agentv1.CapabilitiesResponse{NodeId: "settings-node", Protocol: agentv1.ProtocolVersion, MaxEvents: agentv1.MaxEvents, MaxBytes: agentv1.MaxBytes}, nil
}
func (s *settingsCadenceAgent) ReadMetrics(context.Context, *agentv1.ReadMetricsRequest) (*agentv1.MetricsBatch, error) {
	at := time.Now()
	s.metrics <- at
	return &agentv1.MetricsBatch{NodeId: "settings-node", Samples: []*agentv1.MetricsSample{deviceSample(at, int(s.counter.Add(100)), 1, true, "")}}, nil
}
func (s *settingsCadenceAgent) FetchEvents(ctx context.Context, _ *agentv1.FetchEventsRequest) (*agentv1.EventBatch, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCollectorSettingsActualMTLSRunChangesCadenceWithoutRestart(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := authority.Export()
	node, err := authority.Issue(nodepki.Node, "settings-node", []string{"settings.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := authority.Issue(nodepki.Collector, "settings-collector", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(node.Certificate, node.Key)
	if err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CA) {
		t.Fatal("invalid isolated CA")
	}
	agent := &settingsCadenceAgent{capabilities: make(chan time.Time, 16), metrics: make(chan time.Time, 16)}
	g := grpc.NewServer()
	agentv1.RegisterAgentServiceServer(g, agent)
	defer g.Stop()
	server := httptest.NewUnstartedServer(g)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	n := nodeFixture("settings-node")
	n.Endpoint, n.ServerName = server.Listener.Addr().String(), "settings.test"
	if err := s.PutNode(context.Background(), n, 0, 1); err != nil {
		t.Fatal(err)
	}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer sink.Close()
	c := &Collector{Store: s, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{clientPair}}, Metrics: &Metrics{WriteURL: sink.URL, HTTP: sink.Client()}}
	c.Config.Central.Instance = "settings-collector"
	c.Config.Collector.IntervalSeconds, c.Config.Collector.Concurrency, c.Config.Collector.Shards = 3600, 1, 1
	ctx, stop := context.WithTimeout(context.Background(), 55*time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() { stop(); <-done }()
	wait := func(ch <-chan time.Time) time.Time {
		t.Helper()
		select {
		case at := <-ch:
			return at
		case <-ctx.Done():
			t.Fatal("actual collector did not apply cadence", ctx.Err())
		}
		return time.Time{}
	}
	wait(agent.capabilities)
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{"collector":{"interval_seconds":10}}',version=version+1`)
	reconnected := wait(agent.capabilities)
	first := wait(agent.metrics)
	for first.Before(reconnected) {
		first = wait(agent.metrics)
	}
	second := wait(agent.metrics)
	if gap := second.Sub(first); gap < 9*time.Second || gap > 14*time.Second {
		t.Fatal("real metric RPCs did not use applied ten-second interval", gap)
	}
	if c.Config.Collector.IntervalSeconds != 3600 {
		t.Fatal("shared bootstrap cadence mutated")
	}
	select {
	case err := <-done:
		done <- err
		t.Fatal("collector process exited during settings application", err)
	default:
	}
	var sampled int64
	if err := s.DB.QueryRow(`SELECT sampled_at FROM v3_node_status WHERE node='settings-node'`).Scan(&sampled); err != nil || sampled == 0 {
		t.Fatal("actual metric RPC was not durably committed", sampled, err)
	}
}
