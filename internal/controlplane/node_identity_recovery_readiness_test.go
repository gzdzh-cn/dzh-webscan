package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

type recoveryReadinessAgent struct {
	agentv1.UnimplementedAgentServiceServer
	capability func() *agentv1.CapabilitiesResponse
	metrics    func() *agentv1.MetricsBatch
}

func (s recoveryReadinessAgent) Capabilities(context.Context, *agentv1.CapabilitiesRequest) (*agentv1.CapabilitiesResponse, error) {
	return s.capability(), nil
}

func (s recoveryReadinessAgent) ReadMetrics(context.Context, *agentv1.ReadMetricsRequest) (*agentv1.MetricsBatch, error) {
	return s.metrics(), nil
}

func TestNodeIdentityRecoveryMetricsEnvelopeAndLatestEvidence(t *testing.T) {
	now := time.Now()
	n := nodeFixture("metrics-node")
	n.Config = []byte(`{"scan":{"yara":{"enabled":true},"clamav":{"enabled":true}}}`)
	for _, scenario := range []string{"valid", "nil", "empty", "nil-sample", "empty-text", "other-node", "too-many", "too-large", "nonpositive-time", "duplicate-time", "reversed-time", "old", "future", "before-intent", "malformed", "duplicate-scalar", "labelled-scalar", "yara-unready", "clamav-unready", "latest-unhealthy", "old-unhealthy-latest-healthy"} {
		t.Run(scenario, func(t *testing.T) {
			raw := healthyDeploymentMetrics(t, n.Config, now)
			batch := &agentv1.MetricsBatch{NodeId: n.ID, Samples: []*agentv1.MetricsSample{{UnixMillis: now.UnixMilli(), PrometheusText: raw}}}
			before := now.Add(-time.Second)
			switch scenario {
			case "nil":
				batch = nil
			case "empty":
				batch.Samples = nil
			case "nil-sample":
				batch.Samples[0] = nil
			case "empty-text":
				batch.Samples[0].PrometheusText = nil
			case "other-node":
				batch.NodeId = "other-node"
			case "too-many":
				for range 128 {
					batch.Samples = append(batch.Samples, &agentv1.MetricsSample{UnixMillis: now.UnixMilli() + 1, PrometheusText: raw})
				}
			case "too-large":
				batch.Samples[0].PrometheusText = []byte(strings.Repeat("x", agentv1.MaxBytes+1))
			case "nonpositive-time":
				batch.Samples[0].UnixMillis = 0
			case "duplicate-time":
				batch.Samples = append(batch.Samples, batch.Samples[0])
			case "reversed-time":
				batch.Samples = append(batch.Samples, &agentv1.MetricsSample{UnixMillis: now.UnixMilli() - 1, PrometheusText: raw})
			case "old":
				batch.Samples[0].UnixMillis = now.Add(-61 * time.Second).UnixMilli()
			case "future":
				batch.Samples[0].UnixMillis = now.Add(6 * time.Second).UnixMilli()
			case "before-intent":
				before = now.Add(6 * time.Second)
			case "malformed":
				batch.Samples[0].PrometheusText = []byte("not valid prometheus\n")
			case "duplicate-scalar":
				batch.Samples[0].PrometheusText = append(raw, []byte("webscan_collector_ready 1\n")...)
			case "labelled-scalar":
				batch.Samples[0].PrometheusText = []byte(strings.ReplaceAll(string(raw), "webscan_collector_ready 1", "webscan_collector_ready{source=\"untrusted\"} 1"))
			case "yara-unready":
				batch.Samples[0].PrometheusText = []byte(strings.ReplaceAll(string(raw), "webscan_yara_ready 1", "webscan_yara_ready 0"))
			case "clamav-unready":
				batch.Samples[0].PrometheusText = []byte(strings.ReplaceAll(string(raw), "webscan_clamav_ready 1", "webscan_clamav_ready 0"))
			case "latest-unhealthy":
				batch.Samples = append(batch.Samples, &agentv1.MetricsSample{UnixMillis: now.UnixMilli() + 1, PrometheusText: []byte("webscan_collector_ready 0\n")})
			case "old-unhealthy-latest-healthy":
				batch.Samples = append([]*agentv1.MetricsSample{{UnixMillis: now.UnixMilli() - 1, PrometheusText: []byte("webscan_collector_ready 0\n")}}, batch.Samples...)
			}
			want := scenario == "valid" || scenario == "old-unhealthy-latest-healthy"
			if got := validRecoveryMetrics(n, batch, now, before); got != want {
				t.Fatal("unproved metrics accepted or valid latest rejected", got)
			}
		})
	}
}

func TestNodeIdentityRecoveryReadinessRequiresActualMTLSPeerAndCurrentAuthority(t *testing.T) {
	for _, scenario := range []string{"ready", "reauthorized", "wrong-claim", "wrong-peer", "revoked-peer", "revoked-collector", "lease-lost-during-call", "coverage-missing", "metrics-stale", "metrics-duplicate", "metrics-other-node", "latest-unhealthy"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			f := identityRecoveryFixtureAt(t, listener.Addr().String())
			ctx := context.Background()
			admitRecoveryFixture(t, f)
			signed, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			trustDir := filepath.Join(filepath.Dir(f.identity), "readiness-trust")
			if _, err := nodepki.NewReceiverTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, trustDir, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := nodepki.ActivateNodeRecovery(ctx, f.c.Collector.CAFile, f.identity, trustDir, f.request, f.job.Intent, signed.Certificate, time.Now()); err != nil {
				t.Fatal(err)
			}
			if scenario == "reauthorized" {
				fresh := freshActivatedRecovery(t, f)
				request, err := nodepki.PrepareNodeRecoveryContinuation(ctx, f.c.Collector.CAFile, f.identity, trustDir, f.crl, fresh.Intent, signed.Certificate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(request)
				if _, err := f.s.admitNodeIdentityRecovery(ctx, f.t.vault, f.lease, fresh.ID, raw); err != nil {
					t.Fatal(err)
				}
				replayed, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, fresh.ID)
				if err != nil || replayed.Receipt != signed.Receipt {
					t.Fatal("fresh readiness task changed issuance", err)
				}
				f.job = fresh
			}
			n, err := scanActiveNode(f.s.DB.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, f.job.Node))
			if err != nil {
				t.Fatal(err)
			}
			actual, _, err := nodepki.ReadIdentity(f.c.Collector.CAFile, f.identity, nodepki.Node, f.job.Node, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer clear(actual.Key)
			if scenario == "wrong-peer" {
				actual, err = f.ca.Issue(nodepki.Node, f.job.Node, []string{"192.0.2.1"}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(actual.Key)
			}
			pair, err := tls.X509KeyPair(actual.Certificate, actual.Key)
			if err != nil {
				t.Fatal(err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(actual.CA)
			policy, err := nodepki.NewTrust(actual.CA, f.crl, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			serverTLS := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}, VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) != 1 {
					return nodepki.ErrIdentity
				}
				return policy.Verify(state.PeerCertificates[0], nodepki.Collector, "collector-a", time.Now())
			}}
			g := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
			var calls atomic.Int32
			agentv1.RegisterAgentServiceServer(g, recoveryReadinessAgent{capability: func() *agentv1.CapabilitiesResponse {
				calls.Add(1)
				cap := &agentv1.CapabilitiesResponse{NodeId: f.job.Node, Version: "v3.0.0-local-test", Protocol: agentv1.ProtocolVersion, MaxEvents: agentv1.MaxEvents, MaxBytes: agentv1.MaxBytes, ConfigurationVersion: f.job.NodeVersion, ConfigurationSha256: f.job.ConfigSHA256, CertificateSha256: signed.Receipt.CertificateSHA256, CertificateNotAfterUnix: signed.Receipt.ExpiresAt.Unix()}
				if scenario == "wrong-claim" {
					cap.CertificateSha256 = strings.Repeat("0", 64)
				}
				if scenario == "lease-lost-during-call" {
					if _, err := f.s.DB.Exec(`UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, f.lease.Resource); err != nil {
						t.Error(err)
					}
				}
				return cap
			}, metrics: func() *agentv1.MetricsBatch {
				now := time.Now()
				raw := healthyDeploymentMetrics(t, n.Config, now)
				batch := &agentv1.MetricsBatch{NodeId: n.ID, Samples: []*agentv1.MetricsSample{{UnixMillis: now.UnixMilli(), PrometheusText: raw}}}
				switch scenario {
				case "coverage-missing":
					batch.Samples[0].PrometheusText = []byte(strings.ReplaceAll(string(raw), "webscan_coverage_ok 1", "webscan_coverage_ok 0"))
				case "metrics-stale":
					batch.Samples[0].UnixMillis = now.Add(-2 * time.Minute).UnixMilli()
				case "metrics-duplicate":
					batch.Samples[0].PrometheusText = append(raw, []byte("webscan_coverage_ok 1\n")...)
				case "metrics-other-node":
					batch.NodeId = "different-node"
				case "latest-unhealthy":
					batch.Samples = append(batch.Samples, &agentv1.MetricsSample{UnixMillis: now.UnixMilli() + 1, PrometheusText: []byte("webscan_coverage_ok 0\n")})
				}
				return batch
			}})
			done := make(chan error, 1)
			go func() { done <- g.Serve(listener) }()
			defer func() { g.Stop(); <-done }()
			if scenario == "revoked-peer" || scenario == "revoked-collector" {
				revoked := signed.Certificate
				if scenario == "revoked-collector" {
					revoked = f.collector.Certificate
				}
				crl, err := f.ca.Revoke(f.crl, [][]byte{revoked}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$2 WHERE sha256=$1`, f.input.AuthoritySHA256, crl)
				localWrite(t, f.c.Collector.RevocationFile, crl)
			}
			worker := identityRecoverySSHWorker(t, f, []byte("no-SSH-in-this-readiness-test"))
			call, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = worker.observeAndConfirm(call, f.lease, f.job.ID)
			cancel()
			var status string
			if e := f.s.DB.QueryRow(`SELECT status FROM v3_node_identity_recoveries WHERE id=$1`, f.job.ID).Scan(&status); e != nil {
				t.Fatal(e)
			}
			if scenario == "ready" || scenario == "reauthorized" {
				if err != nil || status != "completed" {
					t.Fatal("actual mTLS readiness not committed", err, status)
				}
			} else if err == nil || status != "signed" {
				t.Fatal("unverified/stale readiness completed recovery", err, status)
			}
			if scenario == "revoked-collector" && calls.Load() != 0 {
				t.Fatal("revoked local collector reached remote RPC")
			}
		})
	}
}
