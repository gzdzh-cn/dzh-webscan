package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

func TestNodeNameChangeReadinessRequiresActualMTLSPeerAndCurrentAuthority(t *testing.T) {
	for _, scenario := range []string{"ready", "reauthorized", "wrong-claim", "wrong-peer", "revoked-peer", "revoked-collector", "lease-lost-during-call", "coverage-missing", "metrics-stale", "metrics-duplicate", "metrics-other-node", "latest-unhealthy", "target-handshake-rejected", "target-stale-capability"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			f := nameChangeRegistryFixtureWith(t, func(f *provisioningFixture) {
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET endpoint=$2,server_name=$3 WHERE id=$1`, f.in.Node, listener.Addr().String(), "source-agent.test")
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET endpoint=$2,server_name=$3 WHERE node=$1`, f.in.Node, listener.Addr().String(), "source-agent.test")
			})
			ctx := context.Background()
			f.admit(t)
			signed, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			trustDir := filepath.Join(filepath.Dir(f.identity), "readiness-trust")
			if _, err := nodepki.NewReceiverTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, trustDir, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, trustDir, f.request, f.job.Intent, signed.Certificate, time.Now()); err != nil {
				t.Fatal(err)
			}
			if scenario == "reauthorized" {
				fresh := freshNameChangeTask(t, f, "fresh-readiness")
				request, err := nodepki.PrepareNodeNameChangeContinuation(ctx, f.c.Collector.CAFile, f.identity, trustDir, f.crl, fresh.Intent, f.request, signed.Certificate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(request)
				if _, err := f.s.admitNodeNameChange(ctx, f.t.vault, f.lease, fresh.ID, raw); err != nil {
					t.Fatal(err)
				}
				replayed, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, fresh.ID)
				if err != nil || replayed.Receipt != signed.Receipt {
					t.Fatal("fresh readiness changed original issuance", err)
				}
				f.job, f.request = fresh, request
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

			var namesMu sync.Mutex
			var names []string
			serverTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				namesMu.Lock()
				names = append(names, hello.ServerName)
				namesMu.Unlock()
				if scenario == "target-handshake-rejected" && hello.ServerName == f.job.TargetName {
					return nil, errors.New("isolated target name denied")
				}
				return nil, nil
			}
			g := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
			var calls atomic.Int32
			agentv1.RegisterAgentServiceServer(g, recoveryReadinessAgent{capability: func() *agentv1.CapabilitiesResponse {
				count := calls.Add(1)
				cap := &agentv1.CapabilitiesResponse{NodeId: f.job.Node, Version: "v3.0.0-local-test", Protocol: agentv1.ProtocolVersion, MaxEvents: agentv1.MaxEvents, MaxBytes: agentv1.MaxBytes, ConfigurationVersion: n.Version, ConfigurationSha256: digest(n.Config), CertificateSha256: signed.Receipt.CertificateSHA256, CertificateNotAfterUnix: signed.Receipt.ExpiresAt.Unix()}
				if scenario == "target-stale-capability" && count == 2 {
					cap.ConfigurationVersion++
				}
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
			worker := nameChangeSSHWorker(t, f, []byte("no-SSH-in-this-readiness-test"))
			call, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = worker.observeAndConfirm(call, f.lease, f.job.ID)
			cancel()
			var status string
			if e := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes WHERE id=$1`, f.job.ID).Scan(&status); e != nil {
				t.Fatal(e)
			}
			if scenario == "ready" || scenario == "reauthorized" {
				if err != nil || status != "completed" {
					t.Fatal("actual dual-name mTLS readiness not committed", err, status)
				}

				namesMu.Lock()
				gotNames := append([]string(nil), names...)
				namesMu.Unlock()
				if len(gotNames) != 2 || gotNames[0] != f.job.SourceName || gotNames[1] != f.job.TargetName {
					t.Fatal("did not observe two fresh TLS names", gotNames)
				}
				var activeName string
				if e := f.s.DB.QueryRow(`SELECT server_name FROM v3_active_nodes WHERE id=$1`, f.job.Node).Scan(&activeName); e != nil || activeName != f.job.SourceName {
					t.Fatal("readiness implicitly applied saved target", e)
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
