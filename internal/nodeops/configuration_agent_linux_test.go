//go:build linux

package nodeops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"webscan/internal/agent"
	"webscan/internal/common"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
	"webscan/internal/persist"
	agentv1 "webscan/sdk/agent/v1"
)

func TestNativeDefinitionPassesSystemdAnalyze(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_SYSTEMD_ANALYZE") != "1" {
		t.Skip("requires explicitly opted-in disposable Linux systemd validator")
	}
	w, r, _ := serviceFixture(t, "native")
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemd-analyze", "verify", "--man=no", filepath.Join(w.configurationDir(r.Spec), nativeServiceName))
	cmd.Env = append(os.Environ(), "SYSTEMD_LOG_LEVEL=warning", "SYSTEMD_COLORS=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real systemd rejected generated unit: %v: %s", err, output)
	}
}

// This test creates the normal fixed Agent data paths only inside an explicitly
// opted-in disposable container. It never adopts or stops an existing service.
func TestGeneratedConfigurationStartsAgentAndRetainsUnconfirmedEvents(t *testing.T) {
	for _, format := range []int{1, 2, 3} {
		t.Run("format-"+strconv.Itoa(format), func(t *testing.T) { testGeneratedConfigurationAgent(t, format) })
	}
}
func TestGeneratedConfigurationAgentResumesExpiredSeed(t *testing.T) {
	testGeneratedConfigurationAgent(t, 2, true)
}

func TestGeneratedConfigurationAgentRecoversExpiredActiveIdentity(t *testing.T) {
	testGeneratedConfigurationAgent(t, 2, false, true)
}

func testGeneratedConfigurationAgent(t *testing.T, format int, historical ...bool) {
	expiredSeed := len(historical) != 0 && historical[0]
	recoverExpired := len(historical) > 1 && historical[1]
	if os.Geteuid() != 0 || os.Getenv("WEBSCAN_V3_TEST_BUNDLE") != "1" {
		t.Skip("requires opted-in disposable Linux scanner container")
	}
	for _, path := range []string{agentDataDirectory, agentLogDirectory} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("refusing existing Agent state", path, err)
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(path) })
	}
	raw, err := os.ReadFile("/usr/local/lib/webscan/agent-native.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	w, r := stageFixture(t, raw)
	w.probe = probeBundle
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	version, err := bundleCommand(ctx, "/usr/local/bin/webscan", "version")
	if err != nil {
		t.Fatal(err)
	}
	r.Spec.Release = strings.TrimSpace(version)
	site := testRoot(t)
	r.Spec.MonitorDirectories = []string{site}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.Spec.MetricsPort = listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	now := time.Now().UTC().Truncate(time.Second)
	caTime := now
	if expiredSeed || recoverExpired {
		caTime = now.Add(-48 * time.Hour)
	}
	ca, err := nodepki.NewAuthority(caTime, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ca.Issue(nodepki.Node, r.Node, []string{"127.0.0.1"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := ca.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ca.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seed, seedCRL := node, crl
	if expiredSeed {
		past := now.Add(-36 * time.Hour)
		seed, err = ca.Issue(nodepki.Node, r.Node, []string{"127.0.0.1"}, past, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		seedCRL, err = ca.Revoke(nil, nil, past, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		crl, err = ca.Revoke(seedCRL, [][]byte{seed.Certificate}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
	}
	if format == 3 || expiredSeed {
		// A real upgrade starts from existing managed state, with no seed in
		// the newly generated configuration. Initialize only this fixture.
		for _, name := range []string{"pki-identity", "pki-trust"} {
			dir := filepath.Join(agentDataDirectory, name)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "ca.crt"), node.CA, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(agentDataDirectory, "pki-trust", "ca.crl"), crl, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := nodepki.PublishIdentity(ctx, filepath.Join(agentDataDirectory, "pki-identity", "ca.crt"), filepath.Join(agentDataDirectory, "pki-identity", "active.pem"), nodepki.Node, r.Node, "", node, now); err != nil {
			t.Fatal(err)
		}
	}
	m := attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
		m.Format = format
		m.ServerName = "127.0.0.1"
		m.CA, m.Certificate, m.Key, m.CRL = seed.CA, seed.Certificate, seed.Key, seedCRL
		if format == 3 {
			m.Certificate, m.Key = nil, nil
		}
	})
	r.Spec.ServerName = m.ServerName
	if _, err := w.Apply(r); err != nil {
		t.Fatal("real bundle/config preparation", err)
	}
	pair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(node.CA)
	configPath := filepath.Join(w.configurationDir(r.Spec), "runtime.json")
	nodeCert, _ := tls.X509KeyPair(node.Certificate, node.Key)
	parsed, _ := x509.ParseCertificate(nodeCert.Certificate[0])
	expectedSerial := parsed.SerialNumber.Text(16)
	start := func() (agentv1.AgentServiceClient, func()) {
		c, err := common.ReadJSON(configPath)
		if err != nil {
			t.Fatal(err)
		}
		a, err := agent.New(c, configPath)
		if err != nil {
			t.Fatal("generated runtime rejected by real Agent", err)
		}
		running, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		startedAt := time.Now().UnixMilli()
		go func() { done <- a.Run(running) }()
		connection, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Spec.MetricsPort)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: m.ServerName, Certificates: []tls.Certificate{pair}})))
		if err != nil {
			stop()
			<-done
			a.Close()
			t.Fatal(err)
		}
		closed := false
		closeAgent := func() {
			if closed {
				return
			}
			closed = true
			connection.Close()
			stop()
			select {
			case err := <-done:
				if err != nil && running.Err() == nil {
					t.Error("Agent stopped unexpectedly", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Agent shutdown did not finish")
			}
			a.Close()
		}
		t.Cleanup(closeAgent)
		rpc := agentv1.NewAgentServiceClient(connection)
		for {
			call, cancel := context.WithTimeout(ctx, time.Second)
			var actualPeer peer.Peer
			capability, err := rpc.Capabilities(call, &agentv1.CapabilitiesRequest{}, grpc.Peer(&actualPeer))
			cancel()
			if err == nil {
				auth, ok := actualPeer.AuthInfo.(credentials.TLSInfo)
				if !ok || len(auth.State.PeerCertificates) < 1 || auth.State.PeerCertificates[0].SerialNumber.Text(16) != expectedSerial {
					t.Fatal("generated Agent served wrong active identity")
				}
				if capability.NodeId != r.Node || capability.ConfigurationVersion != m.Version || capability.ConfigurationSha256 != m.SourceSHA256 {
					t.Fatal("listener did not load task-bound identity/configuration", capability)
				}
				metrics, err := rpc.ReadMetrics(ctx, &agentv1.ReadMetricsRequest{AfterUnixMillis: startedAt - 1})
				if err == nil {
					for _, sample := range metrics.Samples {
						if strings.Contains(string(sample.PrometheusText), "webscan_collector_ready 1\n") && strings.Contains(string(sample.PrometheusText), "webscan_coverage_ok 1\n") {
							return rpc, closeAgent
						}
					}
				}
			}
			select {
			case err := <-done:
				closed = true
				connection.Close()
				stop()
				a.Close()
				t.Fatal("Agent failed before readiness", err)
			case <-ctx.Done():
				t.Fatal("generated runtime never became ready", ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	rpc, stopAgent := start()
	file := filepath.Join(site, "created.php")
	if err := os.WriteFile(file, []byte("<?php echo 'isolated';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	find := func(rpc agentv1.AgentServiceClient, epoch uint64, path string) (*agentv1.EventBatch, string) {
		for {
			batch, err := rpc.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: epoch, Limit: 100, WaitSeconds: 1})
			if err != nil {
				t.Fatal("read generated Agent events", err)
			}
			for _, event := range batch.Events {
				var payload map[string]any
				if err := json.Unmarshal(event.Json, &payload); err != nil {
					t.Fatal(err)
				}
				if payload["path"] == path {
					return batch, event.Id
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("new file was not captured", ctx.Err())
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	_, beforeID := find(rpc, 1, file)
	// Service control is simulated here, while the actual Agent holds its real
	// lifetime flock. Even a misleading "stopped" result cannot back up a live
	// writer. This does not claim an actual systemd/Docker lifecycle test.
	r.Phase = "backup"
	host := &backupHostFixture{installed: Installation{Node: r.Node, Generation: "v3", Mode: "native", Runtime: configPath, Services: []ServiceRecord{}}}
	backup := &transitionBackup{root: w.root, data: agentDataDirectory, logs: agentLogDirectory, host: host}
	if _, err := backup.run(ctx, r); err == nil || err.Error() != "unmanaged-agent-writer-active" {
		t.Fatal("actual Agent writer lock ignored", err)
	}
	if format >= 2 {
		metrics := common.M(mustReadAgentRuntime(t, configPath)["metrics"])
		file := common.S(metrics["identity_file"])
		caFile := common.S(metrics["ca_file"])
		b, current, err := nodepki.ReadIdentity(caFile, file, nodepki.Node, r.Node, time.Now())
		clear(b.Key)
		if err != nil {
			t.Fatal(err)
		}
		request, err := nodepki.PrepareNodeRenewal(ctx, caFile, file, r.Node, current.CertificateSHA256, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		issuer := filepath.Join(w.root, "test-issuer")
		privateCA, err := ca.Export()
		if err != nil {
			t.Fatal(err)
		}
		if err := nodepki.SeedAuthority(ctx, issuer, privateCA, crl, now); err != nil {
			t.Fatal(err)
		}
		clear(privateCA.Key)
		var certificate []byte
		if err := nodepki.SignNodeRenewalRegistered(ctx, issuer, request, now, 2*time.Hour, func(b nodepki.Bundle, _ []byte) error {
			if len(b.Key) != 0 {
				t.Fatal("signer returned private leaf key")
			}
			certificate = append([]byte{}, b.Certificate...)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		trust, err := nodepki.NewTrust(node.CA, crl, now)
		if err != nil {
			t.Fatal(err)
		}
		record, err := nodepki.ActivateNodeRenewal(ctx, caFile, file, r.Node, current.CertificateSHA256, request.SHA256(), certificate, time.Now(), func(cert *x509.Certificate) error { return trust.Verify(cert, nodepki.Node, r.Node, time.Now()) })
		if err != nil {
			t.Fatal(err)
		}
		expectedSerial = record.Serial
	}
	stopAgent() // Leave the event unconfirmed and start with the same SQLite.
	if recoverExpired {
		// Construct an already-expired active identity without changing the
		// process clock or weakening TLS. This fixture alone writes the file;
		// actual recovery below uses the normal CAS/private-history APIs.
		metrics := common.M(mustReadAgentRuntime(t, configPath)["metrics"])
		identityFile, caFile := common.S(metrics["identity_file"]), common.S(metrics["ca_file"])
		past := now.Add(-36 * time.Hour)
		expired, err := ca.Issue(nodepki.Node, r.Node, []string{m.ServerName}, past, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(expired.Key)
		old := append(append([]byte{}, expired.Certificate...), expired.Key...)
		defer clear(old)
		if err := os.WriteFile(identityFile, old, 0600); err != nil {
			t.Fatal(err)
		}
		c, err := common.ReadJSON(configPath)
		if err != nil {
			t.Fatal(err)
		}
		unready, err := agent.New(c, configPath)
		if err != nil {
			t.Fatal(err)
		}
		attempt, stop := context.WithTimeout(ctx, 2*time.Second)
		err = unready.Run(attempt)
		stop()
		unready.Close()
		if err == nil || attempt.Err() == context.DeadlineExceeded {
			t.Fatal("actual Agent did not reject expired active identity before startup", err)
		}
		unchanged, _ := os.ReadFile(identityFile)
		if !bytes.Equal(unchanged, old) {
			t.Fatal("Agent silently fell back to the still-valid installation seed")
		}
		pair, err := tls.X509KeyPair(expired.Certificate, expired.Key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(pair.Certificate[0])
		// Bind the DER CA fingerprint, never the leaf or PEM encoding.
		rootPEM, _ := pem.Decode(node.CA)
		rootCert, err := x509.ParseCertificate(rootPEM.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		parentSHA, authoritySHA := sha256.Sum256(leaf.Raw), sha256.Sum256(rootCert.Raw)
		intent, err := nodepki.NewNodeRecoveryIntent(r.Node, hex.EncodeToString(authoritySHA[:]), hex.EncodeToString(parentSHA[:]), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// The fixed-path production helper performs the local recovery phases.
		// Only the installation's finalized service journal is simulated here;
		// the Agent, TLS, SQLite events and private key files are real.
		writeHelperRecoveryInstallation(t, w, r, m)
		input := IdentityRecoveryInput{Format: 1, Operation: "prepare", Intent: intent, CRL: crl}
		prepared, err := w.identityRecovery(ctx, input)
		if err != nil {
			t.Fatal("local expired identity recovery preparation", err)
		}
		request, err := nodepki.ParseNodeRecoveryRequest(prepared.Request)
		if err != nil {
			t.Fatal("helper returned invalid recovery request", err)
		}
		var certificate []byte
		if err := nodepki.SignNodeRecoveryRegistered(ctx, filepath.Join(w.root, "test-issuer"), request, intent, time.Now(), 3*time.Hour, func(b nodepki.Bundle, _ []byte) error {
			if len(b.Key) != 0 {
				t.Fatal("recovery issuer returned a node private key")
			}
			certificate = append([]byte{}, b.Certificate...)
			return nil
		}); err != nil {
			t.Fatal("isolated recovery issuance", err)
		}
		input.Operation, input.Request, input.Certificate = "activate", prepared.Request, certificate
		activated, err := w.identityRecovery(ctx, input)
		if err != nil {
			t.Fatal("recovery did not activate local pending key", err)
		}
		b, recovered, err := nodepki.ReadIdentity(caFile, identityFile, nodepki.Node, r.Node, time.Now())
		clear(b.Key)
		if err != nil || recovered.CertificateSHA256 != activated.CertificateSHA256 {
			t.Fatal("helper activation did not match actual identity", err)
		}
		prior, err := os.ReadFile(identityFile + ".history/" + intent.CertificateSHA256 + ".pem")
		if err != nil || !bytes.Equal(prior, old) {
			t.Fatal("expired private identity was not retained", err)
		}
		expectedSerial = recovered.Serial
	}
	backupReceipt, err := backup.run(ctx, r)
	if err != nil {
		t.Fatal("stopped real Agent could not be backed up", err)
	}
	expectedIdentityFiles := 6
	if recoverExpired {
		expectedIdentityFiles += 3
	}
	if format >= 2 && len(backupReceipt.IdentityState) != expectedIdentityFiles {
		t.Fatal("active node identity, pin, private history or pending CSR key not backed up", len(backupReceipt.IdentityState))
	}
	rpc, stopAgent = start()
	batch, afterID := find(rpc, 2, file)
	if beforeID != afterID {
		t.Fatal("restart replaced or lost the original event ID")
	}
	ack, err := rpc.AckEvents(ctx, &agentv1.AckEventsRequest{Epoch: 2, Receipt: batch.Receipt, Accepted: []string{afterID}})
	if err != nil || ack.Confirmed != 1 {
		t.Fatal("confirmed original event was not acknowledged", ack, err)
	}
	newFile := filepath.Join(site, "after-snapshot.php")
	if err := os.WriteFile(newFile, []byte("<?php echo 'post-switch';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, newID := find(rpc, 2, newFile)
	stopAgent()
	r.Phase = "restore"
	if count, err := backup.exportRollbackPending(ctx, r, host.installed); err != nil || count < 1 {
		t.Fatal("real Agent pending events could not be re-exported", count, err)
	}
	db, err := persist.OpenReadOnly(filepath.Join(agentDataDirectory, "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var unconfirmed, confirmed int
	if err := db.QueryRow("SELECT count(*) FROM events WHERE id=? AND accepted IS NULL AND exported IS NOT NULL", newID).Scan(&unconfirmed); err != nil || unconfirmed != 1 {
		t.Fatal("post-snapshot event lost during rollback export", err)
	}
	if err := db.QueryRow("SELECT count(*) FROM events WHERE id=? AND accepted IS NOT NULL", beforeID).Scan(&confirmed); err != nil || confirmed != 1 {
		t.Fatal("acknowledgment overwritten by old snapshot", err)
	}
	snapshot, err := persist.OpenReadOnly(filepath.Join(backup.directory(r), "snapshot", "agent.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if err := snapshot.QueryRow("SELECT count(*) FROM events WHERE id=? AND accepted IS NULL", beforeID).Scan(&unconfirmed); err != nil || unconfirmed != 1 {
		t.Fatal("original snapshot modified during rollback export", err)
	}
}

func mustReadAgentRuntime(t *testing.T, path string) common.Map {
	t.Helper()
	c, err := common.ReadJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
