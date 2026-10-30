//go:build linux

package nodeops

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

func TestNativeSystemdKernelIdentityRecoveryRetainsEvents(t *testing.T) {
	runNativeSystemdKernelLifecycle(t, false, true)
}

func TestDockerKernelIdentityRecoveryRetainsEvents(t *testing.T) {
	requireDockerKernelGuest(t)
	runDockerEngineLifecycle(t, true, true)
}

// Only called after a real installation finalized inside the guarded,
// networkless full-kernel guests. The fixture writes a historical expired
// identity while the owned service is stopped; everything thereafter uses
// production helper operations and the actual systemd/Docker service manager.
func recoverKernelIdentity(t *testing.T, ctx context.Context, w *LocalRuntime, r Request, m nodeconfig.Material, ca *nodepki.Authority, collector nodepki.Bundle, crl []byte, eventID string) {
	t.Helper()
	host := newInstallationHost(w.root)
	i, err := host.inventory(ctx, r.Node, r.Spec.Mode)
	if err != nil || len(i.Services) != 1 || !i.Services[0].Running || !i.Services[0].Enabled {
		t.Fatal("kernel recovery requires finalized running owned service", err)
	}
	s := i.Services[0]
	locked, release, err := acquireServiceOperation(ctx, w.root)
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind == "native" {
		_, err = host.command(locked, "systemctl", "stop", nativeServiceName)
	} else {
		_, err = host.docker(locked, "stop", s.ID)
	}
	release()
	if err != nil {
		t.Fatal("stop only the owned disposable service", err)
	}
	expired, err := ca.Issue(nodepki.Node, r.Node, []string{m.ServerName}, time.Now().Add(-24*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(expired.Key)
	identityDir := filepath.Join(agentDataDirectory, "pki-identity")
	identity := filepath.Join(identityDir, "active.pem")
	old := append(append([]byte{}, expired.Certificate...), expired.Key...)
	defer clear(old)
	if err := os.WriteFile(identity, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := nodepki.ReadIdentity(filepath.Join(identityDir, "ca.crt"), identity, nodepki.Node, r.Node, time.Now()); err == nil {
		t.Fatal("expired fixture usable as a normal live identity")
	}
	intent, err := nodepki.NewNodeRecoveryIntent(r.Node, sha(recoveryTestCertificate(t, expired.CA).Raw), sha(recoveryTestCertificate(t, expired.Certificate).Raw), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A real short-lived authorization makes expiry-after-activation testable
	// without changing clocks, trust rules or waiting the full ten minutes.
	intent.ExpiresAt = intent.IssuedAt.Add(45 * time.Second)
	in := IdentityRecoveryInput{Format: 1, Operation: "prepare", Intent: intent, CRL: crl}
	prepared, err := w.identityRecovery(ctx, in)
	if err != nil {
		t.Fatal("prepare from actual finalized installation", err)
	}
	request, err := nodepki.ParseNodeRecoveryRequest(prepared.Request)
	if err != nil {
		t.Fatal(err)
	}
	issuer := testRoot(t)
	b, err := ca.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	if err := os.Mkdir(filepath.Join(issuer, "crls"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"ca.crt": b.CA, "ca.key": b.Key, "ca.crl": crl, "crls/1.pem": crl} {
		if err := os.WriteFile(filepath.Join(issuer, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := nodepki.SignNodeRecoveryRegistered(ctx, issuer, request, intent, time.Now(), 3*time.Hour, func(b nodepki.Bundle, _ []byte) error {
		in.Certificate = b.Certificate
		if len(b.Key) != 0 {
			t.Fatal("node key left the kernel guest")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	in.Operation, in.Request = "activate", prepared.Request
	activated, err := w.identityRecovery(ctx, in)
	if err != nil {
		t.Fatal("kernel identity activation", err)
	}
	in.Operation = "start"
	wait := time.NewTimer(time.Until(intent.ExpiresAt) + 50*time.Millisecond)
	select {
	case <-ctx.Done():
		wait.Stop()
		t.Fatal("kernel recovery deadline before authorization expiry", ctx.Err())
	case <-wait.C:
	}
	if _, err := w.identityRecovery(ctx, in); err == nil {
		t.Fatal("expired original authorization started real service")
	}
	fresh, err := nodepki.NewNodeRecoveryIntent(intent.Node, intent.AuthoritySHA256, intent.CertificateSHA256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in.Operation, in.Intent, in.Request = "reconcile", fresh, nil
	reconciled, err := w.identityRecovery(ctx, in)
	if err != nil {
		t.Fatal("kernel continuation under fresh authorization", err)
	}
	continuation, err := nodepki.ParseNodeRecoveryRequest(reconciled.Request)
	if err != nil || continuation.Renewal.SHA256() != request.Renewal.SHA256() || !bytes.Equal(continuation.ContinuationCertificate, in.Certificate) {
		t.Fatal("kernel continuation did not prove same active issuance", err)
	}
	in.Operation, in.Request = "activate", reconciled.Request
	if receipt, err := w.identityRecovery(ctx, in); err != nil || receipt.CertificateSHA256 != activated.CertificateSHA256 {
		t.Fatal("kernel continuation activation reconciliation", err)
	}
	in.Operation = "start"
	started, err := w.identityRecovery(ctx, in)
	if err != nil || started.CertificateSHA256 != activated.CertificateSHA256 {
		t.Fatal("controlled real service start", err)
	}
	// Use a fresh connection and actual Peer TLSInfo, never the helper receipt.
	pair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(b.CA)
	connection, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Spec.MetricsPort)), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: m.ServerName, RootCAs: roots, Certificates: []tls.Certificate{pair}})))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	rpc := agentv1.NewAgentServiceClient(connection)
	for {
		call, cancel := context.WithTimeout(ctx, time.Second)
		var actual peer.Peer
		cap, err := rpc.Capabilities(call, &agentv1.CapabilitiesRequest{}, grpc.Peer(&actual))
		cancel()
		if err == nil {
			tlsInfo, ok := actual.AuthInfo.(credentials.TLSInfo)
			if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.PeerCertificates) != 1 || sha(tlsInfo.State.PeerCertificates[0].Raw) != activated.CertificateSHA256 || cap.CertificateSha256 != activated.CertificateSHA256 || cap.NodeId != r.Node || cap.ConfigurationVersion != m.Version || cap.ConfigurationSha256 != m.SourceSHA256 {
				t.Fatal("recovered actual mTLS peer/configuration mismatch")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("recovered actual Agent not ready", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	state := func() string {
		t.Helper()
		if s.Kind == "native" {
			status, err := host.native(ctx, s)
			if err != nil || status.MainPID < 1 {
				t.Fatal("actual recovered PID missing", err)
			}
			return strconv.Itoa(status.MainPID)
		}
		d, err := host.dockerRuntime(ctx, s.ID)
		if err != nil || !d.State.Running || d.State.Pid < 1 {
			t.Fatal("actual recovered immutable container missing", err)
		}
		raw, _ := json.Marshal([]any{s.ID, d.State.Pid, d.State.StartedAt, d.RestartCount})
		return string(raw)
	}
	before := state()
	if _, err := w.identityRecovery(ctx, in); err != nil || state() != before {
		t.Fatal("lost response retried by restarting the actual service", err)
	}
	in.Operation = "verify"
	if verified, err := w.identityRecovery(ctx, in); err != nil || !verified.ResourcesVerified || verified.CertificateSHA256 != activated.CertificateSHA256 || state() != before {
		t.Fatal("recovered actual kernel resource policy not proven without restart", err)
	}
	prior, err := os.ReadFile(identity + ".history/" + intent.CertificateSHA256 + ".pem")
	if err != nil || !bytes.Equal(prior, old) {
		t.Fatal("kernel recovery lost original private identity", err)
	}
	newFile := filepath.Join(r.Spec.MonitorDirectories[0], "after-identity-recovery.php")
	if err := os.WriteFile(newFile, []byte("<?php echo 'post-recovery';\n"), 0600); err != nil {
		t.Fatal(err)
	}
	found, newID := false, ""
	for !found || newID == "" {
		batch, err := rpc.FetchEvents(ctx, &agentv1.FetchEventsRequest{Epoch: 1, Limit: 100, WaitSeconds: 1})
		if err != nil {
			t.Fatal("recovered Agent cannot replay unconfirmed events", err)
		}
		for _, event := range batch.Events {
			found = found || event.Id == eventID
			var payload map[string]any
			if json.Unmarshal(event.Json, &payload) == nil && payload["path"] == newFile {
				newID = event.Id
			}
		}
		if ctx.Err() != nil {
			t.Fatal("recovery lost original unconfirmed event", ctx.Err())
		}
	}
	if newID == eventID {
		t.Fatal("post-recovery event reused the original event ID")
	}
	t.Logf("actual %s recovery continued after original authorization expired, retained original/new events, private history and runtime on retry", s.Kind)
}
