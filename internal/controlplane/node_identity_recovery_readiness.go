package controlplane

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"webscan/internal/nodepki"
	"webscan/internal/telemetry"
	agentv1 "webscan/sdk/agent/v1"
)

var errNodeIdentityRecoveryNotReady = errors.New("恢复后的节点尚未完成采集、覆盖和扫描验收")

// Completion uses an actual newly authenticated connection. No caller can
// supply a certificate, capability JSON or arbitrary probe address instead.
// The service must already be running (owned-service startup is separate).
func (w *sshNodeIdentityRecovery) observeAndConfirm(ctx context.Context, l Lease, id string) error {
	if !w.ready() {
		return errNodeIdentityRecovery
	}
	j, err := w.store.checkNodeIdentityRecoveryLease(ctx, w.vault, l, id)
	if err != nil || j.Status != "signed" {
		return errNodeIdentityRecovery
	}
	n, err := scanActiveNode(w.store.DB.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, j.Node))
	if err != nil || n.RuntimeEpoch != j.RuntimeEpoch {
		return errNodeIdentityRecovery
	}
	var certificate []byte
	if err := w.store.DB.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2`, j.Node, j.ParentSHA256).Scan(&certificate); err != nil {
		return errNodeIdentityRecovery
	}
	issued, err := provisioningCertificate(certificate)
	if err != nil {
		return errNodeIdentityRecovery
	}
	crl, err := w.currentCRL(ctx, j)
	if err != nil {
		return err
	}
	ca, err := readTrustData(w.config.Collector.CAFile, false, 64<<10)
	if err != nil {
		return errNodeIdentityRecovery
	}
	trust, err := nodepki.NewTrust(ca, crl, time.Now())
	if err != nil {
		return errNodeIdentityRecovery
	}
	self, err := collectorIdentityMaterial(w.config, time.Now())
	defer clear(self.Key)
	if err != nil {
		return errNodeIdentityRecovery
	}
	collector, err := provisioningCertificate(self.Certificate)
	if err != nil {
		return errNodeIdentityRecovery
	}
	collectorID, err := nodepki.PeerID(collector, nodepki.Collector)
	if err != nil || trust.Verify(collector, nodepki.Collector, collectorID, time.Now()) != nil {
		return errNodeIdentityRecovery
	}
	t, err := CollectorTLS(w.config)
	if err != nil {
		return fmt.Errorf("identity-recovery-collector-tls: %w", errNodeIdentityRecovery)
	}
	t.ServerName = n.ServerName
	t.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 || digest(state.PeerCertificates[0].Raw) != digest(issued.Raw) {
			return nodepki.ErrIdentity
		}
		return trust.Verify(state.PeerCertificates[0], nodepki.Node, n.ID, time.Now())
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx, deadline := context.WithDeadline(ctx, j.ExpiresAt)
	defer deadline()
	connection, err := grpc.NewClient(n.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(t)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(agentv1.MaxBytes)))
	if err != nil {
		return errNodeIdentityRecovery
	}
	defer connection.Close()
	var observed peer.Peer
	cap, err := agentv1.NewAgentServiceClient(connection).Capabilities(ctx, &agentv1.CapabilitiesRequest{}, grpc.Peer(&observed))
	if err != nil {
		return fmt.Errorf("identity-recovery-readiness-rpc: %w", errNodeIdentityRecoveryNotReady)
	}
	if !validCapabilities(n, cap) || cap.ConfigurationVersion != n.Version || cap.ConfigurationSha256 != digest(n.Config) || cap.CertificateSha256 != digest(issued.Raw) || cap.CertificateNotAfterUnix != issued.NotAfter.Unix() {
		return fmt.Errorf("identity-recovery-readiness-capability: %w", errNodeIdentityRecovery)
	}
	auth, ok := observed.AuthInfo.(credentials.TLSInfo)
	if !ok || !auth.State.HandshakeComplete || len(auth.State.VerifiedChains) == 0 || len(auth.State.PeerCertificates) != 1 || digest(auth.State.PeerCertificates[0].Raw) != digest(issued.Raw) {
		return fmt.Errorf("identity-recovery-readiness-peer: %w", errNodeIdentityRecovery)
	}
	// Read current readiness on this authenticated connection, not a historical
	// SQL status or the startup receipt. A running process with missing watches,
	// stale rules, or an unavailable configured scanner is not recovered.
	var metricsPeer peer.Peer
	batch, err := agentv1.NewAgentServiceClient(connection).ReadMetrics(ctx, &agentv1.ReadMetricsRequest{AfterUnixMillis: time.Now().Add(-60 * time.Second).UnixMilli()}, grpc.Peer(&metricsPeer))
	if err != nil {
		return fmt.Errorf("identity-recovery-readiness-metrics: %w", errNodeIdentityRecoveryNotReady)
	}
	metricAuth, ok := metricsPeer.AuthInfo.(credentials.TLSInfo)
	if !ok || !metricAuth.State.HandshakeComplete || len(metricAuth.State.VerifiedChains) == 0 || len(metricAuth.State.PeerCertificates) != 1 || digest(metricAuth.State.PeerCertificates[0].Raw) != digest(issued.Raw) {
		return errNodeIdentityRecovery
	}
	if !validRecoveryMetrics(n, batch, time.Now(), j.Intent.IssuedAt) {
		return errNodeIdentityRecoveryNotReady
	}
	return w.store.confirmNodeIdentityRecovery(ctx, w.config, w.vault, l, id, auth.State.PeerCertificates[0])
}

func validRecoveryMetrics(n Node, batch *agentv1.MetricsBatch, now, notBefore time.Time) bool {
	if batch == nil || batch.NodeId != n.ID || len(batch.Samples) == 0 || len(batch.Samples) > 128 {
		return false
	}
	var last int64
	bytes := 0
	for _, sample := range batch.Samples {
		if sample == nil || sample.UnixMillis <= last || len(sample.PrometheusText) == 0 {
			return false
		}
		last = sample.UnixMillis
		bytes += len(sample.PrometheusText)
		if bytes > agentv1.MaxBytes {
			return false
		}
	}
	latest := batch.Samples[len(batch.Samples)-1]
	metrics, err := telemetry.Parse(string(latest.PrometheusText))
	if err != nil {
		return false
	}
	values := map[string]float64{}
	canonicalDeploymentHealth(metrics, values)
	return validDeploymentHealth(n.Config, values, latest.UnixMillis, now, notBefore)
}
