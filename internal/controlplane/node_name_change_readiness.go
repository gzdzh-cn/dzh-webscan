package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

var errNodeNameChangeNotReady = errors.New("名称变更后的节点尚未完成双名称验证及采集验收")

// Confirm the overlap identity through two fresh, normally verified TLS
// connections to the ORIGINAL active endpoint. The second uses the saved new
// TLS name; it does not claim a new endpoint/listener/config has been applied.
// No JSON certificate claim can stand in for either actual peer observation.
func (w *sshNodeNameChange) observeAndConfirm(ctx context.Context, l Lease, id string) error {
	if !w.ready() {
		return errNodeNameChange
	}
	j, err := w.store.checkNodeNameChangeLease(ctx, w.vault, l, id)
	if err != nil || j.Status != "signed" {
		return errNodeNameChange
	}
	n, err := scanActiveNode(w.store.DB.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, j.Node))
	if err != nil || n.RuntimeEpoch != j.RuntimeEpoch || n.ServerName != j.SourceName {
		return errNodeNameChange
	}
	var certificate []byte
	if err := w.store.DB.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2 AND request_kind='name-change'`, j.Node, j.ParentSHA256).Scan(&certificate); err != nil {
		return errNodeNameChange
	}
	issued, err := provisioningCertificate(certificate)
	if err != nil {
		return errNodeNameChange
	}
	crl, err := w.currentCRL(ctx, j)
	if err != nil {
		return err
	}
	ca, _, err := provisioningCertificateIssuer(w.config, issued, time.Now())
	if err != nil {
		return errNodeNameChange
	}
	trust, err := nodepki.NewTrust(ca, crl, time.Now())
	if err != nil {
		return errNodeNameChange
	}
	self, err := collectorIdentityMaterial(w.config, time.Now())
	defer clear(self.Key)
	if err != nil {
		return errNodeNameChange
	}
	collector, err := provisioningCertificate(self.Certificate)
	if err != nil {
		return errNodeNameChange
	}
	collectorID, err := nodepki.PeerID(collector, nodepki.Collector)
	if err != nil || trust.Verify(collector, nodepki.Collector, collectorID, time.Now()) != nil {
		return errNodeNameChange
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx, deadline := context.WithDeadline(ctx, j.ExpiresAt)
	defer deadline()
	var observed *x509.Certificate
	for _, name := range []string{j.SourceName, j.TargetName} {
		observed, err = w.observeName(ctx, n, j, name, issued, trust, name == j.SourceName)
		if err != nil {
			return err
		}
		if _, err := w.store.checkNodeNameChangeLease(ctx, w.vault, l, id); err != nil {
			return err
		}
	}
	return w.store.confirmNodeNameChange(ctx, w.config, w.vault, l, id, observed)
}

func (w *sshNodeNameChange) observeName(ctx context.Context, n Node, j nodeNameChangeJob, name string, issued *x509.Certificate, trust *nodepki.Trust, metrics bool) (*x509.Certificate, error) {
	return observeMaintainedNodeIdentity(ctx, w.config, n, name, issued, trust, metrics, j.Intent.IssuedAt)
}

func observeMaintainedNodeIdentity(ctx context.Context, config Config, n Node, name string, issued *x509.Certificate, trust *nodepki.Trust, metrics bool, since time.Time) (*x509.Certificate, error) {
	t, err := CollectorTLS(config)
	if err != nil {
		return nil, errNodeNameChange
	}
	t.ServerName = name
	t.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 || digest(state.PeerCertificates[0].Raw) != digest(issued.Raw) {
			return nodepki.ErrIdentity
		}
		return trust.Verify(state.PeerCertificates[0], nodepki.Node, n.ID, time.Now())
	}
	connection, err := grpc.NewClient(n.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(t)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(agentv1.MaxBytes)))
	if err != nil {
		return nil, errNodeNameChange
	}
	defer connection.Close()
	var observed peer.Peer
	client := agentv1.NewAgentServiceClient(connection)
	cap, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{}, grpc.Peer(&observed))
	if err != nil {
		return nil, errNodeNameChangeNotReady
	}
	if !validCapabilities(n, cap) || cap.ConfigurationVersion != n.Version || cap.ConfigurationSha256 != digest(n.Config) || cap.CertificateSha256 != digest(issued.Raw) || cap.CertificateNotAfterUnix != issued.NotAfter.Unix() {
		return nil, errNodeNameChange
	}
	auth, ok := observed.AuthInfo.(credentials.TLSInfo)
	if !ok || !auth.State.HandshakeComplete || len(auth.State.VerifiedChains) == 0 || len(auth.State.PeerCertificates) != 1 || digest(auth.State.PeerCertificates[0].Raw) != digest(issued.Raw) {
		return nil, errNodeNameChange
	}
	if metrics {
		var metricsPeer peer.Peer
		batch, err := client.ReadMetrics(ctx, &agentv1.ReadMetricsRequest{AfterUnixMillis: time.Now().Add(-60 * time.Second).UnixMilli()}, grpc.Peer(&metricsPeer))
		if err != nil {
			return nil, errNodeNameChangeNotReady
		}
		metricAuth, ok := metricsPeer.AuthInfo.(credentials.TLSInfo)
		if !ok || !metricAuth.State.HandshakeComplete || len(metricAuth.State.VerifiedChains) == 0 || len(metricAuth.State.PeerCertificates) != 1 || digest(metricAuth.State.PeerCertificates[0].Raw) != digest(issued.Raw) {
			return nil, errNodeNameChange
		}
		if !validRecoveryMetrics(n, batch, time.Now(), since) {
			return nil, errNodeNameChangeNotReady
		}
	}
	return auth.State.PeerCertificates[0], nil
}
