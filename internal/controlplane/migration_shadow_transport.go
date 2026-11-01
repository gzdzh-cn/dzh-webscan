package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

type migrationShadowVerifier interface {
	Verify(*x509.Certificate, string, string, time.Time) error
}

// Rebuild verification exclusively in memory. NewPersistentFileTrust would
// update a CRL floor and is intentionally forbidden in the shadow path.
func migrationShadowTrust(c Config, now time.Time) (migrationShadowVerifier, error) {
	ca, err := readTrustData(c.Collector.CAFile, false, 64<<10)
	if err != nil || c.Collector.RevocationFile == "" {
		return nil, ErrMigrationShadow
	}
	current, err := readTrustData(c.Collector.RevocationFile, false, nodepki.MaxCRLBytes)
	if err != nil {
		return nil, ErrMigrationShadow
	}
	if c.Collector.RevocationStateDirectory != "" {
		roots, _, err := nodepki.ReadRootSet(c.Collector.RevocationStateDirectory, ca, now)
		if err != nil {
			return nil, ErrMigrationShadow
		}
		if roots != nil {
			return roots, nil
		}
		pinned, err := readTrustData(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crt"), true, 64<<10)
		if err != nil {
			return nil, ErrMigrationShadow
		}
		first, _ := pem.Decode(ca)
		second, _ := pem.Decode(pinned)
		if first == nil || second == nil || !bytes.Equal(first.Bytes, second.Bytes) {
			return nil, ErrMigrationShadow
		}
		floor, err := readTrustData(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crl"), true, nodepki.MaxCRLBytes)
		if err != nil {
			return nil, ErrMigrationShadow
		}
		block, _ := pem.Decode(floor)
		if block == nil {
			return nil, ErrMigrationShadow
		}
		list, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, ErrMigrationShadow
		}
		trust, err := nodepki.NewTrust(ca, floor, list.ThisUpdate)
		if err != nil || trust.UpdateCRL(current, now) != nil {
			return nil, ErrMigrationShadow
		}
		return trust, nil
	}
	trust, err := nodepki.NewTrust(ca, current, now)
	if err != nil {
		return nil, ErrMigrationShadow
	}
	return trust, nil
}

func migrationShadowTLS(c Config) (*tls.Config, error) {
	trust, err := migrationShadowTrust(c, time.Now())
	if err != nil {
		return nil, err
	}
	t, err := CollectorTLS(c)
	if err != nil {
		return nil, ErrMigrationShadow
	}
	material, err := collectorIdentityMaterial(c, time.Now())
	defer clear(material.Key)
	if err != nil {
		return nil, ErrMigrationShadow
	}
	pair, err := tls.X509KeyPair(material.Certificate, material.Key)
	if err != nil || len(pair.Certificate) != 1 {
		return nil, ErrMigrationShadow
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, ErrMigrationShadow
	}
	id, err := nodepki.PeerID(cert, nodepki.Collector)
	if err != nil || trust.Verify(cert, nodepki.Collector, id, time.Now()) != nil {
		return nil, ErrMigrationShadow
	}
	// One already-fixed identity for this run, without live certificate reload,
	// identity maintenance callbacks or writes to the authority/trust directory.
	t.GetClientCertificate = nil
	t.Certificates = []tls.Certificate{pair}
	return t, nil
}

func migrationShadowVerifyPeer(c Config, target migrationShadowTarget, p peer.Peer) (string, error) {
	auth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || !auth.State.HandshakeComplete || len(auth.State.VerifiedChains) == 0 || len(auth.State.PeerCertificates) != 1 {
		return "", ErrMigrationShadow
	}
	trust, err := migrationShadowTrust(c, time.Now())
	if err != nil || trust.Verify(auth.State.PeerCertificates[0], nodepki.Node, target.Node, time.Now()) != nil {
		return "", ErrMigrationShadow
	}
	return digest(auth.State.PeerCertificates[0].Raw), nil
}

func migrationShadowObserve(ctx context.Context, c Config, base *tls.Config, target migrationShadowTarget) MigrationShadowEvidence {
	out := MigrationShadowEvidence{Node: target.Node, SavedVersion: target.Version, SavedConfigSHA256: target.ConfigSHA, Status: "failed", Reason: "authenticated-read-failed", ObservedAt: time.Now().UTC()}
	t := base.Clone()
	t.ServerName = target.ServerName
	t.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 {
			return ErrMigrationShadow
		}
		trust, err := migrationShadowTrust(c, time.Now())
		if err != nil {
			return ErrMigrationShadow
		}
		return trust.Verify(state.PeerCertificates[0], nodepki.Node, target.Node, time.Now())
	}
	connection, err := grpc.NewClient(target.Endpoint, grpc.WithTransportCredentials(credentials.NewTLS(t)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(agentv1.MaxBytes), grpc.MaxCallSendMsgSize(agentv1.MaxBytes)), grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, connection *grpc.ClientConn, invoke grpc.UnaryInvoker, options ...grpc.CallOption) error {
		if method != agentv1.AgentService_Capabilities_FullMethodName && method != agentv1.AgentService_ReadMetrics_FullMethodName {
			return ErrMigrationShadow
		}
		return invoke(ctx, method, req, reply, connection, options...)
	}))
	if err != nil {
		return out
	}
	defer connection.Close()
	client := agentv1.NewAgentServiceClient(connection)
	var capabilitiesPeer peer.Peer
	capabilities, err := client.Capabilities(ctx, &agentv1.CapabilitiesRequest{}, grpc.Peer(&capabilitiesPeer))
	if err != nil || !validCapabilities(Node{ID: target.Node}, capabilities) {
		return out
	}
	certificate, err := migrationShadowVerifyPeer(c, target, capabilitiesPeer)
	if err != nil {
		return out
	}
	out.PeerCertificate = certificate
	out.Protocol = capabilities.Protocol
	out.AgentConfigVersion = capabilities.ConfigurationVersion
	out.AgentConfigSHA256 = capabilities.ConfigurationSha256
	out.MatchesSaved = capabilities.ConfigurationVersion == target.Version && capabilities.ConfigurationSha256 == target.ConfigSHA
	var metricsPeer peer.Peer
	batch, err := client.ReadMetrics(ctx, &agentv1.ReadMetricsRequest{AfterUnixMillis: 0}, grpc.Peer(&metricsPeer))
	if err != nil || batch == nil || batch.NodeId != target.Node || len(batch.Samples) == 0 || len(batch.Samples) > 120 {
		return out
	}
	actual, err := migrationShadowVerifyPeer(c, target, metricsPeer)
	if err != nil || actual != certificate {
		return out
	}
	// Parse bounded original samples, but never derive health, write VM, advance
	// a live cursor or invoke the event protocol. Existing gaps remain gaps.
	if parsed, err := BuildMetrics(target.Node, batch.Samples); err != nil || len(parsed) == 0 {
		return out
	}
	for _, sample := range batch.Samples {
		if sample.UnixMillis < time.Now().Add(-65*time.Minute).UnixMilli() {
			return out
		}
	}
	raw, err := json.Marshal(batch)
	if err != nil || len(raw) > 3<<20 {
		return out
	}
	out.Status, out.Reason = "observed", ""
	if !out.MatchesSaved {
		out.Reason = "saved-configuration-not-running"
	}
	out.Samples = len(batch.Samples)
	out.FirstSample = batch.Samples[0].UnixMillis
	out.LastSample = batch.Samples[len(batch.Samples)-1].UnixMillis
	out.SampleSHA256 = digest(raw)
	out.ObservedAt = time.Now().UTC()
	return out
}
