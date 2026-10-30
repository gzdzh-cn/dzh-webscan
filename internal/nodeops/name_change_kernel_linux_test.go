//go:build linux

package nodeops

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
	agentv1 "webscan/sdk/agent/v1"
)

func TestNativeSystemdKernelNameChangeApplicationAndRollback(t *testing.T) {
	runNativeSystemdKernelLifecycle(t, true, false, true)
}

func TestDockerKernelNameChangeApplicationAndRollback(t *testing.T) {
	requireDockerKernelGuest(t)
	runDockerEngineLifecycle(t, true, false, true)
}

// Called only by the explicitly guarded, networkless full-kernel guests after
// initial installation has finalized. Signing is a local fixture, not the
// controller's SQL issuer or a full pinned-SSH executor integration.
func kernelChangeNodeName(t *testing.T, ctx context.Context, w *LocalRuntime, r Request, m nodeconfig.Material, ca *nodepki.Authority, collector nodepki.Bundle, crl []byte) []byte {
	t.Helper()
	host := newInstallationHost(w.root)
	command := host.command
	host.command = func(ctx context.Context, program string, args ...string) (string, error) {
		started := time.Now()
		out, err := command(ctx, program, args...)
		t.Logf("name verification command=%s duration=%s error=%v", program, time.Since(started), err)
		return out, err
	}
	probe := w.probe
	w.probe = func(ctx context.Context, dir string, s Spec) error {
		started := time.Now()
		err := probe(ctx, dir, s)
		t.Logf("name verification bundle probe duration=%s error=%v", time.Since(started), err)
		return err
	}
	defer func() { w.probe = probe }()
	before := kernelNameServiceSnapshot(t, ctx, host, r)
	identity := filepath.Join(agentDataDirectory, "pki-identity", "active.pem")
	active, record, err := nodepki.ReadIdentity(filepath.Join(agentDataDirectory, "pki-identity", "ca.crt"), identity, nodepki.Node, r.Node, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(active.Key)
	intent, err := nodepki.NewNodeNameChangeIntent(r.Node, sha(recoveryTestCertificate(t, active.CA).Raw), record.CertificateSHA256, "next-kernel-agent.test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in := NameChangeInput{Format: 1, Operation: "prepare", Intent: intent, CRL: crl}
	prepared, err := w.nameChangeWithResources(ctx, in, host, nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"})
	if err != nil {
		t.Fatal("prepare actual kernel Agent name", err)
	}
	certificate := signHelperNameChange(t, helperNameChangeFixture{w: w, r: r, ca: ca, live: active, in: in}, prepared.Request)
	in.Operation, in.Request, in.Certificate = "activate", prepared.Request, certificate
	if _, err := w.nameChangeWithResources(ctx, in, host, nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}); err != nil {
		t.Fatal("activate actual kernel Agent name", err)
	}
	in.Operation = "verify"
	started := time.Now()
	if out, err := w.nameChangeWithResources(ctx, in, host, nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"}); err != nil || !out.ResourcesVerified {
		t.Fatal("verify actual service and kernel resources after name activation", time.Since(started), err)
	}
	t.Logf("actual name verification duration=%s", time.Since(started))
	for _, name := range []string{m.ServerName, intent.ServerName} {
		kernelNameEndpoint(t, ctx, r, m, collector, crl, certificate, name)
	}
	if after := kernelNameServiceSnapshot(t, ctx, host, r); before != after {
		t.Fatal("name overlap restarted or replaced actual service")
	}
	return certificate
}

func kernelNameServiceSnapshot(t *testing.T, ctx context.Context, host installationHost, r Request) string {
	t.Helper()
	i, err := host.inventory(ctx, r.Node, r.Spec.Mode)
	if err != nil || len(i.Services) != 1 || !i.Services[0].Running {
		t.Fatal("actual running Agent not proven", err)
	}
	s := i.Services[0]
	var process any
	if s.Kind == "native" {
		status, err := host.native(ctx, s)
		if err != nil || status.MainPID < 1 {
			t.Fatal("actual native process missing", err)
		}
		process = status.MainPID
	} else {
		state, err := host.dockerRuntime(ctx, s.ID)
		if err != nil || !state.State.Running || state.State.Pid < 1 {
			t.Fatal("actual Docker process missing", err)
		}
		process = struct {
			PID      int
			Started  string
			Restarts int
		}{state.State.Pid, state.State.StartedAt, state.RestartCount}
	}
	raw, err := json.Marshal([]any{s, process})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Every call opens a new connection, with normal hostname, CA, node/collector
// identity and CRL verification. An existing HTTP/2 session is not name proof.
func kernelNameEndpoint(t *testing.T, ctx context.Context, r Request, m nodeconfig.Material, collector nodepki.Bundle, crl, certificate []byte, name string) {
	t.Helper()
	policy, err := nodepki.NewTrust(m.CA, crl, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(collector.Certificate, collector.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(m.CA)
	wanted := sha(recoveryTestCertificate(t, certificate).Raw)
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: pool, Certificates: []tls.Certificate{pair}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 || sha(state.PeerCertificates[0].Raw) != wanted {
			return nodepki.ErrIdentity
		}
		return policy.Verify(state.PeerCertificates[0], nodepki.Node, r.Node, time.Now())
	}}
	conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(r.Spec.MetricsPort)), grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	op, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var actual peer.Peer
	capability, err := agentv1.NewAgentServiceClient(conn).Capabilities(op, &agentv1.CapabilitiesRequest{}, grpc.Peer(&actual), grpc.WaitForReady(true))
	if err != nil {
		t.Fatal("fresh actual Agent name connection", name, err)
	}
	info, ok := actual.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) != 1 || sha(info.State.PeerCertificates[0].Raw) != wanted || capability.NodeId != r.Node || capability.ConfigurationVersion != m.Version || capability.ConfigurationSha256 != m.SourceSHA256 || capability.CertificateSha256 != wanted {
		t.Fatal("actual name peer or running configuration mismatch", name)
	}
}

func kernelNameTargetConfiguration(t *testing.T, w *LocalRuntime, r Request, m nodeconfig.Material) (Request, nodeconfig.Material) {
	t.Helper()
	m.Format, m.Certificate, m.Key = 3, nil, nil
	m.Version++
	m.SourceSHA256, m.ServerName = strings.Repeat("e", 64), "next-kernel-agent.test"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodeconfig.Decode(raw, time.Now()); err != nil {
		t.Fatal("invalid actual target material", err)
	}
	r.Spec.RuntimeSHA256, r.Spec.RuntimeBytes = sha(raw), uint64(len(raw))
	r.Spec.ConfigVersion, r.Spec.ConfigSourceSHA256, r.Spec.ServerName = m.Version, m.SourceSHA256, m.ServerName
	dir := filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return r, m
}
