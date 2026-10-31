package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

// IdentityRecoveryInput is only accepted by the fixed, checksum-pinned SSH
// helper. It is not an Agent RPC or a browser request. No path, executable,
// private key, service name or arbitrary command can be supplied here.
type IdentityRecoveryInput struct {
	Format      int                        `json:"format"`
	Operation   string                     `json:"operation"`
	Intent      nodepki.NodeRecoveryIntent `json:"intent"`
	CRL         []byte                     `json:"crl"`
	Request     json.RawMessage            `json:"request,omitempty"`
	Certificate []byte                     `json:"certificate,omitempty"`
}

type IdentityRecoveryOutput struct {
	Format            int             `json:"format"`
	Operation         string          `json:"operation"`
	Node              string          `json:"node"`
	Challenge         string          `json:"challenge"`
	Request           json.RawMessage `json:"request,omitempty"`
	CertificateSHA256 string          `json:"certificate_sha256,omitempty"`
	ResourcesVerified bool            `json:"resources_verified,omitempty"`
}

const MaxIdentityRecoveryBytes = 2*nodepki.MaxCRLBytes + 4*nodepki.MaxRenewalBytes

var errIdentityRecovery = errors.New("node-identity-recovery-not-verified")

func decodeIdentityRecovery(in io.Reader) (IdentityRecoveryInput, error) {
	var r IdentityRecoveryInput
	raw, err := io.ReadAll(io.LimitReader(in, MaxIdentityRecoveryBytes+1))
	if err != nil || len(raw) > MaxIdentityRecoveryBytes {
		return r, errIdentityRecovery
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Format != 1 || len(r.CRL) == 0 || len(r.CRL) > nodepki.MaxCRLBytes || len(r.Request) > nodepki.MaxRenewalBytes || len(r.Certificate) > 16<<10 {
		return IdentityRecoveryInput{}, errIdentityRecovery
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
		return IdentityRecoveryInput{}, errIdentityRecovery
	}
	proofPhase := r.Operation == "activate" || r.Operation == "start" || r.Operation == "verify"
	if r.Operation == "prepare" && (len(r.Request) != 0 || len(r.Certificate) != 0) || r.Operation == "reconcile" && (len(r.Request) != 0 || len(r.Certificate) == 0) || proofPhase && (len(r.Request) == 0 || len(r.Certificate) == 0) || r.Operation != "prepare" && r.Operation != "reconcile" && !proofPhase {
		return IdentityRecoveryInput{}, errIdentityRecovery
	}
	return r, nil
}

// CommandIdentityRecovery never initializes missing identity state or falls
// back to an installation seed. The fixed start operation proves the already
// installed service; its receipt is not proof of actual mTLS readiness.
func CommandIdentityRecovery(ctx context.Context, in io.Reader, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("node-v3-requires-root-linux-amd64")
	}
	r, err := decodeIdentityRecovery(in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	response, err := NewLocalRuntime().identityRecovery(ctx, r)
	if err != nil {
		return errIdentityRecovery
	}
	if json.NewEncoder(out).Encode(response) != nil {
		return errors.New("node-identity-recovery-response-unavailable")
	}
	return nil
}

func (w *LocalRuntime) identityRecovery(ctx context.Context, in IdentityRecoveryInput) (IdentityRecoveryOutput, error) {
	return w.identityRecoveryWithHost(ctx, in, newInstallationHost(w.root))
}

func (w *LocalRuntime) identityRecoveryWithHost(ctx context.Context, in IdentityRecoveryInput, host installationHost) (IdentityRecoveryOutput, error) {
	return w.identityRecoveryWithResources(ctx, in, host, nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"})
}

func (w *LocalRuntime) identityRecoveryWithResources(ctx context.Context, in IdentityRecoveryInput, host installationHost, fs nativeResources) (IdentityRecoveryOutput, error) {
	var empty IdentityRecoveryOutput
	// Apply the exact decoder to internal callers too.
	raw, err := json.Marshal(in)
	if err != nil {
		return empty, errIdentityRecovery
	}
	if _, err := decodeIdentityRecovery(bytes.NewReader(raw)); err != nil {
		return empty, err
	}
	// Same lock order as lifecycle phases: journal, then service operation.
	// A crashed/incomplete deployment must be continued before key recovery.
	j := &Journal{root: filepath.Join(w.root, "node")}
	if privateDirectoryTree(j.root) != nil {
		return empty, errIdentityRecovery
	}
	lock, err := j.lock()
	if err != nil {
		return empty, errIdentityRecovery
	}
	defer lock.Close()
	if err := privateFile(filepath.Join(j.root, "journal.sqlite3"), false); err != nil {
		return empty, errIdentityRecovery
	}
	db, err := j.database()
	if err != nil {
		return empty, errIdentityRecovery
	}
	defer db.Close()
	var ready bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM meta m JOIN jobs j ON j.id=m.current_job WHERE m.id=1 AND m.node=? AND j.retired=0 AND (EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase='finalize' AND p.status='complete') AND NOT EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase IN ('restore','verify-rollback')) OR EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase='verify-rollback' AND p.status='complete')) AND NOT EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.status='running'))`, in.Intent.Node).Scan(&ready); err != nil || !ready {
		return empty, errIdentityRecovery
	}
	ctx, release, err := acquireServiceOperation(ctx, w.root)
	if err != nil {
		return empty, errIdentityRecovery
	}
	defer release()
	rotated, err := nodepki.RefreshIdentityIssuerCRL(ctx, filepath.Join(w.managedDataDirectory(), "pki-identity", "ca.crt"), filepath.Join(w.managedDataDirectory(), "pki-trust"), in.Intent.AuthoritySHA256, in.CRL, time.Now())
	if err != nil {
		return empty, errIdentityRecovery
	}
	ca, err := w.recoveryInstallation(in)
	if err != nil {
		return empty, errIdentityRecovery
	}
	data := w.managedDataDirectory()
	identity := filepath.Join(data, "pki-identity")
	floor := filepath.Join(data, "pki-trust")
	for _, dir := range []string{data, identity, floor} {
		if privateDirectoryTree(dir) != nil {
			return empty, errIdentityRecovery
		}
	}
	for _, dir := range []string{identity, floor} {
		pinned, err := readPrivate(filepath.Join(dir, "ca.crt"), 64<<10)
		if err != nil || !bytes.Equal(bytes.TrimSpace(ca), bytes.TrimSpace(pinned)) {
			return empty, errIdentityRecovery
		}
	}
	if !rotated {
		previous, err := readPrivate(filepath.Join(floor, "ca.crl"), nodepki.MaxCRLBytes)
		if err != nil || nodepki.ValidateCRLAdvance(ca, previous, in.CRL, time.Now()) != nil {
			return empty, errIdentityRecovery
		}
	}
	caFile, active := filepath.Join(identity, "ca.crt"), filepath.Join(identity, "active.pem")
	var request nodepki.NodeRecoveryRequest
	if in.Operation == "prepare" {
		request, err = nodepki.PrepareNodeRecoveryWithRootState(ctx, caFile, active, floor, in.CRL, in.Intent, time.Now())
	} else if in.Operation == "reconcile" {
		// A prior committed issuance may or may not have reached activation.
		// Both paths retain the original CSR. The second path requires the
		// exact already active replacement and proves its local private key.
		request, err = nodepki.PrepareNodeRecoveryWithRootState(ctx, caFile, active, floor, in.CRL, in.Intent, time.Now())
		if err != nil {
			request, err = nodepki.PrepareNodeRecoveryContinuation(ctx, caFile, active, floor, in.CRL, in.Intent, in.Certificate, time.Now())
		}
	} else {
		request, err = nodepki.ParseNodeRecoveryRequest(in.Request)
	}
	if err != nil {
		return empty, errIdentityRecovery
	}
	// Advance the existing floor before activation, never lower it or drop a
	// revocation. Its own trust lock serializes against a live Agent update.
	if _, err := nodepki.PublishNodeRecoveryTrust(ctx, caFile, floor, in.CRL, request, in.Intent, time.Now()); err != nil {
		return empty, errIdentityRecovery
	}
	response := IdentityRecoveryOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge}
	if in.Operation == "prepare" || in.Operation == "reconcile" {
		response.Request, err = json.Marshal(request)
	} else if in.Operation == "activate" {
		var record nodepki.IdentityRecord
		record, err = nodepki.ActivateNodeRecovery(ctx, caFile, active, floor, request, in.Intent, in.Certificate, time.Now())
		response.CertificateSHA256 = record.CertificateSHA256
	} else {
		err = nodepki.WithRecoveredNodeIdentity(ctx, caFile, active, floor, request, in.Intent, in.Certificate, time.Now(), func(record nodepki.IdentityRecord) error {
			if in.Operation == "start" {
				if err := w.startRecoveredService(ctx, in.Intent.Node, host); err != nil {
					return err
				}
			} else {
				if err := w.verifyRecoveredService(ctx, in, host, fs); err != nil {
					return err
				}
				response.ResourcesVerified = true
			}
			response.CertificateSHA256 = record.CertificateSHA256
			return nil
		})
	}
	if err != nil || ctx.Err() != nil {
		return empty, errIdentityRecovery
	}
	return response, nil
}

// The journal and service-operation locks are held by the caller. Never use a
// request-supplied service name, Docker name lookup for mutation, Compose up,
// enable, restart or stop. A lost response reconciles the same running object.
func (w *LocalRuntime) startRecoveredService(ctx context.Context, node string, host installationHost) error {
	held, locked := ctx.Value(serviceOperationKey{}).(serviceOperation)
	if host.root != w.root || !locked || held.root != w.root || held.file == nil {
		return errIdentityRecovery
	}
	before, err := host.inventory(ctx, node, "native")
	if err != nil || before.Generation != "v3" || len(before.Services) != 1 || hasLegacyMembers(before) {
		return errIdentityRecovery
	}
	s := before.Services[0]
	if !s.Enabled || s.Kind != before.Mode || s.Kind == "native" && s.Name != nativeServiceName || s.Kind == "docker" && s.Name != agentContainerName {
		return errIdentityRecovery
	}
	var active ActiveInstallation
	if _, err := decodePrivateJSON(filepath.Join(w.root, "active.json"), &active, MaxRequestBytes); err != nil || active.Node != node || active.Spec.Mode != before.Mode || w.verifyPrepared(ctx, active.Spec) != nil {
		return errIdentityRecovery
	}
	if !s.Running {
		if s.Kind == "native" {
			_, err = host.command(ctx, "systemctl", "start", nativeServiceName)
		} else {
			_, err = host.docker(ctx, "start", s.ID)
		}
		if err != nil {
			return errIdentityRecovery
		}
	}
	after, err := host.inventory(ctx, node, before.Mode)
	if err != nil || after.Generation != before.Generation || after.Mode != before.Mode || after.Runtime != before.Runtime || len(after.Services) != 1 || hasLegacyMembers(after) {
		return errIdentityRecovery
	}
	want := s
	want.Running = true
	if after.Services[0] != want {
		return errIdentityRecovery
	}
	if s.Kind == "native" {
		status, err := host.native(ctx, want)
		if err != nil || host.proveRunningNativeProcess(status, s.Program, s.Configuration) != nil {
			return errIdentityRecovery
		}
	}
	return ctx.Err()
}

// Authenticate the immutable configuration and generated active runtime. No
// credential/seed key is used to recover the current node-owned identity.
func (w *LocalRuntime) recoveryInstallation(in IdentityRecoveryInput) ([]byte, error) {
	ca, _, err := w.identityMaintenanceInstallation(in.Intent.Node, in.CRL)
	return ca, err
}

// Fixed installation proof shared by separately authorized identity operations.
// Reading a managed package never falls back to an expired installation key.
func (w *LocalRuntime) identityMaintenanceInstallation(node string, crl []byte) ([]byte, string, error) {
	roots, err := w.installedRootState(time.Now())
	if err != nil {
		return nil, "", errIdentityRecovery
	}
	var state *nodepki.RootSetSnapshot
	if roots.Format != 0 {
		state = &roots
	}
	return w.identityMaintenanceInstallationWithRoots(node, crl, state)
}

func (w *LocalRuntime) identityMaintenanceInstallationWithRoots(node string, crl []byte, roots *nodepki.RootSetSnapshot) ([]byte, string, error) {
	raw, err := readPrivate(filepath.Join(w.root, "active.json"), MaxRequestBytes)
	if err != nil {
		return nil, "", errIdentityRecovery
	}
	var a ActiveInstallation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || d.Decode(new(any)) != io.EOF || a.Format != 1 || a.Node != node || a.Spec.Validate() != nil || !a.Spec.configurationValid() || !validDigest(a.RuntimeSHA256) || !validDigest(a.DefinitionSHA256) {
		return nil, "", errIdentityRecovery
	}
	canonical, _ := json.Marshal(a)
	if !bytes.Equal(raw, canonical) {
		return nil, "", errIdentityRecovery
	}
	configDir := filepath.Join(w.root, "configs", a.Spec.RuntimeSHA256)
	activeDir := w.configurationDir(a.Spec)
	for _, dir := range []string{w.root, filepath.Dir(configDir), configDir, filepath.Dir(activeDir), activeDir} {
		if privateDirectoryTree(dir) != nil {
			return nil, "", errIdentityRecovery
		}
	}
	material, err := readPrivate(filepath.Join(configDir, "node.json"), nodeconfig.MaxBytes)
	if err != nil || sha(material) != a.Spec.RuntimeSHA256 || uint64(len(material)) != a.Spec.RuntimeBytes {
		return nil, "", errIdentityRecovery
	}
	defer clear(material)
	var m nodeconfig.Material
	if roots == nil {
		m, err = nodeconfig.DecodeManagedRuntime(material, time.Now(), crl)
	} else {
		m, err = nodeconfig.DecodeManagedRootRuntime(material, time.Now(), *roots)
	}
	defer clear(m.Key)
	if err != nil || m.Node != a.Node || m.Version != a.Spec.ConfigVersion || m.SourceSHA256 != a.Spec.ConfigSourceSHA256 || m.Mode != a.Spec.Mode || m.ServerName != a.Spec.ServerName || m.MetricsPort != a.Spec.MetricsPort || m.Release != a.Spec.Release || m.BundleSHA256 != a.Spec.BundleSHA256 {
		return nil, "", errIdentityRecovery
	}
	files, err := w.configurationFiles(m, a.Spec)
	if err != nil || sha(files["runtime.json"]) != a.RuntimeSHA256 {
		return nil, "", errIdentityRecovery
	}
	name, _, err := w.serviceDefinition(m, a.Spec)
	if err != nil || sha(files[name]) != a.DefinitionSHA256 {
		return nil, "", errIdentityRecovery
	}
	for _, name := range []string{"runtime.json", "ca.crt", "ca.crl", name} {
		got, err := readPrivate(filepath.Join(activeDir, name), nodeconfig.MaxBytes)
		if err != nil || !bytes.Equal(got, files[name]) {
			return nil, "", errIdentityRecovery
		}
	}
	return m.CA, m.ServerName, nil
}
