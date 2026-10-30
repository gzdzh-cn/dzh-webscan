package nodeops

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"webscan/internal/nodepki"
)

// NameChangeInput is a fixed checksum-pinned SSH helper operation. Neither a
// pathname nor an executable/service, private key or arbitrary command can be
// supplied. The controller must durably authorize Intent before invoking it.
type NameChangeInput struct {
	Format      int                          `json:"format"`
	Operation   string                       `json:"operation"`
	Intent      nodepki.NodeNameChangeIntent `json:"intent"`
	CRL         []byte                       `json:"crl"`
	Request     json.RawMessage              `json:"request,omitempty"`
	Certificate []byte                       `json:"certificate,omitempty"`
}

type NameChangeOutput struct {
	Format            int             `json:"format"`
	Operation         string          `json:"operation"`
	Node              string          `json:"node"`
	Challenge         string          `json:"challenge"`
	Request           json.RawMessage `json:"request,omitempty"`
	CertificateSHA256 string          `json:"certificate_sha256,omitempty"`
	ResourcesVerified bool            `json:"resources_verified,omitempty"`
}

const MaxNameChangeBytes = 2*nodepki.MaxCRLBytes + 4*nodepki.MaxRenewalBytes

var errNameChange = errors.New("node-name-change-not-verified")

func decodeNameChange(in io.Reader) (NameChangeInput, error) {
	var r NameChangeInput
	raw, err := io.ReadAll(io.LimitReader(in, MaxNameChangeBytes+1))
	if err != nil || len(raw) > MaxNameChangeBytes {
		return r, errNameChange
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Format != 1 || len(r.CRL) == 0 || len(r.CRL) > nodepki.MaxCRLBytes || len(r.Request) > nodepki.MaxRenewalBytes || len(r.Certificate) > 16<<10 {
		return NameChangeInput{}, errNameChange
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
		return NameChangeInput{}, errNameChange
	}
	proofPhase := r.Operation == "activate" || r.Operation == "verify" || r.Operation == "reconcile"
	if r.Operation == "prepare" && (len(r.Request) != 0 || len(r.Certificate) != 0) || proofPhase && (len(r.Request) == 0 || len(r.Certificate) == 0) || r.Operation != "prepare" && !proofPhase {
		return NameChangeInput{}, errNameChange
	}
	return r, nil
}

// CommandNameChange has no start/stop/restart or configuration apply operation.
// A signed response cannot replace the host's fresh, normal mTLS observation.
func CommandNameChange(ctx context.Context, in io.Reader, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("node-v3-requires-root-linux-amd64")
	}
	r, err := decodeNameChange(in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, nodepki.NameChangeVerificationTimeout)
	defer cancel()
	response, err := NewLocalRuntime().nameChange(ctx, r)
	if err != nil {
		return errNameChange
	}
	if json.NewEncoder(out).Encode(response) != nil {
		return errors.New("node-name-change-response-unavailable")
	}
	return nil
}

func (w *LocalRuntime) nameChange(ctx context.Context, in NameChangeInput) (NameChangeOutput, error) {
	return w.nameChangeWithResources(ctx, in, newInstallationHost(w.root), nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"})
}

func (w *LocalRuntime) nameChangeWithResources(ctx context.Context, in NameChangeInput, host installationHost, fs nativeResources) (NameChangeOutput, error) {
	var empty NameChangeOutput
	raw, err := json.Marshal(in)
	if err != nil {
		return empty, errNameChange
	}
	if _, err := decodeNameChange(bytes.NewReader(raw)); err != nil {
		return empty, err
	}
	ctx, cancel := context.WithDeadline(ctx, in.Intent.ExpiresAt)
	defer cancel()
	// Lifecycle ordering: journal -> service operation -> trust -> identity.
	j := &Journal{root: filepath.Join(w.root, "node")}
	if privateDirectoryTree(j.root) != nil || privateFile(filepath.Join(j.root, "journal.sqlite3"), false) != nil {
		return empty, errNameChange
	}
	lock, err := j.lock()
	if err != nil {
		return empty, errNameChange
	}
	defer lock.Close()
	db, err := j.database()
	if err != nil {
		return empty, errNameChange
	}
	defer db.Close()
	var ready bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM meta m JOIN jobs j ON j.id=m.current_job WHERE m.id=1 AND m.node=? AND j.retired=0 AND (EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase='finalize' AND p.status='complete') AND NOT EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase IN ('restore','verify-rollback')) OR EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase='verify-rollback' AND p.status='complete')) AND NOT EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.status='running'))`, in.Intent.Node).Scan(&ready); err != nil || !ready {
		return empty, errNameChange
	}
	ctx, release, err := acquireServiceOperation(ctx, w.root)
	if err != nil {
		return empty, errNameChange
	}
	defer release()
	ca, sourceName, err := w.identityMaintenanceInstallation(in.Intent.Node, in.CRL)
	if err != nil || sourceName == in.Intent.ServerName {
		return empty, errNameChange
	}
	data := w.managedDataDirectory()
	identity, floor := filepath.Join(data, "pki-identity"), filepath.Join(data, "pki-trust")
	for _, dir := range []string{data, identity, floor} {
		if privateDirectoryTree(dir) != nil {
			return empty, errNameChange
		}
	}
	caFile, activeFile := filepath.Join(identity, "ca.crt"), filepath.Join(identity, "active.pem")
	for _, dir := range []string{identity, floor} {
		pinned, err := readPrivate(filepath.Join(dir, "ca.crt"), 64<<10)
		if err != nil || !bytes.Equal(bytes.TrimSpace(pinned), bytes.TrimSpace(ca)) {
			return empty, errNameChange
		}
	}
	previous, err := readPrivate(filepath.Join(floor, "ca.crl"), nodepki.MaxCRLBytes)
	if err != nil || nodepki.ValidateCRLAdvance(ca, previous, in.CRL, time.Now()) != nil {
		return empty, errNameChange
	}
	// Check incoming revocations before any new local CSR/key is prepared.
	active, _, err := nodepki.ReadIdentity(caFile, activeFile, nodepki.Node, in.Intent.Node, time.Now())
	defer clear(active.Key)
	if err != nil {
		return empty, errNameChange
	}
	block, _ := pem.Decode(active.Certificate)
	if block == nil {
		return empty, errNameChange
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	trust, trustErr := nodepki.NewTrust(ca, in.CRL, time.Now())
	if err != nil || trustErr != nil || trust.Verify(leaf, nodepki.Node, in.Intent.Node, time.Now()) != nil || leaf.VerifyHostname(sourceName) != nil {
		return empty, errNameChange
	}
	var request nodepki.NodeNameChangeRequest
	if in.Operation == "prepare" {
		request, err = nodepki.PrepareNodeNameChange(ctx, caFile, activeFile, floor, in.Intent, time.Now())
	} else if in.Operation == "reconcile" {
		original, parseErr := nodepki.ParseNodeNameChangeRequest(in.Request)
		if parseErr != nil {
			return empty, errNameChange
		}
		request, err = nodepki.PrepareNodeNameChangeContinuation(ctx, caFile, activeFile, floor, in.CRL, in.Intent, original, in.Certificate, time.Now())
	} else {
		request, err = nodepki.ParseNodeNameChangeRequest(in.Request)
	}
	if err != nil {
		return empty, errNameChange
	}
	if _, err := nodepki.PublishNodeNameChangeTrust(ctx, caFile, floor, in.CRL, request, in.Intent, time.Now()); err != nil {
		return empty, errNameChange
	}
	response := NameChangeOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge}
	if in.Operation == "prepare" || in.Operation == "reconcile" {
		response.Request, err = json.Marshal(request)
	} else if in.Operation == "activate" {
		var record nodepki.IdentityRecord
		record, err = nodepki.ActivateNodeNameChange(ctx, caFile, activeFile, floor, request, in.Intent, in.Certificate, time.Now())
		response.CertificateSHA256 = record.CertificateSHA256
	} else {
		err = nodepki.WithNameChangedNodeIdentity(ctx, caFile, activeFile, floor, request, in.Intent, in.Certificate, time.Now(), func(ctx context.Context, record nodepki.IdentityRecord) error {
			if err := w.verifyIdentityMaintenanceService(ctx, in.Intent.Node, in.CRL, host, fs); err != nil {
				return err
			}
			response.CertificateSHA256, response.ResourcesVerified = record.CertificateSHA256, true
			return nil
		})
	}
	if err != nil || ctx.Err() != nil {
		// Preserve internal cancellation/error identity for the local executor
		// and diagnostics. CommandNameChange still emits only the fixed public
		// error, never a filesystem error or private operation input.
		return empty, errors.Join(errNameChange, err, ctx.Err())
	}
	return response, nil
}
