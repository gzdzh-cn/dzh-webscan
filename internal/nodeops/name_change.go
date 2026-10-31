package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
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
	var response NameChangeOutput
	err = w.withIdentityMaintenance(ctx, in.Intent.Node, in.Intent.AuthoritySHA256, in.CRL, func(ctx context.Context, ca []byte, sourceName, caFile, activeFile, floor string) error {
		if sourceName == in.Intent.ServerName {
			return errNameChange
		}
		var request nodepki.NodeNameChangeRequest
		if in.Operation == "prepare" {
			request, err = nodepki.PrepareNodeNameChange(ctx, caFile, activeFile, floor, in.Intent, time.Now())
		} else if in.Operation == "reconcile" {
			original, parseErr := nodepki.ParseNodeNameChangeRequest(in.Request)
			if parseErr != nil {
				return errNameChange
			}
			request, err = nodepki.PrepareNodeNameChangeContinuation(ctx, caFile, activeFile, floor, in.CRL, in.Intent, original, in.Certificate, time.Now())
		} else {
			request, err = nodepki.ParseNodeNameChangeRequest(in.Request)
		}
		if err != nil {
			return errNameChange
		}
		if _, err := nodepki.PublishNodeNameChangeTrust(ctx, caFile, floor, in.CRL, request, in.Intent, time.Now()); err != nil {
			return errNameChange
		}
		response = NameChangeOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge}
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
			return errors.Join(errNameChange, err, ctx.Err())
		}
		return nil
	})
	if err != nil {
		return empty, err
	}
	return response, nil
}
