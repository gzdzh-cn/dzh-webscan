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

	"webscan/internal/nodepki"
)

// NamePruningInput is a fixed, signed-helper SSH operation. The intent's
// names/configuration are derived and authorized by the controller, not by a
// public request. It accepts no filesystem, command or service parameters.
type NamePruningInput struct {
	Format      int                           `json:"format"`
	Operation   string                        `json:"operation"`
	Intent      nodepki.NodeNamePruningIntent `json:"intent"`
	CRL         []byte                        `json:"crl"`
	Request     json.RawMessage               `json:"request,omitempty"`
	Certificate []byte                        `json:"certificate,omitempty"`
}

type NamePruningOutput = NameChangeOutput

var errNamePruning = errors.New("node-name-pruning-not-verified")

func decodeNamePruning(in io.Reader) (NamePruningInput, error) {
	var r NamePruningInput
	raw, err := io.ReadAll(io.LimitReader(in, MaxNameChangeBytes+1))
	if err != nil || len(raw) > MaxNameChangeBytes {
		return r, errNamePruning
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Format != 1 || len(r.CRL) == 0 || len(r.CRL) > nodepki.MaxCRLBytes || len(r.Request) > nodepki.MaxRenewalBytes || len(r.Certificate) > 16<<10 {
		return NamePruningInput{}, errNamePruning
	}
	canonical, err := json.Marshal(r)
	proof := r.Operation == "activate" || r.Operation == "verify" || r.Operation == "reconcile"
	if err != nil || !bytes.Equal(canonical, bytes.TrimSpace(raw)) || r.Operation == "prepare" && (len(r.Request) != 0 || len(r.Certificate) != 0) || proof && (len(r.Request) == 0 || len(r.Certificate) == 0) || r.Operation != "prepare" && !proof {
		return NamePruningInput{}, errNamePruning
	}
	return r, nil
}

func CommandNamePruning(ctx context.Context, in io.Reader, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("node-v3-requires-root-linux-amd64")
	}
	r, err := decodeNamePruning(in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, nodepki.NameChangeVerificationTimeout)
	defer cancel()
	response, err := NewLocalRuntime().namePruning(ctx, r)
	if err != nil {
		return errNamePruning
	}
	if json.NewEncoder(out).Encode(response) != nil {
		return errors.New("node-name-pruning-response-unavailable")
	}
	return nil
}

func (w *LocalRuntime) namePruning(ctx context.Context, in NamePruningInput) (NamePruningOutput, error) {
	return w.namePruningWithResources(ctx, in, newInstallationHost(w.root), nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"})
}

func (w *LocalRuntime) namePruningWithResources(ctx context.Context, in NamePruningInput, host installationHost, fs nativeResources) (NamePruningOutput, error) {
	var response NamePruningOutput
	raw, err := json.Marshal(in)
	if err != nil {
		return response, errNamePruning
	}
	if _, err := decodeNamePruning(bytes.NewReader(raw)); err != nil {
		return response, err
	}
	ctx, cancel := context.WithDeadline(ctx, in.Intent.ExpiresAt)
	defer cancel()
	err = w.withIdentityMaintenance(ctx, in.Intent.Node, in.Intent.AuthoritySHA256, in.CRL, func(ctx context.Context, ca []byte, sourceName, caFile, activeFile, floor string) error {
		if sourceName != in.Intent.ActiveName {
			return errNamePruning
		}
		var installation ActiveInstallation
		if _, err := decodePrivateJSON(filepath.Join(w.root, "active.json"), &installation, MaxRequestBytes); err != nil || installation.Spec.ConfigSourceSHA256 != in.Intent.ConfigurationSHA256 {
			return errNamePruning
		}
		var request nodepki.NodeNamePruningRequest
		var err error
		if in.Operation == "prepare" {
			request, err = nodepki.PrepareNodeNamePruning(ctx, caFile, activeFile, floor, in.Intent, time.Now())
		} else if in.Operation == "reconcile" {
			original, parseErr := nodepki.ParseNodeNamePruningRequest(in.Request)
			if parseErr != nil {
				return errNamePruning
			}
			request, err = nodepki.PrepareNodeNamePruningContinuation(ctx, caFile, activeFile, floor, in.CRL, in.Intent, original, in.Certificate, time.Now())
		} else {
			request, err = nodepki.ParseNodeNamePruningRequest(in.Request)
		}
		if err != nil {
			return err
		}
		if _, err := nodepki.PublishNodeNamePruningTrust(ctx, caFile, floor, in.CRL, request, in.Intent, time.Now()); err != nil {
			return err
		}
		response = NamePruningOutput{Format: 1, Operation: in.Operation, Node: in.Intent.Node, Challenge: in.Intent.Challenge}
		switch in.Operation {
		case "prepare", "reconcile":
			response.Request, err = json.Marshal(request)
		case "activate":
			var record nodepki.IdentityRecord
			record, err = nodepki.ActivateNodeNamePruning(ctx, caFile, activeFile, floor, request, in.Intent, in.Certificate, time.Now())
			response.CertificateSHA256 = record.CertificateSHA256
		case "verify":
			err = nodepki.WithPrunedNodeIdentity(ctx, caFile, activeFile, floor, request, in.Intent, in.Certificate, time.Now(), func(ctx context.Context, record nodepki.IdentityRecord) error {
				if err := w.verifyIdentityMaintenanceService(ctx, in.Intent.Node, in.CRL, host, fs); err != nil {
					return err
				}
				response.CertificateSHA256, response.ResourcesVerified = record.CertificateSHA256, true
				return nil
			})
		}
		return err
	})
	if err != nil || ctx.Err() != nil {
		return NamePruningOutput{}, errors.Join(errNamePruning, err, ctx.Err())
	}
	return response, nil
}
