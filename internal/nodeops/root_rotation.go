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

const MaxRootRotationBytes = 2 << 20

var errRootRotation = errors.New("node-root-rotation-not-verified")

// Fixed root-only signed-helper operation. No caller-selected filesystem,
// program, service, CA private key or command is accepted. This transport is
// for a persistent host administrator task, never a public collection RPC.
type RootRotationInput struct {
	Format        int                   `json:"format"`
	Operation     string                `json:"operation"`
	Node          string                `json:"node"`
	Configuration string                `json:"configuration_sha256"`
	Expected      string                `json:"certificate_sha256"`
	Snapshot      json.RawMessage       `json:"snapshot"`
	Request       json.RawMessage       `json:"request,omitempty"`
	Certificate   []byte                `json:"certificate,omitempty"`
	Delivery      *nodepki.RootDelivery `json:"delivery,omitempty"`
}

type RootRotationOutput struct {
	Format            int             `json:"format"`
	Operation         string          `json:"operation"`
	Node              string          `json:"node"`
	Snapshot          string          `json:"snapshot_sha256"`
	Phase             string          `json:"phase"`
	CertificateSHA256 string          `json:"certificate_sha256,omitempty"`
	Request           json.RawMessage `json:"request,omitempty"`
	ResourcesVerified bool            `json:"resources_verified"`
}

func decodeRootRotation(in io.Reader) (RootRotationInput, nodepki.RootSetSnapshot, error) {
	var r RootRotationInput
	var snapshot nodepki.RootSetSnapshot
	raw, err := io.ReadAll(io.LimitReader(in, MaxRootRotationBytes+1))
	if err != nil || len(raw) > MaxRootRotationBytes {
		return r, snapshot, errRootRotation
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Format != 1 || !idPattern.MatchString(r.Node) || !validDigest(r.Configuration) || !validDigest(r.Expected) || len(r.Snapshot) == 0 || len(r.Snapshot) > nodepki.MaxRootSetBytes || len(r.Request) > nodepki.MaxRenewalBytes || len(r.Certificate) > 16<<10 {
		return RootRotationInput{}, snapshot, errRootRotation
	}
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(canonical, bytes.TrimSpace(raw)) {
		return RootRotationInput{}, snapshot, errRootRotation
	}
	snapshot, err = nodepki.ParseRootSetSnapshot(r.Snapshot)
	if err != nil {
		return RootRotationInput{}, snapshot, errRootRotation
	}
	switch r.Operation {
	case "trust":
		if (len(r.Request) == 0) != (len(r.Certificate) == 0) || len(r.Request) != 0 && snapshot.Final != nil {
			return RootRotationInput{}, snapshot, errRootRotation
		}
	case "prepare", "verify":
		if len(r.Request) != 0 || len(r.Certificate) != 0 || r.Operation == "prepare" && snapshot.Final != nil {
			return RootRotationInput{}, snapshot, errRootRotation
		}
	case "activate":
		if len(r.Request) == 0 || len(r.Certificate) == 0 || snapshot.Final != nil {
			return RootRotationInput{}, snapshot, errRootRotation
		}
	default:
		return RootRotationInput{}, snapshot, errRootRotation
	}
	return r, snapshot, nil
}

func CommandRootRotation(ctx context.Context, in io.Reader, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("node-v3-requires-root-linux-amd64")
	}
	r, _, err := decodeRootRotation(in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, nodepki.NameChangeVerificationTimeout)
	defer cancel()
	response, err := NewLocalRuntime().rootRotation(ctx, r)
	if err != nil {
		return errRootRotation
	}
	if json.NewEncoder(out).Encode(response) != nil {
		return errors.New("node-root-rotation-response-unavailable")
	}
	return nil
}

func (w *LocalRuntime) rootRotation(ctx context.Context, in RootRotationInput) (RootRotationOutput, error) {
	return w.rootRotationWithResources(ctx, in, newInstallationHost(w.root), nativeResources{proc: "/proc", cgroup: "/sys/fs/cgroup"})
}

func (w *LocalRuntime) rootRotationWithResources(ctx context.Context, in RootRotationInput, host installationHost, fs nativeResources) (RootRotationOutput, error) {
	return w.rootRotationAt(ctx, in, host, fs, time.Now())
}

func (w *LocalRuntime) rootRotationAt(ctx context.Context, in RootRotationInput, host installationHost, fs nativeResources, now time.Time) (RootRotationOutput, error) {
	var out RootRotationOutput
	raw, _ := json.Marshal(in)
	_, snapshot, err := decodeRootRotation(bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	err = w.withInstalledNodeOperation(ctx, in.Node, func(ctx context.Context) error {
		anchor, name, err := w.identityMaintenanceInstallationWithRoots(in.Node, nil, &snapshot)
		if err != nil {
			return err
		}
		var installed ActiveInstallation
		if _, err := decodePrivateJSON(filepath.Join(w.root, "active.json"), &installed, MaxRequestBytes); err != nil || installed.Spec.ConfigSourceSHA256 != in.Configuration {
			return errRootRotation
		}
		data := w.managedDataDirectory()
		identity, floor := filepath.Join(data, "pki-identity"), filepath.Join(data, "pki-trust")
		for _, directory := range []string{data, identity, floor} {
			if privateDirectoryTree(directory) != nil {
				return errRootRotation
			}
		}
		caFile, active := filepath.Join(identity, "ca.crt"), filepath.Join(identity, "active.pem")
		for _, directory := range []string{identity, floor} {
			pinned, err := readPrivate(filepath.Join(directory, "ca.crt"), 64<<10)
			if err != nil || !bytes.Equal(pinned, anchor) {
				return errRootRotation
			}
		}
		// Validate current identity against proposed trust before publishing it.
		// Final trust cannot be installed while the node still has an old leaf.
		var b nodepki.Bundle
		var current nodepki.IdentityRecord
		var issued *nodepki.RootIdentityRequest
		if len(in.Request) != 0 {
			request, parseErr := nodepki.ParseRootIdentityRequest(in.Request)
			if parseErr != nil || request.Authorization != nodepki.RootAuthorizationSHA256(snapshot.Dual) {
				return errRootRotation
			}
			issued = &request
			b, current, err = nodepki.ReadRootActivationIdentity(caFile, active, floor, nodepki.Node, in.Node, snapshot, request, in.Certificate, now)
		} else {
			b, current, err = nodepki.ReadIdentityWithRootState(caFile, active, floor, nodepki.Node, in.Node, now)
		}
		defer clear(b.Key)
		if err != nil {
			return errRootRotation
		}
		trust, err := nodepki.NewRootSet(anchor, snapshot, now)
		block, _ := pem.Decode(b.Certificate)
		if block == nil {
			return errRootRotation
		}
		leaf, leafErr := x509.ParseCertificate(block.Bytes)
		if err != nil || leafErr != nil || leaf.VerifyHostname(name) != nil {
			return errRootRotation
		}
		if trust.Verify(leaf, nodepki.Node, in.Node, now) != nil && (issued == nil || current.CertificateSHA256 != issued.CertificateSHA256) {
			return errRootRotation
		}
		if in.Operation != "activate" && current.CertificateSHA256 != in.Expected {
			return errRootRotation
		}
		if in.Operation == "activate" {
			r, err := nodepki.ParseRootIdentityRequest(in.Request)
			if err != nil || r.Role != nodepki.Node || r.ID != in.Node || r.CertificateSHA256 != in.Expected || r.Authorization != nodepki.RootAuthorizationSHA256(snapshot.Dual) {
				return errRootRotation
			}
		}
		var receipt nodepki.RootSetReceipt
		if in.Delivery == nil {
			receipt, err = nodepki.PublishRootSet(ctx, floor, anchor, in.Snapshot, now)
		} else {
			receipt, err = nodepki.PublishDeliveredRootSet(ctx, floor, anchor, in.Snapshot, *in.Delivery, nodepki.Node, in.Node, in.Configuration, in.Expected, now)
		}
		if err != nil {
			return err
		}
		out = RootRotationOutput{Format: 1, Operation: in.Operation, Node: in.Node, Snapshot: receipt.SHA256, Phase: receipt.Phase, CertificateSHA256: current.CertificateSHA256}
		switch in.Operation {
		case "prepare":
			request, err := nodepki.PrepareRootIdentity(ctx, caFile, active, floor, nodepki.Node, in.Node, nodepki.RootAuthorizationSHA256(snapshot.Dual), in.Expected, now)
			if err != nil {
				return err
			}
			out.Request, err = json.Marshal(request)
			return err
		case "activate":
			request, _ := nodepki.ParseRootIdentityRequest(in.Request)
			record, err := nodepki.ActivateRootIdentity(ctx, caFile, active, floor, nodepki.Node, in.Node, request.Authorization, in.Expected, request.SHA256(), in.Certificate, now)
			out.CertificateSHA256 = record.CertificateSHA256
			return err
		case "verify":
			return nodepki.WithRootIdentitySnapshot(ctx, caFile, active, floor, nodepki.Node, in.Node, in.Expected, now, func(ctx context.Context, record nodepki.IdentityRecord) error {
				if err := w.verifyIdentityMaintenanceServiceWithRoots(ctx, in.Node, nil, &snapshot, host, fs); err != nil {
					return err
				}
				out.CertificateSHA256, out.ResourcesVerified = record.CertificateSHA256, true
				return nil
			})
		}
		return ctx.Err()
	})
	if err != nil || ctx.Err() != nil {
		return RootRotationOutput{}, errors.Join(errRootRotation, err, ctx.Err())
	}
	return out, nil
}
