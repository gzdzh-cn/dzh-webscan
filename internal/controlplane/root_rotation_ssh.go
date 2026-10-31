package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"strings"
	"time"

	"webscan/internal/nodeops"
	"webscan/internal/nodepki"
)

type sshRootRotation struct {
	store       *Store
	vault       *Vault
	config      Config
	release     *TrustedRelease
	localHelper string
}

func (w *sshRootRotation) task(ctx context.Context, l Lease, id string, index int) (rootRotationTask, error) {
	if w == nil || w.store == nil || w.vault == nil || w.release == nil || w.localHelper == "" {
		return rootRotationTask{}, errRootRotationTask
	}
	j, err := w.store.checkRootTask(ctx, w.config, w.vault, l, id)
	if err != nil || index < 0 || index >= len(j.Members) || j.Members[index].Role != nodepki.Node || j.Release != w.release.SHA256() || j.Helper != w.release.manifest.Helper.SHA256 || j.Roots == nil {
		return rootRotationTask{}, errRootRotationTask
	}
	return j, nil
}

// Only checksum-pinned commands and task-bound root SSH are used. Caller data
// can never supply a command, program path, CA directory or probe address.
func (w *sshRootRotation) operation(ctx context.Context, l Lease, id string, index int, operation string) (nodeops.RootRotationOutput, error) {
	var empty nodeops.RootRotationOutput
	j, err := w.task(ctx, l, id, index)
	if err != nil {
		return empty, err
	}
	m, state := j.Members[index], j.State[index]
	expected, err := rootMemberCertificateSHA(m)
	if err != nil {
		return empty, err
	}
	switch operation {
	case "trust":
		if state.Activated || j.Roots.Final != nil {
			cert, err := provisioningCertificate(state.Certificate)
			if err != nil {
				return empty, errRootRotationTask
			}
			expected = digest(cert.Raw)
		}
	case "prepare":
		if !state.Trust || len(state.Request) != 0 || j.Roots.Final != nil {
			return empty, errRootRotationTask
		}
	case "activate":
		if len(state.Request) == 0 || len(state.Certificate) == 0 || j.Roots.Final != nil {
			return empty, errRootRotationTask
		}
	case "verify":
		cert, err := provisioningCertificate(state.Certificate)
		if err != nil {
			return empty, errRootRotationTask
		}
		expected = digest(cert.Raw)
	default:
		return empty, errRootRotationTask
	}
	out, err := w.call(ctx, l, j, index, operation, expected)
	// Activation may have completed just before losing SSH. Only the exact
	// committed successor is an allowed second trust probe; never discover or
	// accept an arbitrary certificate from a helper's reported fingerprint.
	if err != nil && operation == "trust" && !state.Activated && j.Roots.Final == nil && len(state.Certificate) != 0 {
		cert, parseErr := provisioningCertificate(state.Certificate)
		if parseErr == nil {
			return w.call(ctx, l, j, index, operation, digest(cert.Raw))
		}
	}
	return out, err
}

func (w *sshRootRotation) call(ctx context.Context, l Lease, j rootRotationTask, index int, operation, expected string) (nodeops.RootRotationOutput, error) {
	var empty nodeops.RootRotationOutput
	m, state := j.Members[index], j.State[index]
	ctx, cancel := context.WithTimeout(ctx, nodepki.NameChangeVerificationTimeout+15*time.Second)
	defer cancel()
	ctx, deadline := context.WithDeadline(ctx, j.ExpiresAt)
	defer deadline()
	a := w.release.manifest.Helper
	f, err := verifiedReleaseFile(ctx, w.localHelper, a, 256<<20)
	if err != nil {
		return empty, DeploymentFailure{"artifact-invalid"}
	}
	defer f.Close()
	if _, err := w.task(ctx, l, j.ID, index); err != nil {
		return empty, err
	}
	credential, err := w.store.ReadCredential(ctx, w.vault, m.Credential, m.ID)
	if err != nil {
		return empty, err
	}
	remote, err := connectCredentialSSH(ctx, credential)
	if err != nil {
		return empty, err
	}
	defer remote.Close()
	if _, err := w.task(ctx, l, j.ID, index); err != nil {
		return empty, err
	}
	capture, err := runNodeCommand(ctx, remote.Client, helperInstallCommand(a), io.LimitReader(f, int64(a.Bytes)+1))
	if err != nil || capture.overflow || strings.TrimSpace(string(capture.raw)) != "helper-ready" {
		return empty, DeploymentFailure{"remote-unavailable"}
	}
	if _, err := w.task(ctx, l, j.ID, index); err != nil {
		return empty, err
	}
	snapshot, _ := json.Marshal(j.Roots)
	delivery, err := nodepki.AuthorizeStoredRootDelivery(ctx, w.config.NodePKI.AuthorityDirectory, j.Anchor, *j.Roots, m.Role, m.ID, m.Configuration, expected, time.Now())
	if err != nil {
		return empty, err
	}
	in := nodeops.RootRotationInput{Format: 1, Operation: operation, Node: m.ID, Configuration: m.Configuration, Expected: expected, Snapshot: snapshot, Delivery: &delivery}
	if operation == "activate" || operation == "trust" && j.Roots.Final == nil && len(state.Certificate) != 0 {
		in.Request, in.Certificate = state.Request, state.Certificate
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > nodeops.MaxRootRotationBytes {
		return empty, errRootRotationTask
	}
	command := strings.TrimSuffix(helperRunCommand(a), "\n") + " --identity-root-rotation\n"
	capture, err = runNodeCommand(ctx, remote.Client, command, bytes.NewReader(raw))
	if err != nil || ctx.Err() != nil || capture.overflow {
		return empty, DeploymentFailure{"remote-unavailable"}
	}
	var out nodeops.RootRotationOutput
	d := json.NewDecoder(bytes.NewReader(capture.raw))
	d.DisallowUnknownFields()
	phase := "dual"
	if j.Roots.Final != nil {
		phase = "new-only"
	}
	if !uniqueProvisioningJSON(json.NewDecoder(bytes.NewReader(capture.raw)), 0) || d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Format != 1 || out.Operation != operation || out.Node != m.ID || out.Snapshot != digest(snapshot) || out.Phase != phase || out.ResourcesVerified != (operation == "verify") {
		return empty, errRootRotationTask
	}
	want := expected
	if operation == "activate" {
		cert, err := provisioningCertificate(state.Certificate)
		if err != nil {
			return empty, errRootRotationTask
		}
		want = digest(cert.Raw)
	}
	if out.CertificateSHA256 != want || operation == "prepare" && (len(out.Request) == 0 || len(out.Request) > nodepki.MaxRenewalBytes) || operation != "prepare" && len(out.Request) != 0 {
		return empty, errRootRotationTask
	}
	if _, err := w.task(ctx, l, j.ID, index); err != nil {
		return empty, err
	}
	return out, nil
}

func (w *sshRootRotation) observe(ctx context.Context, l Lease, id string, index int) (*x509.Certificate, error) {
	j, err := w.task(ctx, l, id, index)
	if err != nil {
		return nil, err
	}
	m, state := j.Members[index], j.State[index]
	n, err := scanActiveNode(w.store.DB.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, m.ID))
	if err != nil || n.RuntimeEpoch != m.RuntimeEpoch {
		return nil, errRootRotationTask
	}
	issued, err := provisioningCertificate(state.Certificate)
	if err != nil {
		return nil, errRootRotationTask
	}
	trust, err := nodepki.NewTrust(j.Roots.Dual.NewCA, j.Roots.NewCRL, time.Now())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	peer, err := observeMaintainedNodeIdentity(ctx, w.config, n, n.ServerName, issued, trust, true, j.Roots.Dual.IssuedAt)
	if err != nil {
		return nil, err
	}
	if _, err := w.task(ctx, l, j.ID, index); err != nil {
		return nil, err
	}
	return peer, nil
}
