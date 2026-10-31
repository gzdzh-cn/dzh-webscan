package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"strings"
	"time"

	"webscan/internal/nodeops"
	"webscan/internal/nodepki"
)

// Host-only transport for a previously authorized durable name change. The
// release object and local executable are administrator-verified startup
// configuration; neither can be supplied by a browser or an Agent.
// An activation receipt is never readiness proof; completion uses a fresh mTLS RPC.
type sshNodeNameChange struct {
	store       *Store
	vault       *Vault
	config      Config
	release     *TrustedRelease
	localHelper string
}

func (w *sshNodeNameChange) ready() bool {
	return w != nil && w.store != nil && w.vault != nil && w.release != nil && w.localHelper != "" && w.config.NodePKI.Enabled && w.config.NodePKI.validate() == nil
}

func (w *sshNodeNameChange) provision(ctx context.Context, l Lease, id string) error {
	if !w.ready() {
		return errNodeNameChange
	}
	j, err := w.store.checkNodeNameChangeLease(ctx, w.vault, l, id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, j.ExpiresAt)
	defer cancel()
	a := w.release.manifest.Helper
	f, err := verifiedReleaseFile(ctx, w.localHelper, a, 256<<20)
	if err != nil {
		return DeploymentFailure{"artifact-invalid"}
	}
	defer f.Close()
	remote, err := w.store.connectNodeNameChangeSSH(ctx, w.vault, l, id)
	if err != nil {
		return err
	}
	defer remote.Close()
	capture, err := runNodeCommand(ctx, remote.Client, helperInstallCommand(a), io.LimitReader(f, int64(a.Bytes)+1))
	if err != nil || ctx.Err() != nil || capture.overflow || strings.TrimSpace(string(capture.raw)) != "helper-ready" {
		return DeploymentFailure{"remote-unavailable"}
	}
	_, err = w.store.checkNodeNameChangeLease(ctx, w.vault, l, id)
	return err
}

func (w *sshNodeNameChange) currentCRL(ctx context.Context, j nodeNameChangeJob) ([]byte, error) {
	var ca, floor []byte
	if err := w.store.DB.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1`, j.AuthoritySHA256).Scan(&ca, &floor); err != nil {
		return nil, errNodeNameChange
	}
	root, err := provisioningCertificate(ca)
	if err != nil || digest(root.Raw) != j.AuthoritySHA256 {
		return nil, errNodeNameChange
	}
	crl, err := provisioningIssuerCRL(w.config, ca, time.Now())
	if err != nil || nodepki.ValidateCRLAdvance(ca, floor, crl, time.Now()) != nil {
		return nil, errNodeNameChange
	}
	return crl, nil
}

func (w *sshNodeNameChange) phase(ctx context.Context, l Lease, id, operation string, signed *signedNodeRenewal) (nodeops.NameChangeOutput, error) {
	var empty nodeops.NameChangeOutput
	if !w.ready() {
		return empty, errNodeNameChange
	}
	j, err := w.store.checkNodeNameChangeLease(ctx, w.vault, l, id)
	signedPhase := operation == "activate" || operation == "verify"
	preparationPhase := operation == "prepare" || operation == "reconcile"
	if err != nil || preparationPhase && j.Status != "prepared" || operation == "prepare" && signed != nil || operation == "reconcile" && signed == nil || signedPhase && (j.Status != "signed" || signed == nil) || !preparationPhase && !signedPhase {
		return empty, errNodeNameChange
	}
	crl, err := w.currentCRL(ctx, j)
	if err != nil {
		return empty, err
	}
	in := nodeops.NameChangeInput{Format: 1, Operation: operation, Intent: j.Intent, CRL: crl}

	if operation == "reconcile" {
		original, certificate, err := nameChangePriorIssuance(ctx, w.store.DB, j.Node, j.AuthoritySHA256, j.ParentSHA256, j.TargetName, j.LifetimeHours)
		if err != nil || !bytes.Equal(certificate, signed.Certificate) {
			return empty, errNodeNameChange
		}
		in.Request, err = json.Marshal(original)
		if err != nil {
			return empty, errNodeNameChange
		}
		in.Certificate = certificate
	}
	if signedPhase {
		r, err := nodepki.ParseNodeNameChangeRequest(j.Request)
		if err != nil || r.SHA256() != j.RequestSHA256 || signed.Receipt.Node != j.Node || signed.Receipt.ParentSHA256 != j.ParentSHA256 || signed.Receipt.RequestSHA256 != r.IssuanceSHA256() || signed.Receipt.AuthoritySHA256 != j.AuthoritySHA256 || (len(r.ContinuationCertificate) == 0 && (signed.Receipt.Snapshot != j.Snapshot || signed.Receipt.RuntimeEpoch != j.RuntimeEpoch)) {
			return empty, errNodeNameChange
		}
		in.Request, in.Certificate = j.Request, signed.Certificate
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > nodeops.MaxNameChangeBytes {
		return empty, errNodeNameChange
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ctx, deadline := context.WithDeadline(ctx, j.ExpiresAt)
	defer deadline()
	remote, err := w.store.connectNodeNameChangeSSH(ctx, w.vault, l, id)
	if err != nil {
		return empty, err
	}
	defer remote.Close()
	command := strings.TrimSuffix(helperRunCommand(w.release.manifest.Helper), "\n") + " --identity-name-change\n"
	capture, err := runNodeCommand(ctx, remote.Client, command, bytes.NewReader(raw))
	if err != nil || ctx.Err() != nil || capture.overflow {
		return empty, DeploymentFailure{"remote-unavailable"}
	}
	if !uniqueProvisioningJSON(json.NewDecoder(bytes.NewReader(capture.raw)), 0) {
		return empty, errNodeNameChange
	}
	var out nodeops.NameChangeOutput
	d := json.NewDecoder(bytes.NewReader(capture.raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Format != 1 || out.Node != j.Node || out.Challenge != j.Intent.Challenge || out.Operation != operation || preparationPhase && (len(out.Request) == 0 || len(out.Request) > nodepki.MaxRenewalBytes || out.CertificateSHA256 != "") || signedPhase && (len(out.Request) != 0 || out.CertificateSHA256 != signed.Receipt.CertificateSHA256) {
		return empty, errNodeNameChange
	}
	if out.ResourcesVerified != (operation == "verify") {
		return empty, errNodeNameChange
	}
	if _, err := w.store.checkNodeNameChangeLease(ctx, w.vault, l, id); err != nil {
		return empty, err
	}
	return out, nil
}

func (w *sshNodeNameChange) prepare(ctx context.Context, l Lease, id string) (nodeNameChangeJob, error) {
	if !w.ready() {
		return nodeNameChangeJob{}, errNodeNameChange
	}
	j, err := w.store.checkNodeNameChangeLease(ctx, w.vault, l, id)
	if err != nil {
		return nodeNameChangeJob{}, err
	}
	if j.Status == "requested" || j.Status == "signed" {
		return w.store.admitNodeNameChange(ctx, w.vault, l, id, j.Request)
	}
	if err := w.provision(ctx, l, id); err != nil {
		return nodeNameChangeJob{}, err
	}
	operation := "prepare"
	var previous *signedNodeRenewal
	_, certificate, priorErr := nameChangePriorIssuance(ctx, w.store.DB, j.Node, j.AuthoritySHA256, j.ParentSHA256, j.TargetName, j.LifetimeHours)
	if priorErr == nil {
		operation, previous = "reconcile", &signedNodeRenewal{Certificate: certificate}
	} else if priorErr != sql.ErrNoRows {
		return nodeNameChangeJob{}, priorErr
	}
	out, err := w.phase(ctx, l, id, operation, previous)
	if err != nil {
		return nodeNameChangeJob{}, err
	}
	return w.store.admitNodeNameChange(ctx, w.vault, l, id, out.Request)
}

func (w *sshNodeNameChange) activate(ctx context.Context, l Lease, id string) error {
	return w.signedPhase(ctx, l, id, "activate")
}

func (w *sshNodeNameChange) verify(ctx context.Context, l Lease, id string) error {
	return w.signedPhase(ctx, l, id, "verify")
}

func (w *sshNodeNameChange) signedPhase(ctx context.Context, l Lease, id, operation string) error {
	if operation != "activate" && operation != "verify" {
		return errNodeNameChange
	}
	if !w.ready() {
		return errNodeNameChange
	}
	if err := w.provision(ctx, l, id); err != nil {
		return err
	}
	// Signing/replay rechecks the durable job and commits to the shared ledger
	// before any certificate bytes are sent to the node.
	signed, err := w.store.signNodeNameChange(ctx, w.config, w.vault, l, id)
	if err != nil {
		return err
	}
	_, err = w.phase(ctx, l, id, operation, &signed)
	return err
}
