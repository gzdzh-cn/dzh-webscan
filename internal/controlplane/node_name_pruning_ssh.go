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

// Host-only transport. The task fixes the credential, SSH pin, configuration,
// permitted SAN subset and helper digest before any remote operation occurs.
type sshNodeNamePruning struct {
	store       *Store
	vault       *Vault
	config      Config
	release     *TrustedRelease
	localHelper string
}

func (w *sshNodeNamePruning) ready() bool {
	return w != nil && w.store != nil && w.vault != nil && w.release != nil && w.localHelper != "" && w.config.NodePKI.Enabled && w.config.NodePKI.validate() == nil
}

func (w *sshNodeNamePruning) provision(ctx context.Context, l Lease, id string) error {
	if !w.ready() {
		return errNodeNamePruning
	}
	j, err := w.store.checkNodeNamePruningLease(ctx, w.config, w.vault, l, id)
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
	remote, err := w.store.connectNodeNamePruningSSH(ctx, w.config, w.vault, l, id)
	if err != nil {
		return err
	}
	defer remote.Close()
	capture, err := runNodeCommand(ctx, remote.Client, helperInstallCommand(a), io.LimitReader(f, int64(a.Bytes)+1))
	if err != nil || ctx.Err() != nil || capture.overflow || strings.TrimSpace(string(capture.raw)) != "helper-ready" {
		return DeploymentFailure{"remote-unavailable"}
	}
	_, err = w.store.checkNodeNamePruningLease(ctx, w.config, w.vault, l, id)
	return err
}

func (w *sshNodeNamePruning) currentCRL(ctx context.Context, j nodeNamePruningJob) ([]byte, error) {
	var ca, floor []byte
	if err := w.store.DB.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1`, j.AuthoritySHA256).Scan(&ca, &floor); err != nil {
		return nil, errNodeNamePruning
	}
	root, err := provisioningCertificate(ca)
	if err != nil || digest(root.Raw) != j.AuthoritySHA256 {
		return nil, errNodeNamePruning
	}
	crl, err := provisioningIssuerCRL(w.config, ca, time.Now())
	if err != nil || nodepki.ValidateCRLAdvance(ca, floor, crl, time.Now()) != nil {
		return nil, errNodeNamePruning
	}
	return crl, nil
}

func (w *sshNodeNamePruning) phase(ctx context.Context, l Lease, id, operation string, signed *signedNodeRenewal) (nodeops.NamePruningOutput, error) {
	var empty nodeops.NamePruningOutput
	if !w.ready() {
		return empty, errNodeNamePruning
	}
	j, err := w.store.checkNodeNamePruningLease(ctx, w.config, w.vault, l, id)
	proof := operation == "activate" || operation == "verify"
	preparation := operation == "prepare" || operation == "reconcile"
	if err != nil || preparation && j.Status != "prepared" || operation == "prepare" && signed != nil || operation == "reconcile" && signed == nil || proof && (j.Status != "signed" || signed == nil) || !preparation && !proof {
		return empty, errNodeNamePruning
	}
	crl, err := w.currentCRL(ctx, j)
	if err != nil {
		return empty, err
	}
	in := nodeops.NamePruningInput{Format: 1, Operation: operation, Intent: j.Intent, CRL: crl}
	if operation == "reconcile" {
		original, certificate, hours, err := namePruningPriorIssuance(ctx, w.store.DB, j.Plan)
		if err != nil || hours != j.LifetimeHours || !bytes.Equal(certificate, signed.Certificate) {
			return empty, errNodeNamePruning
		}
		in.Request, err = json.Marshal(original)
		if err != nil {
			return empty, errNodeNamePruning
		}
		in.Certificate = certificate
	}
	if proof {
		r, err := nodepki.ParseNodeNamePruningRequest(j.Request)
		if err != nil || r.SHA256() != j.RequestSHA256 || signed.Receipt.Node != j.Node || signed.Receipt.ParentSHA256 != j.ParentSHA256 || signed.Receipt.RequestSHA256 != r.IssuanceSHA256() || signed.Receipt.AuthoritySHA256 != j.AuthoritySHA256 || signed.Receipt.Snapshot != j.Snapshot || signed.Receipt.RuntimeEpoch != j.Plan.RuntimeEpoch {
			return empty, errNodeNamePruning
		}
		in.Request, in.Certificate = j.Request, signed.Certificate
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > nodeops.MaxNameChangeBytes {
		return empty, errNodeNamePruning
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ctx, deadline := context.WithDeadline(ctx, j.ExpiresAt)
	defer deadline()
	remote, err := w.store.connectNodeNamePruningSSH(ctx, w.config, w.vault, l, id)
	if err != nil {
		return empty, err
	}
	defer remote.Close()
	command := strings.TrimSuffix(helperRunCommand(w.release.manifest.Helper), "\n") + " --identity-name-pruning\n"
	capture, err := runNodeCommand(ctx, remote.Client, command, bytes.NewReader(raw))
	if err != nil || ctx.Err() != nil || capture.overflow {
		return empty, DeploymentFailure{"remote-unavailable"}
	}
	if !uniqueProvisioningJSON(json.NewDecoder(bytes.NewReader(capture.raw)), 0) {
		return empty, errNodeNamePruning
	}
	var out nodeops.NamePruningOutput
	d := json.NewDecoder(bytes.NewReader(capture.raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Format != 1 || out.Node != j.Node || out.Challenge != j.Intent.Challenge || out.Operation != operation || preparation && (len(out.Request) == 0 || len(out.Request) > nodepki.MaxRenewalBytes || out.CertificateSHA256 != "") || proof && (len(out.Request) != 0 || out.CertificateSHA256 != signed.Receipt.CertificateSHA256) || out.ResourcesVerified != (operation == "verify") {
		return empty, errNodeNamePruning
	}
	if _, err := w.store.checkNodeNamePruningLease(ctx, w.config, w.vault, l, id); err != nil {
		return empty, err
	}
	return out, nil
}

func (w *sshNodeNamePruning) prepare(ctx context.Context, l Lease, id string) (nodeNamePruningJob, error) {
	if !w.ready() {
		return nodeNamePruningJob{}, errNodeNamePruning
	}
	j, err := w.store.checkNodeNamePruningLease(ctx, w.config, w.vault, l, id)
	if err != nil {
		return nodeNamePruningJob{}, err
	}
	if j.Status == "requested" || j.Status == "signed" {
		return w.store.admitNodeNamePruning(ctx, w.config, w.vault, l, id, j.Request)
	}
	if err := w.provision(ctx, l, id); err != nil {
		return nodeNamePruningJob{}, err
	}
	operation := "prepare"
	var previous *signedNodeRenewal
	_, certificate, hours, priorErr := namePruningPriorIssuance(ctx, w.store.DB, j.Plan)
	if priorErr == nil && hours == j.LifetimeHours {
		operation, previous = "reconcile", &signedNodeRenewal{Certificate: certificate}
	} else if priorErr != sql.ErrNoRows {
		return nodeNamePruningJob{}, errNodeNamePruning
	}
	out, err := w.phase(ctx, l, id, operation, previous)
	if err != nil {
		return nodeNamePruningJob{}, err
	}
	return w.store.admitNodeNamePruning(ctx, w.config, w.vault, l, id, out.Request)
}

func (w *sshNodeNamePruning) activate(ctx context.Context, l Lease, id string) error {
	return w.signedPhase(ctx, l, id, "activate")
}
func (w *sshNodeNamePruning) verify(ctx context.Context, l Lease, id string) error {
	return w.signedPhase(ctx, l, id, "verify")
}
func (w *sshNodeNamePruning) signedPhase(ctx context.Context, l Lease, id, operation string) error {
	if operation != "activate" && operation != "verify" || !w.ready() {
		return errNodeNamePruning
	}
	if err := w.provision(ctx, l, id); err != nil {
		return err
	}
	signed, err := w.store.signNodeNamePruning(ctx, w.config, w.vault, l, id)
	if err != nil {
		return err
	}
	_, err = w.phase(ctx, l, id, operation, &signed)
	return err
}
