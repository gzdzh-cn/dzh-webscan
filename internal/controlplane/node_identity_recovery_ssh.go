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

// Host-only transport for a previously authorized durable recovery. The
// release object and local executable are administrator-verified startup
// configuration; neither can be supplied by a browser or an Agent.
// A start receipt is never readiness proof; completion uses a fresh mTLS RPC.
type sshNodeIdentityRecovery struct {
	store       *Store
	vault       *Vault
	config      Config
	release     *TrustedRelease
	localHelper string
}

func (w *sshNodeIdentityRecovery) ready() bool {
	return w != nil && w.store != nil && w.vault != nil && w.release != nil && w.localHelper != "" && w.config.NodePKI.Enabled && w.config.NodePKI.validate() == nil
}

func (w *sshNodeIdentityRecovery) provision(ctx context.Context, l Lease, id string) error {
	if !w.ready() {
		return errNodeIdentityRecovery
	}
	j, err := w.store.checkNodeIdentityRecoveryLease(ctx, w.vault, l, id)
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
	remote, err := w.store.connectNodeIdentityRecoverySSH(ctx, w.vault, l, id)
	if err != nil {
		return err
	}
	defer remote.Close()
	capture, err := runNodeCommand(ctx, remote.Client, helperInstallCommand(a), io.LimitReader(f, int64(a.Bytes)+1))
	if err != nil || ctx.Err() != nil || capture.overflow || strings.TrimSpace(string(capture.raw)) != "helper-ready" {
		return DeploymentFailure{"remote-unavailable"}
	}
	_, err = w.store.checkNodeIdentityRecoveryLease(ctx, w.vault, l, id)
	return err
}

func (w *sshNodeIdentityRecovery) currentCRL(ctx context.Context, j nodeIdentityRecoveryJob) ([]byte, error) {
	var ca, floor []byte
	if err := w.store.DB.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1`, j.AuthoritySHA256).Scan(&ca, &floor); err != nil {
		return nil, errNodeIdentityRecovery
	}
	root, err := provisioningCertificate(ca)
	if err != nil || digest(root.Raw) != j.AuthoritySHA256 {
		return nil, errNodeIdentityRecovery
	}
	crl, err := provisioningIssuerCRL(w.config, ca, time.Now())
	if err != nil || nodepki.ValidateCRLAdvance(ca, floor, crl, time.Now()) != nil {
		return nil, errNodeIdentityRecovery
	}
	return crl, nil
}

func (w *sshNodeIdentityRecovery) phase(ctx context.Context, l Lease, id, operation string, signed *signedNodeRenewal) (nodeops.IdentityRecoveryOutput, error) {
	var empty nodeops.IdentityRecoveryOutput
	if !w.ready() {
		return empty, errNodeIdentityRecovery
	}
	j, err := w.store.checkNodeIdentityRecoveryLease(ctx, w.vault, l, id)
	signedPhase := operation == "activate" || operation == "start" || operation == "verify"
	preparationPhase := operation == "prepare" || operation == "reconcile"
	if err != nil || preparationPhase && j.Status != "prepared" || operation == "reconcile" && signed == nil || signedPhase && (j.Status != "signed" || signed == nil) || !preparationPhase && !signedPhase {
		return empty, errNodeIdentityRecovery
	}
	crl, err := w.currentCRL(ctx, j)
	if err != nil {
		return empty, err
	}
	in := nodeops.IdentityRecoveryInput{Format: 1, Operation: operation, Intent: j.Intent, CRL: crl}
	if operation == "reconcile" {
		in.Certificate = signed.Certificate
	}
	if signedPhase {
		r, err := nodepki.ParseNodeRecoveryRequest(j.Request)
		if err != nil || r.SHA256() != j.RequestSHA256 || signed.Receipt.Node != j.Node || signed.Receipt.ParentSHA256 != j.ParentSHA256 || signed.Receipt.RequestSHA256 != r.Renewal.SHA256() || signed.Receipt.AuthoritySHA256 != j.AuthoritySHA256 {
			return empty, errNodeIdentityRecovery
		}
		in.Request, in.Certificate = j.Request, signed.Certificate
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > nodeops.MaxIdentityRecoveryBytes {
		return empty, errNodeIdentityRecovery
	}
	ctx, cancel := context.WithTimeout(ctx, nodepki.NameChangeVerificationTimeout+15*time.Second)
	defer cancel()
	ctx, deadline := context.WithDeadline(ctx, j.ExpiresAt)
	defer deadline()
	remote, err := w.store.connectNodeIdentityRecoverySSH(ctx, w.vault, l, id)
	if err != nil {
		return empty, err
	}
	defer remote.Close()
	command := strings.TrimSuffix(helperRunCommand(w.release.manifest.Helper), "\n") + " --identity-recovery\n"
	capture, err := runNodeCommand(ctx, remote.Client, command, bytes.NewReader(raw))
	if err != nil || ctx.Err() != nil || capture.overflow {
		return empty, DeploymentFailure{"remote-unavailable"}
	}
	var out nodeops.IdentityRecoveryOutput
	d := json.NewDecoder(bytes.NewReader(capture.raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Format != 1 || out.Node != j.Node || out.Challenge != j.Intent.Challenge || out.Operation != operation || preparationPhase && (len(out.Request) == 0 || len(out.Request) > nodepki.MaxRenewalBytes || out.CertificateSHA256 != "") || signedPhase && (len(out.Request) != 0 || out.CertificateSHA256 != signed.Receipt.CertificateSHA256) {
		return empty, errNodeIdentityRecovery
	}
	if out.ResourcesVerified != (operation == "verify") {
		return empty, errNodeIdentityRecovery
	}
	if _, err := w.store.checkNodeIdentityRecoveryLease(ctx, w.vault, l, id); err != nil {
		return empty, err
	}
	return out, nil
}

func (w *sshNodeIdentityRecovery) prepare(ctx context.Context, l Lease, id string) (nodeIdentityRecoveryJob, error) {
	if !w.ready() {
		return nodeIdentityRecoveryJob{}, errNodeIdentityRecovery
	}
	j, err := w.store.checkNodeIdentityRecoveryLease(ctx, w.vault, l, id)
	if err != nil {
		return nodeIdentityRecoveryJob{}, err
	}
	if j.Status == "requested" || j.Status == "signed" {
		return w.store.admitNodeIdentityRecovery(ctx, w.vault, l, id, j.Request)
	}
	if err := w.provision(ctx, l, id); err != nil {
		return nodeIdentityRecoveryJob{}, err
	}
	// A receipt may have been committed before an earlier intent expired or
	// was canceled. It is immutable public material, checked again on admission
	// and signing replay. No private seed or signing key is retrieved here.
	var previous signedNodeRenewal
	var authority string
	var hours int
	err = w.store.DB.QueryRowContext(ctx, `SELECT certificate,authority,lifetime_hours FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2 AND request_kind='renewal'`, j.Node, j.ParentSHA256).Scan(&previous.Certificate, &authority, &hours)
	operation := "prepare"
	var receipt *signedNodeRenewal
	if err == nil {
		if authority != j.AuthoritySHA256 || hours != j.LifetimeHours {
			return nodeIdentityRecoveryJob{}, errNodeIdentityRecovery
		}
		operation, receipt = "reconcile", &previous
	} else if err != sql.ErrNoRows {
		return nodeIdentityRecoveryJob{}, err
	}
	out, err := w.phase(ctx, l, id, operation, receipt)
	if err != nil {
		return nodeIdentityRecoveryJob{}, err
	}
	return w.store.admitNodeIdentityRecovery(ctx, w.vault, l, id, out.Request)
}

func (w *sshNodeIdentityRecovery) activate(ctx context.Context, l Lease, id string) error {
	return w.signedPhase(ctx, l, id, "activate")
}

func (w *sshNodeIdentityRecovery) start(ctx context.Context, l Lease, id string) error {
	return w.signedPhase(ctx, l, id, "start")
}

func (w *sshNodeIdentityRecovery) verify(ctx context.Context, l Lease, id string) error {
	return w.signedPhase(ctx, l, id, "verify")
}

func (w *sshNodeIdentityRecovery) signedPhase(ctx context.Context, l Lease, id, operation string) error {
	if operation != "activate" && operation != "start" && operation != "verify" {
		return errNodeIdentityRecovery
	}
	if !w.ready() {
		return errNodeIdentityRecovery
	}
	if err := w.provision(ctx, l, id); err != nil {
		return err
	}
	// Signing/replay rechecks the durable job and commits to the shared ledger
	// before any certificate bytes are sent to the node.
	signed, err := w.store.signNodeIdentityRecovery(ctx, w.config, w.vault, l, id)
	if err != nil {
		return err
	}
	_, err = w.phase(ctx, l, id, operation, &signed)
	return err
}
