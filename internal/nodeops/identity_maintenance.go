package nodeops

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"time"
	"webscan/internal/nodepki"
)

// Hold journal -> service operation locks while validating the installed
// configuration, existing trust floor and current live identity. Identity
// maintenance must never initialize a missing floor or overlap deployment.
func (w *LocalRuntime) withIdentityMaintenance(ctx context.Context, node, issuer string, crl []byte, use func(context.Context, []byte, string, string, string, string) error) error {
	return w.withInstalledNodeOperation(ctx, node, func(ctx context.Context) error {
		return w.validateIdentityMaintenance(ctx, node, issuer, crl, use)
	})
}

// Shared journal/service serialization for fixed identity operations. The
// callback must validate its own signed trust policy before publishing files.
func (w *LocalRuntime) withInstalledNodeOperation(ctx context.Context, node string, use func(context.Context) error) error {
	// Lifecycle ordering: journal -> service operation -> trust -> identity.
	j := &Journal{root: filepath.Join(w.root, "node")}
	if privateDirectoryTree(j.root) != nil || privateFile(filepath.Join(j.root, "journal.sqlite3"), false) != nil {
		return errNameChange
	}
	lock, err := j.lock()
	if err != nil {
		return errNameChange
	}
	defer lock.Close()
	db, err := j.database()
	if err != nil {
		return errNameChange
	}
	defer db.Close()
	var ready bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM meta m JOIN jobs j ON j.id=m.current_job WHERE m.id=1 AND m.node=? AND j.retired=0 AND (EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase='finalize' AND p.status='complete') AND NOT EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase IN ('restore','verify-rollback')) OR EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.phase='verify-rollback' AND p.status='complete')) AND NOT EXISTS(SELECT 1 FROM phases p WHERE p.job=j.id AND p.status='running'))`, node).Scan(&ready); err != nil || !ready {
		return errNameChange
	}
	ctx, release, err := acquireServiceOperation(ctx, w.root)
	if err != nil {
		return errNameChange
	}
	defer release()
	return use(ctx)
}

func (w *LocalRuntime) validateIdentityMaintenance(ctx context.Context, node, issuer string, crl []byte, use func(context.Context, []byte, string, string, string, string) error) error {
	if _, err := nodepki.RefreshIdentityIssuerCRL(ctx, filepath.Join(w.managedDataDirectory(), "pki-identity", "ca.crt"), filepath.Join(w.managedDataDirectory(), "pki-trust"), issuer, crl, time.Now()); err != nil {
		return errNameChange
	}
	ca, sourceName, err := w.identityMaintenanceInstallation(node, crl)
	if err != nil {
		return errNameChange
	}
	data := w.managedDataDirectory()
	identity, floor := filepath.Join(data, "pki-identity"), filepath.Join(data, "pki-trust")
	for _, dir := range []string{data, identity, floor} {
		if privateDirectoryTree(dir) != nil {
			return errNameChange
		}
	}
	caFile, activeFile := filepath.Join(identity, "ca.crt"), filepath.Join(identity, "active.pem")
	for _, dir := range []string{identity, floor} {
		pinned, err := readPrivate(filepath.Join(dir, "ca.crt"), 64<<10)
		if err != nil || !bytes.Equal(bytes.TrimSpace(pinned), bytes.TrimSpace(ca)) {
			return errNameChange
		}
	}
	roots, err := w.installedRootState(time.Now())
	if err != nil {
		return errNameChange
	}
	if roots.Format == 0 {
		previous, err := readPrivate(filepath.Join(floor, "ca.crl"), nodepki.MaxCRLBytes)
		if err != nil || nodepki.ValidateCRLAdvance(ca, previous, crl, time.Now()) != nil {
			return errNameChange
		}
	}
	// Check incoming revocations before any new local CSR/key is prepared.
	active, _, err := nodepki.ReadIdentityWithRootState(caFile, activeFile, floor, nodepki.Node, node, time.Now())
	defer clear(active.Key)
	if err != nil {
		return errNameChange
	}
	block, _ := pem.Decode(active.Certificate)
	if block == nil {
		return errNameChange
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	trust, trustErr := nodepki.NewTrust(active.CA, crl, time.Now())
	if err != nil || trustErr != nil || trust.Verify(leaf, nodepki.Node, node, time.Now()) != nil || leaf.VerifyHostname(sourceName) != nil {
		return errNameChange
	}
	return use(ctx, ca, sourceName, caFile, activeFile, floor)
}
