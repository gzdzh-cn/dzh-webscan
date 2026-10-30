//go:build linux

package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"webscan/internal/nodepki"
	"webscan/internal/pull"
)

type nodeIdentityRenewer struct {
	caFile, identityFile, node string
	trust                      *nodepki.FileTrust
}

func (r *nodeIdentityRenewer) Status(ctx context.Context) (pull.IdentityStatus, error) {
	var empty pull.IdentityStatus
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if r.trust == nil {
		return empty, nodepki.ErrRevocation
	}
	now := time.Now()
	b, record, err := nodepki.ReadIdentity(r.caFile, r.identityFile, nodepki.Node, r.node, now)
	defer clear(b.Key)
	if err != nil {
		return empty, err
	}
	block, _ := pem.Decode(b.Certificate)
	if block == nil {
		return empty, nodepki.ErrIdentity
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || r.trust.Verify(cert, nodepki.Node, r.node, now) != nil {
		return empty, nodepki.ErrIdentity
	}
	return pull.IdentityStatus{SHA256: record.CertificateSHA256, ExpiresAt: record.ExpiresAt}, nil
}

func (r *nodeIdentityRenewer) Prepare(ctx context.Context, expected string) ([]byte, error) {
	current, err := r.Status(ctx)
	if err != nil || current.SHA256 != expected {
		return nil, nodepki.ErrIdentity
	}
	request, err := nodepki.PrepareNodeRenewal(ctx, r.caFile, r.identityFile, r.node, expected, time.Now())
	if err != nil {
		return nil, err
	}
	return json.Marshal(request)
}

func (r *nodeIdentityRenewer) Activate(ctx context.Context, expected, requestSHA string, cert []byte) (pull.IdentityStatus, error) {
	var empty pull.IdentityStatus
	if _, err := r.Status(ctx); err != nil {
		return empty, err
	}
	record, err := nodepki.ActivateNodeRenewal(ctx, r.caFile, r.identityFile, r.node, expected, requestSHA, cert, time.Now(), func(leaf *x509.Certificate) error {
		return r.trust.Verify(leaf, nodepki.Node, r.node, time.Now())
	})
	if err != nil {
		return empty, err
	}
	return pull.IdentityStatus{SHA256: record.CertificateSHA256, ExpiresAt: record.ExpiresAt}, nil
}
