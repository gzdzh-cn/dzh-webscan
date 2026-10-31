package nodepki

import (
	"context"
	"crypto/x509"
	"time"
)

// RefreshRoots accepts CRL refreshes for an already installed authorization.
// It cannot start a rotation, finalize it, or alter its fixed membership. Those
// actions require the separate privileged administrator rollout.
func (p *ReceiverTrust) RefreshRoots(ctx context.Context, peer *x509.Certificate, raw []byte, now time.Time) (RootSetReceipt, error) {
	if p == nil || p.FileTrust == nil || ctx.Err() != nil {
		return RootSetReceipt{}, ErrRootRotation
	}
	proposed, err := ParseRootSetSnapshot(raw)
	if err != nil {
		return RootSetReceipt{}, err
	}
	roots, err := NewRootSet(p.ca, proposed, now)
	if err != nil {
		return RootSetReceipt{}, err
	}
	id, err := PeerID(peer, Collector)
	if err != nil || roots.Verify(peer, Collector, id, now) != nil {
		return RootSetReceipt{}, ErrIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case p.updates <- struct{}{}:
		defer func() { <-p.updates }()
	case <-ctx.Done():
		return RootSetReceipt{}, ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	receipt, err := publishRootSet(ctx, p.stateDirectory, p.ca, raw, now, func(previous, next RootSetSnapshot) error {
		if previous.Format != 1 || RootAuthorizationSHA256(previous.Dual) != RootAuthorizationSHA256(next.Dual) || (previous.Final == nil) != (next.Final == nil) {
			return ErrRootRotation
		}
		if previous.Final != nil && RootAuthorizationSHA256(*previous.Final) != RootAuthorizationSHA256(*next.Final) {
			return ErrRootRotation
		}
		if p.rootSet != nil {
			floor, err := ParseRootSetSnapshot(p.rootSet.raw)
			if err != nil || ValidateRootSetAdvance(p.ca, floor, next, now) != nil {
				return ErrRootRotation
			}
		}
		return nil
	})
	if err != nil {
		return RootSetReceipt{}, err
	}
	p.rootSet, p.rootReceipt = roots, receipt
	p.lastCheck, p.lastErr = now, nil
	return receipt, nil
}

// HandshakeRootPool supplies authenticated issuer keys even if their CRLs
// expired. This grants only TLS admission, not ordinary RPC authorization:
// every ordinary RPC still checks live revocation policy, and refresh methods
// independently verify their caller under a fresh proposed snapshot. A bad
// signature, missing state or lower process floor cannot open the listener.
func (p *ReceiverTrust) HandshakeRootPool(now time.Time) (*x509.CertPool, error) {
	if p == nil || p.FileTrust == nil {
		return nil, ErrRootRotation
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	roots, receipt, err := readRootSet(p.stateDirectory, p.ca, now, true)
	if err != nil {
		return nil, err
	}
	if roots != nil {
		if p.rootSet != nil && p.rootReceipt.SHA256 != receipt.SHA256 {
			previous, e1 := ParseRootSetSnapshot(p.rootSet.raw)
			next, e2 := ParseRootSetSnapshot(roots.raw)
			if e1 != nil || e2 != nil || ValidateRootSetAdvance(p.ca, previous, next, now) != nil {
				return nil, ErrRootRotation
			}
		}
		p.rootSet, p.rootReceipt = roots, receipt
		return roots.Pool(), nil
	}
	if p.rootSet != nil || p.trust == nil {
		return nil, ErrRootRotation
	}
	raw, err := readIdentityFile(p.crlFile, MaxCRLBytes, true)
	root, e2 := parseCertificate(p.ca)
	if err != nil || e2 != nil || !validAuthority(root, now) {
		return nil, ErrRevocation
	}
	list, err := parseCRL(raw, root)
	if err != nil || list.ThisUpdate.After(now) || p.trust.UpdateCRL(raw, list.ThisUpdate) != nil {
		return nil, ErrRevocation
	}
	return p.trust.roots.Clone(), nil
}
