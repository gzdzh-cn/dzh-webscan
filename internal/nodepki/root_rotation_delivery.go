package nodepki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

// A fresh, target-bound delivery can resume a durable rotation whose immutable
// authorization is older than ten minutes. It cannot change that authorization,
// its membership, the target configuration, current identity or CRL bytes.
// Only the isolated host administrator runner has both issuer keys.
type RootDelivery struct {
	Format             int       `json:"format"`
	Task               string    `json:"task"`
	Snapshot           string    `json:"snapshot_sha256"`
	Role               string    `json:"role"`
	ID                 string    `json:"id"`
	Configuration      string    `json:"configuration_sha256"`
	Certificate        string    `json:"certificate_sha256"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	AnchorSignature    []byte    `json:"anchor_signature"`
	SuccessorSignature []byte    `json:"successor_signature"`
}

func rootDeliveryMessage(d RootDelivery) []byte {
	d.AnchorSignature, d.SuccessorSignature = nil, nil
	raw, _ := json.Marshal(d)
	return append([]byte("webscan-v3/explicit-root-delivery/v1\x00"), raw...)
}

func (a *Authority) AuthorizeRootDelivery(next *Authority, snapshot RootSetSnapshot, role, id, configuration, certificate string, now time.Time) (RootDelivery, error) {
	var out RootDelivery
	if a == nil || next == nil || len(a.key) != ed25519.PrivateKeySize || len(next.key) != ed25519.PrivateKeySize || !bytes.Equal(snapshot.Dual.NewCA, certificatePEM(next.certificate)) {
		return out, ErrRootRotation
	}
	anchor := certificatePEM(a.certificate)
	if _, err := NewRootSet(anchor, snapshot, now); err != nil {
		return out, err
	}
	if _, err := Identity(role, id); err != nil || !recoverySHA(configuration) || !recoverySHA(certificate) {
		return out, ErrRootRotation
	}
	raw, _ := json.Marshal(snapshot)
	at := now.UTC().Truncate(time.Second)
	out = RootDelivery{Format: 1, Task: snapshot.Dual.Rotation, Snapshot: publicSHA(raw), Role: role, ID: id, Configuration: configuration, Certificate: certificate, IssuedAt: at, ExpiresAt: at.Add(10 * time.Minute)}
	message := rootDeliveryMessage(out)
	out.AnchorSignature, out.SuccessorSignature = ed25519.Sign(a.key, message), ed25519.Sign(next.key, message)
	return out, nil
}

func VerifyRootDelivery(anchor, raw []byte, d RootDelivery, role, id, configuration, certificate string, now time.Time) error {
	s, err := ParseRootSetSnapshot(raw)
	if err != nil || d.Format != 1 || d.Task != s.Dual.Rotation || d.Snapshot != publicSHA(raw) || d.Role != role || d.ID != id || d.Configuration != configuration || d.Certificate != certificate || !recoverySHA(configuration) || !recoverySHA(certificate) || d.IssuedAt.IsZero() || d.IssuedAt.After(now) || !now.Before(d.ExpiresAt) || !d.ExpiresAt.Equal(d.IssuedAt.Add(10*time.Minute)) {
		return ErrRootRotation
	}
	if _, err := Identity(role, id); err != nil {
		return ErrRootRotation
	}
	if _, err := NewRootSet(anchor, s, now); err != nil {
		return err
	}
	old, err := parseCertificate(anchor)
	next, e2 := parseCertificate(s.Dual.NewCA)
	if err != nil || e2 != nil || !validAuthority(old, d.IssuedAt) || !validAuthority(next, now) {
		return ErrRootRotation
	}
	message := rootDeliveryMessage(d)
	if !ed25519.Verify(old.PublicKey.(ed25519.PublicKey), message, d.AnchorSignature) || !ed25519.Verify(next.PublicKey.(ed25519.PublicKey), message, d.SuccessorSignature) {
		return ErrRootRotation
	}
	return nil
}

// PublishDeliveredRootSet permits only a freshly co-signed delivery of the
// exact immutable task. History/CRL floors, phase ordering and finalization
// checks remain mandatory. The caller must separately prove the local target
// installation and fingerprint before invoking this root-only primitive.
func PublishDeliveredRootSet(ctx context.Context, directory string, anchor, raw []byte, delivery RootDelivery, role, id, configuration, certificate string, now time.Time) (RootSetReceipt, error) {
	started := time.Now()
	if err := VerifyRootDelivery(anchor, raw, delivery, role, id, configuration, certificate, now); err != nil {
		return RootSetReceipt{}, err
	}
	return publishRootSetAuthorized(ctx, directory, anchor, raw, now, false, func(_, _ RootSetSnapshot) error {
		// Recheck wall time after waiting for the floor lock.
		return VerifyRootDelivery(anchor, raw, delivery, role, id, configuration, certificate, now.Add(time.Since(started)))
	})
}
