package nodepki

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real keys and durable files, with an explicit clock. This is not the SSH or
// kernel acceptance gate; it covers all same-issuer maintenance after old-root
// retirement, including when the original CRL has already expired.
func TestSuccessorMaintenancePreservesOriginalAnchor(t *testing.T) {
	ctx := context.Background()
	old, next, anchor, roots, now := rootRotationFixture(t)
	floor := rootRotationState(t, anchor, roots.OldCRL, now)
	directory := privateTestDir(t)
	ca, active := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "active.pem")
	if err := os.WriteFile(ca, anchor, 0600); err != nil {
		t.Fatal(err)
	}
	seed, err := old.Issue(Node, "node-a", []string{"old.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed.Key)
	prior, err := PublishIdentity(ctx, ca, active, Node, "node-a", "", seed, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(roots)
	if _, err := PublishRootSet(ctx, floor, anchor, encoded, now); err != nil {
		t.Fatal(err)
	}
	r, err := PrepareRootIdentity(ctx, ca, active, floor, Node, "node-a", RootAuthorizationSHA256(roots.Dual), prior.CertificateSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	issuer := filepath.Join(privateTestDir(t), "authority")
	b, err := next.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	if err := SeedAuthority(ctx, issuer, b, roots.NewCRL, now); err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	if err := SignRootIdentityRegistered(ctx, issuer, anchor, roots, r, now, 72*time.Hour, func(b Bundle) error { certificate = b.Certificate; return nil }); err != nil {
		t.Fatal(err)
	}
	current, err := ActivateRootIdentity(ctx, ca, active, floor, Node, "node-a", r.Authorization, prior.CertificateSHA256, r.SHA256(), certificate, now)
	if err != nil {
		t.Fatal(err)
	}
	final, err := old.AuthorizeRootRotation(next, roots.Dual.Rotation, roots.Dual.MembersSHA256, &roots.Dual, strings.Repeat("e", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	roots.Final = &final
	encoded, _ = json.Marshal(roots)
	if _, err := PublishRootSet(ctx, floor, anchor, encoded, now); err != nil {
		t.Fatal(err)
	}
	at := now.Add(26 * time.Hour)
	_, crl, _, err := RefreshCRL(ctx, issuer, at, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sha, _ := RootFingerprint(b.CA)
	if changed, err := RefreshIdentityIssuerCRL(ctx, ca, floor, sha, crl, at); err != nil || !changed {
		t.Fatal("refresh successor", err)
	}
	oldSHA, _ := RootFingerprint(anchor)
	if _, err := RefreshIdentityIssuerCRL(ctx, ca, floor, oldSHA, roots.OldCRL, at); err == nil {
		t.Fatal("retired issuer was reauthorized")
	}
	intent, err := NewNodeNameChangeIntent("node-a", sha, current.CertificateSHA256, "new.test", at)
	if err != nil {
		t.Fatal(err)
	}
	change, err := PrepareNodeNameChange(ctx, ca, active, floor, intent, at)
	if err != nil {
		t.Fatal("successor name preparation", err)
	}
	if err := SignNodeNameChangeRegistered(ctx, issuer, change, intent, at, 96*time.Hour, func(b Bundle, _ []byte) error { certificate = b.Certificate; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishNodeNameChangeTrust(ctx, ca, floor, crl, change, intent, at); err != nil {
		t.Fatal(err)
	}
	current, err = ActivateNodeNameChange(ctx, ca, active, floor, change, intent, certificate, at)
	if err != nil {
		t.Fatal("successor name activation", err)
	}
	if err := WithNameChangedNodeIdentity(ctx, ca, active, floor, change, intent, certificate, at, func(context.Context, IdentityRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	prune, err := NewNodeNamePruningIntent("node-a", sha, current.CertificateSHA256, strings.Repeat("c", 64), 1, "new.test", []string{"new.test"}, at)
	if err != nil {
		t.Fatal(err)
	}
	pruning, err := PrepareNodeNamePruning(ctx, ca, active, floor, prune, at)
	if err != nil {
		t.Fatal("successor pruning preparation", err)
	}
	if err := SignNodeNamePruningRegistered(ctx, issuer, pruning, prune, at, 120*time.Hour, func(b Bundle, _ []byte) error { certificate = b.Certificate; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishNodeNamePruningTrust(ctx, ca, floor, crl, pruning, prune, at); err != nil {
		t.Fatal(err)
	}
	current, err = ActivateNodeNamePruning(ctx, ca, active, floor, pruning, prune, certificate, at)
	if err != nil {
		t.Fatal("successor pruning activation", err)
	}
	if err := WithPrunedNodeIdentity(ctx, ca, active, floor, pruning, prune, certificate, at, func(context.Context, IdentityRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	expired := current.ExpiresAt.Add(time.Hour)
	_, crl, _, err = RefreshCRL(ctx, issuer, expired, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshIdentityIssuerCRL(ctx, ca, floor, sha, crl, expired); err != nil {
		t.Fatal(err)
	}
	recovery, err := NewNodeRecoveryIntent("node-a", sha, current.CertificateSHA256, expired)
	if err != nil {
		t.Fatal(err)
	}
	recoverRequest, err := PrepareNodeRecoveryWithRootState(ctx, ca, active, floor, crl, recovery, expired)
	if err != nil {
		t.Fatal("expired successor preparation", err)
	}
	if _, err := PrepareNodeRenewalWithRootState(ctx, ca, active, floor, "node-a", current.CertificateSHA256, expired); err == nil {
		t.Fatal("expired leaf accepted online")
	}
	if err := SignNodeRecoveryRegistered(ctx, issuer, recoverRequest, recovery, expired, 120*time.Hour, func(b Bundle, _ []byte) error { certificate = b.Certificate; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishNodeRecoveryTrust(ctx, ca, floor, crl, recoverRequest, recovery, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateNodeRecovery(ctx, ca, active, floor, recoverRequest, recovery, certificate, expired); err != nil {
		t.Fatal("expired successor activation", err)
	}
	if err := WithRecoveredNodeIdentity(ctx, ca, active, floor, recoverRequest, recovery, certificate, expired, func(IdentityRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(ca)
	if err != nil || !bytes.Equal(got, anchor) {
		t.Fatal("immutable anchor changed", err)
	}
	_, receipt, err := ReadRootSet(floor, anchor, expired)
	if err != nil || receipt.Phase != "new-only" {
		t.Fatal("maintenance undid finalization", err)
	}
}
