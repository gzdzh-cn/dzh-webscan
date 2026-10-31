package nodepki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Only the privileged test setup performs the root/leaf transition. Ordinary
// renewal must keep working afterwards, but may never initiate that transition.
func TestRootRotationNodeRenewsUnderSuccessorAfterFinalization(t *testing.T) {
	old, next, anchor, snapshot, now := rootRotationFixture(t)
	ctx := context.Background()
	floor := rootRotationState(t, anchor, snapshot.OldCRL, now)
	identity := privateTestDir(t)
	caFile, active := filepath.Join(identity, "ca.crt"), filepath.Join(identity, "active.pem")
	if err := os.WriteFile(caFile, anchor, 0600); err != nil {
		t.Fatal(err)
	}
	prior, err := old.Issue(Node, "node-a", []string{"node.example.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(prior.Key)
	initial, err := PublishIdentity(ctx, caFile, active, Node, "node-a", "", prior, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	if _, err := PublishRootSet(ctx, floor, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	approved, err := next.Issue(Node, "node-a", []string{"node.example.test"}, now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(approved.Key)
	if _, err := PublishIdentityWithRootState(ctx, caFile, active, floor, Node, "node-a", initial.CertificateSHA256, approved, now); err == nil {
		t.Fatal("ordinary renewal crossed issuers during dual trust")
	}
	if raw, err := os.ReadFile(active); err != nil || !bytes.Equal(raw, append(append([]byte{}, prior.Certificate...), prior.Key...)) {
		t.Fatal("rejected implicit rotation changed current identity", err)
	}
	// Model the separate privileged identity rollout without claiming that the
	// administrator task/SSH publisher is implemented by this test.
	if err := os.WriteFile(active, append(append([]byte{}, approved.Certificate...), approved.Key...), 0600); err != nil {
		t.Fatal(err)
	}
	_, current, err := ReadIdentityWithRootState(caFile, active, floor, Node, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	request, err := PrepareNodeRenewalWithRootState(ctx, caFile, active, floor, "node-a", current.CertificateSHA256, now)
	if err != nil {
		t.Fatal("successor identity could not prepare renewal", err)
	}
	retry, err := PrepareNodeRenewalWithRootState(ctx, caFile, active, floor, "node-a", current.CertificateSHA256, now)
	if err != nil || retry.SHA256() != request.SHA256() {
		t.Fatal("request retry regenerated the node-local key", err)
	}
	if err := ValidateNodeRenewalRequest(approved.CA, snapshot.NewCRL, request, now); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNodeRenewalRequest(anchor, snapshot.OldCRL, request, now); err == nil {
		t.Fatal("successor renewal was admitted to retired issuer")
	}
	issuer := filepath.Join(privateTestDir(t), "successor")
	bundle, err := next.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle.Key)
	if err := SeedAuthority(ctx, issuer, bundle, snapshot.NewCRL, now); err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	if err := SignNodeRenewalRegistered(ctx, issuer, request, now, 3*time.Hour, func(b Bundle, _ []byte) error {
		certificate = append([]byte{}, b.Certificate...)
		if len(b.Key) != 0 {
			t.Fatal("issuer exported a node private key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	final, err := old.AuthorizeRootRotation(next, snapshot.Dual.Rotation, snapshot.Dual.MembersSHA256, &snapshot.Dual, strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Final = &final
	raw, _ = json.Marshal(snapshot)
	if _, err := PublishRootSet(ctx, floor, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	roots, _, err := ReadRootSet(floor, anchor, now)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(c *x509.Certificate) error { return roots.Verify(c, Node, "node-a", now) }
	result, err := ActivateNodeRenewalWithRootState(ctx, caFile, active, floor, "node-a", current.CertificateSHA256, request.SHA256(), certificate, now, verify)
	if err != nil || !result.Changed {
		t.Fatal("successor renewal did not activate after finalization", err)
	}
	lost, err := ActivateNodeRenewalWithRootState(ctx, caFile, active, floor, "node-a", current.CertificateSHA256, request.SHA256(), certificate, now, verify)
	if err != nil || lost.Changed || lost.CertificateSHA256 != result.CertificateSHA256 {
		t.Fatal("lost activation response was not replayable", err)
	}
	material, got, err := ReadIdentityWithRootState(caFile, active, floor, Node, "node-a", now)
	defer clear(material.Key)
	if err != nil || got.CertificateSHA256 != result.CertificateSHA256 || bytes.Equal(material.Key, approved.Key) {
		t.Fatal("renewal did not retain node-local replacement key", err)
	}
	seed, err := os.ReadFile(caFile)
	if err != nil || !bytes.Equal(seed, anchor) {
		t.Fatal("immutable installation anchor changed", err)
	}
	if _, err := PublishIdentityWithRootState(ctx, caFile, active, floor, Node, "node-a", result.CertificateSHA256, prior, now); err == nil {
		t.Fatal("retired issuer was restored")
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
