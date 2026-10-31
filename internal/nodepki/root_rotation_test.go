package nodepki

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func rootRotationFixture(t *testing.T) (*Authority, *Authority, []byte, RootSetSnapshot, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	old, err := NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := old.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	a, err := old.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	oldCRL, err := old.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCRL, err := next.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return old, next, b.CA, RootSetSnapshot{Format: 1, Dual: a, OldCRL: oldCRL, NewCRL: newCRL}, now
}

func TestRootRotationRequiresExplicitDualSignaturesAndFreshAuthorization(t *testing.T) {
	_, _, anchor, s, now := rootRotationFixture(t)
	if err := VerifyRootAuthorization(anchor, s.Dual, nil, now, true); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRootAuthorization(anchor, s.Dual, nil, now.Add(11*time.Minute), true); err == nil {
		t.Fatal("expired administrator authorization applied")
	}
	if err := VerifyRootAuthorization(anchor, s.Dual, nil, now.Add(11*time.Minute), false); err != nil {
		t.Fatal("accepted durable authorization needed reauthorization", err)
	}
	for _, change := range []func(*RootAuthorization){
		func(a *RootAuthorization) { a.NewCA = anchor },
		func(a *RootAuthorization) { a.MembersSHA256 = strings.Repeat("c", 64) },
		func(a *RootAuthorization) { a.SuccessorSignature = nil },
		func(a *RootAuthorization) { a.AnchorSignature = nil },
		func(a *RootAuthorization) { a.Phase = "new-only" },
	} {
		changed := s.Dual
		change(&changed)
		if err := VerifyRootAuthorization(anchor, changed, nil, now, false); err == nil {
			t.Fatal("tampered root authorization accepted")
		}
	}
}

func TestRootRotationSeparatesIssuerRevocationsAndRejectsOldRootAfterConfirmation(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	a, err := old.Issue(Node, "node-a", []string{"node.example.test"}, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(a.Key)
	b, err := next.Issue(Node, "node-a", []string{"node.example.test"}, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	previous := s
	s.OldCRL, err = old.Revoke(s.OldCRL, [][]byte{a.Certificate}, now.Add(time.Second), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewRootSet(anchor, s, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	oldCert, _ := parseCertificate(a.Certificate)
	newCert, _ := parseCertificate(b.Certificate)
	if set.Verify(oldCert, Node, "node-a", now.Add(time.Second)) == nil {
		t.Fatal("old revoked certificate accepted during dual trust")
	}
	if err := set.Verify(newCert, Node, "node-a", now.Add(time.Second)); err != nil {
		t.Fatal("new issuer affected by old issuer revocations", err)
	}
	if err := ValidateRootSetAdvance(anchor, previous, s, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRootSetAdvance(anchor, s, previous, now.Add(time.Second)); err == nil {
		t.Fatal("old CRL floor was lowered")
	}
	final, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, strings.Repeat("d", 64), now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	s.Final = &final
	if err := ValidateRootSetAdvance(anchor, previous, s, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	set, err = NewRootSet(anchor, s, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if set.Verify(oldCert, Node, "node-a", now.Add(2*time.Second)) == nil {
		t.Fatal("retired issuer still accepted")
	}
	if err := set.Verify(newCert, Node, "node-a", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRootSetAdvance(anchor, s, previous, now.Add(2*time.Second)); err == nil {
		t.Fatal("root retirement reverted")
	}
	if err := ValidateRootSetAdvance(anchor, RootSetSnapshot{}, s, now.Add(2*time.Second)); err == nil {
		t.Fatal("new-only trust accepted without durable dual-root phase")
	}
}

func TestRootRotationCannotSubstituteMembershipOrConfirmationOrUnrelatedCA(t *testing.T) {
	old, next, anchor, s, now := rootRotationFixture(t)
	if _, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, strings.Repeat("f", 64), &s.Dual, strings.Repeat("d", 64), now); err == nil {
		t.Fatal("membership changed before root removal")
	}
	if _, err := old.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, &s.Dual, "", now); err == nil {
		t.Fatal("missing confirmations allowed root removal")
	}
	attacker, err := NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := attacker.AuthorizeRootRotation(next, s.Dual.Rotation, s.Dual.MembersSHA256, nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyRootAuthorization(anchor, foreign, nil, now, true) == nil {
		t.Fatal("unrelated authority was trusted")
	}
	// An old-key-only signature cannot be used to substitute another CA's
	// acknowledgement, even if the altered payload remains otherwise valid.
	forged := s.Dual
	forged.MembersSHA256 = strings.Repeat("e", 64)
	forged.AnchorSignature = ed25519.Sign(old.key, rootAuthorizationMessage(forged))
	if VerifyRootAuthorization(anchor, forged, nil, now, true) == nil {
		t.Fatal("unconfirmed replacement-key signature accepted")
	}
	other := s
	other.NewCRL = s.OldCRL
	if _, err := NewRootSet(anchor, other, now); err == nil {
		t.Fatal("wrong issuer CRL accepted")
	}
	raw, _ := hex.DecodeString(s.Dual.AnchorSHA256)
	hash := sha256.Sum256(old.certificate.Raw)
	if string(raw) != string(hash[:]) {
		t.Fatal("fingerprint used PEM formatting rather than certificate DER")
	}
}
