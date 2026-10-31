package nodepki

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootMaintenanceRefreshesBothIssuersAndKeepsFinalization(t *testing.T) {
	old, next, anchor, snapshot, now := rootRotationFixture(t)
	ctx := context.Background()
	authority := filepath.Join(privateTestDir(t), "authority")
	for _, issuer := range []struct {
		path string
		ca   *Authority
		crl  []byte
	}{{authority, old, snapshot.OldCRL}, {SuccessorAuthorityDirectory(authority), next, snapshot.NewCRL}} {
		b, err := issuer.ca.Export()
		if err != nil {
			t.Fatal(err)
		}
		err = SeedAuthority(ctx, issuer.path, b, issuer.crl, now)
		clear(b.Key)
		if err != nil {
			t.Fatal(err)
		}
	}
	floor := rootRotationState(t, anchor, snapshot.OldCRL, now)
	caFile := filepath.Join(floor, "ca.crt")
	oldSHA, _ := RootFingerprint(anchor)
	nextSHA, _ := RootFingerprint(snapshot.Dual.NewCA)
	if _, err := IdentityAuthority(authority, caFile, floor, nextSHA, now); err == nil {
		t.Fatal("successor directory alone authorized signing")
	}
	raw, _ := json.Marshal(snapshot)
	if _, err := PublishRootSet(ctx, floor, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []string{oldSHA, nextSHA} {
		if _, err := IdentityAuthority(authority, caFile, floor, issuer, now); err != nil {
			t.Fatal("approved dual issuer could not be selected", err)
		}
	}
	// An expired authentic CRL is a maintenance floor, never live admission.
	later := now.Add(25 * time.Hour)
	if _, _, err := ReadRootSet(floor, anchor, later); err == nil {
		t.Fatal("expired CRLs accepted for ordinary requests")
	}
	updated, err := RefreshAuthorizedRootSet(ctx, authority, caFile, floor, later)
	if err != nil || bytes.Equal(updated.OldCRL, snapshot.OldCRL) || bytes.Equal(updated.NewCRL, snapshot.NewCRL) || updated.Final != nil || RootAuthorizationSHA256(updated.Dual) != RootAuthorizationSHA256(snapshot.Dual) {
		t.Fatal("refresh changed authorization or failed to renew both CRLs", err)
	}
	if _, _, err := ReadRootSet(floor, anchor, later); err != nil {
		t.Fatal("refreshed dual roots unusable", err)
	}
	final, err := old.AuthorizeRootRotation(next, snapshot.Dual.Rotation, snapshot.Dual.MembersSHA256, &snapshot.Dual, strings.Repeat("c", 64), later)
	if err != nil {
		t.Fatal(err)
	}
	updated.Final = &final
	raw, _ = json.Marshal(updated)
	if _, err := PublishRootSet(ctx, floor, anchor, raw, later); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(authority, "ca.key")); err != nil {
		t.Fatal(err)
	}
	oldFloor := append([]byte{}, updated.OldCRL...)
	updated, err = RefreshAuthorizedRootSet(ctx, authority, caFile, floor, later.Add(25*time.Hour))
	if err != nil || updated.Final == nil || !bytes.Equal(updated.OldCRL, oldFloor) {
		t.Fatal("finalized maintenance needed retired key or rewrote its floor", err)
	}
	if _, err := IdentityAuthority(authority, caFile, floor, oldSHA, later.Add(25*time.Hour)); err == nil {
		t.Fatal("finalization allowed retired signing authority")
	}
	if _, err := IdentityAuthority(authority, caFile, floor, nextSHA, later.Add(25*time.Hour)); err != nil {
		t.Fatal("finalization disabled successor signer", err)
	}
	prior, _ := os.ReadFile(filepath.Join(floor, "root-rotation", "roots.json"))
	if err := os.WriteFile(filepath.Join(SuccessorAuthorityDirectory(authority), "ca.crt"), anchor, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshAuthorizedRootSet(ctx, authority, caFile, floor, later.Add(26*time.Hour)); err == nil {
		t.Fatal("wrong successor issuer accepted")
	}
	after, _ := os.ReadFile(filepath.Join(floor, "root-rotation", "roots.json"))
	if !bytes.Equal(prior, after) {
		t.Fatal("failed refresh changed accepted trust")
	}
}

func TestRootMaintenanceRenewsSuccessorCollectorWithoutChangingAnchor(t *testing.T) {
	old, next, anchor, snapshot, now := rootRotationFixture(t)
	ctx := context.Background()
	authority := filepath.Join(privateTestDir(t), "authority")
	for i, issuer := range []*Authority{old, next} {
		path, crl := authority, snapshot.OldCRL
		if i == 1 {
			path, crl = SuccessorAuthorityDirectory(authority), snapshot.NewCRL
		}
		b, _ := issuer.Export()
		err := SeedAuthority(ctx, path, b, crl, now)
		clear(b.Key)
		if err != nil {
			t.Fatal(err)
		}
	}
	floor := rootRotationState(t, anchor, snapshot.OldCRL, now)
	directory := privateTestDir(t)
	caFile, file := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "active.pem")
	if err := os.WriteFile(caFile, anchor, 0600); err != nil {
		t.Fatal(err)
	}
	b, _ := old.Issue(Collector, "collector-a", nil, now, time.Hour)
	defer clear(b.Key)
	before, err := PublishIdentity(ctx, caFile, file, Collector, "collector-a", "", b, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	if _, err := PublishRootSet(ctx, floor, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	authorization := RootAuthorizationSHA256(snapshot.Dual)
	r, err := PrepareRootIdentity(ctx, caFile, file, floor, Collector, "collector-a", authorization, before.CertificateSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	if err := SignRootIdentityRegistered(ctx, SuccessorAuthorityDirectory(authority), anchor, snapshot, r, now, 2*time.Hour, func(b Bundle) error { certificate = b.Certificate; return nil }); err != nil {
		t.Fatal(err)
	}
	activated, err := ActivateRootIdentity(ctx, caFile, file, floor, Collector, "collector-a", authorization, before.CertificateSHA256, r.SHA256(), certificate, now)
	if err != nil {
		t.Fatal(err)
	}
	final, _ := old.AuthorizeRootRotation(next, snapshot.Dual.Rotation, snapshot.Dual.MembersSHA256, &snapshot.Dual, strings.Repeat("d", 64), now)
	snapshot.Final = &final
	raw, _ = json.Marshal(snapshot)
	if _, err := PublishRootSet(ctx, floor, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(authority, "ca.key")); err != nil {
		t.Fatal(err)
	}
	renewed, err := MaintainIdentityWithRootState(ctx, authority, caFile, file, floor, Collector, "collector-a", now, 3*time.Hour, 4*time.Hour)
	if err != nil || !renewed.Changed || renewed.CertificateSHA256 == activated.CertificateSHA256 {
		t.Fatal("successor collector did not renew", err)
	}
	current, _, err := ReadIdentityWithRootState(caFile, file, floor, Collector, "collector-a", now)
	defer clear(current.Key)
	if err != nil || !bytes.Equal(current.CA, snapshot.Dual.NewCA) {
		t.Fatal("renewal changed issuer", err)
	}
	seed, _ := os.ReadFile(caFile)
	if !bytes.Equal(seed, anchor) {
		t.Fatal("renewal overwrote immutable anchor")
	}
	// Revocation under the current issuer must block offline renewal too.
	crl, err := next.Revoke(snapshot.NewCRL, [][]byte{current.Certificate}, now.Add(time.Second), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(SuccessorAuthorityDirectory(authority), "crls", "2.pem"), crl, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(SuccessorAuthorityDirectory(authority), "ca.crl"), crl, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshAuthorizedRootSet(ctx, authority, caFile, floor, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := MaintainIdentityWithRootState(ctx, authority, caFile, file, floor, Collector, "collector-a", now.Add(time.Second), 5*time.Hour, 6*time.Hour); !errors.Is(err, ErrRevocation) {
		t.Fatal("revoked successor renewed", err)
	}
}
