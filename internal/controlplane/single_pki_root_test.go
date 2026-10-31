package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

// This verifies the real maintenance path after privileged local rollout. It
// does not substitute for the persistent administrator/SSH rollout gate.
func TestSinglePKIRootRolloverKeepsMaintenanceAndVerifiedStatus(t *testing.T) {
	s, _, now := prepareSinglePKIFixture(t)
	ctx := context.Background()
	c := s.configuration()
	authority := filepath.Join(s.Root, "authority")
	anchor, err := readTrustData(filepath.Join(authority, "ca.crt"), true, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	key, err := readTrustData(filepath.Join(authority, "ca.key"), true, 64<<10)
	defer clear(key)
	if err != nil {
		t.Fatal(err)
	}
	old, err := nodepki.ParseAuthority(anchor, key, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := nodepki.NewAuthority(now, 2*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := next.Export()
	defer clear(bundle.Key)
	if err != nil {
		t.Fatal(err)
	}
	newCRL, err := next.Revoke(nil, nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodepki.SeedAuthority(ctx, nodepki.SuccessorAuthorityDirectory(authority), bundle, newCRL, now); err != nil {
		t.Fatal(err)
	}
	oldCRL, err := readTrustData(filepath.Join(authority, "ca.crl"), true, nodepki.MaxCRLBytes)
	if err != nil {
		t.Fatal(err)
	}
	dual, err := old.AuthorizeRootRotation(next, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	state := nodepki.RootSetSnapshot{Format: 1, Dual: dual, OldCRL: oldCRL, NewCRL: newCRL}
	raw, _ := json.Marshal(state)
	if _, err := nodepki.PublishRootSet(ctx, c.Collector.RevocationStateDirectory, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	if receipt, err := maintainSinglePKI(ctx, s, now); err != nil || receipt.State != "healthy" {
		t.Fatal("dual trust blocked original collector maintenance", err)
	}
	identity, before, err := nodepki.ReadIdentityWithRootState(c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, s.Instance, now)
	clear(identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	authorization := nodepki.RootAuthorizationSHA256(dual)
	request, err := nodepki.PrepareRootIdentity(ctx, c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, s.Instance, authorization, before.CertificateSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	if err := nodepki.SignRootIdentityRegistered(ctx, nodepki.SuccessorAuthorityDirectory(authority), anchor, state, request, now, 32*24*time.Hour, func(b nodepki.Bundle) error { certificate = b.Certificate; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ActivateRootIdentity(ctx, c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, s.Instance, authorization, before.CertificateSHA256, request.SHA256(), certificate, now); err != nil {
		t.Fatal(err)
	}
	store := testStore(t)
	if err := recordSinglePKIMaintenance(ctx, store, s, nodeRenewalSigningResult{}, nil); err != nil {
		t.Fatal("approved successor not reflected in verified dashboard status", err)
	}
	var details []byte
	if err := store.DB.QueryRow(`SELECT details FROM v3_role_status WHERE role='pki-maintenance' AND instance=$1`, s.Instance).Scan(&details); err != nil {
		t.Fatal(err)
	}
	var report struct {
		CAExpires time.Time `json:"ca_expires_at"`
	}
	ca, _ := provisioningCertificate(bundle.CA)
	if json.Unmarshal(details, &report) != nil || !report.CAExpires.Equal(ca.NotAfter) {
		t.Fatal("dashboard reported retired issuer lifetime")
	}
	final, err := old.AuthorizeRootRotation(next, dual.Rotation, dual.MembersSHA256, &dual, strings.Repeat("c", 64), now)
	if err != nil {
		t.Fatal(err)
	}
	state.Final = &final
	raw, _ = json.Marshal(state)
	if _, err := nodepki.PublishRootSet(ctx, c.Collector.RevocationStateDirectory, anchor, raw, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(authority, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if err := verifySinglePKI(s, now); err != nil {
		t.Fatal("finalized installation still required retired signing key", err)
	}
	later := now.Add(26 * 24 * time.Hour)
	receipt, err := maintainSinglePKI(ctx, s, later)
	if err != nil || receipt.State != "healthy" || !receipt.Identity.Changed || !receipt.Identity.ExpiresAt.After(later.Add(29*24*time.Hour)) {
		t.Fatal("successor maintenance failed after both old CRLs expired", err)
	}
	if err := verifySinglePKI(s, later); err != nil {
		t.Fatal("renewed installation did not verify", err)
	}
	pinned, err := readTrustData(c.Collector.CAFile, true, 64<<10)
	if err != nil || !bytes.Equal(pinned, anchor) {
		t.Fatal("maintenance changed immutable anchor", err)
	}
}
