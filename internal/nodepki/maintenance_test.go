package nodepki

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSeedAuthorityAtomicResumeAndExpiredCRLRenewal(t *testing.T) {
	ctx := context.Background()
	root := commandRoot(t)
	dir := filepath.Join(root, "issuer")
	now := time.Now().UTC().Truncate(time.Second)
	a, err := NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := a.Export()
	defer clear(b.Key)
	crl, _ := a.Revoke(nil, nil, now, 24*time.Hour)
	if err := SeedAuthority(ctx, dir, b, crl, now); err != nil {
		t.Fatal(err)
	}
	if err := SeedAuthority(ctx, dir, b, crl, now); err != nil {
		t.Fatal("seed resume", err)
	}
	_, same, changed, err := RefreshCRL(ctx, dir, now, 12*time.Hour, 24*time.Hour)
	if err != nil || changed || !bytes.Equal(same, crl) {
		t.Fatal("not-due CRL changed", err)
	}
	_, next, changed, err := RefreshCRL(ctx, dir, now.Add(25*time.Hour), 12*time.Hour, 24*time.Hour)
	if err != nil || !changed || bytes.Equal(next, crl) {
		t.Fatal("expired CRL failed renewal", err)
	}
	if err := SeedAuthority(ctx, dir, b, crl, now.Add(26*time.Hour)); err != nil {
		t.Fatal("advanced authority replaced or rejected", err)
	}
	current, _ := os.ReadFile(filepath.Join(dir, "ca.crl"))
	if !bytes.Equal(current, next) {
		t.Fatal("seed rolled back CRL")
	}
	// The immutable newer snapshot is authoritative after a response/write
	// failure leaves the active source behind. Refresh repairs, never resets.
	os.WriteFile(filepath.Join(dir, "ca.crl"), crl, 0600)
	_, repaired, changed, err := RefreshCRL(ctx, dir, now.Add(26*time.Hour), 12*time.Hour, 24*time.Hour)
	if err != nil || changed || !bytes.Equal(repaired, next) {
		t.Fatal("publication recovery", err)
	}
	other, _ := NewAuthority(now, 365*24*time.Hour)
	otherBundle, _ := other.Export()
	defer clear(otherBundle.Key)
	if err := SeedAuthority(ctx, dir, otherBundle, crl, now); err == nil {
		t.Fatal("different authority accepted")
	}
	bad := filepath.Join(root, "incomplete")
	os.Mkdir(bad, 0700)
	if err := SeedAuthority(ctx, bad, b, crl, now); err == nil {
		t.Fatal("incomplete authority overwritten")
	}
	link := filepath.Join(root, "issuer-link")
	os.Symlink(dir, link)
	if err := SeedAuthority(ctx, link, b, crl, now); err == nil {
		t.Fatal("authority link accepted")
	}
}

func TestMaintainIdentitySchedulesRenewalWithoutRevivingRevokedLeaves(t *testing.T) {
	f := newLiveFixture(t, Collector, "collector-a")
	ctx := context.Background()
	b, _ := f.a.Export()
	defer clear(b.Key)
	crl, _ := f.a.Revoke(nil, nil, f.now, 24*time.Hour)
	authority := filepath.Join(f.root, "authority")
	if err := SeedAuthority(ctx, authority, b, crl, f.now); err != nil {
		t.Fatal(err)
	}
	first, err := MaintainIdentity(ctx, authority, f.caFile, f.file, Collector, "collector-a", f.now, 7*24*time.Hour, 30*24*time.Hour)
	if err != nil || !first.Changed || first.CertificateSHA256 == f.record.CertificateSHA256 {
		t.Fatal("due renewal", err)
	}
	next, err := MaintainIdentity(ctx, authority, f.caFile, f.file, Collector, "collector-a", f.now.Add(time.Hour), 7*24*time.Hour, 30*24*time.Hour)
	if err != nil || next.Changed || next.CertificateSHA256 != first.CertificateSHA256 {
		t.Fatal("unnecessary rotation", err)
	}
	// Complete offline downtime: expired leaf plus expired CRL can be recovered
	// only with the same installed private authority and authentic history.
	later, err := MaintainIdentity(ctx, authority, f.caFile, f.file, Collector, "collector-a", f.now.Add(31*24*time.Hour), 7*24*time.Hour, 30*24*time.Hour)
	if err != nil || !later.Changed || !later.ExpiresAt.After(first.ExpiresAt) {
		t.Fatal("offline expiry recovery", err)
	}
	active, _, err := ReadIdentity(f.caFile, f.file, Collector, "collector-a", f.now.Add(31*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(active.Key)
	leafFile := filepath.Join(f.root, "current.crt")
	os.WriteFile(leafFile, active.Certificate, 0600)
	// Command uses wall time, so revoke through the signer with the same test
	// time and durably add its next numbered snapshot.
	current, _ := os.ReadFile(filepath.Join(authority, "ca.crl"))
	revoked, err := f.a.Revoke(current, [][]byte{active.Certificate}, f.now.Add(31*24*time.Hour), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := parseCRL(revoked, f.a.certificate)
	os.WriteFile(filepath.Join(authority, "crls", list.Number.Text(10)+".pem"), revoked, 0600)
	os.WriteFile(filepath.Join(authority, "ca.crl"), revoked, 0600)
	if _, err := MaintainIdentity(ctx, authority, f.caFile, f.file, Collector, "collector-a", f.now.Add(31*24*time.Hour), 7*24*time.Hour, 30*24*time.Hour); err == nil {
		t.Fatal("revoked not-due identity accepted")
	}
	if _, err := MaintainIdentity(ctx, authority, f.caFile, f.file, Collector, "collector-a", f.now.Add(62*24*time.Hour), 7*24*time.Hour, 30*24*time.Hour); err == nil {
		t.Fatal("revoked expired identity revived")
	}
}
