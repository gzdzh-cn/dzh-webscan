package nodepki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func persistentFixture(t *testing.T) (*Authority, time.Time, string, string, string, []byte) {
	t.Helper()
	a, now := testAuthority(t)
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	exported, _ := a.Export()
	initial, _ := a.Revoke(nil, nil, now, time.Hour)
	ca, crl, state := filepath.Join(root, "source-ca.crt"), filepath.Join(root, "source-ca.crl"), filepath.Join(root, "accepted")
	if err := os.WriteFile(ca, exported.CA, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crl, initial, 0600); err != nil {
		t.Fatal(err)
	}
	return a, now, ca, crl, state, initial
}

func TestPersistentTrustRejectsCRLRollbackAfterRestartAndExpiredFloor(t *testing.T) {
	a, now, ca, crl, state, initial := persistentFixture(t)
	leaf, cert := testLeaf(t, a, Collector, "collector-a", now)
	p, err := NewPersistentFileTrust(ca, crl, state, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(cert, Collector, "collector-a", now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Second)
	revoked, _ := a.Revoke(initial, [][]byte{leaf.Certificate}, later, time.Hour)
	os.WriteFile(crl, revoked, 0600)
	if p.Verify(cert, Collector, "collector-a", later) == nil {
		t.Fatal("existing connection not revoked")
	}
	floor, err := os.ReadFile(filepath.Join(state, "ca.crl"))
	if err != nil || !bytes.Equal(floor, revoked) {
		t.Fatal("revocation not durable before acceptance", err)
	}
	// Constructing a fresh cache models a process restart with old config files.
	os.WriteFile(crl, initial, 0600)
	if _, err := NewPersistentFileTrust(ca, crl, state, later); err == nil {
		t.Fatal("restart accepted old signed CRL")
	}
	// Expiration of the durable historical floor must not prevent an authentic
	// renewal, and must not drop earlier revocations in that renewal.
	muchLater := now.Add(2 * time.Hour)
	renewed, err := a.Revoke(revoked, nil, muchLater, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(crl, renewed, 0600)
	restarted, err := NewPersistentFileTrust(ca, crl, state, muchLater)
	if err != nil {
		t.Fatal("cannot advance an expired floor", err)
	}
	if restarted.Verify(cert, Collector, "collector-a", muchLater) == nil {
		t.Fatal("restart/renewal forgot revocation")
	}
	for _, name := range []string{"ca.crt", "ca.crl", ".lock"} {
		st, err := os.Stat(filepath.Join(state, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("unsafe durable state", name, err)
		}
	}
}

func TestPersistentTrustRejectsSignedUnrevocationAndRootReplacement(t *testing.T) {
	a, now, ca, crl, state, initial := persistentFixture(t)
	leaf, _ := testLeaf(t, a, Collector, "collector-a", now)
	revoked, _ := a.Revoke(initial, [][]byte{leaf.Certificate}, now, time.Hour)
	os.WriteFile(crl, revoked, 0600)
	if _, err := NewPersistentFileTrust(ca, crl, state, now); err != nil {
		t.Fatal(err)
	}
	list, _ := parseCRL(revoked, a.certificate)
	list.Number.Add(list.Number, big.NewInt(1))
	list.RevokedCertificateEntries, list.RevokedCertificates = nil, nil
	der, err := x509.CreateRevocationList(rand.Reader, list, a.certificate, a.key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(crl, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0600)
	if _, err := NewPersistentFileTrust(ca, crl, state, now); err == nil {
		t.Fatal("signed higher revision removed earlier revocation")
	}
	other, _ := testAuthority(t)
	otherCA, _ := other.Export()
	otherCRL, _ := other.Revoke(nil, nil, now, time.Hour)
	os.WriteFile(ca, otherCA.CA, 0600)
	os.WriteFile(crl, otherCRL, 0600)
	if _, err := NewPersistentFileTrust(ca, crl, state, now); err == nil {
		t.Fatal("replacing the CA reset the accepted floor")
	}
}

func TestPersistentTrustSharedInstancesCannotLowerAcceptedFloor(t *testing.T) {
	a, now, ca, crl, state, initial := persistentFixture(t)
	_, cert := testLeaf(t, a, Collector, "collector-a", now)
	older, err := NewPersistentFileTrust(ca, crl, state, now)
	if err != nil {
		t.Fatal(err)
	}
	renewed, _ := a.Revoke(initial, nil, now.Add(time.Second), time.Hour)
	os.WriteFile(crl, renewed, 0600)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := NewPersistentFileTrust(ca, crl, state, now.Add(time.Second))
			if err != nil {
				t.Error(err)
				return
			}
			if err := p.Verify(cert, Collector, "collector-a", now.Add(time.Second)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	os.WriteFile(crl, initial, 0600)
	if older.Verify(cert, Collector, "collector-a", now.Add(2*time.Second)) == nil {
		t.Fatal("older live process ignored floor advanced by another instance")
	}
	os.WriteFile(crl, renewed, 0600)
	if err := older.Verify(cert, Collector, "collector-a", now.Add(3*time.Second)); err != nil {
		t.Fatal("repair did not recover", err)
	}
}

func TestPersistentTrustCorruptOrMissingStateFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "symlink", "permissions", "empty-directory", "parent-symlink"} {
		t.Run(kind, func(t *testing.T) {
			_, now, ca, crl, state, _ := persistentFixture(t)
			if _, err := NewPersistentFileTrust(ca, crl, state, now); err != nil {
				t.Fatal(err)
			}
			floor := filepath.Join(state, "ca.crl")
			switch kind {
			case "missing":
				os.Remove(floor)
			case "corrupt":
				os.WriteFile(floor, []byte("broken"), 0600)
			case "symlink":
				os.Remove(floor)
				os.Symlink(crl, floor)
			case "permissions":
				os.Chmod(floor, 0644)
			case "empty-directory":
				os.RemoveAll(state)
				os.Mkdir(state, 0700)
			case "parent-symlink":
				link := filepath.Join(filepath.Dir(state), "link")
				os.Symlink(state, link)
				state = link
			}
			if _, err := NewPersistentFileTrust(ca, crl, state, now); err == nil {
				t.Fatal("invalid initialized floor was reset/accepted")
			}
		})
	}
}
