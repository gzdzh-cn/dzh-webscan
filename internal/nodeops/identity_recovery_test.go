package nodeops

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

type helperRecoveryFixture struct {
	w       *LocalRuntime
	r       Request
	ca      *nodepki.Authority
	in      IdentityRecoveryInput
	expired nodepki.Bundle
}

func recoveryTestCertificate(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(raw)
	if b == nil {
		t.Fatal("missing certificate PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newHelperRecoveryFixture(t *testing.T, mode string) helperRecoveryFixture {
	t.Helper()
	w, r, m, ca, _ := keylessConfigurationFixture(t)
	if mode == "docker" {
		r.Spec.Mode, m.Mode = mode, mode
		r.Spec.AgentImage = "docker.io/example/agent@sha256:" + strings.Repeat("a", 64)
		r.Spec.MonitorDirectories = []string{"/www/wwwroot"}
		m.Settings.Monitor.Roots, m.Settings.ProbeDirectory = r.Spec.MonitorDirectories, "/www/wwwroot/.webscan-probe"
		m = attachConfiguration(t, w, &r, func(target *nodeconfig.Material) { *target = m })
	}
	if err := w.prepare(context.Background(), r.Spec); err != nil {
		t.Fatal(err)
	}
	if err := w.prepareConfiguration(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	writeHelperRecoveryInstallation(t, w, r, m)
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-24 * time.Hour)
	expired, err := ca.Issue(nodepki.Node, r.Node, []string{"node.test"}, past, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Install historical active state without changing the valid installation
	// artifact. Recovery must use this local key, never the artifact's seed.
	active := filepath.Join(w.identityData, "pki-identity", "active.pem")
	if err := os.WriteFile(active, append(append([]byte{}, expired.Certificate...), expired.Key...), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(expired.Key) })
	root := recoveryTestCertificate(t, expired.CA)
	leaf := recoveryTestCertificate(t, expired.Certificate)
	intent, err := nodepki.NewNodeRecoveryIntent(r.Node, sha(root.Raw), sha(leaf.Raw), now)
	if err != nil {
		t.Fatal(err)
	}
	return helperRecoveryFixture{w, r, ca, IdentityRecoveryInput{Format: 1, Operation: "prepare", Intent: intent, CRL: m.CRL}, expired}
}

// Fixture-only finalization: service management remains simulated here.
func writeHelperRecoveryInstallation(t *testing.T, w *LocalRuntime, r Request, m nodeconfig.Material) {
	t.Helper()
	files, err := w.configurationFiles(m, r.Spec)
	if err != nil {
		t.Fatal(err)
	}
	name, _, _ := w.serviceDefinition(m, r.Spec)
	a := ActiveInstallation{Format: 1, Node: r.Node, Spec: r.Spec, RuntimeSHA256: sha(files["runtime.json"]), DefinitionSHA256: sha(files[name]), Job: r.Job, PlanDigest: r.PlanDigest}
	raw, _ := json.Marshal(a)
	if err := os.WriteFile(filepath.Join(w.root, "active.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	j, err := Open(filepath.Join(w.root, "node"), w)
	if err != nil {
		t.Fatal(err)
	}
	db, err := j.database()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, query := range []string{`INSERT INTO meta VALUES(1,'` + r.Node + `','` + r.Job + `')`, `INSERT INTO jobs(id,digest,spec_digest,epoch) VALUES('` + r.Job + `','` + r.PlanDigest + `','` + strings.Repeat("a", 64) + `',1)`, `INSERT INTO phases(job,phase,status) VALUES('` + r.Job + `','finalize','complete')`} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIdentityRecoveryHelperLocalRoundTripAndLostResponse(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			f := newHelperRecoveryFixture(t, mode)
			ctx := context.Background()
			first, err := f.w.identityRecovery(ctx, f.in)
			if err != nil {
				t.Fatal("prepare", err)
			}
			retry, err := f.w.identityRecovery(ctx, f.in)
			if err != nil || !bytes.Equal(first.Request, retry.Request) {
				t.Fatal("lost preparation response changed CSR", err)
			}
			r, err := nodepki.ParseNodeRecoveryRequest(first.Request)
			if err != nil {
				t.Fatal(err)
			}
			dir := testRoot(t)
			b, err := f.ca.Export()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(b.Key)
			if err := os.Mkdir(filepath.Join(dir, "crls"), 0700); err != nil {
				t.Fatal(err)
			}
			for name, raw := range map[string][]byte{"ca.crt": b.CA, "ca.key": b.Key, "ca.crl": f.in.CRL, "crls/1.pem": f.in.CRL} {
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var certificate []byte
			if err := nodepki.SignNodeRecoveryRegistered(ctx, dir, r, f.in.Intent, time.Now(), 72*time.Hour, func(b nodepki.Bundle, crl []byte) error {
				certificate = b.Certificate
				f.in.CRL = crl
				if len(b.Key) != 0 {
					t.Fatal("issuer returned private key")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			f.in.Operation, f.in.Request, f.in.Certificate = "activate", first.Request, certificate
			out, err := f.w.identityRecovery(ctx, f.in)
			if err != nil || out.CertificateSHA256 != sha(recoveryTestCertificate(t, certificate).Raw) {
				t.Fatal("activate", err)
			}
			replay, err := f.w.identityRecovery(ctx, f.in)
			if err != nil || replay.CertificateSHA256 != out.CertificateSHA256 {
				t.Fatal("lost activation response cannot reconcile", err)
			}
			active := filepath.Join(f.w.identityData, "pki-identity", "active.pem")
			old, err := os.ReadFile(filepath.Join(active+".history", f.in.Intent.CertificateSHA256+".pem"))
			if err != nil || !bytes.Contains(old, f.expired.Key) {
				t.Fatal("prior identity not retained", err)
			}
			encoded, _ := json.Marshal([]IdentityRecoveryOutput{first, retry, out, replay})
			if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, f.expired.Key) || len(out.Request) != 0 {
				t.Fatal("helper response exposed key material")
			}
		})
	}
}

func TestIdentityRecoveryHelperRejectsUntrustedStateBeforeKeyPreparation(t *testing.T) {
	for _, scenario := range []string{"bad-challenge", "expired-intent", "wrong-node", "wrong-root", "revoked-parent", "crl-rollback", "missing-floor", "identity-symlink", "active-pointer", "runtime", "definition", "pending-deployment", "failed-rollback", "journal-node", "operation-lock", "journal-lock"} {
		t.Run(scenario, func(t *testing.T) {
			f := newHelperRecoveryFixture(t, "native")
			ctx := context.Background()
			active := filepath.Join(f.w.identityData, "pki-identity", "active.pem")
			floor := filepath.Join(f.w.identityData, "pki-trust", "ca.crl")
			switch scenario {
			case "bad-challenge":
				f.in.Intent.Challenge = "bad"
			case "expired-intent":
				f.in.Intent.IssuedAt, f.in.Intent.ExpiresAt = time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
			case "wrong-node":
				f.in.Intent.Node = "other-node"
			case "wrong-root":
				f.in.Intent.AuthoritySHA256 = strings.Repeat("0", 64)
			case "revoked-parent", "crl-rollback":
				crl, err := f.ca.Revoke(f.in.CRL, [][]byte{f.expired.Certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "crl-rollback" {
					if err := os.WriteFile(floor, crl, 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					f.in.CRL = crl
				}
			case "missing-floor":
				if err := os.Remove(floor); err != nil {
					t.Fatal(err)
				}
			case "identity-symlink":
				if err := os.Rename(active, active+"-foreign"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(active+"-foreign", active); err != nil {
					t.Fatal(err)
				}
			case "active-pointer":
				if err := os.WriteFile(filepath.Join(f.w.root, "active.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "runtime", "definition":
				name := "runtime.json"
				if scenario == "definition" {
					name = nativeServiceName
				}
				if err := os.WriteFile(filepath.Join(f.w.configurationDir(f.r.Spec), name), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending-deployment", "failed-rollback", "journal-node":
				j := &Journal{root: filepath.Join(f.w.root, "node")}
				db, err := j.database()
				if err != nil {
					t.Fatal(err)
				}
				query := `UPDATE phases SET status='running'`
				if scenario == "journal-node" {
					query = `UPDATE meta SET node='other-node'`
				}
				if scenario == "failed-rollback" {
					query = `INSERT INTO phases(job,phase,status) SELECT current_job,'restore','failed' FROM meta WHERE id=1`
				}
				_, err = db.Exec(query)
				db.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "operation-lock":
				_, release, err := acquireServiceOperation(ctx, f.w.root)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "journal-lock":
				lock, err := (&Journal{root: filepath.Join(f.w.root, "node")}).lock()
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			}
			before, err := os.ReadFile(active)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.w.identityRecovery(ctx, f.in); err == nil {
				t.Fatal("untrusted state accepted")
			}
			after, _ := os.ReadFile(active)
			if !bytes.Equal(before, after) {
				t.Fatal("failed recovery changed active identity")
			}
			_, pendingErr := os.Lstat(filepath.Join(filepath.Dir(active), "renewals", f.in.Intent.CertificateSHA256))
			if !os.IsNotExist(pendingErr) {
				t.Fatal("rejected recovery created pending key")
			}
		})
	}
}

func TestIdentityRecoveryInputRejectsPathsAndOversize(t *testing.T) {
	for _, raw := range []string{`{"format":1,"path":"/tmp/key"}`, strings.Repeat("x", MaxIdentityRecoveryBytes+1), `{}`, `{"format":1,"operation":"restart"}`, `{} {}`} {
		if _, err := decodeIdentityRecovery(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid helper envelope accepted")
		}
	}
	f := newHelperRecoveryFixture(t, "native")
	raw, _ := json.Marshal(f.in)
	duplicate := bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1)
	if _, err := decodeIdentityRecovery(bytes.NewReader(duplicate)); err == nil {
		t.Fatal("duplicate recovery envelope field accepted")
	}
}
