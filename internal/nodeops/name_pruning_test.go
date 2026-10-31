package nodeops

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

func helperPruningFixture(t *testing.T, mode string) (helperNameChangeFixture, NamePruningInput) {
	t.Helper()
	f := signedHelperNameChange(t, mode, true)
	caFile := filepath.Join(f.w.identityData, "pki-identity", "ca.crt")
	b, record, err := nodepki.ReadIdentity(caFile, filepath.Join(f.w.identityData, "pki-identity", "active.pem"), nodepki.Node, f.r.Node, time.Now())
	defer clear(b.Key)
	if err != nil {
		t.Fatal(err)
	}
	i, err := nodepki.NewNodeNamePruningIntent(f.r.Node, f.in.Intent.AuthoritySHA256, record.CertificateSHA256, f.r.Spec.ConfigSourceSHA256, 1, f.r.Spec.ServerName, []string{f.r.Spec.ServerName}, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return f, NamePruningInput{Format: 1, Operation: "prepare", Intent: i, CRL: f.in.CRL}
}

func signHelperPruning(t *testing.T, f helperNameChangeFixture, in NamePruningInput, request []byte) []byte {
	t.Helper()
	r, err := nodepki.ParseNodeNamePruningRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	a, err := f.ca.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(a.Key)
	dir := filepath.Join(testRoot(t), "pruning-authority")
	if err := nodepki.SeedAuthority(context.Background(), dir, a, in.CRL, time.Now()); err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	if err := nodepki.SignNodeNamePruningRegistered(context.Background(), dir, r, in.Intent, time.Now(), 240*time.Hour, func(b nodepki.Bundle, crl []byte) error {
		if len(b.Key) != 0 || !bytes.Equal(crl, in.CRL) {
			t.Fatal("signer returned private key or changed CRL")
		}
		certificate = append([]byte(nil), b.Certificate...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestNamePruningHelperPreservesRuntimeAndQueuedDataAcrossReplay(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			f, in := helperPruningFixture(t, mode)
			ctx := context.Background()
			active := filepath.Join(f.w.identityData, "pki-identity", "active.pem")
			before, _ := os.ReadFile(active)
			defer clear(before)
			installation, _ := os.ReadFile(filepath.Join(f.w.root, "active.json"))
			config, _ := os.ReadFile(filepath.Join(f.w.configurationDir(f.r.Spec), "runtime.json"))
			marker := filepath.Join(f.w.identityData, "queued-event-marker")
			os.WriteFile(marker, []byte("unconfirmed events and baselines preserved"), 0600)
			prepared, err := f.w.namePruning(ctx, in)
			if err != nil {
				t.Fatal("prepare", err)
			}
			replayed, err := f.w.namePruning(ctx, in)
			if err != nil || !bytes.Equal(prepared.Request, replayed.Request) {
				t.Fatal("lost prepare response replaced CSR/key", err)
			}
			in.Operation, in.Request, in.Certificate = "activate", prepared.Request, signHelperPruning(t, f, in, prepared.Request)
			for range 2 {
				out, err := f.w.namePruning(ctx, in)
				if err != nil || out.CertificateSHA256 != sha(recoveryTestCertificate(t, in.Certificate).Raw) || len(out.Request) != 0 || out.ResourcesVerified {
					t.Fatal("activation/replay", err)
				}
			}
			ca := filepath.Join(f.w.identityData, "pki-identity", "ca.crt")
			b, _, err := nodepki.ReadIdentity(ca, active, nodepki.Node, f.r.Node, time.Now())
			defer clear(b.Key)
			leaf := recoveryTestCertificate(t, b.Certificate)
			if err != nil || leaf.VerifyHostname(in.Intent.ActiveName) != nil || leaf.VerifyHostname(f.in.Intent.ServerName) == nil {
				t.Fatal("removed name still accepted or active name lost", err)
			}
			history, err := os.ReadFile(active + ".history/" + in.Intent.CertificateSHA256 + ".pem")
			defer clear(history)
			if err != nil || !bytes.Equal(history, before) {
				t.Fatal("previous private identity lost", err)
			}
			gotInstallation, _ := os.ReadFile(filepath.Join(f.w.root, "active.json"))
			gotConfig, _ := os.ReadFile(filepath.Join(f.w.configurationDir(f.r.Spec), "runtime.json"))
			gotMarker, _ := os.ReadFile(marker)
			if !bytes.Equal(installation, gotInstallation) || !bytes.Equal(config, gotConfig) || string(gotMarker) != "unconfirmed events and baselines preserved" {
				t.Fatal("pruning changed installed configuration or queued data")
			}
			public, _ := json.Marshal(prepared)
			if bytes.Contains(public, []byte("PRIVATE KEY")) || bytes.Contains(public, b.Key) {
				t.Fatal("private key leaked in receipt")
			}
		})
	}
}

func TestNamePruningHelperRejectsUnboundIntentAndUnsafeState(t *testing.T) {
	for _, scenario := range []string{"wrong-config", "wrong-name", "name-added", "expired", "missing-floor", "pending-deployment", "start", "verify-before-activation"} {
		t.Run(scenario, func(t *testing.T) {
			f, in := helperPruningFixture(t, "native")
			active := filepath.Join(f.w.identityData, "pki-identity", "active.pem")
			before, _ := os.ReadFile(active)
			defer clear(before)
			switch scenario {
			case "wrong-config":
				in.Intent.ConfigurationSHA256 = strings.Repeat("a", 64)
			case "wrong-name":
				in.Intent.ActiveName = f.in.Intent.ServerName
			case "name-added":
				in.Intent.Names = []string{"arbitrary.invalid", in.Intent.ActiveName}
			case "expired":
				in.Intent.IssuedAt, in.Intent.ExpiresAt = time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
			case "missing-floor":
				os.Remove(filepath.Join(f.w.identityData, "pki-trust", "ca.crl"))
			case "pending-deployment":
				j := &Journal{root: filepath.Join(f.w.root, "node")}
				db, err := j.database()
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec(`INSERT INTO phases(job,phase,status) VALUES(?,'switch','running')`, f.r.Job); err != nil {
					t.Fatal(err)
				}
			case "start":
				in.Operation = "start"
			case "verify-before-activation":
				out, err := f.w.namePruning(context.Background(), in)
				if err != nil {
					t.Fatal(err)
				}
				in.Operation, in.Request, in.Certificate = "verify", out.Request, signHelperPruning(t, f, in, out.Request)
			}
			if _, err := f.w.namePruning(context.Background(), in); err == nil {
				t.Fatal("accepted unbound or unsafe state")
			}
			after, _ := os.ReadFile(active)
			defer clear(after)
			if !bytes.Equal(before, after) {
				t.Fatal("failure replaced active identity")
			}
		})
	}
}

// Reauthorization must obtain a fresh active-key proof for the old immutable
// CSR/receipt. These are installed-service fixtures, not real kernel tests.
func TestNamePruningHelperReauthorizationPreservesOriginalRequestAndIdentity(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, activated := range []bool{false, true} {
			label := mode + map[bool]string{false: "/pending", true: "/active"}[activated]
			t.Run(label, func(t *testing.T) {
				f, in := helperPruningFixture(t, mode)
				ctx := context.Background()
				first, err := f.w.namePruning(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				certificate := signHelperPruning(t, f, in, first.Request)
				original := in.Intent
				in.Operation, in.Request, in.Certificate = "activate", first.Request, certificate
				if activated {
					if _, err := f.w.namePruning(ctx, in); err != nil {
						t.Fatal(err)
					}
				}
				active := filepath.Join(f.w.identityData, "pki-identity", "active.pem")
				before, err := os.ReadFile(active)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(before)
				in.Intent, err = nodepki.NewNodeNamePruningIntent(original.Node, original.AuthoritySHA256, original.CertificateSHA256, original.ConfigurationSHA256, original.RuntimeEpoch, original.ActiveName, original.Names, time.Now().UTC().Truncate(time.Second))
				if err != nil {
					t.Fatal(err)
				}
				in.Operation = "reconcile"
				proof, err := f.w.namePruning(ctx, in)
				if err != nil || proof.Operation != "reconcile" || proof.Challenge != in.Intent.Challenge {
					t.Fatal("new proof", err)
				}
				request, err := nodepki.ParseNodeNamePruningRequest(proof.Request)
				old, oldErr := nodepki.ParseNodeNamePruningRequest(first.Request)
				if err != nil || oldErr != nil || request.IssuanceSHA256() != old.SHA256() || request.SHA256() == old.SHA256() || !bytes.Equal(request.OriginalRequest, first.Request) {
					t.Fatal("lost ancestry", err)
				}
				after, _ := os.ReadFile(active)
				defer clear(after)
				if !bytes.Equal(before, after) {
					t.Fatal("reconciliation changed active key")
				}
				in.Operation, in.Request = "activate", proof.Request
				for range 2 {
					out, err := f.w.namePruning(ctx, in)
					if err != nil || out.CertificateSHA256 != sha(recoveryTestCertificate(t, certificate).Raw) {
						t.Fatal("original receipt activation", err)
					}
				}
				if activated {
					after, _ := os.ReadFile(active)
					defer clear(after)
					if !bytes.Equal(before, after) {
						t.Fatal("continuation rewrote active key")
					}
				}
				if _, err := f.w.namePruning(ctx, NamePruningInput{Format: 1, Operation: "reconcile", Intent: in.Intent, CRL: in.CRL, Request: proof.Request, Certificate: certificate}); err == nil {
					t.Fatal("nested continuation accepted")
				}
			})
		}
	}
}
