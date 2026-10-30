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

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

type helperNameChangeFixture struct {
	w    *LocalRuntime
	r    Request
	ca   *nodepki.Authority
	live nodepki.Bundle
	in   NameChangeInput
}

func newHelperNameChangeFixture(t *testing.T, mode string) helperNameChangeFixture {
	t.Helper()
	w, r, m, ca, live := keylessConfigurationFixture(t)
	t.Cleanup(func() { clear(live.Key) })
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
	root, leaf := recoveryTestCertificate(t, live.CA), recoveryTestCertificate(t, live.Certificate)
	i, err := nodepki.NewNodeNameChangeIntent(r.Node, sha(root.Raw), sha(leaf.Raw), "next-node.test", time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return helperNameChangeFixture{w, r, ca, live, NameChangeInput{Format: 1, Operation: "prepare", Intent: i, CRL: m.CRL}}
}

func signHelperNameChange(t *testing.T, f helperNameChangeFixture, raw []byte) []byte {
	t.Helper()
	r, err := nodepki.ParseNodeNameChangeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(testRoot(t), "authority")
	b, err := f.ca.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	if err := nodepki.SeedAuthority(context.Background(), root, b, f.in.CRL, time.Now()); err != nil {
		t.Fatal(err)
	}
	var certificate []byte
	if err := nodepki.SignNodeNameChangeRegistered(context.Background(), root, r, f.in.Intent, time.Now(), 120*time.Hour, func(b nodepki.Bundle, crl []byte) error {
		if len(b.Key) != 0 || !bytes.Equal(crl, f.in.CRL) {
			t.Fatal("name issuance exposed key or changed trust")
		}
		certificate = append([]byte(nil), b.Certificate...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestNameChangeHelperPreservesInstallationAndDataAcrossReplay(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			f := newHelperNameChangeFixture(t, mode)
			ctx := context.Background()
			activeFile := filepath.Join(f.w.identityData, "pki-identity", "active.pem")
			installation, _ := os.ReadFile(filepath.Join(f.w.root, "active.json"))
			config, _ := os.ReadFile(filepath.Join(f.w.configurationDir(f.r.Spec), "runtime.json"))
			marker := filepath.Join(f.w.identityData, "agent-data-marker")
			if err := os.WriteFile(marker, []byte("baseline, queued events and unfinished scan marker"), 0600); err != nil {
				t.Fatal(err)
			}
			prepared, err := f.w.nameChange(ctx, f.in)
			if err != nil {
				t.Fatal("prepare", err)
			}
			retry, err := f.w.nameChange(ctx, f.in)
			if err != nil || !bytes.Equal(prepared.Request, retry.Request) {
				t.Fatal("lost preparation response changed key/CSR", err)
			}
			certificate := signHelperNameChange(t, f, prepared.Request)
			f.in.Operation, f.in.Request, f.in.Certificate = "activate", prepared.Request, certificate
			for i := 0; i < 2; i++ {
				out, err := f.w.nameChange(ctx, f.in)
				if err != nil || out.CertificateSHA256 != sha(recoveryTestCertificate(t, certificate).Raw) || len(out.Request) != 0 || out.ResourcesVerified {
					t.Fatal("activation/replay", err)
				}
			}
			history, err := os.ReadFile(filepath.Join(activeFile+".history", f.in.Intent.CertificateSHA256+".pem"))
			if err != nil || !bytes.Contains(history, f.live.Key) {
				t.Fatal("original identity lost", err)
			}
			defer clear(history)
			b, _, err := nodepki.ReadIdentity(filepath.Join(f.w.identityData, "pki-identity", "ca.crt"), activeFile, nodepki.Node, f.r.Node, time.Now())
			defer clear(b.Key)
			if err != nil || bytes.Equal(b.Key, f.live.Key) {
				t.Fatal("node-local successor key not active", err)
			}
			leaf := recoveryTestCertificate(t, b.Certificate)
			if leaf.VerifyHostname(f.r.Spec.ServerName) != nil || leaf.VerifyHostname(f.in.Intent.ServerName) != nil {
				t.Fatal("source/target name overlap missing")
			}
			gotInstallation, _ := os.ReadFile(filepath.Join(f.w.root, "active.json"))
			gotConfig, _ := os.ReadFile(filepath.Join(f.w.configurationDir(f.r.Spec), "runtime.json"))
			gotMarker, _ := os.ReadFile(marker)
			if !bytes.Equal(installation, gotInstallation) || !bytes.Equal(config, gotConfig) || string(gotMarker) != "baseline, queued events and unfinished scan marker" {
				t.Fatal("name change modified installation/runtime/data marker")
			}
			public, _ := json.Marshal([]NameChangeOutput{prepared, retry})
			if bytes.Contains(public, []byte("PRIVATE KEY")) || bytes.Contains(public, f.live.Key) || bytes.Contains(public, b.Key) {
				t.Fatal("private identity leaked")
			}
		})
	}
}

func TestNameChangeHelperRejectsUnsafeStateBeforePreparingKey(t *testing.T) {
	for _, scenario := range []string{"expired", "bad-challenge", "wrong-node", "wrong-root", "revoked", "crl-rollback", "missing-floor", "identity-link", "active-pointer", "runtime", "pending-deployment", "failed-rollback", "operation-lock", "journal-lock", "unsupported-start"} {
		t.Run(scenario, func(t *testing.T) {
			f := newHelperNameChangeFixture(t, "native")
			ctx := context.Background()
			active := filepath.Join(f.w.identityData, "pki-identity", "active.pem")
			before, _ := os.ReadFile(active)
			defer clear(before)
			switch scenario {
			case "expired":
				f.in.Intent.IssuedAt, f.in.Intent.ExpiresAt = time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
			case "bad-challenge":
				f.in.Intent.Challenge = "bad"
			case "wrong-node":
				f.in.Intent.Node = "other-node"
			case "wrong-root":
				f.in.Intent.AuthoritySHA256 = strings.Repeat("0", 64)
			case "revoked", "crl-rollback":
				crl, err := f.ca.Revoke(f.in.CRL, [][]byte{f.live.Certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "revoked" {
					f.in.CRL = crl
				} else if err := os.WriteFile(filepath.Join(f.w.identityData, "pki-trust", "ca.crl"), crl, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-floor":
				if err := os.Remove(filepath.Join(f.w.identityData, "pki-trust", "ca.crl")); err != nil {
					t.Fatal(err)
				}
			case "identity-link":
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
			case "runtime":
				if err := os.WriteFile(filepath.Join(f.w.configurationDir(f.r.Spec), "runtime.json"), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending-deployment", "failed-rollback":
				j := &Journal{root: filepath.Join(f.w.root, "node")}
				db, err := j.database()
				if err != nil {
					t.Fatal(err)
				}
				phase, state := "switch", "running"
				if scenario == "failed-rollback" {
					phase, state = "restore", "failed"
				}
				_, err = db.Exec(`INSERT INTO phases(job,phase,status) VALUES(?,?,?)`, f.r.Job, phase, state)
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
				j := &Journal{root: filepath.Join(f.w.root, "node")}
				lock, err := j.lock()
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			case "unsupported-start":
				f.in.Operation = "start"
			}
			out, err := f.w.nameChange(ctx, f.in)
			if err == nil || len(out.Request) != 0 || out.CertificateSHA256 != "" {
				t.Fatal("unsafe state authorized identity operation", err)
			}
			after, _ := os.ReadFile(active)
			defer clear(after)
			if !bytes.Equal(before, after) {
				t.Fatal("failed preparation changed active identity")
			}
			pending := filepath.Join(filepath.Dir(active), "name-changes")
			if entries, err := os.ReadDir(pending); err == nil && len(entries) != 0 {
				t.Fatal("unsafe state created a new pending key")
			}
		})
	}
}

func TestNameChangeHelperInputIsBoundedCanonicalAndHasNoCommandFields(t *testing.T) {
	f := newHelperNameChangeFixture(t, "native")
	raw, _ := json.Marshal(f.in)
	if _, err := decodeNameChange(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{
		append(append([]byte{}, raw...), []byte(` {}`)...),
		append([]byte(`{"format":1,`), raw[1:]...),
		append([]byte(`{"path":"/tmp/foreign",`), raw[1:]...),
		append([]byte(`{"command":"systemctl restart business",`), raw[1:]...),
		bytes.Repeat([]byte("x"), MaxNameChangeBytes+1),
		[]byte(`{}`),
	} {
		if _, err := decodeNameChange(bytes.NewReader(value)); err == nil {
			t.Fatal("noncanonical, oversized or command input accepted")
		}
	}
}

func TestNameChangeHelperReconcilesExactOriginalIssuance(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, active := range []bool{false, true} {
			label := "pending"
			if active {
				label = "active"
			}
			t.Run(mode+"/"+label, func(t *testing.T) {
				f := signedHelperNameChange(t, mode, active)
				ctx := context.Background()
				original := append([]byte{}, f.in.Request...)
				before, err := os.ReadFile(filepath.Join(f.w.identityData, "pki-identity", "active.pem"))
				if err != nil {
					t.Fatal(err)
				}
				defer clear(before)
				intent, err := nodepki.NewNodeNameChangeIntent(f.in.Intent.Node, f.in.Intent.AuthoritySHA256, f.in.Intent.CertificateSHA256, f.in.Intent.ServerName, time.Now().UTC().Truncate(time.Second))
				if err != nil {
					t.Fatal(err)
				}
				f.in.Intent, f.in.Operation = intent, "reconcile"
				out, err := f.w.nameChange(ctx, f.in)
				if err != nil || len(out.Request) == 0 || out.CertificateSHA256 != "" || out.ResourcesVerified {
					t.Fatal("reconciliation", err)
				}
				r, err := nodepki.ParseNodeNameChangeRequest(out.Request)
				if err != nil || !bytes.Equal(r.OriginalRequest, original) {
					t.Fatal("original request lost", err)
				}
				retry, err := f.w.nameChange(ctx, f.in)
				if err != nil || !bytes.Equal(out.Request, retry.Request) {
					t.Fatal("lost-response reconciliation changed proof", err)
				}
				f.in.Operation, f.in.Request = "activate", out.Request
				for i := 0; i < 2; i++ {
					receipt, err := f.w.nameChange(ctx, f.in)
					if err != nil || receipt.CertificateSHA256 == "" {
						t.Fatal("reconciled activation/replay", err)
					}
				}
				if active {
					after, _ := os.ReadFile(filepath.Join(f.w.identityData, "pki-identity", "active.pem"))
					defer clear(after)
					if !bytes.Equal(before, after) {
						t.Fatal("reconciliation rewrote active identity")
					}
				}
				entries, err := os.ReadDir(filepath.Join(f.w.identityData, "pki-identity", "name-changes"))
				if err != nil || len(entries) != 1 {
					t.Fatal("reconciliation created a new CSR/key directory", err)
				}
			})
		}
	}
}
