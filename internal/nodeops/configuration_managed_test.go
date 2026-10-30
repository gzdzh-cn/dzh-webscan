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

func keylessConfigurationFixture(t *testing.T) (*LocalRuntime, Request, nodeconfig.Material, *nodepki.Authority, nodepki.Bundle) {
	t.Helper()
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := nodepki.NewAuthority(now.Add(-48*time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	live, err := ca.Issue(nodepki.Node, r.Node, []string{"node.test"}, now.Add(-time.Hour), 72*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ca.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	w.identityData = testRoot(t)
	for _, dir := range []string{"pki-identity", "pki-trust"} {
		if err := os.Mkdir(filepath.Join(w.identityData, dir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(w.identityData, dir, "ca.crt"), live.CA, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := nodepki.PublishIdentity(context.Background(), filepath.Join(w.identityData, "pki-identity", "ca.crt"), filepath.Join(w.identityData, "pki-identity", "active.pem"), nodepki.Node, r.Node, "", live, now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.identityData, "pki-trust", "ca.crl"), crl, 0600); err != nil {
		t.Fatal(err)
	}
	m := attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
		m.Format, m.CA, m.CRL, m.Certificate, m.Key = 3, live.CA, crl, nil, nil
	})
	return w, r, m, ca, live
}

func TestKeylessConfigurationRetainsLocalKeyAcrossRenewalAndResume(t *testing.T) {
	w, r, m, ca, live := keylessConfigurationFixture(t)
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.crt", "identity.key"} {
		if _, err := os.Lstat(filepath.Join(w.configurationDir(r.Spec), name)); !os.IsNotExist(err) {
			t.Fatal("keyless configuration contains an identity seed", err)
		}
	}
	active := filepath.Join(w.identityData, "pki-identity", "active.pem")
	old, err := os.ReadFile(active)
	if err != nil || !bytes.Contains(old, live.Key) {
		t.Fatal("live key lost", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	next, err := ca.Issue(nodepki.Node, r.Node, []string{"node.test"}, now, 80*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, record, err := nodepki.ReadIdentity(filepath.Join(w.identityData, "pki-identity", "ca.crt"), active, nodepki.Node, r.Node, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.PublishIdentity(context.Background(), filepath.Join(w.identityData, "pki-identity", "ca.crt"), active, nodepki.Node, r.Node, record.CertificateSHA256, next, now); err != nil {
		t.Fatal(err)
	}
	// A new process resumes the same immutable artifact after local rotation.
	restarted := &LocalRuntime{root: w.root, identityData: w.identityData, rulesProbe: w.rulesProbe, probe: w.probe}
	if err := restarted.verifyConfiguration(context.Background(), r); err != nil {
		t.Fatal("renewal stranded prepared configuration", err)
	}
	got, _ := os.ReadFile(active)
	if !bytes.Contains(got, next.Key) || bytes.Equal(got, old) {
		t.Fatal("upgrade rolled back locally renewed key")
	}
	for _, mode := range []string{"native", "docker"} {
		m.Mode = mode
		spec := r.Spec
		spec.Mode = mode
		if mode == "docker" {
			spec.AgentImage = "webscan/agent@sha256:" + strings.Repeat("a", 64)
			m.Settings.Monitor.Roots = []string{"/www/wwwroot"}
			m.Settings.ProbeDirectory = "/www/wwwroot/.webscan-probe"
			spec.MonitorDirectories = []string{"/www/wwwroot"}
		}
		files, err := w.configurationFiles(m, spec)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range files {
			if bytes.Contains(raw, []byte("PRIVATE KEY")) {
				t.Fatal("node private key escaped into generated files")
			}
		}
	}
}

func TestKeylessConfigurationRejectsInvalidLiveIdentityBeforePublish(t *testing.T) {
	for _, scenario := range []string{"missing-identity", "missing-floor", "wrong-node", "wrong-host", "expired", "revoked", "floor-rollback", "wrong-root", "public-key-permissions", "identity-symlink", "floor-symlink"} {
		t.Run(scenario, func(t *testing.T) {
			w, r, m, ca, live := keylessConfigurationFixture(t)
			now := time.Now().UTC().Truncate(time.Second)
			active := filepath.Join(w.identityData, "pki-identity", "active.pem")
			floor := filepath.Join(w.identityData, "pki-trust", "ca.crl")
			switch scenario {
			case "missing-identity":
				os.Remove(active)
			case "missing-floor":
				os.Remove(floor)
			case "wrong-node", "wrong-host", "expired":
				id, host, start := r.Node, "node.test", now
				if scenario == "wrong-node" {
					id = "other-node"
				}
				if scenario == "wrong-host" {
					host = "other.test"
				}
				if scenario == "expired" {
					start = now.Add(-2 * time.Hour)
				}
				bad, err := ca.Issue(nodepki.Node, id, []string{host}, start, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(active, append(append([]byte{}, bad.Certificate...), bad.Key...), 0600); err != nil {
					t.Fatal(err)
				}
			case "revoked", "floor-rollback":
				certs := [][]byte{live.Certificate}
				next, err := ca.Revoke(m.CRL, certs, now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "floor-rollback" {
					if err := os.WriteFile(floor, next, 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					m.CRL = next
					raw, _ := json.Marshal(m)
					r.Spec.RuntimeSHA256, r.Spec.RuntimeBytes = nodeconfig.Digest(raw), uint64(len(raw))
					dir := filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256)
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "node.json"), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong-root":
				if err := os.WriteFile(filepath.Join(w.identityData, "pki-trust", "ca.crt"), []byte("wrong"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-key-permissions":
				os.Chmod(active, 0644)
			case "identity-symlink", "floor-symlink":
				path := active
				if scenario == "floor-symlink" {
					path = floor
				}
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(active)
			if _, err := w.Apply(r); err == nil {
				t.Fatal("invalid live identity accepted", scenario)
			}
			if _, err := os.Lstat(w.configurationDir(r.Spec)); !os.IsNotExist(err) {
				t.Fatal("invalid upgrade configuration published", err)
			}
			after, _ := os.ReadFile(active)
			if !bytes.Equal(before, after) {
				t.Fatal("failed validation changed local identity")
			}
		})
	}
}

func TestManagedSeedResumeAfterSeedAndCRLExpire(t *testing.T) {
	w, r, m, ca, live := keylessConfigurationFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-36 * time.Hour)
	seed, err := ca.Issue(nodepki.Node, r.Node, []string{m.ServerName}, past, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldCRL, err := ca.Revoke(nil, nil, past, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	currentCRL, err := ca.Revoke(oldCRL, [][]byte{seed.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	floor := filepath.Join(w.identityData, "pki-trust", "ca.crl")
	if err := os.WriteFile(floor, currentCRL, 0600); err != nil {
		t.Fatal(err)
	}
	m.Format, m.Certificate, m.Key, m.CRL = 2, seed.Certificate, seed.Key, oldCRL
	raw, _ := json.Marshal(m)
	if _, err := nodeconfig.Decode(raw, now); err == nil {
		t.Fatal("ordinary provisioning accepted expired seed and CRL")
	}
	r.Spec.RuntimeSHA256, r.Spec.RuntimeBytes = nodeconfig.Digest(raw), uint64(len(raw))
	dir := filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(w.identityData, "pki-identity", "active.pem")
	before, _ := os.ReadFile(active)
	if _, err := w.Apply(r); err != nil {
		t.Fatal("historical seed/CRL stranded current managed identity", err)
	}
	if err := w.verifyConfiguration(context.Background(), r); err != nil {
		t.Fatal("resume failed", err)
	}
	after, _ := os.ReadFile(active)
	floorAfter, _ := os.ReadFile(floor)
	artifact, _ := os.ReadFile(filepath.Join(dir, "node.json"))
	if !bytes.Equal(before, after) || !bytes.Contains(after, live.Key) || !bytes.Equal(floorAfter, currentCRL) || !bytes.Equal(artifact, raw) {
		t.Fatal("resume changed live key, floor or immutable artifact")
	}
	// A valid historical seed is never a substitute for a valid live key.
	if err := os.WriteFile(active, append(append([]byte{}, seed.Certificate...), seed.Key...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.verifyConfiguration(context.Background(), r); err == nil {
		t.Fatal("expired/revoked active key accepted through historical decoder")
	}
}

func managedLifecycleRequest(t *testing.T, w *LocalRuntime, r Request, data string) (Request, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256, "node.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := nodeconfig.Decode(raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w.identityData = data
	for _, name := range []string{"pki-identity", "pki-trust"} {
		dir := filepath.Join(data, name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ca.crt"), m.CA, 0600); err != nil {
			t.Fatal(err)
		}
	}
	active := filepath.Join(data, "pki-identity", "active.pem")
	if err := os.WriteFile(active, append(append([]byte{}, m.Certificate...), m.Key...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "pki-trust", "ca.crl"), m.CRL, 0600); err != nil {
		t.Fatal(err)
	}
	m.Format, m.Certificate, m.Key = 3, nil, nil
	raw, _ = json.Marshal(m)
	r.Spec.RuntimeSHA256, r.Spec.RuntimeBytes = nodeconfig.Digest(raw), uint64(len(raw))
	dir := filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.prepareConfiguration(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Phase, r.Operation = "backup", "apply"
	return r, active
}

func TestManagedIdentityRecheckedBeforeNativeOrDockerServiceStop(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			var w *LocalRuntime
			var request Request
			var data string
			var apply func(Request) (Outcome, error)
			var machine *installationMachine
			if mode == "native" {
				n, a, _, _ := nativeJournalFixture(t, false)
				w, request, data, apply, machine = n.runtime, a.request, n.activation.backup.data, n.Apply, a.machine
			} else {
				d, a, _, _ := dockerJournalFixture(t, false)
				w, request, data, apply, machine = d.runtime, a.request, d.activation.backup.data, d.Apply, a.machine
			}
			r, active := managedLifecycleRequest(t, w, request, data)
			// Preparation succeeded. Corruption immediately before backup must
			// still fail without invoking either service manager's stop command.
			if err := os.WriteFile(active, []byte("damaged-after-stage"), 0600); err != nil {
				t.Fatal(err)
			}
			machine.calls = nil
			if _, err := apply(r); err == nil {
				t.Fatal("damaged identity reached service stop")
			}
			for _, call := range machine.calls {
				if strings.Contains(call, " stop ") || strings.Contains(call, " kill ") {
					t.Fatal("service stopped before identity validation", call)
				}
			}
			if mode == "native" && !machine.nativeRunning {
				t.Fatal("original native service stopped")
			}
			for _, c := range machine.containers {
				if c.Status != "running" {
					t.Fatal("original container stopped")
				}
			}
		})
	}
}
