package nodeops

import (
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

func attachConfiguration(t *testing.T, w *LocalRuntime, r *Request, change func(*nodeconfig.Material)) nodeconfig.Material {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	authority, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authority.Issue(nodepki.Node, r.Node, []string{"node.test"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := authority.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	settings := nodeconfig.DefaultSettings()
	settings.Monitor.Roots = append([]string{}, r.Spec.MonitorDirectories...)
	settings.Scan.ClamAV.Enabled = r.Spec.ClamAV
	settings.ProbeDirectory = filepath.Join(settings.Monitor.Roots[0], ".webscan-probe")
	m := nodeconfig.Material{Format: 1, Node: r.Node, Version: 1, SourceSHA256: strings.Repeat("c", 64), Mode: r.Spec.Mode, Release: r.Spec.Release, BundleSHA256: r.Spec.BundleSHA256, ServerName: "node.test", MetricsPort: r.Spec.MetricsPort, Collectors: []string{"collector-a"}, Settings: settings, CA: identity.CA, Certificate: identity.Certificate, Key: identity.Key, CRL: crl, YARA: []byte("rule fixture { condition: false }")}
	if change != nil {
		change(&m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	r.Spec.RuntimeSHA256, r.Spec.RuntimeBytes = nodeconfig.Digest(raw), uint64(len(raw))
	r.Spec.ConfigVersion, r.Spec.ConfigSourceSHA256, r.Spec.ServerName = 1, strings.Repeat("c", 64), "node.test"
	dir := filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return m
}
func TestConfigurationPreparationBindsTaskAndRevalidatesPrivateFiles(t *testing.T) {
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	m := attachConfiguration(t, w, &r, nil)
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	dir := w.configurationDir(r.Spec)
	for _, name := range []string{"runtime.json", "rules.yar", "identity.key", "identity.crt", "ca.crt", "ca.crl", "clamd.conf"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("unsafe configuration file", name, err)
		}
	}
	if state, _, err := w.Reconcile(r); err != nil || state != "complete" {
		t.Fatal("valid configuration not reconciled", state, err)
	}
	if err := w.VerifyCompleted(r, Outcome{}); err != nil {
		t.Fatal(err)
	}
	// Never accept an old stage receipt after a private key was replaced.
	if err := os.WriteFile(filepath.Join(dir, "identity.key"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.VerifyCompleted(r, Outcome{}); err == nil {
		t.Fatal("changed key accepted")
	}
	if _, err := w.Apply(r); err == nil {
		t.Fatal("changed configuration overwritten")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "identity.key"))
	if string(raw) != "tampered" {
		t.Fatal("unverified configuration repaired silently")
	}
	if string(m.Key) == "tampered" {
		t.Fatal("bad fixture")
	}
}
func TestConfigurationMismatchOrRulesFailureDoesNotPublish(t *testing.T) {
	for _, kind := range []string{"node", "version", "source", "mode", "release", "bundle", "port", "name", "roots", "clamav", "rules"} {
		t.Run(kind, func(t *testing.T) {
			files := bundleFiles()
			bundleChecksums(files)
			w, r := stageFixture(t, archiveFiles(t, files, nil))
			attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
				switch kind {
				case "node":
					m.Node = "other"
				case "version":
					m.Version++
				case "source":
					m.SourceSHA256 = strings.Repeat("f", 64)
				case "mode":
					m.Mode = "docker"
				case "release":
					m.Release = "v3.0.1"
				case "bundle":
					m.BundleSHA256 = strings.Repeat("f", 64)
				case "port":
					m.MetricsPort++
				case "name":
					m.ServerName = "wrong.test"
				case "roots":
					m.Settings.Monitor.Roots = []string{"/different"}
				case "clamav":
					m.Settings.Scan.ClamAV.Enabled = !m.Settings.Scan.ClamAV.Enabled
				}
			})
			if kind == "rules" {
				w.rulesProbe = func(context.Context, string, string) error { return os.ErrInvalid }
			}
			if _, err := w.Apply(r); err == nil {
				t.Fatal("bad configuration accepted")
			}
			if _, err := os.Lstat(w.configurationDir(r.Spec)); !os.IsNotExist(err) {
				t.Fatal("unverified configuration published", err)
			}
		})
	}
}
func TestMissingConfigurationAfterStageCanBePreparedAgain(t *testing.T) {
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	attachConfiguration(t, w, &r, nil)
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(w.configurationDir(r.Spec)); err != nil {
		t.Fatal(err)
	}
	if state, _, err := w.Reconcile(r); err != nil || state != "absent" {
		t.Fatal("private interrupted stage cannot retry", state, err)
	}
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	r.Spec.ConfigVersion++
	if err := w.VerifyCompleted(r, Outcome{}); err == nil {
		t.Fatal("configuration for a different version accepted")
	}
}
