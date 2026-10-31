package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func singlePKIUpgradeFixture(t *testing.T) (singleInstallSpec, singlePKIUpgradeSpec, string) {
	t.Helper()
	s, oldHelper, _ := prepareSinglePKIFixture(t)
	j, err := readSingleInstallation(s, oldHelper)
	if err != nil {
		t.Fatal(err)
	}
	j.Step = 3
	if err := saveSingleJournal(s.Root, j); err != nil {
		t.Fatal(err)
	}
	f := newTrustToolFixture(t)
	f.sign.Output += "-maintenance"
	if err := ReleaseCommand(context.Background(), f.sign, io.Discard); err != nil {
		t.Fatal(err)
	}
	f.signed = f.sign.Output
	return s, singlePKIUpgradeSpec{Format: 1, Installation: filepath.Join(s.Root, "install.json"), PublicKeyFile: f.config().PublicKeyFile, ManifestFile: f.config().ManifestFile, SignatureFile: f.config().SignatureFile, HelperFile: f.helper}, filepath.Join(filepath.Dir(s.Root), "maintenance-upgrade")
}

func publishSinglePKIUpgradeFixture(t *testing.T, spec singlePKIUpgradeSpec, output string) {
	t.Helper()
	raw, _ := json.Marshal(spec)
	source := filepath.Join(filepath.Dir(output), "upgrade-input.json")
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Command(context.Background(), Options{Action: "prepare-single-pki-upgrade", Source: source, Output: output}, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestSinglePKIUpgradePreservesInstallationAndKeys(t *testing.T) {
	s, spec, output := singlePKIUpgradeFixture(t)
	before := map[string][]byte{}
	for _, name := range []string{"install.json", "journal.json", "webscan", "ca.crt", "ca.key", "collector.crt", "collector.key", "config.yaml", "pki-maintenance.service", "authority/ca.key", "collector-pki/collector.pem", "state/collector-trust/ca.crl"} {
		path := filepath.Join(s.Root, name)
		var err error
		before[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	files, err := singlePKIUpgradeFiles(context.Background(), spec, output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("preview wrote files")
	}
	service := string(files["pki-maintenance.service"])
	if !strings.Contains(service, filepath.Join(output, "webscan")) || !strings.Contains(service, "--action maintain-single-pki-upgrade") || strings.Contains(service, "ExecStart="+filepath.Join(s.Root, "webscan")) || !strings.Contains(service, "ProtectSystem=strict") {
		t.Fatal("wrong maintenance helper or privileges")
	}
	for name := range files {
		if strings.HasSuffix(name, ".key") || name == "config.yaml" || name == "install.json" || name == "vault.key" {
			t.Fatal("overlay copied/regenerated a protected file", name)
		}
	}
	publishSinglePKIUpgradeFixture(t, spec, output)
	var result bytes.Buffer
	if err := Command(context.Background(), Options{Action: "check-single-pki-upgrade", Source: filepath.Join(output, "maintenance.json")}, nil, &result); err != nil || !strings.Contains(result.String(), `"database_checked":false`) {
		t.Fatal("prepared overlay not verifiable", err, result.String())
	}
	if _, _, err := readSinglePKIUpgrade(context.Background(), filepath.Join(output, "maintenance.json"), filepath.Join(output, "webscan"), deploymentFixtureRelease(t)); err != nil {
		t.Fatal("new executing helper rejected", err)
	}
	if _, _, err := readSinglePKIUpgrade(context.Background(), filepath.Join(output, "maintenance.json"), filepath.Join(s.Root, "webscan"), deploymentFixtureRelease(t)); err == nil {
		t.Fatal("old helper accepted as upgraded helper")
	}
	for _, version := range []string{"", "development", "v0.0.0-mismatched"} {
		if _, _, err := readSinglePKIUpgrade(context.Background(), filepath.Join(output, "maintenance.json"), filepath.Join(output, "webscan"), version); err == nil {
			t.Fatal("executing helper version did not match signed release", version)
		}
	}
	st, err := os.Stat(filepath.Join(output, "webscan"))
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("helper not private/executable", err)
	}
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("modified original installation or key", path, err)
		}
	}
	raw, _ := json.Marshal(spec)
	input := filepath.Join(filepath.Dir(output), "upgrade-input.json")
	os.WriteFile(input, raw, 0600)
	if err := Command(context.Background(), Options{Action: "prepare-single-pki-upgrade", Source: input, Output: output}, nil, io.Discard); err == nil {
		t.Fatal("overwrote an existing overlay")
	}
}

func TestSinglePKIUpgradeRejectsInvalidInputs(t *testing.T) {
	for _, scenario := range []string{"unsigned-helper", "invalid-signature", "untrusted-key", "changed-installation", "unsafe-output", "output-in-installation", "source-in-output", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			s, spec, output := singlePKIUpgradeFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "unsigned-helper":
				os.WriteFile(spec.HelperFile, []byte("unexpected helper"), 0600)
			case "invalid-signature":
				os.WriteFile(spec.SignatureFile, bytes.Repeat([]byte{1}, 64), 0600)
			case "untrusted-key":
				spec.PublicKeyFile = newTrustToolFixture(t).config().PublicKeyFile
			case "changed-installation":
				os.WriteFile(filepath.Join(s.Root, "ca.key"), []byte("bad key"), 0600)
			case "unsafe-output":
				output += "%n"
			case "output-in-installation":
				output = filepath.Join(s.Root, "override")
			case "source-in-output":
				output = filepath.Dir(spec.HelperFile)
			case "canceled":
				cancel()
			}
			if _, err := singlePKIUpgradeFiles(ctx, spec, output); err == nil {
				t.Fatal("accepted invalid overlay", scenario)
			}
		})
	}
}

func TestSinglePKIUpgradeRejectsTamperedPublishedPackage(t *testing.T) {
	for _, scenario := range []string{"helper", "helper-symlink", "timer", "install", "trust-anchor", "missing-trust-floor", "schema", "uninitialized", "unknown-field", "duplicate-field", "manifest-link"} {
		t.Run(scenario, func(t *testing.T) {
			s, spec, output := singlePKIUpgradeFixture(t)
			publishSinglePKIUpgradeFixture(t, spec, output)
			source := filepath.Join(output, "maintenance.json")
			switch scenario {
			case "helper":
				os.WriteFile(filepath.Join(output, "webscan"), []byte("tampered"), 0700)
			case "helper-symlink":
				os.Remove(filepath.Join(output, "webscan"))
				os.Symlink(spec.HelperFile, filepath.Join(output, "webscan"))
			case "timer":
				os.WriteFile(filepath.Join(output, "pki-maintenance.timer"), []byte("tampered"), 0600)
			case "install":
				os.WriteFile(filepath.Join(s.Root, "collector.key"), []byte("tampered"), 0600)
			case "trust-anchor":
				pub, _ := os.ReadFile(newTrustToolFixture(t).config().PublicKeyFile)
				os.WriteFile(spec.PublicKeyFile, pub, 0600)
			case "missing-trust-floor":
				os.Remove(filepath.Join(s.Root, "collector-pki", "binding.json"))
			case "schema":
				raw, _ := os.ReadFile(source)
				var m singlePKIUpgradeManifest
				json.Unmarshal(raw, &m)
				m.Schema--
				raw, _ = json.Marshal(m)
				os.WriteFile(source, raw, 0600)
			case "uninitialized":
				_, _, j, _ := singlePKIUpgradeInstallation(spec.Installation)
				j.Step = 1
				saveSingleJournal(s.Root, j)
			case "unknown-field", "duplicate-field":
				raw, _ := os.ReadFile(source)
				name := "unrecognized"
				if scenario == "duplicate-field" {
					name = "format"
				}
				os.WriteFile(source, append([]byte(`{"`+name+`":1,`), raw[1:]...), 0600)
			case "manifest-link":
				os.Link(source, source+".hardlink")
			}
			if _, _, err := readSinglePKIUpgrade(context.Background(), source, "", ""); err == nil {
				t.Fatal("accepted tampered package", scenario)
			}
		})
	}
}
