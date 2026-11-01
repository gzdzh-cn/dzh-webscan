package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
)

func singleHostWatchdogConfig(root string) HostWatchdogConfig {
	return HostWatchdogConfig{Enabled: true, Socket: filepath.Join(root+"-watchdog-run", "control.sock"), StateDirectory: root + "-watchdog-state", SpecFile: filepath.Join(root, "watchdog-support", "watchdog.json")}
}

func ensureSingleHostWatchdog(ctx context.Context, s singleInstallSpec) error {
	if !s.HostWatchdog {
		return nil
	}
	// The immutable installation is published first. The independently
	// authenticated overlay pins it without introducing a circular file hash.
	artifact, err := hashTrustArtifact(ctx, filepath.Join(s.Root, "webscan"), 256<<20)
	if err != nil {
		return err
	}
	if _, err := readSingleInstallation(s, artifact.SHA256); err != nil {
		return err
	}
	c, err := LoadConfig(filepath.Join(s.Root, "executor.yaml"))
	if err != nil {
		return err
	}
	installed, err := hashTrustArtifact(ctx, filepath.Join(s.Root, "install.json"), 64<<10)
	if err != nil {
		return err
	}
	for _, path := range []string{c.HostWatchdog.StateDirectory, filepath.Dir(c.HostWatchdog.Socket)} {
		if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return errHostWatchdog
		}
		d, err := trustDirectory(path, true)
		if err != nil {
			return err
		}
		d.Close()
	}
	spec := HostWatchdogSpec{Format: 1, Instance: s.Instance, InstallationFile: filepath.Join(s.Root, "install.json"), InstallationSHA256: installed.SHA256, HostConfigFile: filepath.Join(s.Root, "executor.yaml"), HelperFile: filepath.Join(s.Root, "webscan"), HelperSHA256: artifact.SHA256, StateDirectory: c.HostWatchdog.StateDirectory, Socket: c.HostWatchdog.Socket, APIURL: "http://" + c.Central.Listen, MetricsURL: c.Metrics.QueryURL}
	hostBytes, err := readTrustData(spec.HostConfigFile, true, 2<<20)
	if err != nil {
		return err
	}
	spec.HostConfigSHA256 = digest(hostBytes)
	files, err := prepareHostWatchdogFiles(ctx, c, spec)
	if err != nil {
		return err
	}
	directory := filepath.Dir(c.HostWatchdog.SpecFile)
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return publishTrustFiles(ctx, directory, files)
	} else if err != nil {
		return err
	}
	// Resume accepts exactly the previously generated overlay. It does not
	// overwrite a changed trust record or replace an active watchdog database.
	for name, expected := range files {
		raw, err := readTrustData(filepath.Join(directory, name), true, 64<<10)
		if err != nil {
			return errHostWatchdog
		}
		if name == "watchdog.json" {
			v, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
			if err != nil {
				return errHostWatchdog
			}
			existing, err := loadHostSpec(filepath.Join(directory, name), v)
			var generated HostWatchdogSpec
			if err != nil || json.Unmarshal(expected, &generated) != nil {
				return errHostWatchdog
			}
			// A retained Vault key remains valid across key rotation. Compare
			// authenticated bindings without re-signing the immutable overlay.
			existing.KeyID, existing.Proof = "", ""
			generated.KeyID, generated.Proof = "", ""
			if !reflect.DeepEqual(existing, generated) {
				return errHostWatchdog
			}
		} else if !bytes.Equal(raw, expected) {
			return errHostWatchdog
		}
	}
	return nil
}
