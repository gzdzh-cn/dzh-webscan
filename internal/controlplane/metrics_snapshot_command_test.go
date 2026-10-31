package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
	"webscan/internal/progress"
)

func TestMetricsSnapshotCommandBindsCompletedSingleInstallation(t *testing.T) {
	for _, kind := range []string{"valid", "unfinished", "other-instance", "other-endpoint", "other-dsn", "modified-installation", "linked-config", "public-config", "unknown-config", "linked-installation"} {
		t.Run(kind, func(t *testing.T) {
			s, helper, _ := prepareSinglePKIFixture(t)
			journal, err := readSingleInstallation(s, helper)
			if err != nil {
				t.Fatal(err)
			}
			journal.Step = 6
			if kind == "unfinished" {
				journal.Step = 3
			}
			if err := saveSingleJournal(s.Root, journal); err != nil {
				t.Fatal(err)
			}
			c := s.configuration()
			options := Options{Config: filepath.Join(filepath.Dir(s.Root), "actual.yaml"), Source: filepath.Join(s.Root, "install.json")}
			switch kind {
			case "other-instance":
				c.Central.Instance = "unrelated-center"
			case "other-endpoint":
				c.Metrics.QueryURL = "http://127.0.0.1:38428"
			case "other-dsn":
				c.Database.DSNFile = filepath.Join(s.Root, "other.dsn")
			case "modified-installation":
				os.WriteFile(filepath.Join(s.Root, "ca.key"), []byte("do not silently repair"), 0600)
			case "linked-installation":
				options.Source = filepath.Join(filepath.Dir(s.Root), "install-alias.json")
				os.Symlink(filepath.Join(s.Root, "install.json"), options.Source)
			}
			raw, _ := yaml.Marshal(c)
			if kind == "unknown-config" {
				raw = append(raw, []byte("arbitrary_command: must-not-run\n")...)
			}
			if err := os.WriteFile(options.Config, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "linked-config" {
				alias := options.Config + ".alias"
				os.Symlink(options.Config, alias)
				options.Config = alias
			}
			if kind == "public-config" {
				os.Chmod(options.Config, 0644)
			}
			v, err := metricsSnapshotInstallation(options)
			if kind == "valid" {
				if err != nil || v.Directory != filepath.Join(s.Root, "metrics-data") || v.URL != c.Metrics.QueryURL {
					t.Fatal(v, err)
				}
			} else if err == nil {
				t.Fatal("accepted mismatched or unsafe installation", kind)
			}
		})
	}
}

func TestMetricsSnapshotCommandFailureIsActionableAndPrivate(t *testing.T) {
	f := newMetricsSnapshotFixture(t)
	receipt, err := f.store.backup(context.Background(), filepath.Join(f.parent, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(metricsSnapshotRestoreSpec{Format: 1, Directory: receipt.Directory, ManifestSHA256: receipt.ManifestSHA256})
	source := filepath.Join(f.parent, "request.json")
	os.WriteFile(source, request, 0600)
	os.WriteFile(filepath.Join(receipt.Directory, "metadata/extra"), []byte("private-error-detail"), 0600)
	var out bytes.Buffer
	err = Command(context.Background(), Options{Action: "verify-metrics-backup", Source: source}, nil, &out)
	if err == nil || out.Len() != 0 || progress.Explain(err) != errMetricsSnapshot.Error() || err.Error() != "metrics_snapshot_failed" {
		t.Fatal("failed verification leaked details or lacked an actionable message", out.String(), err)
	}
}
