package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSingleMetricsLayersComposeAndImmutableCompatibility(t *testing.T) {
	old := singleSpecFixture(t)
	if strings.Contains(string(singleCompose(old, "proof")), "metrics-raw:") {
		t.Fatal("implicit old topology change")
	}
	trust := newTrustToolFixture(t)
	c := trust.config()
	s := old
	s.Format = 3
	s.ReleaseTrust = &c
	s.RulesFile = filepath.Join(trust.root, "rules.yar")
	s.MetricsLayers = true
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	if s.RawMetricsHours != 48 || s.HistoryMetricsDays != 15 || s.RawMetricsPort != 8429 || len(s.localPorts()) != 4 {
		t.Fatal("wrong defaults")
	}
	if s.configuration().Metrics.RawURL != "http://127.0.0.1:8429" {
		t.Fatal("missing raw endpoint")
	}
	var doc struct {
		Services map[string]struct {
			Command []string
			Volumes []struct{ Source, Target string }
		}
	}
	if yaml.Unmarshal(singleCompose(s, "proof"), &doc) != nil || len(doc.Services) != 4 {
		t.Fatal("bad layers")
	}
	if !strings.Contains(strings.Join(doc.Services["metrics-raw"].Command, " "), "-retentionPeriod=48h") || !strings.Contains(strings.Join(doc.Services["metrics"].Command, " "), "-retentionPeriod=15d") {
		t.Fatal("wrong physical retention")
	}
	if doc.Services["metrics-raw"].Volumes[0].Source == doc.Services["metrics"].Volumes[0].Source {
		t.Fatal("shared engine data")
	}
	for _, change := range []func(*singleInstallSpec){func(v *singleInstallSpec) { v.RawMetricsHours = 23 }, func(v *singleInstallSpec) { v.RawMetricsPort = v.MetricsPort }, func(v *singleInstallSpec) { v.HistoryMetricsDays = 91 }, func(v *singleInstallSpec) { v.MetricsLayers = false }} {
		bad := s
		change(&bad)
		if bad.validate() == nil {
			t.Fatal("invalid layers accepted")
		}
	}
}

func TestSingleBackupCapturesBothMetricsLayersAndRestoresSeparately(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	p, _ := newSingleBackupFixtureOptions(t, "", 3, false, false, true)
	result, err := s.backupSingle(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := verifySingleBackup(ctx, result.Directory, result.ManifestSHA256)
	if err != nil || manifest.RawMetrics == "" {
		t.Fatal("raw snapshot missing", err)
	}
	for _, f := range manifest.Files {
		if strings.Contains(f.Path, "raw-live-do-not-copy") {
			t.Fatal("copied live raw files")
		}
	}
	output := filepath.Join(filepath.Dir(p.output), "two-layer-restore")
	if err := restoreSingleBackupOffline(ctx, p.output, result.ManifestSHA256, output); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"metrics", "metrics-raw"} {
		if st, err := os.Stat(filepath.Join(output, name)); err != nil || !st.IsDir() {
			t.Fatal("missing restored layer", name, err)
		}
	}
	localWrite(t, filepath.Join(result.Directory, "metrics-raw", "manifest.json"), []byte(`{}`))
	if _, err := verifySingleBackup(ctx, result.Directory, result.ManifestSHA256); err == nil {
		t.Fatal("accepted raw snapshot tampering")
	}
}
