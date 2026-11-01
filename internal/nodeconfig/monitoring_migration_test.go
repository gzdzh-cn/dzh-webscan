package nodeconfig

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

func TestMonitoringMigrationPrivateMaterialKeepsAdvancedSettingsAndQueueIdentity(t *testing.T) {
	original := materialFixture(t)
	for _, mode := range []string{"native", "docker"} {
		t.Run(mode, func(t *testing.T) {
			m := original
			m.Mode = mode
			m.Settings.Monitor = Monitor{
				Roots: []string{"/srv/customer-site", "/srv/static"}, Extensions: []string{".php", ".phtml"},
				ImportantFilenames: []string{".htaccess", "config.json"}, CriticalPaths: []string{"/srv/customer-site/config.php"},
				ExcludePaths: []string{"/srv/customer-site/**/cache/**"}, SiteNameMode: original.Settings.Monitor.SiteNameMode,
				Reconciliation: Reconciliation{24, 77, 17, 11, 2},
			}
			m.Settings.ProbeDirectory = "/srv/customer-site/.approved-probe"
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := Decode(raw, time.Now())
			if err != nil {
				t.Fatal("new effective monitor cannot enter private material", err)
			}
			if !reflect.DeepEqual(decoded.Settings.Monitor, m.Settings.Monitor) || decoded.Settings.Resources != original.Settings.Resources || decoded.Settings.Transport != original.Settings.Transport || !bytes.Equal(decoded.YARA, original.YARA) || !bytes.Equal(decoded.Key, original.Key) || !bytes.Equal(decoded.Certificate, original.Certificate) {
				t.Fatal("monitor update mutated unrelated protected material")
			}
			runtime, err := decoded.Runtime("/immutable/new-monitor", "/immutable/release")
			if err != nil {
				t.Fatal(err)
			}
			monitor := common.M(runtime["monitor"])
			if !reflect.DeepEqual(common.SS(monitor["roots"]), m.Settings.Monitor.Roots) || common.I(common.M(monitor["reconciliation"])["interval_hours"]) != 24 || common.I(common.M(monitor["reconciliation"])["start_jitter_minutes"]) != 77 {
				t.Fatal("runtime did not retain effective rules or advanced tuning")
			}
			if common.S(runtime["data_dir"]) != "/var/lib/webscan-v1" || common.S(runtime["log_dir"]) != "/var/log/webscan-v1" || common.S(runtime["transport_mode"]) != "pull" {
				t.Fatal("rule migration changed persistent queue identity or transport")
			}
			if common.I(runtime["config_version"]) != int(m.Version) || common.S(runtime["config_sha256"]) != m.SourceSHA256 {
				t.Fatal("effective rule update lost signed configuration identity")
			}
		})
	}
}

func TestMonitoringMigrationRequiresCompleteProbeAndCanonicalPrivateMaterial(t *testing.T) {
	m := materialFixture(t)
	m.Settings.Monitor.Roots = []string{"/srv/customer-site"}
	raw, _ := json.Marshal(m)
	if _, err := Decode(raw, time.Now()); err == nil {
		t.Fatal("roots changed while old probe is outside coverage")
	}
	m.Settings.ProbeDirectory = "/srv/customer-site/.webscan-probe"
	m.Settings.Monitor.ExcludePaths = []string{"/srv/customer-site/.webscan-probe"}
	raw, _ = json.Marshal(m)
	if _, err := Decode(raw, time.Now()); err == nil {
		t.Fatal("excluded actual probe accepted")
	}
	m.Settings.ProbeDirectory = "/srv/customer-site/.approved-probe"
	raw, _ = json.Marshal(m)
	if _, err := Decode(raw, time.Now()); err != nil {
		t.Fatal("valid explicit probe with inherited rules rejected", err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"roots":["/srv/customer-site"]`), []byte(`"roots":["/srv/customer-site"],"roots":["/etc"]`), 1),
		bytes.Replace(raw, []byte(`"roots":["/srv/customer-site"]`), []byte(`"roots":["/srv/customer-site"],"inheritance":"public"`), 1),
		bytes.Replace(raw, []byte(`"roots":["/srv/customer-site"]`), []byte(`"roots":["relative-root"]`), 1),
		append(append([]byte{}, raw...), []byte(` {}`)...),
	} {
		if bytes.Equal(bad, raw) {
			t.Fatal("malformed-rule fixture did not change input")
		}
		if _, err := Decode(bad, time.Now()); err == nil {
			t.Fatal("ambiguous public metadata or malformed rule material accepted")
		}
	}
	if strings.Contains(string(raw), `"inheritance"`) {
		t.Fatal("public inheritance metadata entered private signed artifact")
	}
}
