package nodeconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
	"webscan/internal/nodepki"
)

func materialFixture(t *testing.T) Material {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := nodepki.NewAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ca.Issue(nodepki.Node, "node-a", []string{"node.test", "127.0.0.1"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ca.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return Material{Format: 1, Node: "node-a", Version: 17, SourceSHA256: strings.Repeat("a", 64), Mode: "native", Release: "v3.0.0", BundleSHA256: strings.Repeat("b", 64), ServerName: "node.test", MetricsPort: 19100, Collectors: []string{"collector-a"}, Settings: DefaultSettings(), CA: bundle.CA, Certificate: bundle.Certificate, Key: bundle.Key, CRL: crl, YARA: []byte("rule example { condition: false }")}
}

func TestManagedRuntimeDecoderDoesNotRelaxProvisioning(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	past := now.Add(-36 * time.Hour)
	ca, err := nodepki.NewAuthority(past.Add(-time.Hour), 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := ca.Issue(nodepki.Node, "node-a", []string{"node.test"}, past, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldCRL, err := ca.Revoke(nil, nil, past, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	liveCRL, err := ca.Revoke(oldCRL, [][]byte{seed.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m := materialFixture(t)
	m.Format, m.CA, m.Certificate, m.Key, m.CRL = 2, seed.CA, seed.Certificate, seed.Key, oldCRL
	raw, _ := json.Marshal(m)
	if _, err := Decode(raw, now); err == nil {
		t.Fatal("expired seed accepted for provisioning")
	}
	got, err := DecodeManagedRuntime(raw, now, liveCRL)
	if err != nil || got.Format != m.Format || !bytes.Equal(got.Key, m.Key) || !bytes.Equal(got.CRL, oldCRL) {
		t.Fatal("historical material mutated or rejected", err)
	}
	for _, change := range []func(*Material){
		func(m *Material) { m.Format = 1 },
		func(m *Material) { m.Key = []byte("broken") },
		func(m *Material) { m.CRL = []byte("broken") },
		func(m *Material) { m.Node = "other-node" },
		func(m *Material) { m.ServerName = "other.test" },
		func(m *Material) { m.Settings.Resources.CPUs = 0 },
	} {
		bad := m
		change(&bad)
		raw, _ := json.Marshal(bad)
		if _, err := DecodeManagedRuntime(raw, now, liveCRL); err == nil {
			t.Fatal("invalid historical seed accepted")
		}
	}
	if _, err := DecodeManagedRuntime(raw, now, oldCRL); err == nil {
		t.Fatal("expired trust accepted as live")
	}
}
func TestPrivateConfigurationRoundTripAndGeneratedRuntime(t *testing.T) {
	m := materialFixture(t)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Key, m.Key) || restored.Version != 17 {
		t.Fatal("configuration changed")
	}
	for _, mode := range []string{"native", "docker"} {
		restored.Mode = mode
		runtime, err := restored.Runtime("/var/lib/webscan-deploy/v3/configurations/"+Digest(raw), "/var/lib/webscan-deploy/v3/releases/"+m.BundleSHA256)
		if err != nil {
			t.Fatal(err)
		}
		if common.S(runtime["transport_mode"]) != "pull" || runtime["public_url"] != nil || runtime["token"] != nil || common.S(runtime["data_dir"]) != "/var/lib/webscan-v1" {
			t.Fatal("unsafe runtime transport or data directory")
		}
		configRoot := filepath.Dir(common.S(common.M(runtime["metrics"])["key_file"]))
		if !strings.HasSuffix(configRoot, Digest(raw)) || common.S(common.M(runtime["pull"])["revocation_file"]) != filepath.Join(configRoot, "ca.crl") {
			t.Fatal("configuration path not bound to artifact")
		}
		if common.S(common.M(runtime["pull"])["revocation_state_directory"]) != "/var/lib/webscan-v1/pki-trust" {
			t.Fatal("revocation floor is not outside replaceable configuration")
		}
		if !common.B(common.M(runtime["pull"])["revocation_updates"]) {
			t.Fatal("new node runtime cannot receive signed CRL updates")
		}
		if common.I(runtime["config_version"]) != 17 || common.S(runtime["config_sha256"]) != m.SourceSHA256 {
			t.Fatal("missing effective config identity")
		}
		proc := common.S(common.M(runtime["host_metrics"])["proc"])
		if mode == "docker" && proc != "/host/proc" || mode == "native" && proc != "/proc" {
			t.Fatal("wrong host metric source", mode, proc)
		}
		encoded, _ := json.Marshal(runtime)
		if bytes.Contains(encoded, []byte("PRIVATE KEY")) {
			t.Fatal("private material in runtime JSON instead of private path")
		}
	}
}
func TestConfigurationRejectsWrongIdentityKeyRevocationAndMalformedJSON(t *testing.T) {
	m := materialFixture(t)
	for _, change := range []func(*Material){
		func(m *Material) { m.Node = "other" }, func(m *Material) { m.ServerName = "wrong.test" }, func(m *Material) { m.Version = 0 },
		func(m *Material) { m.Key = []byte("broken") }, func(m *Material) { m.CRL = []byte("broken") }, func(m *Material) { m.Collectors = []string{"../root"} },
		func(m *Material) { m.Collectors = []string{"a", "a"} }, func(m *Material) { m.Settings.Resources.CPUs = 0 }, func(m *Material) { m.Settings.Scan.AuditD.Enabled = true },
		func(m *Material) { m.Settings.Transport.QueueMiB = 0 }, func(m *Material) { m.Settings.Monitor.Roots = []string{"/www/../etc"} },
		func(m *Material) { m.Settings.ProbeDirectory = "/tmp\ncommand" }, func(m *Material) { m.Settings.Scan.YARA.TimeoutSeconds = 0 },
		func(m *Material) { m.Settings.Resources.GoMemoryMiB = m.Settings.Resources.MemoryMiB },
	} {
		bad := m
		bad.Settings = m.Settings
		change(&bad)
		raw, err := json.Marshal(bad)
		if err == nil {
			if _, err := Decode(raw, time.Now()); err == nil {
				t.Fatal("invalid runtime accepted")
			}
		}
	}
	raw, _ := json.Marshal(m)
	for _, input := range [][]byte{append(append([]byte{}, raw...), []byte("{}")...), bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1), bytes.Replace(raw, []byte(`"format":1`), []byte(`"command":"id","format":1`), 1), bytes.Repeat([]byte(" "), MaxBytes+1)} {
		if _, err := Decode(input, time.Now()); err == nil {
			t.Fatal("ambiguous or oversized configuration accepted")
		}
	}
	// A cert from a different CA cannot be accepted even when its name matches.
	other := materialFixture(t)
	m.CA = other.CA
	if m.Validate(time.Now()) == nil {
		t.Fatal("foreign certificate authority accepted")
	}
	if _, err := x509.ParseCertificate(m.Certificate); err == nil {
		t.Fatal("fixture should be PEM, not DER")
	}
}

func TestManagedIdentityRuntimeFormatKeepsLegacyConfigurationStable(t *testing.T) {
	m := materialFixture(t)
	for _, mode := range []string{"native", "docker"} {
		m.Mode = mode
		legacy, err := m.Runtime("/immutable/configuration", "/immutable/release")
		if err != nil {
			t.Fatal(err)
		}
		metrics := common.M(legacy["metrics"])
		if common.S(metrics["identity_file"]) != "" || common.S(metrics["identity_seed_directory"]) != "" || common.S(metrics["cert_file"]) != "/immutable/configuration/identity.crt" {
			t.Fatal("legacy runtime changed")
		}
		if common.B(common.M(legacy["pull"])["identity_renewal"]) {
			t.Fatal("legacy split-key configuration enabled managed renewal")
		}
		m.Format = 2
		raw, _ := json.Marshal(m)
		if _, err := Decode(raw, time.Now()); err != nil {
			t.Fatal(err)
		}
		managed, err := m.Runtime("/immutable/configuration", "/immutable/release")
		if err != nil {
			t.Fatal(err)
		}
		metrics = common.M(managed["metrics"])
		if common.S(metrics["identity_file"]) != "/var/lib/webscan-v1/pki-identity/active.pem" || common.S(metrics["identity_seed_directory"]) != "/immutable/configuration" || metrics["cert_file"] != nil || metrics["key_file"] != nil {
			t.Fatal("managed identity is not isolated from immutable files")
		}
		if !common.B(common.M(managed["pull"])["identity_renewal"]) {
			t.Fatal("managed configuration did not enable node-local renewal")
		}
		m.Format = 1
	}
	m.Format = 4
	if m.Validate(time.Now()) == nil {
		t.Fatal("unknown material format accepted")
	}
}

func TestKeylessManagedUpgradeMaterial(t *testing.T) {
	m := materialFixture(t)
	m.Format, m.Certificate, m.Key = 3, nil, nil
	raw, _ := json.Marshal(m)
	if _, err := Decode(raw, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"native", "docker"} {
		m.Mode = mode
		runtime, err := m.Runtime("/immutable/configuration", "/immutable/release")
		if err != nil {
			t.Fatal(err)
		}
		metrics := common.M(runtime["metrics"])
		if common.S(metrics["identity_file"]) != "/var/lib/webscan-v1/pki-identity/active.pem" || metrics["identity_seed_directory"] != nil || metrics["cert_file"] != nil || metrics["key_file"] != nil || !common.B(common.M(runtime["pull"])["identity_renewal"]) {
			t.Fatal("keyless runtime attempts seed import or disables renewal")
		}
	}
	for _, change := range []func(*Material){
		func(m *Material) { m.Key = []byte("private-key") },
		func(m *Material) { m.Certificate = []byte("stale-seed") },
		func(m *Material) { m.CRL = []byte("broken") },
		func(m *Material) { m.CA = []byte("broken") },
		func(m *Material) { m.ServerName = "" },
		func(m *Material) { m.ServerName = "bad\nname" },
	} {
		bad := m
		change(&bad)
		if bad.Validate(time.Now()) == nil {
			t.Fatal("ambiguous or invalid keyless material accepted")
		}
	}
}
