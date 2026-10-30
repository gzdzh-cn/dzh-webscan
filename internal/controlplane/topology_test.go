package controlplane

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTopologyDefaultsAndUpgradePreservation(t *testing.T) {
	for _, test := range []struct {
		saved, requested      string
		fresh, nonInteractive bool
		input, want           string
		fail                  bool
	}{
		{fresh: true, input: "\n", want: "single"}, {fresh: true, input: "2\n", want: "ha"}, {fresh: true, nonInteractive: true, want: "single"}, {saved: "ha", want: "ha"}, {saved: "single", requested: "ha", fail: true}, {requested: "bad", fresh: true, fail: true}, {fresh: true, input: "", fail: true},
	} {
		var out bytes.Buffer
		got, e := SelectTopology(test.saved, test.requested, test.fresh, test.nonInteractive, strings.NewReader(test.input), &out)
		if (e != nil) != test.fail || got != test.want {
			t.Fatalf("%+v: %s %v", test, got, e)
		}
	}
}
func TestConfigureDoesNotOverwriteOrChangeTopology(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.yaml")
	var out bytes.Buffer
	o := Options{Config: path, Action: "configure", NonInteractive: true, PublicURL: "https://monitor.example.test"}
	if e := Command(context.Background(), o, strings.NewReader(""), &out); e != nil {
		t.Fatal(e)
	}
	c, e := LoadConfig(path)
	if e != nil || c.Central.Topology != "single" {
		t.Fatal(c, e)
	}
	before, _ := os.ReadFile(path)
	o.Topology = "ha"
	if e = Command(context.Background(), o, strings.NewReader(""), &out); e == nil {
		t.Fatal("implicit topology migration")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing config overwritten")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
}
func TestSecretSymlinkAndPermissionsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	os.WriteFile(path, []byte("private-value"), 0644)
	if _, e := ReadSecret(path); e == nil {
		t.Fatal("public secret accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadSecret(link); e == nil {
		t.Fatal("symlink accepted")
	}
	if v, e := ReadSecret(path); e != nil || v != "private-value" {
		t.Fatal("valid secret rejected", e)
	}
}

func TestPersistentCollectorRevocationConfigRequiresSourceAndCanonicalState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.yaml")
	var output bytes.Buffer
	if err := Command(context.Background(), Options{Config: path, Action: "configure", NonInteractive: true, PublicURL: "https://monitor.example.test"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	base, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"relative/state", "/state/../state", "/var/lib/webscan-v3/collector-trust"} {
		c := base
		c.Collector.RevocationStateDirectory = value
		if c.Validate() == nil {
			t.Fatal("state enabled without a revocation source")
		}
		c.Collector.RevocationFile = "/etc/webscan-v3/pki/ca.crl"
		if err := c.Validate(); (value == "/var/lib/webscan-v3/collector-trust") != (err == nil) {
			t.Fatal("unexpected path validation", value, err)
		}
	}
}
