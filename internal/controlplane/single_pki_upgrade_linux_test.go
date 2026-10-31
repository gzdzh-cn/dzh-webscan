package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"webscan/internal/deploy"
)

// Explicit opt-in, disposable PostgreSQL only. This runs the actual signed
// Linux helper in a subprocess, including its executable/schema checks. It
// does not simulate systemd or claim native/Docker kernel acceptance.
func TestSinglePKIUpgradeSignedHelperLinux(t *testing.T) {
	helper := os.Getenv("WEBSCAN_V3_TEST_MAINTENANCE_HELPER")
	if helper == "" {
		t.Skip("explicit current Linux helper and isolated PostgreSQL required")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Fatal("isolated Linux amd64 root runner required")
	}
	store := testStore(t)
	var schema string
	if err := store.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if err != nil || dsn.Scheme != "postgres" && dsn.Scheme != "postgresql" {
		t.Fatal("invalid isolated test DSN")
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	s, spec, output := singlePKIUpgradeFixture(t)
	// Bind a freshly CREATED isolated fixture to this test schema before
	// preparing its overlay; this is never an upgrade step for a real install.
	localDSN := []byte(dsn.String())
	if err := os.WriteFile(filepath.Join(s.Root, "postgres.dsn"), localDSN, 0600); err != nil {
		t.Fatal(err)
	}
	var install singleInstallManifest
	raw, _ := os.ReadFile(spec.Installation)
	json.Unmarshal(raw, &install)
	install.Files["postgres.dsn"] = digest(localDSN)
	raw, _ = json.Marshal(install)
	os.WriteFile(spec.Installation, raw, 0600)
	var journal singleInstallJournal
	journalRaw, _ := os.ReadFile(filepath.Join(s.Root, "journal.json"))
	json.Unmarshal(journalRaw, &journal)
	journal.Manifest = digest(raw)
	if err := saveSingleJournal(s.Root, journal); err != nil {
		t.Fatal(err)
	}
	f := newTrustToolFixture(t)
	binary, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal("current helper unreadable")
	}
	if err := os.WriteFile(f.helper, binary, 0700); err != nil {
		t.Fatal(err)
	}
	f.sign.Output += "-current"
	f.sign.Release = deploy.Release
	if err := ReleaseCommand(context.Background(), f.sign, io.Discard); err != nil {
		t.Fatal(err)
	}
	spec.PublicKeyFile, spec.ManifestFile, spec.SignatureFile, spec.HelperFile = f.config().PublicKeyFile, filepath.Join(f.sign.Output, "release.json"), filepath.Join(f.sign.Output, "release.sig"), f.helper
	before := map[string][]byte{}
	for _, name := range []string{"install.json", "journal.json", "webscan", "ca.key", "authority/ca.key", "collector-pki/collector.pem"} {
		before[name], err = os.ReadFile(filepath.Join(s.Root, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	publishSinglePKIUpgradeFixture(t, spec, output)
	call := func(action string) []byte {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), filepath.Join(output, "webscan"), "control-v3", "--action", action, "--source", filepath.Join(output, "maintenance.json"))
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("signed helper %s failed: %v %s", action, err, raw)
		}
		return raw
	}
	call("check-single-pki-upgrade")
	var receipt singlePKIReceipt
	if json.Unmarshal(call("maintain-single-pki-upgrade"), &receipt) != nil || receipt.State != "healthy" || receipt.NodeRenewals == nil || receipt.NodeRenewals.State != "healthy" {
		t.Fatalf("current signed helper could not maintain upgraded database: %+v", receipt)
	}
	for name, want := range before {
		got, err := os.ReadFile(filepath.Join(s.Root, name))
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("rewrote immutable installation/keys or unnecessarily rotated collector", name)
		}
	}
	// An older database must defer signing, never migrate from the timer or
	// prevent local trust maintenance during infrastructure startup.
	mustHistoryExec(t, store.DB, `DELETE FROM v3_schema WHERE version=$1`, SchemaVersion)
	if json.Unmarshal(call("maintain-single-pki-upgrade"), &receipt) != nil || receipt.State != "healthy" || receipt.NodeRenewals == nil || receipt.NodeRenewals.State != "deferred" {
		t.Fatal("mismatched schema not reported independently")
	}
	if version, err := currentSchema(context.Background(), store.DB); err != nil || version != SchemaVersion-1 {
		t.Fatal("maintenance migrated database")
	}
	// A valid signature over the same executable with an incorrect version
	// label must not authorize runtime maintenance.
	f.sign.Output += "-mismatched"
	f.sign.Release = "v0.0.0-mismatched"
	if err := ReleaseCommand(context.Background(), f.sign, io.Discard); err != nil {
		t.Fatal(err)
	}
	spec.ManifestFile = filepath.Join(f.sign.Output, "release.json")
	spec.SignatureFile = filepath.Join(f.sign.Output, "release.sig")
	mismatched := output + "-mismatched"
	publishSinglePKIUpgradeFixture(t, spec, mismatched)
	cmd := exec.CommandContext(context.Background(), filepath.Join(mismatched, "webscan"), "control-v3", "--action", "maintain-single-pki-upgrade", "--source", filepath.Join(mismatched, "maintenance.json"))
	if raw, err := cmd.CombinedOutput(); err == nil || bytes.Contains(raw, []byte(`"state":"healthy"`)) {
		t.Fatal("mismatched signed release label authorized maintenance")
	}
	t.Log("actual independently signed Linux helper, original installation/key preservation, PostgreSQL renewal queue and fail-closed schema checks passed")
}
