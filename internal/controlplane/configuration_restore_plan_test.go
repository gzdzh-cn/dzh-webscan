package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"webscan/internal/common"
)

func restorePlanFixture(t *testing.T, id, secret string) Node {
	t.Helper()
	n := nodeFixture(id)
	n.Config = common.JSON(common.Map{"monitor": common.Map{"roots": []any{"/srv/www"}}, "private": common.Map{"opaque": secret}})
	return n
}
func restorePlanRoundtrip(t *testing.T, d configurationDocument) []byte {
	t.Helper()
	v, err := marshalConfigurationDocument(d)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestConfigurationRestorePlanKeepsCredentialIdentityAndNodeVersions(t *testing.T) {
	old := restorePlanFixture(t, "node-a", "backup-node-secret")
	old.Version = 90
	backup := configurationDocumentFixture(t, old)
	now := restorePlanFixture(t, "node-a", "current-node-secret")
	now.Version = 101
	current := configurationDocumentFixture(t, now)
	common.M(current.Settings["email"])["password"] = "current-mail-password"
	common.M(current.Settings["email"])["smtp_host"] = "current-smtp.example.test"
	common.M(current.Settings["email"])["recipients"] = []any{"current@example.test"}
	common.M(current.Settings["feishu"])["webhook_url"] = "https://open.feishu.cn/open-apis/bot/v2/hook/current-hook"
	current.SettingsVersion = 30
	common.M(backup.Settings["retention"])["sqlite_events_days"] = 90
	backup.Settings["future_private"] = map[string]any{"opaque": "backup-private-settings"}
	sourceBefore, currentBefore := restorePlanRoundtrip(t, backup), restorePlanRoundtrip(t, current)
	plan, err := prepareConfigurationRestore(backup, current, configurationRestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Summary.CanPrepare || !plan.Summary.SettingsChanged || plan.Summary.Updated != 0 || plan.Summary.Unchanged != 1 || plan.Summary.CredentialsReplaced != 0 || plan.Summary.CredentialsKept < 4 {
		t.Fatal("wrong restore plan", plan.Summary)
	}
	if !reflect.DeepEqual(plan.Candidate.Settings["email"], current.Settings["email"]) || !reflect.DeepEqual(plan.Candidate.Settings["feishu"], current.Settings["feishu"]) || !reflect.DeepEqual(plan.Candidate.Settings["future_private"], current.Settings["future_private"]) {
		t.Fatal("credential identity was rebound")
	}
	n := plan.Candidate.Nodes[now.ID]
	if n.Version != 101 || plan.Candidate.SettingsVersion != 30 || common.M(plan.Candidate.Profiles[n.Profile].Config["private"])["opaque"] != "current-node-secret" {
		t.Fatal("credential or version restored from an old source")
	}
	if common.I(common.M(plan.Candidate.Settings["retention"])["sqlite_events_days"]) != 90 {
		t.Fatal("nonprivate policy not restored")
	}
	if !bytes.Equal(sourceBefore, restorePlanRoundtrip(t, backup)) || !bytes.Equal(currentBefore, restorePlanRoundtrip(t, current)) {
		t.Fatal("planning mutated input")
	}
	common.M(plan.Candidate.Settings["email"])["password"] = "candidate-only"
	if common.M(current.Settings["email"])["password"] != "current-mail-password" {
		t.Fatal("private map alias retained")
	}
	if _, err := json.Marshal(plan); err != errConfigurationRestorePrivate { // encoding/json wraps MarshalerError.
		if err == nil || !strings.Contains(err.Error(), errConfigurationRestorePrivate.Error()) {
			t.Fatal("private plan serialized", err)
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", plan, plan), "password") {
		t.Fatal("diagnostic exposed plan")
	}
}

func TestConfigurationRestorePlanExplicitCredentialReplacementAndSafeSummary(t *testing.T) {
	backup := configurationDocumentFixture(t, restorePlanFixture(t, "node-a", "backup-node-secret"))
	current := configurationDocumentFixture(t, restorePlanFixture(t, "node-a", "current-node-secret"))
	common.M(current.Settings["email"])["password"] = "current-mail-secret"
	backup.Settings["private-key-name-do-not-expose"] = map[string]any{"opaque": "backup-private-value"}
	n := backup.Nodes["node-a"]
	n.Name = "private-node-name"
	n.Endpoint = "192.0.2.77:19100"
	backup.Nodes["node-a"] = n
	plan, err := prepareConfigurationRestore(backup, current, configurationRestoreOptions{UseBackupCredentials: true})
	if err != nil || !plan.Summary.CanPrepare || plan.Summary.CredentialsReplaced < 2 || plan.Summary.Updated != 1 {
		t.Fatal("explicit replacement failed", err, plan.Summary)
	}
	if common.M(plan.Candidate.Settings["email"])["password"] != "private-mail-value" {
		t.Fatal("backup credential not selected")
	}
	safe, err := json.Marshal(plan.Summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-key-name-do-not-expose", "private-node-name", "192.0.2.77", "private-mail-value", "backup-node-secret", "backup-private-value", "/srv/www", "private@example.test", "private-hook"} {
		if bytes.Contains(safe, []byte(secret)) {
			t.Fatal("summary exposed configuration", secret)
		}
	}
	if !bytes.Contains(safe, []byte(`"other"`)) || !bytes.Contains(safe, []byte(`"node-a"`)) {
		t.Fatal("missing safe difference scope")
	}
}

func TestConfigurationRestorePlanRedactedMissingAndSharedNodeIdentity(t *testing.T) {
	a, b := restorePlanFixture(t, "node-a", "secret-a"), restorePlanFixture(t, "node-b", "secret-b")
	current := configurationDocumentFixture(t, a, b)
	backup := configurationDocumentFixture(t, a, b, restorePlanFixture(t, "new-node", "new-secret"))
	public, err := backup.redacted()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareConfigurationRestore(public, current, configurationRestoreOptions{UseBackupCredentials: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.CanPrepare || plan.Summary.Added != 1 || !reflect.DeepEqual(plan.Summary.MissingNodes, []string{"new-node"}) || plan.Summary.CredentialsMissing != 1 {
		t.Fatal("incomplete new identity accepted", plan.Summary)
	}
	for _, n := range []Node{a, b} {
		got := plan.Candidate.Nodes[n.ID]
		if !reflect.DeepEqual(plan.Candidate.Profiles[got.Profile].Config, current.Profiles[current.Nodes[n.ID].Profile].Config) {
			t.Fatal("credentials borrowed across node identity")
		}
	}
	// Omitted values resolved from current state are kept, not reported replaced.
	if plan.Summary.CredentialsReplaced != 0 || plan.Summary.CredentialsKept == 0 {
		t.Fatal("redacted source falsely claimed credential replacement", plan.Summary)
	}
}

func TestConfigurationRestorePlanRequiresDedicatedArchitectureAndRemoval(t *testing.T) {
	a, b := restorePlanFixture(t, "node-a", "a"), restorePlanFixture(t, "node-b", "b")
	current := configurationDocumentFixture(t, a, b)
	backup := configurationDocumentFixture(t, a)
	n := backup.Nodes[a.ID]
	n.Mode = "docker"
	backup.Nodes[a.ID] = n
	common.M(backup.Bootstrap["collector"])["shards"] = json.Number("128")
	plan, err := prepareConfigurationRestore(backup, current, configurationRestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.CanPrepare || plan.Summary.Removed != 1 || !reflect.DeepEqual(plan.Summary.BlockedReasons, []string{"topology_migration_required", "node_mode_migration_required", "node_uninstall_required"}) {
		t.Fatal("architecture change accepted ordinary restore", plan.Summary)
	}
	if plan.Summary.Added != 0 || len(plan.Summary.Nodes) != 2 || plan.Summary.Nodes[1].Action != "remove" || !plan.Summary.RequiresCenterRestart {
		t.Fatal("removal or restart hidden", plan.Summary)
	}
}

func TestConfigurationRestorePlanNormalizesProvenanceAndRejectsMalformedSources(t *testing.T) {
	n := restorePlanFixture(t, "node-a", "unchanged")
	current := configurationDocumentFixture(t, n)
	backup := configurationDocumentFixture(t, n)
	old := backup.Nodes[n.ID]
	old.Version = 9999
	backup.Nodes[n.ID] = old
	backup.SettingsVersion = 9999
	backup.Created = "2026-01-01T00:00:00Z"
	plan, err := prepareConfigurationRestore(backup, current, configurationRestoreOptions{})
	if err != nil || !plan.Summary.CanPrepare || plan.Summary.Updated != 0 || plan.Summary.SettingsChanged || plan.Summary.BootstrapChanged || plan.Summary.Unchanged != 1 {
		t.Fatal("provenance masqueraded as live config change", err, plan.Summary)
	}
	invalid := backup
	invalid.Format = 2
	if _, err := prepareConfigurationRestore(invalid, current, configurationRestoreOptions{}); err != errConfigurationDocument {
		t.Fatal("malformed archive accepted", err)
	}
	public, err := current.redacted()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareConfigurationRestore(backup, public, configurationRestoreOptions{}); err != errConfigurationDocument {
		t.Fatal("incomplete current state accepted", err)
	}
}

func TestConfigurationRestorePlanProtectsPrivateArraysAndRetainsMissingCredentialsAsIncomplete(t *testing.T) {
	n := restorePlanFixture(t, "node-a", "private-node-value")
	current := configurationDocumentFixture(t, n)
	backup := configurationDocumentFixture(t, n)
	// A member's private key must never be copied onto another identity by index.
	common.M(current.Bootstrap["ha"])["members"] = []any{map[string]any{"id": "current-member", "host": "192.0.2.1", "private_address": "10.0.0.1", "ssh_port": 22, "ssh_key_file": "/private/current-key"}}
	common.M(backup.Bootstrap["ha"])["members"] = []any{map[string]any{"id": "other-member", "host": "192.0.2.2", "private_address": "10.0.0.2", "ssh_port": 22, "ssh_key_file": "/private/backup-key"}}
	plan, err := prepareConfigurationRestore(backup, current, configurationRestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.CanPrepare || !configurationRestoreEqual(common.M(plan.Candidate.Bootstrap["ha"])["members"], common.M(current.Bootstrap["ha"])["members"]) || !reflect.DeepEqual(plan.Summary.BlockedReasons, []string{"topology_migration_required"}) {
		t.Fatal("private array rebound or migration hidden", plan.Summary)
	}
	// Explicitly requesting a complete encrypted archive may use that archive's
	// identity, but does not bypass the dedicated topology migration gate.
	plan, err = prepareConfigurationRestore(backup, current, configurationRestoreOptions{UseBackupCredentials: true})
	if err != nil || plan.Summary.CanPrepare || !configurationRestoreEqual(common.M(plan.Candidate.Bootstrap["ha"])["members"], common.M(backup.Bootstrap["ha"])["members"]) {
		t.Fatal("explicit option bypassed architecture gate", err)
	}
	current = configurationDocumentFixture(t, nodeFixture("node-a"))
	delete(current.Settings, "email")
	delete(current.Settings, "future_private")
	backup = configurationDocumentFixture(t, n)
	plan, err = prepareConfigurationRestore(backup, current, configurationRestoreOptions{})
	if err != nil || plan.Summary.CanPrepare || !plan.Summary.MissingSettings || plan.Summary.CredentialsMissing != 3 || !reflect.DeepEqual(plan.Summary.MissingNodes, []string{"node-a"}) {
		t.Fatal("missing private groups not explicit", err, plan.Summary)
	}
	// The missing group is absent and marked; a mask or stale backup credential
	// cannot be mistaken for a usable current secret.
	if _, present := plan.Candidate.Settings["email"]; present {
		t.Fatal("backup mail identity used without explicit selection")
	}
	if !plan.Summary.RequiresLocalValidation {
		t.Fatal("pure comparison claimed local path readiness")
	}
}

func TestConfigurationRestorePlanKeepsIndependentTrustAndRevocationPaths(t *testing.T) {
	c := configurationBootstrapFixture(t)
	c.DeploymentTrust = DeploymentTrustConfig{VaultKeyFile: "/private/current-vault.key", PublicKeyFile: "/private/current-release.pub", ManifestFile: "/private/current-manifest.json", SignatureFile: "/private/current-manifest.sig", HelperFile: "/private/current-helper", NativeBundleFile: "/private/current-bundle.tar"}
	c.Collector.RevocationFile = "/private/current.crl"
	c.Collector.RevocationStateDirectory = "/private/current-revocation-state"
	current, err := newConfigurationDocument(c, []byte(`{}`), 3, []Node{nodeFixture("node-a")}, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	c.DeploymentTrust.VaultKeyFile = "/backup/old-vault.key"
	c.DeploymentTrust.PublicKeyFile = "/backup/old-release.pub"
	c.Collector.RevocationFile = "/backup/old.crl"
	c.Collector.RevocationStateDirectory = "/backup/old-revocation-state"
	backup, err := newConfigurationDocument(c, []byte(`{}`), 2, []Node{nodeFixture("node-a")}, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareConfigurationRestore(backup, current, configurationRestoreOptions{})
	if err != nil || !plan.Summary.CanPrepare || plan.Summary.BootstrapChanged || !configurationRestoreEqual(plan.Candidate.Bootstrap, current.Bootstrap) {
		t.Fatal("restore rolled back independent trust or revocation references", err, plan.Summary)
	}
	explicit, err := prepareConfigurationRestore(backup, current, configurationRestoreOptions{UseBackupCredentials: true})
	if err != nil || !explicit.Summary.BootstrapChanged || !explicit.Summary.RequiresLocalValidation || !explicit.Summary.RequiresCenterRestart {
		t.Fatal("explicit reference changes hidden", err)
	}
}

func TestConfigurationRestorePlanTenThousandSharedProfiles(t *testing.T) {
	seed := restorePlanFixture(t, "node-seed", strings.Repeat("s", 64<<10))
	current := configurationDocumentFixture(t, seed)
	template := current.Nodes[seed.ID]
	current.Nodes = map[string]configurationDocumentNode{}
	for i := 0; i < 10000; i++ {
		current.Nodes[fmt.Sprintf("node-%05d", i)] = template
	}
	before := time.Now()
	plan, err := prepareConfigurationRestore(current, current, configurationRestoreOptions{})
	if err != nil || plan.Summary.Unchanged != 10000 || len(plan.Candidate.Profiles) != 1 || len(plan.Summary.Nodes) != 0 || plan.Summary.CredentialsKept < 10000 {
		t.Fatal("shared rule/identity planning failed", err, plan.Summary.Unchanged)
	}
	t.Logf("10,000 shared-profile identities planned in %s; document planning only, not a collection capacity test", time.Since(before))
	// Output rule state is detached even when every node shares one profile.
	p := plan.Candidate.Profiles[plan.Candidate.Nodes["node-00000"].Profile]
	common.M(p.Config["private"])["opaque"] = "candidate-only"
	if common.M(current.Profiles[template.Profile].Config["private"])["opaque"] == "candidate-only" {
		t.Fatal("shared profile aliases source")
	}
}

func TestConfigurationRestorePlanRejectsExpandedProfilesBeforeUnboundedAllocation(t *testing.T) {
	seed := nodeFixture("node-seed")
	seed.Config = common.JSON(common.Map{"large_extension": strings.Repeat("r", 256<<10)})
	imported := configurationDocumentFixture(t, seed)
	current := configurationDocumentFixture(t, nodeFixture("node-seed"))
	template := imported.Nodes[seed.ID]
	imported.Nodes = map[string]configurationDocumentNode{}
	current.Nodes = map[string]configurationDocumentNode{}
	current.Profiles = map[string]configurationDocumentRules{}
	for i := 0; i < 140; i++ {
		id := fmt.Sprintf("node-%03d", i)
		profile := fmt.Sprintf("p%d", i+1)
		imported.Nodes[id] = template
		n := template
		n.Profile = profile
		current.Nodes[id] = n
		current.Profiles[profile] = configurationDocumentRules{Config: configurationValues{"private": map[string]any{"opaque": id}}, Omitted: []string{}}
	}
	p := imported.Profiles[template.Profile]
	p.Omitted = []string{"/private"}
	imported.Profiles[template.Profile] = p
	if imported.validate() != nil || current.validate() != nil {
		t.Fatal("invalid expansion fixture")
	}
	if _, _, err := resolveConfigurationOmissions(imported, current); err != errConfigurationDocument {
		t.Fatal("profile expansion exceeded document bound", err)
	}
	if _, err := prepareConfigurationRestore(imported, current, configurationRestoreOptions{UseBackupCredentials: true}); err != errConfigurationDocument {
		t.Fatal("restore accepted oversized expanded configuration", err)
	}
	if len(imported.Profiles) != 1 || len(current.Profiles) != 140 {
		t.Fatal("failure changed inputs")
	}
}
