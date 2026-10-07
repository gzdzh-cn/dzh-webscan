package deploy

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/assets"
	"webscan/internal/common"
)

func fixture(t *testing.T) *Config {
	t.Helper()
	b, _ := assets.Files.ReadFile("schema.yaml")
	var raw common.Map
	if e := yaml.Unmarshal(b, &raw); e != nil {
		t.Fatal(e)
	}
	raw["config_version"] = 2
	raw["registry"] = common.Map{"prefix": "registry.example:5000/team", "auth_required": false, "username": "", "password": ""}
	raw["images"] = common.Map{"central": "webscan-central:v2.0.0", "agent": "webscan-agent:v2.0.0"}
	common.M(raw["feishu"])["enabled"] = false
	common.M(raw["central"])["public_url"] = "https://192.0.2.1:19443"
	for _, v := range common.A(raw["nodes"]) {
		n := common.M(v)
		common.M(n["ssh"])["host_key_sha256"] = "SHA256:fixture"
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(p, YAML(raw), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestConfigRegistryAndRedaction(t *testing.T) {
	c := fixture(t)
	if c.Image("central") != "registry.example:5000/team/webscan-central:v2.0.0" {
		t.Fatal(c.Image("central"))
	}
	reg := common.M(c.Raw["registry"])
	reg["auth_required"] = true
	reg["password"] = "private-secret"
	reg["username"] = ""
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, e := Load(c.Path); e == nil {
		t.Fatal("missing private username accepted")
	}
	reg["username"] = "publisher"
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, e := Load(c.Path); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(common.JSON(Redact(c.Raw))), "private-secret") {
		t.Fatal("credential leak")
	}
	common.M(c.Raw["images"])["agent"] = "webscan-agent:latest"
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, e := Load(c.Path); e == nil {
		t.Fatal("latest accepted")
	}
}

func TestConfigHostFingerprintOptionalAndLegacyCompatible(t *testing.T) {
	c := fixture(t)
	for _, value := range common.A(c.Raw["nodes"]) {
		delete(common.M(common.M(value)["ssh"]), "host_key_sha256")
	}
	delete(common.M(common.M(c.Raw["node_defaults"])["ssh"]), "host_key_sha256")
	if err := os.WriteFile(c.Path, YAML(c.Raw), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(c.Path)
	if err != nil {
		t.Fatal("omitted fingerprint rejected", err)
	}
	for _, node := range loaded.Nodes {
		if common.S(common.M(node["ssh"])["host_key_sha256"]) != "" {
			t.Fatal("schema injected a hard-coded node fingerprint")
		}
	}
	first := common.M(common.A(c.Raw["nodes"])[0])
	common.M(first["ssh"])["host_key_sha256"] = ""
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, err := Load(c.Path); err != nil {
		t.Fatal("empty fingerprint rejected", err)
	}
	common.M(first["ssh"])["host_key_sha256"] = "SHA256:legacy-value"
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, err := Load(c.Path); err != nil {
		t.Fatal("legacy fingerprint rejected", err)
	}
	common.M(first["ssh"])["host_key_sha256"] = "invalid"
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, err := Load(c.Path); err == nil {
		t.Fatal("invalid explicit fingerprint accepted")
	}
}

func TestTwoImagesAndLegacyDeployerFieldCompatibility(t *testing.T) {
	c := fixture(t)
	if len(common.M(c.Raw["images"])) != 2 {
		t.Fatal("two-image YAML required an extra image")
	}
	common.M(c.Raw["images"])["deployer"] = "unused-legacy-reference"
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	loaded, err := Load(c.Path)
	if err != nil {
		t.Fatal("legacy field prevented package upgrade", err)
	}
	if len(common.M(loaded.Raw["images"])) != 2 {
		t.Fatal("obsolete image retained in effective configuration")
	}
	delete(common.M(c.Raw["images"]), "central")
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, err := Load(c.Path); err == nil {
		t.Fatal("missing central image accepted")
	}
}

func TestVersionTagWithImmutableDigestConfiguration(t *testing.T) {
	c := fixture(t)
	digest := strings.Repeat("a", 64)
	common.M(c.Raw["images"])["central"] = "webscan-central:v2.0.11@sha256:" + digest
	if err := os.WriteFile(c.Path, YAML(c.Raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(c.Path); err != nil {
		t.Fatal("visible version plus locked digest rejected", err)
	}
	common.M(c.Raw["images"])["central"] = "webscan-central:latest@sha256:" + digest
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, err := Load(c.Path); err == nil {
		t.Fatal("latest accepted with digest")
	}
}

func TestLegacyDeployerLockIsExcludedWithoutDeletingRollbackHistory(t *testing.T) {
	d := additionFixture(t)
	common.M(d.State["image_lock"])["deployer"] = "old/deployer@sha256:rollback-history"
	if err := d.save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := New(d.C, d.O)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if _, ok := loaded.Images["deployer"]; ok {
		t.Fatal("obsolete image remained in active locks")
	}
	if common.S(common.M(loaded.State["image_lock"])["deployer"]) == "" {
		t.Fatal("rollback history deleted on load")
	}
	if err = loaded.initialize(); err != nil {
		t.Fatal(err)
	}
	if common.S(common.M(loaded.State["previous_image_lock"])["deployer"]) == "" {
		t.Fatal("old run cannot restore its original image locks")
	}
}
func TestRepositoryParsing(t *testing.T) {
	for _, pair := range [][2]string{{"registry.example:5000/ns/image:v1", "registry.example:5000/ns/image"}, {"team/image@sha256:abc", "team/image"}, {"debian:12.13-slim", "debian"}} {
		if got := imageRepository(pair[0]); got != pair[1] {
			t.Fatalf("%s: %s", pair[0], got)
		}
	}
}
func TestJournalRestore(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "existing")
	b := filepath.Join(dir, "new")
	os.WriteFile(a, []byte("old"), 0640)
	j, e := NewJournal(filepath.Join(dir, "journal"))
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Write(a, []byte("new"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = j.Write(a, []byte("newer"), 0600); e != nil {
		t.Fatal(e)
	}
	j.Write(b, []byte("new"), 0600)
	j, e = NewJournal(j.Dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Rollback(); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(a)
	st, _ := os.Stat(a)
	if string(raw) != "old" || st.Mode().Perm() != 0640 {
		t.Fatal("old content or mode lost")
	}
	if _, e = os.Stat(b); !os.IsNotExist(e) {
		t.Fatal("new file retained")
	}
}
func TestLiteralFeishuEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), "env")
	os.WriteFile(p, []byte("export FEISHU_WEBHOOK_URL='https://open.feishu.cn/open-apis/bot/v2/hook/fixture'\nFEISHU_SECRET='$(touch /tmp/must-not-execute)'\n"), 0600)
	f, e := resolvedFeishu(common.Map{"enabled": true, "mode": "existing", "existing_env_file": p, "signing_enabled": true})
	if e != nil {
		t.Fatal(e)
	}
	if common.S(f["signing_secret"]) != "$(touch /tmp/must-not-execute)" {
		t.Fatal("literal changed")
	}
}
func TestDirectoryMountAndGrafanaPort(t *testing.T) {
	c := fixture(t)
	s := common.M(common.M(ComposeAgent(c, c.Nodes[0], "sha256:fixture")["services"])["agent"])
	if !common.Contains(common.SS(s["volumes"]), "/etc/webscan-v1:/etc/webscan-v1:ro") {
		t.Fatal("atomic replacement invisible")
	}
	if !common.Contains(common.SS(s["cap_add"]), "DAC_READ_SEARCH") {
		t.Fatal("private www files cannot be read")
	}
	if strings.Contains(string(common.JSON(s)), "private-secret") {
		t.Fatal("registry secret in runtime")
	}
	common.M(common.M(c.Raw["central"])["grafana"])["host_port"] = 3300
	if GrafanaURL(c) != "http://192.0.2.1:3300" {
		t.Fatal(GrafanaURL(c))
	}
}

func TestMirrorConfigurationAndCandidates(t *testing.T) {
	c := fixture(t)
	reg := common.M(c.Raw["registry"])
	reg["mirrors"] = []string{"https://mirror.example/", "https://backup.example:5000"}
	os.WriteFile(c.Path, YAML(c.Raw), 0600)
	if _, e := Load(c.Path); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		image string
		want  []string
	}{
		{"debian:12.13-slim", []string{"mirror.example/library/debian:12.13-slim", "backup.example:5000/library/debian:12.13-slim", "docker.io/library/debian:12.13-slim"}},
		{"docker.io/prom/prometheus@sha256:abc", []string{"mirror.example/prom/prometheus@sha256:abc", "backup.example:5000/prom/prometheus@sha256:abc", "docker.io/prom/prometheus@sha256:abc"}},
		{"registry.example:5000/team/webscan-agent:v2", []string{"registry.example:5000/team/webscan-agent:v2"}},
		{"ghcr.io/team/image:v1", []string{"ghcr.io/team/image:v1"}},
		{"mirror.example/library/debian@sha256:abc", []string{"mirror.example/library/debian@sha256:abc", "backup.example:5000/library/debian@sha256:abc", "docker.io/library/debian@sha256:abc"}},
	}
	for _, tt := range cases {
		got := pullCandidates(c, tt.image)
		if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
			t.Fatalf("%s: %v", tt.image, got)
		}
	}
	for _, mirror := range []string{"http://unsafe.example", "https://user:password@mirror.example", "https://mirror.example/path", "https://mirror.example/?token=secret", "not-a-url"} {
		reg["mirrors"] = []string{mirror}
		os.WriteFile(c.Path, YAML(c.Raw), 0600)
		if _, e := Load(c.Path); e == nil {
			t.Fatalf("accepted invalid mirror: %s", mirror)
		}
	}
}
func TestRemotePullCredentialScoping(t *testing.T) {
	c := fixture(t)
	reg := common.M(c.Raw["registry"])
	reg["auth_required"] = true
	reg["username"] = "publisher"
	reg["password"] = "private-secret"
	cmd, in := remotePullCommand(c, "mirror.example/library/debian@sha256:abc")
	if in != nil || strings.Contains(cmd, " login ") || strings.Contains(cmd, "private-secret") {
		t.Fatal("private credentials used for mirror")
	}
	cmd, in = remotePullCommand(c, c.Image("agent"))
	if in == nil || !strings.Contains(cmd, "--password-stdin") || strings.Contains(cmd, "private-secret") {
		t.Fatal("private login unsafe")
	}
	reg["auth_required"] = false
	cmd, in = remotePullCommand(c, c.Image("agent"))
	if in != nil || strings.Contains(cmd, " login ") || !strings.Contains(cmd, "mktemp -d") {
		t.Fatal("anonymous pull reused authentication")
	}
}

func TestInterruptedMigrationRetainsBackupRunAndTarget(t *testing.T) {
	oldRoot, oldRelease := StateRoot, Release
	StateRoot = t.TempDir()
	Release = "v2.0.0-test"
	defer func() { StateRoot, Release = oldRoot, oldRelease }()
	c := fixture(t)
	d, e := New(c, Options{Upgrade: true})
	if e != nil {
		t.Fatal(e)
	}
	d.State["central_installed"] = true
	if e = d.initialize(); e != nil {
		t.Fatal(e)
	}
	run := d.RunID
	resumed, e := New(c, Options{Resume: true})
	if e != nil {
		t.Fatal(e)
	}
	if e = resumed.initialize(); e != nil {
		t.Fatal(e)
	}
	if resumed.RunID != run || resumed.Journal.Dir != d.Journal.Dir {
		t.Fatal("resume created new backup run")
	}
	repeated, e := New(c, Options{Upgrade: true})
	if e != nil {
		t.Fatal(e)
	}
	if e = repeated.initialize(); e == nil {
		t.Fatal("unfinished migration accepted without resume")
	}
	Release = "v2.0.1-test"
	if e = resumed.initialize(); e == nil {
		t.Fatal("resume accepted changed target release")
	}
}

func TestRollbackDoesNotTouchNodesFromPreviousRun(t *testing.T) {
	c := fixture(t)
	d := &Deploy{C: c, State: common.Map{"run_id": "current", "nodes": common.Map{"node-202": common.Map{"go_run_id": "previous"}, "node-28": common.Map{"go_run_id": "current"}}}}
	nodes := d.rollbackNodes()
	if len(nodes) != 1 || common.S(nodes[0]["id"]) != "node-28" {
		t.Fatal("untouched node included in current rollback")
	}
	d.O.Node = "node-202"
	nodes = d.rollbackNodes()
	if len(nodes) != 1 || common.S(nodes[0]["id"]) != "node-202" {
		t.Fatal("explicit node rollback was lost")
	}
	d.O.CentralOnly = true
	if len(d.rollbackNodes()) != 0 {
		t.Fatal("central-only rollback includes nodes")
	}
}

func TestAgentResourceLimitsRenderAndValidate(t *testing.T) {
	c := fixture(t)
	s := common.M(common.M(ComposeAgent(c, c.Nodes[0], "sha256:fixture")["services"])["agent"])
	if common.S(s["mem_limit"]) != "256m" || common.S(common.M(s["environment"])["GOMEMLIMIT"]) != "64MiB" {
		t.Fatal("resource settings not applied")
	}
	r := common.M(common.M(c.Raw["node_defaults"])["resources"])
	r["go_memory_mib"] = 256
	p := filepath.Join(t.TempDir(), "invalid.yaml")
	os.WriteFile(p, YAML(c.Raw), 0600)
	if _, e := Load(p); e == nil {
		t.Fatal("Go memory target leaves no room for scanners")
	}
}
