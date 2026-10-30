package nodeops

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/nodeconfig"
)

func serviceFixture(t *testing.T, mode string) (*LocalRuntime, Request, nodeconfig.Material) {
	t.Helper()
	files := bundleFiles()
	bundleChecksums(files)
	w, r := stageFixture(t, archiveFiles(t, files, nil))
	r.Spec.Mode = mode
	r.Spec.MonitorDirectories = []string{"/www/site one/$HOME/100%"}
	if mode == "docker" {
		r.Spec.AgentImage, _ = imageFixture()
	}
	m := attachConfiguration(t, w, &r, func(m *nodeconfig.Material) {
		m.Settings.Resources = nodeconfig.Resources{MemoryMiB: 512, GoMemoryMiB: 256, CPUs: 1.25, GoMaxProcs: 3, FileDescriptors: 32768}
		m.Settings.Monitor.CriticalPaths = []string{"/srv/security/.user.ini"}
	})
	return w, r, m
}

func TestNativeServiceUsesBoundConfigAndExactLimitsWithoutShell(t *testing.T) {
	w, r, m := serviceFixture(t, "native")
	name, raw, err := w.serviceDefinition(m, r.Spec)
	if err != nil || name != nativeServiceName {
		t.Fatal(name, err)
	}
	s := string(raw)
	for _, required := range []string{
		"ExecStart=" + unitPath(filepath.Join(w.releaseDir(r.Spec), "webscan"), true) + " agent --config " + unitPath(filepath.Join(w.configurationDir(r.Spec), "runtime.json"), true),
		"MemoryMax=512M\n", "CPUQuota=125%\n", "LimitNOFILE=32768\n", "Environment=GOMEMLIMIT=256MiB\n", "Environment=GOMAXPROCS=3\n",
		"NoNewPrivileges=yes\n", "ProtectSystem=strict\n", "KillMode=control-group\n", `"/www/site one/$HOME/100%%/.webscan-probe"`,
	} {
		if !strings.Contains(s, required) {
			t.Fatalf("missing enforced service property %q", required)
		}
	}
	for _, forbidden := range []string{"/bin/sh", "ExecStartPre=", "PrivateTmp=", "identity.key", "PRIVATE KEY", "/run/clamav"} {
		if strings.Contains(s, forbidden) {
			t.Fatal("unexpected service content", forbidden)
		}
	}
	if got := unitPath(`/opt/$CREDENTIALS_DIRECTORY/100%/"quoted"`, true); got != `"/opt/$$CREDENTIALS_DIRECTORY/100%%/\"quoted\""` {
		t.Fatal("unsafe systemd expansions", got)
	}
	m.Settings.Scan.ClamAV.Enabled = true
	r.Spec.ClamAV = true
	_, raw, err = w.serviceDefinition(m, r.Spec)
	if err != nil || !strings.Contains(string(raw), `"/run/clamav"`) {
		t.Fatal("clamd socket is not accessible", err)
	}
}

func TestDockerServiceHostMountsAreReadOnlyAndResourcesAreBound(t *testing.T) {
	w, r, m := serviceFixture(t, "docker")
	name, raw, err := w.serviceDefinition(m, r.Spec)
	if err != nil || name != "compose.json" {
		t.Fatal(name, err)
	}
	assertDockerDefinition(t, raw, m, r.Spec, w, true)
	// A signed offline archive may be loaded without any RepoDigests. Compose
	// must use that verified local config ID, not attempt a registry download.
	r.Spec.ImageArchiveSHA256, r.Spec.ImageArchiveBytes, r.Spec.ImageConfigSHA256 = strings.Repeat("d", 64), 1024, strings.Repeat("e", 64)
	_, raw, err = w.serviceDefinition(m, r.Spec)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	s := doc["services"].(map[string]any)["agent"].(map[string]any)
	if s["image"] != "sha256:"+r.Spec.ImageConfigSHA256 || s["pull_policy"] != "never" {
		t.Fatal("offline image proof was discarded")
	}
}

func assertDockerDefinition(t *testing.T, raw []byte, m nodeconfig.Material, spec Spec, w *LocalRuntime, escaped bool) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	s := doc["services"].(map[string]any)["agent"].(map[string]any)
	cpu := s["cpus"]
	if text, ok := cpu.(string); ok {
		value, err := strconv.ParseFloat(text, 64)
		if err != nil {
			t.Fatal("invalid parsed CPU quota", err)
		}
		cpu = value // Compose may serialize its decimal quota type as a string.
	}
	memory := s["mem_limit"]
	if text, ok := memory.(string); ok {
		value, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			t.Fatal("invalid parsed memory limit", err)
		}
		memory = float64(value)
	}
	if s["network_mode"] != "host" || s["read_only"] != true || memory != float64(512<<20) || cpu != 1.25 || s["pull_policy"] != "never" || s["privileged"] == true {
		t.Fatalf("wrong network/isolation/resource policy: network=%#v ro=%#v memory=%#v cpu=%#v pull=%#v privileged=%#v", s["network_mode"], s["read_only"], s["mem_limit"], cpu, s["pull_policy"], s["privileged"])
	}
	limit := s["ulimits"].(map[string]any)["nofile"].(map[string]any)
	if limit["soft"] != float64(32768) || limit["hard"] != float64(32768) {
		t.Fatal("file descriptor limits not enforced")
	}
	entry := s["entrypoint"].([]any)
	if len(entry) != 1 || entry[0] != filepath.Join(w.releaseDir(spec), "webscan") {
		t.Fatal("unbound entrypoint", entry)
	}
	command := s["command"].([]any)
	if !reflect.DeepEqual(command, []any{"agent", "--config", filepath.Join(w.configurationDir(spec), "runtime.json")}) {
		t.Fatal("configuration not bound", command)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) || bytes.Contains(raw, m.Key) {
		t.Fatal("private key leaked into service definition")
	}
	byTarget := map[string]map[string]any{}
	for _, item := range s["volumes"].([]any) {
		v := item.(map[string]any)
		target := v["target"].(string)
		if escaped {
			target = strings.ReplaceAll(target, "$$", "$")
		}
		if byTarget[target] != nil || v["type"] != "bind" {
			t.Fatal("duplicate or unexpected mount", target)
		}
		byTarget[target] = v
		if v["bind"].(map[string]any)["create_host_path"] != false {
			t.Fatal("missing source would silently create an empty directory")
		}
	}
	for _, target := range []string{"/host/proc", "/host/sys", "/rootfs", w.configurationDir(spec), w.releaseDir(spec), m.Settings.Monitor.Roots[0], "/srv/security"} {
		v := byTarget[target]
		if v == nil || v["read_only"] != true {
			t.Fatal("host/config/rules mount is not read only", target)
		}
	}
	if byTarget["/host/proc"]["source"] != "/proc" || byTarget["/host/sys"]["source"] != "/sys" || byTarget["/rootfs"]["source"] != "/" {
		t.Fatal("not reading actual host filesystems")
	}
	for _, target := range []string{agentDataDirectory, agentLogDirectory, m.Settings.ProbeDirectory} {
		v := byTarget[target]
		if v == nil || v["read_only"] != nil && v["read_only"] != false {
			t.Fatal("persistent data or controlled probe is not writable", target)
		}
	}
	for target, v := range byTarget {
		if v["read_only"] != true && target != agentDataDirectory && target != agentLogDirectory && target != m.Settings.ProbeDirectory && !(target == "/run/clamav" && m.Settings.Scan.ClamAV.Enabled) {
			t.Fatal("unexpected writable host path", target)
		}
	}
}

func TestDockerServiceRefusesMountCollisionsAndUnpinnedImages(t *testing.T) {
	w, r, m := serviceFixture(t, "docker")
	for _, root := range []string{"/", "/var", "/var/lib/webscan-v1", "/proc", "/rootfs", "/tmp/site", w.configurationDir(r.Spec)} {
		bad := m
		bad.Settings.Monitor.Roots = []string{root}
		bad.Settings.ProbeDirectory = filepath.Join(root, ".webscan-probe")
		if _, _, err := w.serviceDefinition(bad, r.Spec); err == nil {
			t.Fatal("mount could hide runtime/data/host sources", root)
		}
	}
	bad := m
	bad.Settings.Monitor.CriticalPaths = []string{"/var/lib/webscan-v1/agent.sqlite3"}
	if _, _, err := w.serviceDefinition(bad, r.Spec); err == nil {
		t.Fatal("critical path mount could shadow data")
	}
	r.Spec.AgentImage = "gzdzh/webscan-agent:latest"
	if _, _, err := w.serviceDefinition(m, r.Spec); err == nil {
		t.Fatal("mutable tag accepted")
	}
	paths, err := dockerMonitorMounts(nodeconfig.Monitor{Roots: []string{"/www/site", "/www", "/www", "/www2"}, CriticalPaths: []string{"/www/site/a.php", "/srv/security/.user.ini"}}, []string{agentDataDirectory})
	if err != nil || !reflect.DeepEqual(paths, []string{"/www", "/www2", "/srv/security"}) {
		t.Fatal("mount minimization changed distinct paths", paths, err)
	}
}

func TestPreparedServiceDefinitionCannotChangeAfterStage(t *testing.T) {
	w, r, _ := serviceFixture(t, "native")
	if _, err := w.Apply(r); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(w.configurationDir(r.Spec), nativeServiceName)
	if err := os.WriteFile(file, []byte("[Service]\nExecStart=/bin/false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := w.VerifyCompleted(r, Outcome{}); err == nil {
		t.Fatal("changed startup definition accepted by existing receipt")
	}
	if _, err := w.Apply(r); err == nil {
		t.Fatal("changed startup definition silently repaired")
	}
}

func TestComposeParserPreservesLiteralPathsAndResourcePolicy(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_SERVICE_DEFINITIONS") != "1" {
		t.Skip("requires explicit local read-only Compose validator")
	}
	w, r, m := serviceFixture(t, "docker")
	_, raw, err := w.serviceDefinition(m, r.Spec)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(testRoot(t), "compose.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "compose", "-f", file, "config", "--format", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real Compose parser rejected generated definition: %v: %s", err, output)
	}
	// Compose re-escapes literal dollars when serializing a reusable config.
	assertDockerDefinition(t, output, m, r.Spec, w, true)
	var doc map[string]any
	json.Unmarshal(output, &doc)
	s := doc["services"].(map[string]any)["agent"].(map[string]any)
	for _, item := range s["volumes"].([]any) {
		v := item.(map[string]any)
		if strings.Contains(v["target"].(string), "$HOME") && !strings.Contains(v["source"].(string), "$HOME") {
			t.Fatal("Compose expanded a local environment variable into a mount source")
		}
	}
}

func TestComposeLiteralPathsReachContainerWithoutExpansion(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_SERVICE_DEFINITIONS") != "1" {
		t.Skip("requires explicitly opted-in disposable local container creation")
	}
	dir := testRoot(t)
	source := filepath.Join(dir, "literal-$HOME-100%")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	project := "webscan-v3-path-" + sha([]byte(dir))[:16]
	name := project + "-proof"
	image := os.Getenv("WEBSCAN_V3_AGENT_TEST_IMAGE")
	if image == "" {
		image = "gzdzh/webscan-agent:v2.0.46"
	}
	// Create one stopped, unprivileged test container. No Agent is started and
	// no host system/data directories, ports or Docker socket are mounted.
	doc := map[string]any{"name": project, "services": map[string]any{"proof": map[string]any{
		"image": image, "platform": "linux/amd64", "pull_policy": "never", "container_name": name,
		"network_mode": "none", "read_only": true, "cap_drop": []string{"ALL"},
		"volumes": []serviceMount{{"bind", composeLiteral(source), "/literal-$$HOME-100%", true, bindOptions{CreateHostPath: false}}},
	}}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "compose.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if output, err := exec.Command("docker", "compose", "-p", project, "-f", file, "down", "--volumes").CombinedOutput(); err != nil {
			t.Errorf("test container cleanup failed: %v: %s", err, output)
		}
	})
	if output, err := exec.Command("docker", "compose", "-p", project, "-f", file, "create").CombinedOutput(); err != nil {
		t.Fatalf("isolated container creation failed: %v: %s", err, output)
	}
	output, err := exec.Command("docker", "inspect", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	var containers []struct {
		State  struct{ Status string }
		Mounts []struct {
			Source, Destination string
			RW                  bool
		}
	}
	if json.Unmarshal(output, &containers) != nil || len(containers) != 1 || containers[0].State.Status != "created" || len(containers[0].Mounts) != 1 {
		t.Fatal("unexpected isolated container state")
	}
	mount := containers[0].Mounts[0]
	if mount.Source != source || mount.Destination != "/literal-$HOME-100%" || mount.RW {
		t.Fatal("actual engine received expanded path or writable mount", mount)
	}
}
