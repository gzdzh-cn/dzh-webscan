package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"webscan/internal/assets"
	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/deploy"
)

func sslFlowFixture(t *testing.T) string {
	t.Helper()
	old := deploy.StateRoot
	deploy.StateRoot = t.TempDir()
	t.Cleanup(func() { deploy.StateRoot = old })
	b, err := assets.Files.ReadFile("schema.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var raw common.Map
	if err = yaml.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	common.M(raw["feishu"])["enabled"] = false
	raw["registry"] = common.Map{"prefix": "docker.io/gzdzh", "auth_required": false}
	raw["images"] = common.Map{"central": "webscan-central:latest", "agent": "webscan-agent:latest"}
	delete(raw, "ssl") // legacy default must also be offered
	path := filepath.Join(t.TempDir(), "webscan.yaml")
	if err = os.WriteFile(path, append([]byte("# preserve this comment\n"), deploy.YAML(raw)...), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFirstInstallWizardSelectionsAndSharedInput(t *testing.T) {
	path := sslFlowFixture(t)
	before, _ := os.ReadFile(path)
	for _, tc := range []struct{ input, mode string }{
		{"1\n1\n", "on"}, {"1\n2\n", "off"}, {"1\n\n", "on"},
		{"1\ninvalid\n2\n", "off"}, {"1\n0\n5\n2\n", "off"},
	} {
		out := new(bytes.Buffer)
		args, err := selectAction([]string{"--config", path}, strings.NewReader(tc.input), out)
		want := []string{"--config", path, "--set-ssl", tc.mode}
		if err != nil || !reflect.DeepEqual(args, want) {
			t.Fatal(tc.input, args, err)
		}
		if !strings.Contains(out.String(), "当前 YAML 设置：HTTPS") {
			t.Fatal(out.String())
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("selection modified YAML before deployment")
		}
	}
	for _, input := range []string{"1\n", "1\n0\n0\n"} {
		_, err := selectAction([]string{"--config", path}, strings.NewReader(input), new(bytes.Buffer))
		if err == nil {
			t.Fatal("EOF/cancel started installation")
		}
	}
	args, err := selectAction([]string{"--install", "--config=" + path}, strings.NewReader("2\n"), new(bytes.Buffer))
	if err != nil || !reflect.DeepEqual(args, []string{"--config=" + path, "--set-ssl", "off"}) {
		t.Fatal(args, err)
	}
	_, err = selectAction([]string{"--install", "--config", path}, strings.NewReader("0\n"), new(bytes.Buffer))
	if !errors.Is(err, errMenuExit) {
		t.Fatal(err)
	}
	if err = saveSSLChoice(path, false, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	args, err = selectAction([]string{"--config", path}, strings.NewReader("1\n\n"), out)
	if err != nil || args[len(args)-1] != "off" || !strings.Contains(out.String(), "当前 YAML 设置：HTTP") {
		t.Fatal(args, err, out.String())
	}
}

func TestInstalledPendingAndOfflineOperationsSkipWizard(t *testing.T) {
	path := sslFlowFixture(t)
	state := common.Map{"run_id": "go-incomplete", "step": "central"}
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), state)
	out := new(bytes.Buffer)
	got, err := selectAction([]string{"--config", path}, strings.NewReader("1\n"), out)
	if err != nil || got[len(got)-1] != "--install" || !strings.Contains(out.String(), "沿用原任务的 SSL 协议") {
		t.Fatal(got, err, out.String())
	}
	os.Remove(filepath.Join(deploy.StateRoot, "state.json"))
	for _, action := range [][]string{{"--install", "--non-interactive"}, {"--reinstall", "--non-interactive"}, {"--reinstall", "--dry-run"}, {"--reinstall", "--set-ssl", "off"}, {"--install", "--dry-run"}, {"--upgrade", "--dry-run"}, {"--check"}, {"--help"}, {"--config-help"}, {"--resume"}, {"--rollback"}, {"--reload-rules"}, {"--install", "--node=node-28"}} {
		out := new(bytes.Buffer)
		args := append([]string{"--config", path}, action...)
		got, err := selectAction(args, strings.NewReader(""), out)
		if err != nil || !reflect.DeepEqual(args, got) || out.Len() != 0 {
			t.Fatal(action, got, err, out.String())
		}
	}
}

func TestAutomaticSSLDeploymentPreservesBackupAndReleasesLock(t *testing.T) {
	path := sslFlowFixture(t)
	for _, installed := range []bool{false, true} {
		state := common.Map{"central_installed": installed, "step": "complete"}
		if err := common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), state); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(path)
		args, err := prepareSSLDeployment(path, "off", []string{"--config", path, "--set-ssl=off", "--non-interactive"}, new(bytes.Buffer))
		expected := "--install"
		if installed {
			expected = "--upgrade"
		}
		if err != nil || args[len(args)-1] != expected {
			t.Fatal(args, err)
		}
		if err = validateActions(args); err != nil {
			t.Fatal(args, err)
		}
		c, err := configuration.Load(path)
		if err != nil || c.SSLEnabled() {
			t.Fatal(err)
		}
		unlock, err := lockSSLSettings()
		if err != nil {
			t.Fatal("deployment lock wasn't released", err)
		}
		unlock()
		backups, _ := filepath.Glob(filepath.Join(deploy.StateRoot, "config-backups", "*.yaml"))
		matched := false
		for _, backup := range backups {
			b, _ := os.ReadFile(backup)
			st, _ := os.Stat(backup)
			if st.Mode().Perm() != 0600 {
				t.Fatal("insecure backup")
			}
			matched = matched || bytes.Equal(b, before)
		}
		if !matched {
			t.Fatal("original YAML backup missing")
		}
	}
	before, _ := os.ReadFile(path)
	unlock, err := lockSSLSettings()
	if err != nil {
		t.Fatal(err)
	}
	_, err = prepareSSLDeployment(path, "on", []string{"--set-ssl", "on"}, new(bytes.Buffer))
	unlock()
	if err == nil {
		t.Fatal("active deployment lock bypassed")
	}
	for _, state := range []common.Map{{"run_id": "go-test", "step": "node"}, {"central_uninstall_pending": true}, {"single_uninstall": common.Map{"node": "node-28", "complete": false}}} {
		common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), state)
		if _, err = prepareSSLDeployment(path, "on", []string{"--set-ssl", "on"}, new(bytes.Buffer)); err == nil {
			t.Fatal("pending operation bypassed", state)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("blocked operation modified YAML")
		}
	}
}

func TestMenuInstallResumesWithOriginalToolAfterScriptUpdate(t *testing.T) {
	sslFlowFixture(t)
	state := common.Map{"run_id": "go-interrupted", "step": "central-go-ready", "target_release": "v2.0.23", "target_tool_image": "docker.io/gzdzh/webscan-central@sha256:" + strings.Repeat("a", 64)}
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), state)
	if got := bootstrapImageForOperation("docker.io/gzdzh/webscan-central:latest", []string{"--install"}); got != state["target_tool_image"] {
		t.Fatal("new latest replaced unfinished run tool", got)
	}
	state["step"] = "complete"
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), state)
	if got := bootstrapImageForOperation("docker.io/gzdzh/webscan-central:latest", []string{"--install"}); got != "docker.io/gzdzh/webscan-central:latest" {
		t.Fatal("completed run pinned normal upgrade", got)
	}
}

func TestInstalledInstallationAndReinstallationAlwaysOfferSSL(t *testing.T) {
	path := sslFlowFixture(t)
	for _, state := range []common.Map{{"central_installed": true, "go_release": "v2.0.24", "step": "complete"}, {"go_release": "v2.0.24", "central_uninstalled": true, "step": "central-uninstalled"}} {
		common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), state)
		for _, tc := range []struct{ selection, mode string }{{"1", "on"}, {"1", "off"}, {"2", "on"}, {"2", "off"}, {"2", ""}} {
			input := tc.selection + "\n1\n"
			if tc.mode == "off" {
				input = tc.selection + "\n2\n"
			}
			if tc.mode == "" {
				input = tc.selection + "\n\n"
			}
			before, _ := os.ReadFile(path)
			out := new(bytes.Buffer)
			args, err := selectAction([]string{"--config", path}, strings.NewReader(input), out)
			if err != nil || !strings.Contains(out.String(), "请选择 SSL 模式") {
				t.Fatal(args, err, out.String())
			}
			if err = validateActions(args); err != nil {
				t.Fatal(args, err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("prompt wrote config")
			}
			mode := "on"
			if tc.mode == "off" {
				mode = "off"
			}
			args, err = prepareSSLDeployment(path, mode, args, new(bytes.Buffer))
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parseBootstrapArgs(args)
			if err != nil {
				t.Fatal(err)
			}
			if tc.selection == "2" && (parsed["--reinstall"] != "true" || parsed["--upgrade"] != "" || parsed["--install"] != "") {
				t.Fatal("reinstall changed into upgrade", args)
			}
			if tc.selection == "1" && parsed["--upgrade"] != "true" {
				t.Fatal("existing install failed to upgrade", args)
			}
		}
		before, _ := os.ReadFile(path)
		_, err := selectAction([]string{"--config", path}, strings.NewReader("2\n0\n0\n"), new(bytes.Buffer))
		if !errors.Is(err, errMenuExit) {
			t.Fatal(err)
		}
		_, err = selectAction([]string{"--config", path}, strings.NewReader("2\n"), new(bytes.Buffer))
		if err == nil {
			t.Fatal("EOF installed")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("cancel modified YAML")
		}
	}
	common.AtomicJSON(filepath.Join(deploy.StateRoot, "state.json"), common.Map{"run_id": "go-pending", "step": "central"})
	before, _ := os.ReadFile(path)
	if _, err := selectAction([]string{"--config", path}, strings.NewReader("2\n2\n"), new(bytes.Buffer)); err == nil {
		t.Fatal("reinstallation changed unfinished config")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("unfinished config changed")
	}
}
