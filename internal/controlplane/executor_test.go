package controlplane

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestExecutorConfigurationIsExplicitAndRolesFailBeforeDatabase(t *testing.T) {
	ctx := context.Background()
	if err := Serve(ctx, Config{}, "executor"); err == nil || !strings.Contains(err.Error(), "显式") {
		t.Fatal("disabled executor was started", err)
	}
	if err := Serve(ctx, Config{}, "unknown"); err == nil {
		t.Fatal("invalid role accepted")
	}
	for _, role := range []string{"api", "all", "collector", "notifier", "websites", "executor"} {
		if !validServiceRole(role) {
			t.Fatal(role)
		}
	}
	if err := (ExecutorConfig{}).validate(DeploymentTrustConfig{}); err != nil {
		t.Fatal(err)
	}
	f := newTrustToolFixture(t)
	trust := f.config()
	for _, c := range []ExecutorConfig{{Enabled: true}, {Enabled: true, ConfigurationDirectory: "relative"}, {Enabled: true, ConfigurationDirectory: f.root + "/../invalid"}, {Enabled: true, ConfigurationDirectory: f.root, Concurrency: 33}, {Enabled: true, ConfigurationDirectory: f.root, Concurrency: -1}} {
		if err := c.validate(trust); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	c := ExecutorConfig{Enabled: true, ConfigurationDirectory: f.root, Concurrency: 4}
	if err := c.validate(trust); err != nil {
		t.Fatal(err)
	}
	if err := c.validate(DeploymentTrustConfig{}); err == nil {
		t.Fatal("executor without trust enabled")
	}
	c.Enabled = false
	if err := c.validate(DeploymentTrustConfig{}); err != nil {
		t.Fatal("disabling executor lost preferences", err)
	}
}

func TestSSHRuntimeConfigurationIsPerJobAndCannotFollowLinks(t *testing.T) {
	root := privateTestDir(t)
	ctx := context.Background()
	runtime := &SSHNodeRuntime{Lifecycle: true, ConfigurationDirectory: root}
	var jobs []DeploymentJob
	for _, raw := range [][]byte{[]byte("node-a-private-configuration"), []byte("node-b-private-configuration")} {
		a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
		if _, err := writeNodeConfiguration(root, a, raw); err != nil {
			t.Fatal(err)
		}
		jobs = append(jobs, DeploymentJob{Plan: DeploymentPlan{Request: DeploymentRequest{RuntimeArtifact: &a}}})
	}
	var wg sync.WaitGroup
	fail := make(chan string, 100)
	for n := 0; n < 100; n++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			j := jobs[i%2]
			path, err := runtime.configurationFile(ctx, j)
			if err != nil || filepath.Base(filepath.Dir(path)) != j.Plan.Request.RuntimeArtifact.SHA256 {
				fail <- "configuration crossed jobs"
			}
		}(n)
	}
	wg.Wait()
	close(fail)
	for reason := range fail {
		t.Fatal(reason)
	}
	for _, phase := range append(append([]string{}, deploymentPhases...), rollbackPhases...) {
		if !runtime.SupportsDeploymentPhase(phase) {
			t.Fatal("missing phase", phase)
		}
	}
	if runtime.SupportsDeploymentPhase("complete") {
		t.Fatal("unknown phase accepted")
	}
	if _, err := runtime.configurationFile(ctx, DeploymentJob{}); err == nil {
		t.Fatal("unbound runtime accepted")
	}
	path, _ := runtime.configurationFile(ctx, jobs[0])
	original, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.configurationFile(ctx, jobs[0]); err == nil {
		t.Fatal("configuration change accepted")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "config-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	runtime.ConfigurationDirectory = link
	if _, err := runtime.configurationFile(ctx, jobs[0]); err == nil {
		t.Fatal("root link accepted")
	}
	runtime.ConfigurationDirectory = root
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, jobs[1].Plan.Request.RuntimeArtifact.SHA256, "node.json"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.configurationFile(ctx, jobs[0]); err == nil {
		t.Fatal("file link accepted")
	}
	runtime.LocalConfiguration = "other"
	if _, err := runtime.configurationFile(ctx, jobs[1]); err == nil {
		t.Fatal("mutable global file also selected")
	}
}

func TestConfiguredExecutorLoadsTrustedArtifactsBeforeClaimingTasks(t *testing.T) {
	s := testStore(t)
	f := newTrustToolFixture(t)
	ctx := context.Background()
	var c Config
	c.Central.Instance = "test-executor"
	c.DeploymentTrust = f.config()
	c.Executor = ExecutorConfig{Enabled: true, ConfigurationDirectory: f.root, Concurrency: 2}
	runner, err := newDeploymentExecutor(ctx, s, c)
	if err != nil {
		t.Fatal(err)
	}
	runtime, ok := runner.Runtime.(*SSHNodeRuntime)
	if !ok || !runtime.Lifecycle || runner.Concurrency != 2 || runtime.LocalConfiguration != "" || runtime.ConfigurationDirectory != f.root || runner.Vault == nil || runner.Vault != runtime.Vault {
		t.Fatal("wrong executor binding")
	}
	if err := os.WriteFile(f.helper, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newDeploymentExecutor(ctx, s, c); err == nil {
		t.Fatal("changed release enabled executor")
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 {
		t.Fatal("trust validation created a task")
	}
	// Optional new config survives the real YAML parser without changing the
	// default topology or opening production deployment writes.
	configPath := filepath.Join(f.root, "configuration.yaml")
	var out bytes.Buffer
	if err := Initialize(Options{Config: configPath, PublicURL: "https://monitor.example.test", NonInteractive: true}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	base, _ := os.ReadFile(configPath)
	if err := os.WriteFile(configPath, append(base, []byte("\nexecutor:\n  enabled: false\n  concurrency: 2\n  configuration_directory: "+f.root+"\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	parsed, err := LoadConfig(configPath)
	if err != nil || parsed.Executor.Enabled || parsed.Executor.Concurrency != 2 {
		t.Fatal("configuration round trip", err)
	}
}
