package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"webscan/internal/assets"
	"webscan/internal/common"
	configuration "webscan/internal/config"
)

func setupTemp(t *testing.T) string {
	t.Helper()
	base, e := filepath.Abs("../../.cache")
	if e != nil {
		t.Fatal(e)
	}
	os.MkdirAll(base, 0700)
	dir, e := os.MkdirTemp(base, "v30-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
func testPackage(t *testing.T) (string, packagePaths) {
	t.Helper()
	dir := setupTemp(t)
	stage := filepath.Join(dir, "stage")
	os.Mkdir(stage, 0700)
	p := packagePaths{filepath.Join(dir, "deploy"), filepath.Join(dir, "state"), filepath.Join(dir, "bin/webscan"), filepath.Join(dir, "profile/webscan.sh")}
	script := []byte("#!/bin/bash\n# Webscan v2.0.30. Embedded test.\necho test\n")
	example, _ := assets.Files.ReadFile("configuration-example.yaml")
	os.WriteFile(filepath.Join(stage, "deploy-webscan.sh"), script, 0600)
	os.WriteFile(filepath.Join(stage, "webscan.example.yaml"), example, 0600)
	manifest := "release=v2.0.30\nsource_commit=" + strings.Repeat("a", 40) + "\nscript_sha256=" + common.Hash(script) + "\nexample_sha256=" + common.Hash(example) + "\n"
	os.WriteFile(filepath.Join(stage, "install-manifest.txt"), []byte(manifest), 0600)
	return stage, p
}
func setupReader(input string, out *bytes.Buffer) setupInput {
	return setupInput{scanner: bufio.NewScanner(strings.NewReader(input)), out: out}
}

// name, IP, source default, SSL, website on, port, Grafana port, both accounts,
// Feishu off, root default, no second root, no nodes, save.
func initialAnswers(ssl string) string {
	return "\n203.0.113.10\n\n" + ssl + "\n\n\n\n\n\n2\n\n2\n2\n1\n"
}
func TestFreshPackageAndWizardWithoutNodes(t *testing.T) {
	for _, mode := range []string{"1", "2"} {
		t.Run(mode, func(t *testing.T) {
			stage, p := testPackage(t)
			var out bytes.Buffer
			if e := preparePackage(stage, p, &out); e != nil {
				t.Fatal(e)
			}
			yamlPath := filepath.Join(p.dir, "webscan.yaml")
			before, _ := os.ReadFile(yamlPath)
			initialized, e := initializeConfig(yamlPath, p.state, setupReader(initialAnswers(mode), &out))
			if e != nil || !initialized {
				t.Fatalf("init %v %v\n%s", initialized, e, out.String())
			}
			c, e := configuration.Load(yamlPath)
			if e != nil {
				t.Fatal(e)
			}
			if len(c.Nodes) != 0 || c.SSLEnabled() != (mode == "1") {
				t.Fatal(c.Nodes, c.SSLEnabled())
			}
			after, _ := os.ReadFile(yamlPath)
			if bytes.Equal(before, after) || !bytes.Contains(after, []byte("# GoFrame")) {
				t.Fatal("configuration/comments not saved")
			}
			if _, e = os.Stat(filepath.Join(p.dir, ".setup-pending.json")); !os.IsNotExist(e) {
				t.Fatal("marker remains")
			}
			if initialized, e = initializeConfig(yamlPath, p.state, setupReader("", &out)); e != nil || initialized {
				t.Fatal("reinitialized", e)
			}
			for path, want := range map[string]os.FileMode{yamlPath: 0600, filepath.Join(p.dir, "deploy-webscan.sh"): 0700, p.command: 0755, p.profile: 0644} {
				st, e := os.Stat(path)
				if e != nil || st.Mode().Perm() != want {
					t.Fatal(path, e)
				}
			}
		})
	}
}
func TestCancelledOrEOFSetupDoesNotCommit(t *testing.T) {
	for _, input := range []string{"0\n", "\n203.0.113.10\n"} {
		t.Run(input, func(t *testing.T) {
			stage, p := testPackage(t)
			if e := preparePackage(stage, p, new(bytes.Buffer)); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(p.dir, "webscan.yaml")
			before, _ := os.ReadFile(path)
			_, e := initializeConfig(path, p.state, setupReader(input, new(bytes.Buffer)))
			if e == nil {
				t.Fatal("accepted cancellation/EOF")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("committed partial input")
			}
		})
	}
}
func TestRepeatedPackagePreservesConfigurationAndVersion(t *testing.T) {
	stage, p := testPackage(t)
	if e := preparePackage(stage, p, new(bytes.Buffer)); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(p.dir, "webscan.yaml")
	before := []byte("# actual credentials remain private\ncustom: keep\n")
	os.WriteFile(path, before, 0600)
	old := []byte("#!/bin/bash\n# Webscan v2.0.31. Newer local.\n")
	os.WriteFile(filepath.Join(p.dir, "deploy-webscan.sh"), old, 0700)
	if e := preparePackage(stage, p, new(bytes.Buffer)); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(path)
	script, _ := os.ReadFile(filepath.Join(p.dir, "deploy-webscan.sh"))
	if !bytes.Equal(before, after) || !bytes.Equal(old, script) {
		t.Fatal("overwrote YAML or downgraded script")
	}
}
func TestInstalledMissingConfigAndPendingTasks(t *testing.T) {
	for _, state := range []common.Map{{"central_installed": true}, {"run_id": "go-test", "step": "switching"}, {"central_uninstall_pending": true}, {"single_uninstall": common.Map{"complete": false, "node": "x"}}} {
		stage, p := testPackage(t)
		if e := preparePackage(stage, p, new(bytes.Buffer)); e != nil {
			t.Fatal(e)
		}
		before, _ := os.ReadFile(filepath.Join(p.dir, "deploy-webscan.sh"))
		common.AtomicJSON(filepath.Join(p.state, "state.json"), state)
		if hasPendingTask(state) {
			if e := preparePackage(stage, p, new(bytes.Buffer)); e != nil {
				t.Fatal(e)
			}
			after, _ := os.ReadFile(filepath.Join(p.dir, "deploy-webscan.sh"))
			if !bytes.Equal(before, after) {
				t.Fatal("replaced pending script")
			}
		}
		os.Remove(filepath.Join(p.dir, "webscan.yaml"))
		if e := preparePackage(stage, p, new(bytes.Buffer)); e == nil {
			t.Fatal("reinitialized installed/pending system")
		}
	}
}
func TestPackageChecksumsLinksAndConflict(t *testing.T) {
	for _, kind := range []string{"digest", "symlink", "command", "lock"} {
		t.Run(kind, func(t *testing.T) {
			stage, p := testPackage(t)
			switch kind {
			case "digest":
				os.WriteFile(filepath.Join(stage, "webscan.example.yaml"), []byte("tampered"), 0600)
			case "symlink":
				os.MkdirAll(p.dir, 0700)
				os.Symlink(filepath.Join(stage, "webscan.example.yaml"), filepath.Join(p.dir, "webscan.yaml"))
			case "command":
				os.MkdirAll(filepath.Dir(p.command), 0755)
				os.WriteFile(p.command, []byte("#!/bin/bash\nother software\n"), 0755)
			case "lock":
				unlock, e := packageLock(p.state, "deploy.lock")
				if e != nil {
					t.Fatal(e)
				}
				defer unlock()
			}
			if e := preparePackage(stage, p, new(bytes.Buffer)); e == nil {
				t.Fatal("unsafe operation succeeded")
			}
		})
	}
}
func TestNodeWizardAndMenuWithNoConfiguredNodes(t *testing.T) {
	stage, p := testPackage(t)
	out := new(bytes.Buffer)
	if e := preparePackage(stage, p, out); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(p.dir, "webscan.yaml")
	if _, e := initializeConfig(path, p.state, setupReader(initialAnswers("2"), out)); e != nil {
		t.Fatal(e)
	}
	common.AtomicJSON(filepath.Join(p.state, "state.json"), common.Map{"central_installed": true})
	// Password node, custom roots, then save. Secret never appears in terminal output.
	i := setupReader("\n\n198.51.100.40\n2222\n2\nprivate-password\n1\n/data/sites\n2\n1\n", out)
	args, e := addConfiguredNode(path, p.state, i)
	if e != nil {
		t.Fatalf("%v\n%s", e, out.String())
	}
	if strings.Join(args, " ") != "--add-node --node node-1" {
		t.Fatal(args)
	}
	c, e := configuration.Load(path)
	if e != nil || len(c.Nodes) != 1 {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "private-password") {
		t.Fatal("secret echoed")
	}
	if common.SS(common.M(c.Nodes[0]["monitor"])["roots"])[0] != "/data/sites" {
		t.Fatal("node roots lost")
	}
	var menu bytes.Buffer
	called := false
	selection, e := selectAdditionWithNew(bufio.NewScanner(strings.NewReader("N\n")), &menu, func() ([]common.Map, error) { return nil, nil }, func(*bufio.Scanner, io.Writer) ([]string, error) { called = true; return args, nil })
	if e != nil || !called || len(selection) != 3 {
		t.Fatal(selection, e)
	}
}
func TestSetupCannotChangePendingOrChangedConfig(t *testing.T) {
	stage, p := testPackage(t)
	if e := preparePackage(stage, p, new(bytes.Buffer)); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(p.dir, "webscan.yaml")
	if _, e := initializeConfig(path, p.state, setupReader(initialAnswers("2"), new(bytes.Buffer))); e != nil {
		t.Fatal(e)
	}
	doc, before, e := loadYAMLDocument(path)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(path, append(before, []byte("\n# concurrent edit\n")...), 0600)
	if e = saveSetup(path, doc, before, p.state); e == nil {
		t.Fatal("lost concurrent edit")
	}
	os.WriteFile(path, before, 0600)
	common.AtomicJSON(filepath.Join(p.state, "state.json"), common.Map{"run_id": "go-test", "step": "switching"})
	if e = saveSetup(path, doc, before, p.state); e == nil {
		t.Fatal("changed pending configuration")
	}
}
func TestPackageLockExclusion(t *testing.T) {
	p := setupTemp(t)
	unlock, e := packageLock(p, "bootstrap.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	if u, e := packageLock(p, "bootstrap.lock"); e == nil {
		u()
		t.Fatal("concurrent lock accepted")
	}
	if !errors.Is(unix.EWOULDBLOCK, unix.EAGAIN) {
		t.Fatal("platform lock error")
	}
}

func TestExistingPackageDoesNotNeedTemplateDownload(t *testing.T) {
	stage, p := testPackage(t)
	if e := preparePackage(stage, p, new(bytes.Buffer)); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(p.dir, "webscan.yaml"))
	os.Remove(filepath.Join(stage, "webscan.example.yaml"))
	if e := preparePackage(stage, p, new(bytes.Buffer)); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(filepath.Join(p.dir, "webscan.yaml"))
	if !bytes.Equal(before, after) {
		t.Fatal("changed existing config")
	}
}

func TestLocalScriptContinuesWithoutReplacingOtherCommand(t *testing.T) {
	_, p := testPackage(t)
	if err := os.MkdirAll(filepath.Dir(p.command), 0755); err != nil {
		t.Fatal(err)
	}
	original := []byte("#!/bin/bash\necho another-application\n")
	if err := os.WriteFile(p.command, original, 0755); err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	if registerLocalShortcut(p, out) {
		t.Fatal("conflicting command registered")
	}
	after, _ := os.ReadFile(p.command)
	if !bytes.Equal(original, after) || !strings.Contains(out.String(), "本次继续") {
		t.Fatal("fallback or conflict protection failed")
	}
}
