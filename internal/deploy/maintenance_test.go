package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
)

func TestInstallAutomaticallySelectsUpgradeOrResume(t *testing.T) {
	for _, tc := range []struct {
		state           common.Map
		upgrade, resume bool
	}{
		{common.Map{}, false, false},
		{common.Map{"go_release": Release, "step": "complete"}, true, false},
		{common.Map{"central_installed": true}, true, false},
		{common.Map{"run_id": "go-test", "step": "installing"}, false, true},
		{common.Map{"run_id": "go-test", "step": "rolled-back", "go_release": "old"}, true, false},
	} {
		d := &Deploy{C: fixture(t), State: tc.state, O: Options{Install: true}}
		d.selectInstallMode()
		if d.O.Upgrade != tc.upgrade || d.O.Resume != tc.resume {
			t.Fatal(d.O)
		}
	}
}

func TestUninstallFindsPreviouslyInstalledDisabledNodes(t *testing.T) {
	c := fixture(t)
	n := c.Nodes[0]
	id := common.S(n["id"])
	n["enabled"] = false
	d := &Deploy{C: c, State: common.Map{"nodes": common.Map{id: common.Map{"go_run_id": "go-old", "phase": "complete"}}}}
	got, err := d.maintenanceNodes()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range got {
		found = found || common.S(n["id"]) == id
	}
	if !found {
		t.Fatal("missed disabled installed node")
	}
	common.M(d.State["nodes"])["missing-node"] = common.Map{"go_run_id": "go-old"}
	if _, err = d.maintenanceNodes(); err == nil {
		t.Fatal("missing historical connection accepted")
	}
}

func TestRuntimeRemovalProtectsDeploymentAndData(t *testing.T) {
	for _, p := range []string{"/", "relative", "/opt", "/opt/monitor/data", "/opt/monitor"} {
		if err := safeRuntimeRemoval(p, "/opt/monitor/data"); err == nil {
			t.Fatal("unsafe path", p)
		}
	}
	if err := safeRuntimeRemoval("/opt/monitor/runtime", "/opt/monitor/data", "/root/webscan-deploy"); err != nil {
		t.Fatal(err)
	}
}

func TestSingleUninstallCanSelectDisabledNodeOutsideDeploymentOrder(t *testing.T) {
	c := fixture(t)
	node := c.Nodes[len(c.Nodes)-1]
	id := common.S(node["id"])
	node["enabled"] = false
	common.M(c.Raw["deployment"])["node_order"] = []string{common.S(c.Nodes[0]["id"])}
	d := &Deploy{C: c, O: Options{Uninstall: true, Node: id}, State: common.Map{"nodes": common.Map{}}}
	nodes, err := d.maintenanceNodes()
	if err != nil || len(nodes) != 1 || common.S(nodes[0]["id"]) != id {
		t.Fatal(nodes, err)
	}
	d.O.Node = ""
	nodes, err = d.maintenanceNodes()
	if err != nil || len(nodes) != len(c.Nodes) {
		t.Fatal("full scope did not include all configured nodes")
	}
}

func TestCentralOnlyUninstallAndRestoreKeepsNodeIdentity(t *testing.T) {
	c := fixture(t)
	root := t.TempDir()
	center := common.M(c.Raw["central"])
	center["install_dir"] = filepath.Join(root, "install")
	center["data_dir"] = filepath.Join(root, "data")
	center["backup_dir"] = filepath.Join(root, "db-backup")
	os.MkdirAll(common.S(center["data_dir"]), 0700)
	db := filepath.Join(common.S(center["data_dir"]), "events-v1.sqlite3")
	os.WriteFile(db, []byte("history-and-queue"), 0600)
	oldStateRoot := StateRoot
	StateRoot = filepath.Join(root, "state")
	t.Cleanup(func() { StateRoot = oldStateRoot })
	os.MkdirAll(StateRoot, 0700)
	bin := filepath.Join(root, "bin")
	os.Mkdir(bin, 0700)
	os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\n[ \"$1\" = info ] || [ \"$1\" = ps ]\n"), 0700)
	os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\n[ \"$1\" != is-active ]\n"), 0700)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("TASK_UNITS", filepath.Join(root, "units"))
	if err := certificates(c); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(c.CentralRoot(), "pki", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	id := common.S(c.Nodes[0]["id"])
	secrets := common.Map{"admin_password": "saved-grafana-password", "nodes": common.Map{id: common.Map{"token": "saved-node-token"}}}
	common.AtomicJSON(filepath.Join(StateRoot, "credentials.json"), secrets)
	d := &Deploy{C: c, O: Options{Uninstall: true, CentralOnly: true}, State: common.Map{
		"run_id": "go-old", "step": "complete", "go_release": "old", "active": []string{id},
		"nodes": common.Map{id: common.Map{"go_run_id": "go-old", "phase": "complete"}},
	}, Secrets: secrets}
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.CentralRoot()); !os.IsNotExist(err) {
		t.Fatal("central runtime retained")
	}
	if !common.B(d.State["central_uninstalled"]) || len(common.SS(d.State["active"])) != 1 || common.S(common.M(common.M(d.State["nodes"])[id])["phase"]) != "complete" {
		t.Fatal("running node state lost")
	}
	if b, err := os.ReadFile(db); err != nil || string(b) != "history-and-queue" {
		t.Fatal("database lost")
	}
	fresh, err := New(c, Options{Install: true, CentralOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	fresh.selectInstallMode()
	if !fresh.O.Upgrade || fresh.O.Resume {
		t.Fatal("main reinstall incorrectly resumed old run")
	}
	if err = fresh.restoreRetainedPKI(); err != nil {
		t.Fatal(err)
	}
	if err = certificates(c); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(c.CentralRoot(), "pki", "ca.crt")); err != nil || string(got) != string(ca) {
		t.Fatal("original nodes no longer trust receiver")
	}
	if common.S(common.M(common.M(fresh.Secrets["nodes"])[id])["token"]) != "saved-node-token" || common.S(fresh.Secrets["admin_password"]) != "saved-grafana-password" {
		t.Fatal("credentials changed")
	}
}

// Opt-in integration: only disposable containers with a unique Compose label.
// A mock systemctl and temporary unit directory prevent touching host services.
func TestCentralUninstallIsolatedContainers(t *testing.T) {
	version := os.Getenv("WEBSCAN_IMAGE_VERSION")
	if version == "" {
		t.Skip("requires locally built versioned images")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := func(args ...string) string {
		t.Helper()
		b, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %s", args[0], b)
		}
		return strings.TrimSpace(string(b))
	}
	project := "webscan-uninstall-test-" + common.ID()[:8]
	target, other := project+"-target", project+"-unrelated"
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", target, other).Run()
		exec.Command("docker", "network", "rm", project+"-monitor").Run()
	})
	run("network", "create", project+"-monitor")
	image := "webscan-central:" + version
	run("run", "-d", "--name", target, "--network", project+"-monitor", "--label", "com.docker.compose.project="+project, "--entrypoint", "/bin/sleep", image, "300")
	run("run", "-d", "--name", other, "--entrypoint", "/bin/sleep", image, "300")
	dir := t.TempDir()
	runtime, data, backup, units := filepath.Join(dir, "runtime"), filepath.Join(dir, "data"), filepath.Join(dir, "backup"), filepath.Join(dir, "units")
	for _, p := range []string{runtime, data, units} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(runtime, "runtime.json"), []byte("configuration"), 0600)
	os.WriteFile(filepath.Join(data, "events-v1.sqlite3"), []byte("preserved-history"), 0600)
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0700)
	os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\n[ \"$1\" != is-active ]\n"), 0700)
	script := "TASK_UNITS=" + Q(units) + "\n" + centralUninstallScript(backup, runtime, data, project, "")
	// A failed backup must restart the stopped container and keep runtime intact.
	os.WriteFile(filepath.Join(bin, "tar"), []byte("#!/bin/sh\nexit 47\n"), 0700)
	failed := exec.CommandContext(ctx, "bash", "-se")
	failed.Stdin = strings.NewReader(script)
	failed.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	if err := failed.Run(); err == nil {
		t.Fatal("backup failure unexpectedly succeeded")
	}
	if got := run("inspect", "-f", "{{.State.Running}}", target); got != "true" {
		t.Fatal("backup failure did not restart target")
	}
	if _, err := os.Stat(runtime); err != nil {
		t.Fatal("runtime removed before backup success")
	}
	os.Remove(filepath.Join(bin, "tar"))
	execute := func() {
		t.Helper()
		cmd := exec.CommandContext(ctx, "bash", "-se")
		cmd.Stdin = strings.NewReader(script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated uninstall: %v %s", err, b)
		}
	}
	execute()
	if exec.Command("docker", "inspect", target).Run() == nil {
		t.Fatal("target still exists")
	}
	if got := run("inspect", "-f", "{{.State.Running}}", other); got != "true" {
		t.Fatal("unrelated container stopped")
	}
	if _, err := os.Stat(runtime); !os.IsNotExist(err) {
		t.Fatal("runtime not removed")
	}
	b, err := os.ReadFile(filepath.Join(data, "events-v1.sqlite3"))
	if err != nil || string(b) != "preserved-history" {
		t.Fatal("data lost")
	}
	b, err = exec.Command("tar", "-tzf", filepath.Join(backup, "central-runtime-and-database.tar.gz")).CombinedOutput()
	if err != nil || !strings.Contains(string(b), "runtime.json") || !strings.Contains(string(b), "events-v1.sqlite3") {
		t.Fatal("backup incomplete", err)
	}
	// A repeat with its own backup succeeds even when runtime and containers are absent.
	script = "TASK_UNITS=" + Q(units) + "\n" + centralUninstallScript(filepath.Join(dir, "backup-repeat"), runtime, data, project, "")
	execute()
}

func TestNodeUninstallIsolatedLinuxFilesystem(t *testing.T) {
	version := os.Getenv("WEBSCAN_IMAGE_VERSION")
	if version == "" {
		t.Skip("requires Linux container")
	}
	body, err := assets.Files.ReadFile("uninstall-node.sh")
	if err != nil {
		t.Fatal(err)
	}
	setup := `set -e
mkdir -p /mock /etc/webscan-v1 /opt/webscan-go /var/lib/webscan-v1 /var/lib/webscan-vector-v1 /www/wwwroot/site /root/webscan-deploy
echo keep > /var/lib/webscan-v1/agent.sqlite3
echo queue > /var/lib/webscan-vector-v1/buffer
echo website > /www/wwwroot/site/index.php
echo yaml > /root/webscan-deploy/webscan.yaml
echo code > /opt/webscan-go/program
cat > /mock/systemctl <<'MOCK'
#!/bin/bash
if [ "$1" = is-active ]; then exit 1; fi
exit 0
MOCK
cat > /mock/docker <<'MOCK'
#!/bin/bash
if [ "$1" = info ]; then exit 0; fi
if [ "$1" = inspect ]; then exit 1; fi
exit 0
MOCK
chmod +x /mock/*
export PATH=/mock:$PATH
TASK_BACKUP=/backup
`
	verify := `
test ! -e /etc/webscan-v1
test ! -e /opt/webscan-go
test "$(cat /var/lib/webscan-v1/agent.sqlite3)" = keep
test "$(cat /var/lib/webscan-vector-v1/buffer)" = queue
test "$(cat /www/wwwroot/site/index.php)" = website
test "$(cat /root/webscan-deploy/webscan.yaml)" = yaml
tar -tzf /backup/node-runtime-and-database.tar.gz | grep agent.sqlite3 >/dev/null
`
	script := setup + "\n" + string(body) + "\n" + verify
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "-i", "--entrypoint", "/bin/bash", "webscan-central:"+version, "-se")
	cmd.Stdin = strings.NewReader(script)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated node uninstall: %v %s", err, b)
	}
}
