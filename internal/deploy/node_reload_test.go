package deploy

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"webscan/internal/common"
)

func TestNativeRegistrationAndRollbackNeverInvokeDocker(t *testing.T) {
	d := additionFixture(t)
	d.O.AddNode = true
	common.M(common.M(d.C.Raw["central"])["monitoring"])["mode"] = "native"
	// Preserve a second node's maintenance state across the target operation.
	path := filepath.Join(d.C.CentralRoot(), "runtime.json")
	original, _ := common.ReadJSON(path)
	common.M(original["monitoring"])["mode"] = "native"
	common.M(original["monitoring"])["maintenance_nodes"] = []string{"other-maintenance"}
	common.AtomicJSON(path, original)
	active := registryRevision(original)
	loads := 0
	maintenanceServer(t, d, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			w.Write([]byte(`{"ready":true}`))
		case "/node-capabilities":
			w.Write(common.JSON(common.Map{"node_registry_reload": true, "revision": active}))
		case "/reload-nodes":
			next, _ := common.ReadJSON(path)
			active = registryRevision(next)
			loads++
			w.Write(common.JSON(common.Map{"ok": true, "revision": active}))
		default:
			t.Error("unexpected endpoint", r.URL.Path)
			w.WriteHeader(400)
		}
	})
	if e := d.initialize(); e != nil {
		t.Fatal(e)
	}
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nprintf invoked > \"$WEBSCAN44_DOCKER_CALL\"\nexit 1\n"), 0700)
	t.Setenv("WEBSCAN44_DOCKER_CALL", filepath.Join(bin, "called"))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if e := d.registerAddition(context.Background()); e != nil {
		t.Fatal(e)
	}
	next, _ := common.ReadJSON(path)
	if !common.Contains(common.SS(common.M(next["monitoring"])["maintenance_nodes"]), "other-maintenance") {
		t.Fatal("other maintenance lost")
	}
	// A lost confirmation is safe to retry without recreating any service.
	if e := d.registerAddition(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := d.rollbackAddition(context.Background()); e != nil {
		t.Fatal(e)
	}
	restored, _ := common.ReadJSON(path)
	if registryRevision(restored) != registryRevision(original) || active != registryRevision(original) {
		t.Fatal("registry rollback not confirmed")
	}
	if _, e := os.Stat(filepath.Join(bin, "called")); !os.IsNotExist(e) {
		t.Fatal("node operation invoked Docker")
	}
	if loads != 3 {
		t.Fatal(loads)
	}
}
func TestOldCenterStopsBeforeNativeRegistration(t *testing.T) {
	d := additionFixture(t)
	common.M(common.M(d.C.Raw["central"])["monitoring"])["mode"] = "native"
	maintenanceServer(t, d, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	before, _ := os.ReadFile(filepath.Join(d.C.CentralRoot(), "runtime.json"))
	if _, e := d.nodeCapabilities(context.Background()); e == nil {
		t.Fatal("old center accepted")
	}
	after, _ := os.ReadFile(filepath.Join(d.C.CentralRoot(), "runtime.json"))
	if string(before) != string(after) {
		t.Fatal("capability probe changed configuration")
	}
}
func TestExplicitChildCLIUpgradeUsesNodeScope(t *testing.T) {
	for _, o := range []Options{{Node: "child", Upgrade: true}, {Node: "child", Install: true}} {
		d := &Deploy{O: o}
		d.normalizeNodeScope()
		if !d.O.AddNode || d.O.Upgrade || d.O.Install {
			t.Fatal("child CLI may rebuild center", d.O)
		}
	}
	for _, o := range []Options{{Upgrade: true}, {Node: "child", Check: true}, {Node: "child", Uninstall: true}} {
		d := &Deploy{O: o}
		d.normalizeNodeScope()
		if d.O.AddNode {
			t.Fatal("unrelated scope changed")
		}
	}
}
