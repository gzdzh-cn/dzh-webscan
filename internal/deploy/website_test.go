package deploy

import (
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/website"
)

func TestWebsiteCredentialsRuntimeAndCompose(t *testing.T) {
	c := fixture(t)
	common.M(c.Raw["central"])["website_monitor"] = common.Map{"enabled": true, "bind_address": "0.0.0.0", "host_port": 19444, "admin_username": "console-admin", "admin_password": "", "interval_seconds": 60, "timeout_seconds": 5, "max_concurrent": 128, "extra_memory_mib": 128}
	secrets := common.Map{}
	if e := websiteCredentials(c, secrets); e != nil {
		t.Fatal(e)
	}
	password := common.S(secrets["website_password"])
	hash := common.S(secrets["website_password_hash"])
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		t.Fatal("bad hash")
	}
	if e := websiteCredentials(c, secrets); e != nil {
		t.Fatal(e)
	}
	if common.S(secrets["website_password_hash"]) != hash {
		t.Fatal("reinstall changes credential")
	}
	runtime := CentralRuntime(c, secrets, nil)
	wm := common.M(runtime["website_monitor"])
	if _, ok := wm["admin_password"]; ok || strings.Contains(string(common.JSON(runtime)), password) {
		t.Fatal("plaintext runtime")
	}
	service := ReceiverService(c, c.Image("central"))
	if !strings.Contains(strings.Join(common.SS(service["ports"]), ","), "19444:19444") || common.S(service["mem_limit"]) != "256m" {
		t.Fatal(service)
	}
	common.M(c.Raw["registry"])["prefix"] = "docker.io/gzdzh"
	dir := filepath.Join(t.TempDir(), "package")
	if e := PrepareCompose(c, dir, []byte("include: []\n")); e != nil {
		t.Fatal(e)
	}
	credential, e := common.ReadJSON(filepath.Join(dir, "central/website-credentials.json"))
	if e != nil || common.S(credential["password"]) == "" {
		t.Fatal(e)
	}
	info, _ := os.Stat(filepath.Join(dir, "central/website-credentials.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
}

func TestPersistentWebsiteCredentialsOverrideYAMLAndRollback(t *testing.T) {
	c := fixture(t)
	central := common.M(c.Raw["central"])
	central["data_dir"] = t.TempDir()
	central["website_monitor"] = common.Map{"enabled": true, "admin_username": "old-yaml", "admin_password": "old-yaml-password"}
	path := filepath.Join(common.S(central["data_dir"]), "events-v1.sqlite3")
	db, e := persist.OpenDB(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.Exec("CREATE TABLE website_admin(id INTEGER PRIMARY KEY,username TEXT,password_hash TEXT,revision INTEGER,modified INTEGER)")
	hash, _ := bcrypt.GenerateFromPassword([]byte("changed-password"), bcrypt.MinCost)
	db.Exec("INSERT INTO website_admin VALUES(1,'persisted-admin',?,3,1)", string(hash))
	secrets := common.Map{"website_password": "old-yaml-password"}
	if e = websiteCredentials(c, secrets); e != nil {
		t.Fatal(e)
	}
	if common.S(secrets["website_username"]) != "persisted-admin" || common.S(secrets["website_password"]) != "" || common.S(secrets["website_password_hash"]) != string(hash) {
		t.Fatal("persistent account replaced")
	}
	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	common.AtomicJSON(runtimePath, common.Map{"website_monitor": common.Map{"enabled": true, "password_hash": "old-hash"}, "data_dir": "keep"})
	account, e := website.AccountAt(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = preserveWebsiteAccount(runtimePath, account); e != nil {
		t.Fatal(e)
	}
	runtime, e := common.ReadJSON(runtimePath)
	if e != nil {
		t.Fatal(e)
	}
	if common.S(common.M(runtime["website_monitor"])["password_hash"]) != string(hash) || common.S(runtime["data_dir"]) != "keep" {
		t.Fatal("rollback password lost")
	}
}

func TestFirstAccountMigrationUsesCurrentRuntimeInsteadOfEditedYAML(t *testing.T) {
	c := fixture(t)
	central := common.M(c.Raw["central"])
	central["data_dir"] = t.TempDir()
	central["install_dir"] = t.TempDir()
	central["website_monitor"] = common.Map{"enabled": true, "admin_username": "new-yaml-user", "admin_password": "new-yaml-password"}
	hash, _ := bcrypt.GenerateFromPassword([]byte("current-runtime-password"), bcrypt.MinCost)
	if e := common.AtomicJSON(filepath.Join(c.CentralRoot(), "runtime.json"), common.Map{"website_monitor": common.Map{"admin_username": "current-admin", "password_hash": string(hash)}}); e != nil {
		t.Fatal(e)
	}
	secrets := common.Map{"website_password": "outdated-secret-password"}
	if e := websiteCredentials(c, secrets); e != nil {
		t.Fatal(e)
	}
	if common.S(secrets["website_username"]) != "current-admin" || common.S(secrets["website_password_hash"]) != string(hash) || common.S(secrets["website_password"]) != "" {
		t.Fatal("first upgrade replaced running account with YAML")
	}
}
