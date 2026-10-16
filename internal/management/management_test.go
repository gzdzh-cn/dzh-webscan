package management

import (
	"bytes"
	"context"
	"gopkg.in/yaml.v3"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
	"webscan/internal/config"
)

func TestRecoveryArgumentsPreserveOriginalScope(t *testing.T) {
	for _, tc := range []struct {
		kind, node string
		state      common.Map
		want       []string
	}{
		{"resume", "new-node", common.Map{"target_node": "new-node", "target_add_node": true}, []string{"--resume", "--node", "new-node", "--add-node"}},
		{"rollback", "new-node", common.Map{"target_node": "new-node", "target_add_node": true}, []string{"--rollback", "--node", "new-node"}},
		{"resume", "", common.Map{"target_central_only": true}, []string{"--resume", "--central-only"}},
		{"rollback", "", common.Map{"target_central_only": true}, []string{"--rollback", "--central-only"}},
		{"resume", "", common.Map{}, []string{"--resume"}},
	} {
		got, err := recoveryArguments(tc.kind, tc.node, tc.state)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatal(tc, got, err)
		}
	}
	if _, err := recoveryArguments("resume", "other-node", common.Map{"target_node": "new-node"}); err == nil {
		t.Fatal("scope change accepted")
	}
}

func managerFixture(t *testing.T) *Service {
	t.Helper()
	b, e := assets.Files.ReadFile("schema.yaml")
	if e != nil {
		t.Fatal(e)
	}
	var raw common.Map
	yaml.Unmarshal(b, &raw)
	common.M(raw["feishu"])["enabled"] = false
	common.M(raw["central"])["public_url"] = "https://192.0.2.1:19443"
	common.M(common.M(raw["central"])["monitoring"])["mode"] = "native"
	common.M(raw["feishu"])["signing_secret"] = "protected-test-secret"
	dir := t.TempDir()
	p := filepath.Join(dir, "webscan.yaml")
	for _, v := range common.A(raw["nodes"]) {
		ssh := common.M(common.M(v)["ssh"])
		ssh["auth_method"] = "password"
		ssh["password"] = "fixture-only-password"
	}
	b, _ = yaml.Marshal(raw)
	os.WriteFile(p, append([]byte("# 保留这条注释\n"), b...), 0600)
	if _, e = config.Load(p); e != nil {
		t.Fatal(e)
	}
	s, e := Open(p, filepath.Join(dir, "state"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}
func request(t *testing.T, s *Service, method, path string, input any) (int, common.Map) {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(common.JSON(input)))
	w := httptest.NewRecorder()
	s.Handler(w, r)
	v, e := common.Decode(w.Body.Bytes())
	if e != nil {
		t.Fatal(w.Body.String())
	}
	return w.Code, common.M(v)
}
func revision(t *testing.T, s *Service) string {
	t.Helper()
	b, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	return common.Hash(b)
}
func TestConfigurationProtectedAndConflict(t *testing.T) {
	s := managerFixture(t)
	rev := revision(t, s)
	status, v := request(t, s, "GET", "/settings", nil)
	if status != 200 || strings.Contains(string(common.JSON(v)), "protected-test-secret") {
		t.Fatal(status, v)
	}
	edit := Edit{Revision: rev, Patch: common.Map{"central.name": "新主服务器", "feishu.signing_secret": ""}}
	status, v = request(t, s, "PUT", "/settings", edit)
	if status != 200 {
		t.Fatal(status, v)
	}
	b, _ := os.ReadFile(s.ConfigPath)
	if !strings.Contains(string(b), "# 保留这条注释") || !strings.Contains(string(b), "protected-test-secret") {
		t.Fatal("comments/secret lost")
	}
	status, _ = request(t, s, "PUT", "/settings", edit)
	if status != 409 {
		t.Fatal("lost update", status)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM config_backups").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
	_, preview, e := prepare(s.ConfigPath, Edit{Revision: revision(t, s), Patch: common.Map{"central.monitoring": common.Map{"mode": "legacy"}}})
	if e == nil {
		t.Fatal("bypassed migration", preview)
	}
	linked := filepath.Join(filepath.Dir(s.ConfigPath), "linked.yaml")
	os.Symlink(s.ConfigPath, linked)
	if _, _, e = prepare(linked, Edit{Revision: revision(t, s), Patch: common.Map{}}); e == nil {
		t.Fatal("followed symlink")
	}
}
func TestBackupRestoreRevisionAndTaskProtection(t *testing.T) {
	s := managerFixture(t)
	old, _ := os.ReadFile(s.ConfigPath)
	id, e := s.backup(old, "手工")
	if e != nil {
		t.Fatal(e)
	}
	request(t, s, "PUT", "/settings", Edit{Revision: revision(t, s), Patch: common.Map{"central.name": "已修改"}})
	rev := revision(t, s)
	status, p := request(t, s, "POST", "/backups/"+id+"/preview", common.Map{"revision": rev})
	if status != 200 || len(common.A(p["changes"])) == 0 {
		t.Fatal(status, p)
	}
	request(t, s, "PUT", "/settings", Edit{Revision: rev, Patch: common.Map{"central.name": "又修改"}})
	status, _ = request(t, s, "POST", "/backups/"+id+"/restore", common.Map{"revision": rev})
	if status != 409 {
		t.Fatal(status)
	}
	_, newPreview := request(t, s, "POST", "/backups/"+id+"/preview", common.Map{"revision": revision(t, s)})
	status, p = request(t, s, "POST", "/backups/"+id+"/restore", common.Map{"revision": revision(t, s), "token": newPreview["token"]})
	if status != 200 {
		t.Fatal(status, p)
	}
	restored, _ := os.ReadFile(s.ConfigPath)
	var oldConfig, newConfig common.Map
	yaml.Unmarshal(old, &oldConfig)
	yaml.Unmarshal(restored, &newConfig)
	if string(common.JSON(oldConfig)) != string(common.JSON(newConfig)) {
		t.Fatal("restore changed configuration")
	}
	common.AtomicJSON(filepath.Join(s.StateDir, "state.json"), common.Map{"step": "central-go-ready"})
	status, _ = request(t, s, "PUT", "/settings", Edit{Revision: revision(t, s), Patch: common.Map{"central.name": "bad"}})
	if status != 409 {
		t.Fatal("modified pending task")
	}
}
func TestJobIdempotencyAndValidationBeforeSave(t *testing.T) {
	s := managerFixture(t)
	finished := make(chan struct{})
	s.execute = func(context.Context, string, string, string) error { <-finished; return nil }
	before := revision(t, s)
	bad := Start{Key: "invalid", Revision: before, Kind: "add-node", Node: "missing", Edit: &Edit{Revision: before, Patch: common.Map{"central.name": "must-not-save"}}}
	status, _ := request(t, s, "POST", "/jobs", bad)
	if status == 202 || revision(t, s) != before {
		t.Fatal("invalid task changed YAML")
	}
	in := Start{Key: "same-request", Revision: before, Kind: "apply"}
	status, first := request(t, s, "POST", "/jobs", in)
	if status != 202 {
		t.Fatal(status, first)
	}
	status, next := request(t, s, "POST", "/jobs", in)
	if status != 200 || first["id"] != next["id"] {
		t.Fatal(status, next)
	}
	status, _ = request(t, s, "PUT", "/settings", Edit{Revision: before, Patch: common.Map{"central.name": "cannot-save"}})
	if status != 409 {
		t.Fatal(status)
	}
	close(finished)
	for i := 0; i < 100; i++ {
		s.mu.Lock()
		done := !s.running
		s.mu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("job did not settle")
}
func TestLogRedactsSplitSecrets(t *testing.T) {
	s := managerFixture(t)
	w := lineWriter{writer: logWriter{s, "id", []string{"sensitive-string"}}}
	w.Write([]byte("output sensitive-"))
	w.Write([]byte("string\n"))
	w.close()
	var raw string
	s.DB.QueryRow("SELECT message FROM logs").Scan(&raw)
	if strings.Contains(raw, "sensitive") || !strings.Contains(raw, "已隐藏") {
		t.Fatal(raw)
	}
}
func TestNodeInheritanceAndNestedFieldSafety(t *testing.T) {
	s := managerFixture(t)
	c, _ := config.Load(s.ConfigPath)
	node := common.Clone(common.M(common.A(c.Raw["nodes"])[0]))
	node["monitor"] = common.Map{"roots": []string{"/extra"}}
	raw, _ := yaml.Marshal(yamlValue(common.Merge(c.Raw, common.Map{"nodes": []any{node, common.A(c.Raw["nodes"])[1]}})))
	os.WriteFile(s.ConfigPath, raw, 0600)
	id := common.S(node["id"])
	patch := common.Map{"id": id, "monitor": nil}
	next, _, e := prepare(s.ConfigPath, Edit{Revision: revision(t, s), Node: patch, NodeID: id})
	if e != nil {
		t.Fatal(e)
	}
	var parsed common.Map
	yaml.Unmarshal(next, &parsed)
	if _, ok := common.M(common.A(parsed["nodes"])[0])["monitor"]; ok {
		t.Fatal("inheritance did not remove override")
	}
	patch["ssh"] = common.Map{"username": "other-user"}
	if _, _, e = prepare(s.ConfigPath, Edit{Revision: revision(t, s), Node: patch, NodeID: id}); e == nil {
		t.Fatal("accepted unrelated SSH user")
	}
}

func TestNewNodeInheritsMonitorAndErrorsExplainFields(t *testing.T) {
	s := managerFixture(t)
	node := common.Map{"id": "ui-node", "name": "UI fixture", "host": "198.51.100.22", "enabled": true, "monitor": nil, "ssh": common.Map{"username": "root", "port": 22, "auth_method": "key", "private_key_path": "/root/.ssh/fixture", "password": ""}}
	edit := Edit{Revision: revision(t, s), Patch: common.Map{}, Node: node}
	status, v := request(t, s, "POST", "/settings/preview", edit)
	if status != 200 {
		t.Fatal(status, v)
	}
	status, v = request(t, s, "PUT", "/settings", edit)
	if status != 200 {
		t.Fatal(status, v)
	}
	loaded, e := config.Load(s.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	n := loaded.Selected("ui-node")
	if len(n) != 1 || len(common.SS(common.M(n[0]["monitor"])["roots"])) == 0 {
		t.Fatal("lost inherited roots", n)
	}
	node["ssh"] = common.Map{"username": "root", "port": 0, "auth_method": "key", "private_key_path": "/root/.ssh/fixture"}
	edit.NodeID = "ui-node"
	edit.Revision = revision(t, s)
	status, v = request(t, s, "POST", "/settings/preview", edit)
	if status != 400 || !strings.Contains(common.S(v["message"]), "ssh.port") || strings.Contains(common.S(v["message"]), "*config.Diagnostic") {
		t.Fatal(status, v)
	}
	status, v = request(t, s, "PUT", "/settings", Edit{Revision: "old", Patch: common.Map{}})
	if status != 409 || !strings.Contains(common.S(v["message"]), "刷新") {
		t.Fatal(status, v)
	}
}

func TestNodeAppendPreservesExistingNestedComments(t *testing.T) {
	s := managerFixture(t)
	b, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	var doc yaml.Node
	if e = yaml.Unmarshal(b, &doc); e != nil {
		t.Fatal(e)
	}
	root := doc.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "nodes" {
			first := root.Content[i+1].Content[0]
			first.Content[1].LineComment = "existing node identity"
			first.Content[2].HeadComment = "keep advanced node notes"
		}
	}
	b, e = yaml.Marshal(&doc)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(s.ConfigPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	edit := Edit{Revision: revision(t, s), Patch: common.Map{}, Node: common.Map{"id": "added", "host": "198.51.100.44", "name": "fixture", "enabled": false, "ssh": common.Map{"username": "root", "port": 22, "auth_method": "key", "private_key_path": "/root/.ssh/fixture"}}}
	updated, _, e := prepare(s.ConfigPath, edit)
	if e != nil {
		t.Fatal(e)
	}
	for _, note := range []string{"existing node identity", "keep advanced node notes"} {
		if !strings.Contains(string(updated), note) {
			t.Fatal("lost comment", note)
		}
	}
}

func TestEmailSecretEditsAndRedaction(t *testing.T) {
	s := managerFixture(t)
	edit := Edit{Revision: revision(t, s), Patch: common.Map{"email.password": "fixture-email-authorization", "email.recipients": []string{"a@example.com", "a@example.com"}}}
	status, v := request(t, s, "POST", "/settings/preview", edit)
	if status != 200 || strings.Contains(string(common.JSON(v)), "fixture-email-authorization") {
		t.Fatal(status, "secret in preview or preview failed")
	}
	status, _ = request(t, s, "PUT", "/settings", edit)
	if status != 200 {
		t.Fatal(status)
	}
	status, v = request(t, s, "GET", "/settings", nil)
	if status != 200 || strings.Contains(string(common.JSON(v)), "fixture-email-authorization") {
		t.Fatal("secret returned")
	}
	request(t, s, "PUT", "/settings", Edit{Revision: revision(t, s), Patch: common.Map{"email.password": ""}})
	b, e := os.ReadFile(s.ConfigPath)
	if e != nil || !strings.Contains(string(b), "fixture-email-authorization") {
		t.Fatal("blank password erased saved authorization")
	}
}
