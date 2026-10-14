package management

import (
	"bytes"
	"context"
	"encoding/base64"
	"gopkg.in/yaml.v3"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
)

func secureRequest(t *testing.T, s *Service, path string, input any) (int, common.Map) {
	r := httptest.NewRequest("POST", path, bytes.NewReader(common.JSON(input)))
	r.Header.Set("X-Webscan-Secure", "true")
	r.Header.Set("X-Webscan-Owner", "admin")
	w := httptest.NewRecorder()
	s.Handler(w, r)
	v, e := common.Decode(w.Body.Bytes())
	if e != nil {
		t.Fatal(w.Body.String())
	}
	return w.Code, common.M(v)
}
func TestConfigBackupRedactionAgeImportAndTokenBinding(t *testing.T) {
	s := managerFixture(t)
	ctx := context.Background()
	raw, _ := os.ReadFile(s.ConfigPath)
	id, e := s.backup(raw, "手动")
	if e != nil {
		t.Fatal(e)
	}
	code, redacted := request(t, s, "POST", "/backups/"+id+"/export", common.Map{})
	text := common.S(redacted["content"])
	if code != 200 || strings.Contains(text, "protected-test-secret") || strings.Contains(text, "fixture-only-password") || strings.Contains(text, "192.0.2.1") || strings.Contains(text, "保留这条注释") {
		t.Fatal("leaked", code)
	}
	doc, e := parseDocument([]byte(text))
	if e != nil || len(doc.Omitted) == 0 {
		t.Fatal(e)
	}
	password := "Isolated-Age-Passphrase!"
	code, _ = request(t, s, "POST", "/backups/"+id+"/export", common.Map{"encrypted": true, "password": password, "confirm_password": password})
	if code == 200 {
		t.Fatal("HTTP credential export")
	}
	code, encrypted := secureRequest(t, s, "/backups/"+id+"/export", common.Map{"encrypted": true, "password": password, "confirm_password": password})
	if code != 200 {
		t.Fatal(encrypted)
	}
	ageBytes, e := base64.StdEncoding.DecodeString(common.S(encrypted["content"]))
	if e != nil || !bytes.HasPrefix(ageBytes, []byte("age-encryption.org/v1\n")) {
		t.Fatal("not standard age")
	}
	if _, e = decryptDocument(common.S(encrypted["content"]), "wrong"); e == nil {
		t.Fatal("wrong password")
	}
	before := revision(t, s)
	code, imported := secureRequest(t, s, "/backups/import", common.Map{"encrypted": true, "content": encrypted["content"], "password": password})
	if code != 201 || revision(t, s) != before {
		t.Fatal(code, imported)
	}
	code, preview := secureRequest(t, s, "/backups/"+common.S(imported["id"])+"/preview", common.Map{"revision": before})
	if code != 200 {
		t.Fatal(code, preview)
	}
	if can, _ := s.backupDeletable(ctx, common.S(imported["id"])); can {
		t.Fatal("unprotected preview")
	}
	code, _ = secureRequest(t, s, "/backups/"+common.S(imported["id"])+"/restore", common.Map{"revision": before, "token": preview["token"], "keep_credentials": false})
	if code == 200 {
		t.Fatal("option binding")
	}
	code, _ = request(t, s, "POST", "/backups/"+common.S(imported["id"])+"/restore", common.Map{"revision": before, "token": preview["token"]})
	if code == 200 {
		t.Fatal("owner binding")
	}
	s.DB.Exec("UPDATE config_backup_previews SET expires=0")
	code, _ = secureRequest(t, s, "/backups/"+common.S(imported["id"])+"/restore", common.Map{"revision": before, "token": preview["token"]})
	if code == 200 {
		t.Fatal("expired preview")
	}
	duplicate := []byte("format_version: 1\nformat_version: 1\ncreated_at: 2026-10-14T00:00:00Z\nconfiguration: {}\n")
	if _, e = parseDocument(duplicate); e == nil {
		t.Fatal("duplicate keys")
	}
}
func TestNodeCredentialsMergeByIDAndDeploymentArchiveIdempotence(t *testing.T) {
	target := common.Map{"nodes": []any{common.Map{"id": "b", "ssh": common.Map{"password": "backup-b"}}, common.Map{"id": "a", "ssh": common.Map{"password": "backup-a"}}}}
	current := common.Map{"nodes": []any{common.Map{"id": "a", "ssh": common.Map{"password": "current-a"}}, common.Map{"id": "b", "ssh": common.Map{"password": "current-b"}}}}
	mergeMissing(target, current, true)
	nodes := common.A(target["nodes"])
	if common.S(common.M(common.M(nodes[0])["ssh"])["password"]) != "current-b" {
		t.Fatal("array position credential match")
	}
	s := managerFixture(t)
	old := time.Now().Unix() - 172800
	s.DB.Exec("INSERT INTO jobs VALUES('old','same','apply','','complete',?,?,'rev','result')", old, old)
	s.DB.Exec("INSERT INTO logs(job,time,message) VALUES('old',?,'log')", old)
	j, e := s.Operations.Create(context.Background(), "root", "deployment-job", "delete-key", []string{"old"})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Operations.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	done, _ := s.Operations.Job(context.Background(), "root", j.ID)
	if done.Status != "complete" {
		t.Fatal(done)
	}
	code, list := request(t, s, "GET", "/jobs", nil)
	if code != 200 || len(common.A(list["items"])) != 0 {
		t.Fatal(code, list)
	}
	code, replay := request(t, s, "POST", "/jobs", Start{Key: "same", Kind: "apply", Revision: "rev"})
	if code != 200 || common.S(replay["id"]) != "old" {
		t.Fatal("retriggered archived task", replay)
	}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM logs").Scan(&n)
	if n != 0 {
		t.Fatal("logs retained")
	}
	var parsed common.Map
	b, _ := os.ReadFile(s.ConfigPath)
	if yaml.Unmarshal(b, &parsed) != nil {
		t.Fatal("configuration changed")
	}
}
