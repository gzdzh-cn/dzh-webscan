package central

import (
	"context"
	"crypto/tls"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/website"
)

func TestWebsiteVerificationInternalOnlyAndAfterPasswordChange(t *testing.T) {
	s := testStore(t)
	s.Config["alert_token"] = "internal-management-token"
	s.Config["https"] = common.Map{"allowed_sources": []string{"127.0.0.1/32"}}
	hash, _ := bcrypt.GenerateFromPassword([]byte("old-fixture-password"), bcrypt.MinCost)
	var e error
	s.Websites, e = website.New(s.DB, common.Map{"password_hash": string(hash), "admin_username": "admin"}, nil, &s.mu, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = website.ResetPassword(s.DB, "changed-fixture-password"); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		token  string
		public bool
		want   int
	}{{"", false, 401}, {"wrong", false, 401}, {"internal-management-token", false, 200}, {"internal-management-token", true, 404}} {
		r := httptest.NewRequest("POST", "/website-verify", strings.NewReader("{}"))
		r.RemoteAddr = "127.0.0.1:1234"
		if tc.public {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		s.Handler(w, r)
		if w.Code != tc.want {
			t.Fatal(w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "hash") {
			t.Fatal("credential leak")
		}
	}
	r := httptest.NewRequest("POST", "/api/website-verify", nil)
	w := httptest.NewRecorder()
	s.Websites.Handler(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("console exposed management")
	}
}
func TestConsistentBackupIncludesWebsiteFilesAndEffectiveAccount(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	s.Config["backup_dir"] = root
	s.Config["backup"] = common.Map{"include_sqlite": true, "include_runtime_config": true, "keep_days": 30}
	hash, _ := bcrypt.GenerateFromPassword([]byte("initial-fixture-password"), bcrypt.MinCost)
	s.Config["website_monitor"] = common.Map{"password_hash": string(hash), "admin_username": "admin"}
	var e error
	s.Websites, e = website.New(s.DB, common.Clone(common.M(s.Config["website_monitor"])), nil, &s.mu, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = website.ResetPassword(s.DB, "changed-fixture-password"); e != nil {
		t.Fatal(e)
	}
	common.Atomic(filepath.Join(root, "website-config", "fixture.json"), []byte("{}"), 0600)
	if e = s.Backup(); e != nil {
		t.Fatal(e)
	}
	files, _ := filepath.Glob(filepath.Join(root, "*", "website-config.tar.gz"))
	if len(files) != 1 {
		t.Fatal("website files not archived")
	}
	runtime, e := common.ReadJSON(filepath.Join(filepath.Dir(files[0]), "runtime.json"))
	if e != nil {
		t.Fatal(e)
	}
	if bcrypt.CompareHashAndPassword([]byte(common.S(common.M(runtime["website_monitor"])["password_hash"])), []byte("changed-fixture-password")) != nil {
		t.Fatal("backup retained old password")
	}
	if _, e = os.Stat(filepath.Join(root, "website-config", "fixture.json")); e != nil {
		t.Fatal("manual backup pruned")
	}
	if e = s.Websites.Verify(context.Background()); e != nil {
		t.Fatal(e)
	}
}
