package website

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func loggedIn(t *testing.T, m *Monitor, password string) (*http.Cookie, string) {
	t.Helper()
	w := request(m, "POST", "/api/login", string(common.JSON(common.Map{"username": "admin", "password": password})), nil, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var v struct {
		CSRF string `json:"csrf_token"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &v); e != nil {
		t.Fatal(e)
	}
	return w.Result().Cookies()[0], v.CSRF
}
func TestPasswordPersistenceAllSessionsResetAndRateLimit(t *testing.T) {
	m := testMonitor(t)
	site := insertSite(t, m, "kept")
	c1, csrf := loggedIn(t, m, "fixture-password")
	c2, _ := loggedIn(t, m, "fixture-password")
	body := func(old, next, confirm string) string {
		return string(common.JSON(common.Map{"current_password": old, "new_password": next, "confirm_password": confirm}))
	}
	if w := request(m, "POST", "/api/account/password", body("fixture-password", "replacement-password", "replacement-password"), c1, ""); w.Code != 403 {
		t.Fatal("csrf")
	}
	for _, tc := range []struct{ old, next, confirm, field string }{{"wrong", "replacement-password", "replacement-password", "current_password"}, {"fixture-password", "short", "short", "new_password"}, {"fixture-password", "replacement-password", "different-password", "confirm_password"}} {
		w := request(m, "POST", "/api/account/password", body(tc.old, tc.next, tc.confirm), c1, csrf)
		if w.Code != 400 || !strings.Contains(w.Body.String(), tc.field) {
			t.Fatal(w.Body.String())
		}
	}
	w := request(m, "POST", "/api/account/password", body("fixture-password", "replacement-password", "replacement-password"), c1, csrf)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, c := range []*http.Cookie{c1, c2} {
		if w = request(m, "GET", "/api/session", "", c, ""); w.Code != 401 {
			t.Fatal("session survived")
		}
	}
	a, e := ReadAccount(m.DB)
	if e != nil || a.Revision != 2 || bcrypt.CompareHashAndPassword([]byte(a.Hash), []byte("replacement-password")) != nil {
		t.Fatal(a.Revision, e)
	}
	newConfig := common.Clone(m.Config)
	newConfig["password_hash"] = "invalid-old-yaml-hash"
	newConfig["admin_username"] = "old-yaml-user"
	reopened, e := New(m.DB, newConfig, m.Nodes, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	c, csrf := loggedIn(t, reopened, "replacement-password")
	for i := 0; i < 6; i++ {
		w = request(reopened, "POST", "/api/account/password", body("wrong", "another-password", "another-password"), c, csrf)
		if i == 5 && w.Code != 429 {
			t.Fatal("no change throttle")
		}
	}
	if e = ResetPassword(m.DB, "terminal-password"); e != nil {
		t.Fatal(e)
	}
	if w = request(reopened, "GET", "/api/session", "", c, ""); w.Code != 401 {
		t.Fatal("terminal reset did not revoke")
	}
	loggedIn(t, reopened, "terminal-password")
	if stateFor(t, m, site.ID).Status != "pending" {
		t.Fatal("site changed")
	}
	var seq int
	var name, path string
	m.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path)
	readonly, e := persist.OpenReadOnly(path)
	if e != nil {
		t.Fatal(e)
	}
	defer readonly.Close()
	if _, e = readonly.Exec("DELETE FROM websites"); e == nil {
		t.Fatal("discovery connection writable")
	}
}
func makeBackup(t *testing.T, m *Monitor, doc BackupDocument) Backup {
	t.Helper()
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	b, e := m.storeBackup(context.Background(), doc, "manual")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestBackupRoundTripMergeRevivalAndStaleResults(t *testing.T) {
	ctx := context.Background()
	m := testMonitor(t)
	unchanged := insertSite(t, m, "unchanged")
	updated := insertSite(t, m, "updated")
	revived := insertSite(t, m, "revived")
	other := insertSite(t, m, "other")
	runResult(t, m, unchanged, true, time.Now().Unix())
	kept := stateFor(t, m, unchanged.ID)
	m.DB.Exec("UPDATE websites SET deleted=1,version=version+1 WHERE id=?", revived.ID)
	m.DB.Exec("INSERT INTO website_incidents(site,kind,started,reason) VALUES(?,'outage',1,'history')", revived.ID)
	m.DB.Exec("INSERT INTO website_outbox(site,node,kind,message,created) VALUES(?,'node','outage','pending-message',1)", updated.ID)
	doc := BackupDocument{1, time.Now().UTC().Format(time.RFC3339), []SiteConfig{configuration(unchanged), configuration(updated), configuration(revived), {Name: "new", URL: "https://new.example.com/", Node: "missing", Paused: true}}}
	doc.Sites[1].Keyword = "required"
	b := makeBackup(t, m, doc)
	data, e := os.ReadFile(filepath.Join(m.backupDir(), b.ID+".json"))
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := parseBackup(data)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(data), "password") || strings.Contains(string(data), "pending-message") {
		t.Fatal("backup leaks runtime")
	}
	info, _ := os.Stat(filepath.Join(m.backupDir(), b.ID+".json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	preview, e := m.preview(ctx, parsed, b)
	if e != nil || preview.Added != 2 || preview.Updated != 1 || preview.Unchanged != 1 || len(preview.Unknown) != 1 {
		t.Fatal(preview, e)
	}
	if _, e = m.restore(ctx, parsed, b, preview.Token); e != nil {
		t.Fatal(e)
	}
	sites, e := m.sites(ctx)
	if e != nil || len(sites) != 5 {
		t.Fatal(len(sites), e)
	}
	if stateFor(t, m, unchanged.ID) != kept {
		t.Fatal("unchanged state lost")
	}
	var id int64
	m.DB.QueryRow("SELECT id FROM websites WHERE url=? AND deleted=0", revived.URL).Scan(&id)
	if id != revived.ID {
		t.Fatal("revival lost history id")
	}
	var node string
	m.DB.QueryRow("SELECT node FROM websites WHERE name='new'").Scan(&node)
	if node != "" {
		t.Fatal("unknown node kept")
	}
	var history, outbox, backups int
	m.DB.QueryRow("SELECT count(*) FROM website_incidents WHERE site=?", revived.ID).Scan(&history)
	m.DB.QueryRow("SELECT count(*) FROM website_outbox").Scan(&outbox)
	m.DB.QueryRow("SELECT count(*) FROM website_backups").Scan(&backups)
	if history != 1 || outbox != 1 || backups != 2 {
		t.Fatal(history, outbox, backups)
	}
	if e = m.apply(ctx, updated, Result{Time: time.Now().Unix(), OK: true}); e != nil {
		t.Fatal(e)
	}
	if stateFor(t, m, updated.ID).Last.Time != 0 {
		t.Fatal("stale task overwrote restored config")
	}
	if stateFor(t, m, other.ID).Last.Time != 0 {
		t.Fatal("unrelated changed")
	}
	preview, e = m.preview(ctx, parsed, b)
	if e != nil {
		t.Fatal(e)
	}
	m.DB.Exec("UPDATE websites SET name='changed',version=version+1 WHERE id=?", other.ID)
	if _, e = m.restore(ctx, parsed, b, preview.Token); e == nil {
		t.Fatal("stale preview accepted")
	}
	reopened, e := New(m.DB, m.Config, m.Nodes, nil, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = reopened.loadBackup(ctx, b.ID); e != nil {
		t.Fatal("backup restart", e)
	}
}
func TestBackupImportValidationPermissionsAndNoAutomaticRestore(t *testing.T) {
	m := testMonitor(t)
	c, csrf := loggedIn(t, m, "fixture-password")
	doc := BackupDocument{1, time.Now().UTC().Format(time.RFC3339), []SiteConfig{{Name: "site", URL: "https://example.com/"}}}
	w := request(m, "POST", "/api/backups/import", string(common.JSON(doc)), c, csrf)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	sites, _ := m.sites(context.Background())
	if len(sites) != 0 {
		t.Fatal("import restored")
	}
	if w = request(m, "POST", "/api/backups", "", c, ""); w.Code != 403 {
		t.Fatal("missing csrf")
	}
	if w = request(m, "GET", "/api/backups", "", nil, ""); w.Code != 401 {
		t.Fatal("missing auth")
	}
	var b Backup
	json.Unmarshal(request(m, "POST", "/api/backups", "", c, csrf).Body.Bytes(), &b)
	if w = request(m, "GET", "/api/backups/"+b.ID+"/export", "", c, ""); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), b.ID) {
		t.Fatal("export")
	}
	if w = request(m, "POST", "/api/backups/import", strings.Repeat(" ", backupLimit+1), c, csrf); w.Code != 413 {
		t.Fatal("limit", w.Code)
	}
	for _, mutate := range []func(*BackupDocument){func(d *BackupDocument) { d.Format = 99 }, func(d *BackupDocument) { d.Sites = append(d.Sites, d.Sites[0]) }, func(d *BackupDocument) { d.Sites[0].URL = "http://127.0.0.1/" }, func(d *BackupDocument) { d.Sites = make([]SiteConfig, 1001) }} {
		bad := BackupDocument{doc.Format, doc.Created, append([]SiteConfig{}, doc.Sites...)}
		mutate(&bad)
		if w = request(m, "POST", "/api/backups/import", string(common.JSON(bad)), c, csrf); w.Code != 400 {
			t.Fatal(w.Body.String())
		}
	}
	if w = request(m, "GET", "/api/backups/../../runtime.json/export", "", c, ""); w.Code == 200 {
		t.Fatal("path injection")
	}
}
func TestRestoreBackupFailureAndTransactionalFailure(t *testing.T) {
	ctx := context.Background()
	m := testMonitor(t)
	first := insertSite(t, m, "first")
	second := insertSite(t, m, "second")
	doc := BackupDocument{1, time.Now().UTC().Format(time.RFC3339), []SiteConfig{configuration(first), configuration(second)}}
	doc.Sites[0].Name = "first-new"
	doc.Sites[1].Name = "second-new"
	b := makeBackup(t, m, doc)
	p, _ := m.preview(ctx, doc, b)
	file := filepath.Join(t.TempDir(), "no-directory")
	os.WriteFile(file, []byte("full"), 0600)
	m.Config["backup_dir"] = file
	if _, e := m.restore(ctx, doc, b, p.Token); e == nil {
		t.Fatal("backup failure ignored")
	}
	m.Config["backup_dir"] = ""
	m.DB.Exec(fmt.Sprintf("CREATE TRIGGER reject_restore BEFORE UPDATE ON websites WHEN OLD.id=%d BEGIN SELECT RAISE(ABORT,'fixture failure'); END", second.ID))
	if _, e := m.restore(ctx, doc, b, p.Token); e == nil {
		t.Fatal("transaction failure ignored")
	}
	s, e := scanSite(m.DB.QueryRow("SELECT "+columns+" FROM websites WHERE id=?", first.ID))
	if e != nil || s.Name != first.Name {
		t.Fatal("partial merge", s, e)
	}
}
func TestMigrationSnapshotPreservesAllTablesAndFailsClosed(t *testing.T) {
	m := testMonitor(t)
	s := insertSite(t, m, "existing")
	runResult(t, m, s, false, 1)
	m.DB.Exec("CREATE TABLE file_events(id INTEGER PRIMARY KEY,content TEXT)")
	m.DB.Exec("INSERT INTO file_events VALUES(1,'existing-event')")
	m.DB.Exec("INSERT INTO tasks(node,event_id,target,payload,created,next_try) VALUES('node','existing','feishu','existing-message',1,1)")
	m.DB.Exec("DROP TABLE website_admin")
	m.DB.Exec("DROP TABLE website_backups")
	file := filepath.Join(t.TempDir(), "blocked")
	os.WriteFile(file, []byte(""), 0600)
	m.Config["backup_dir"] = file
	if _, e := New(m.DB, m.Config, m.Nodes, nil, true); e == nil {
		t.Fatal("migration without backup")
	}
	var n int
	m.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='website_admin'").Scan(&n)
	if n != 0 {
		t.Fatal("migration modified db")
	}
	dir := t.TempDir()
	m.Config["backup_dir"] = dir
	if _, e := New(m.DB, m.Config, m.Nodes, nil, true); e != nil {
		t.Fatal(e)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "website-migrations", "*.sqlite3"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	backup, e := persist.OpenReadOnly(files[0])
	if e != nil {
		t.Fatal(e)
	}
	defer backup.Close()
	for _, db := range []*sql.DB{m.DB, backup} {
		for _, table := range []string{"websites", "file_events", "tasks"} {
			if e = db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != 1 {
				t.Fatal(table, n, e)
			}
		}
	}
	if stateFor(t, m, s.ID).Failures != 1 {
		t.Fatal("state lost")
	}
}
func TestCertificateExactBoundaryExpiryReminderNetworkAndRenewal(t *testing.T) {
	ctx := context.Background()
	m := testMonitor(t)
	s := insertSite(t, m, "cert")
	now := time.Now().Unix()
	apply := func(stamp, expiry int64, certError string, observed bool) {
		t.Helper()
		if e := m.apply(ctx, s, Result{Time: stamp, OK: false, HTTP: 404, CertExpires: expiry, CertError: certError, CertObserved: observed, CertChecked: stamp, CertHost: "cert.example.com", CertApplicable: true}); e != nil {
			t.Fatal(e)
		}
	}
	count := func() int {
		var n int
		m.DB.QueryRow("SELECT count(*) FROM website_outbox WHERE kind LIKE 'certificate%'").Scan(&n)
		return n
	}
	apply(now, now+7*86400+1, "", true)
	if count() != 0 {
		t.Fatal("too early")
	}
	apply(now+1, now+1+7*86400, "", true)
	if count() != 1 {
		t.Fatal("exact boundary")
	}
	apply(now+2, now+7*86400, "", true)
	if count() != 1 {
		t.Fatal("duplicate")
	}
	apply(now+3, now+3, "证书校验失败", true)
	if count() != 2 || !stateFor(t, m, s.ID).CertExpired {
		t.Fatal("no immediate expired notice")
	}
	apply(now+4, 0, "网络失败", false)
	st := stateFor(t, m, s.ID)
	if st.Last.CertExpires != now+3 || !st.CertWarn || count() != 2 {
		t.Fatal("network lost cert or false recovery")
	}
	apply(now+86404, now+3, "证书校验失败", true)
	if count() != 3 {
		t.Fatal("daily reminder")
	}
	apply(now+86405, now+30*86400, "", true)
	if count() != 4 || stateFor(t, m, s.ID).CertWarn {
		t.Fatal("renewal")
	}
	if !strings.Contains(m.Metrics(ctx), "webscan_website_certificate_known") {
		t.Fatal("metrics")
	}
}
func tlsFixture(t *testing.T, expiry time.Time) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com", "first.example.com", "second.example.com"}, NotBefore: time.Now().Add(-30 * 24 * time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "first.example.com" {
			http.Redirect(w, r, "https://second.example.com/", 302)
			return
		}
		w.WriteHeader(404)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)
	return server, pool
}
func certificateProber(server *httptest.Server, pool *x509.CertPool) *prober {
	return &prober{lookup: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}, tls: &tls.Config{RootCAs: pool}}
}
func TestExpiredHandshakeAndFirstHTTPSRedirectMetadata(t *testing.T) {
	expired := time.Now().Add(-time.Hour)
	server, pool := tlsFixture(t, expired)
	p := certificateProber(server, pool)
	r := p.check(context.Background(), Site{URL: "https://example.com/"}, time.Second)
	if r.OK || r.CertExpires != expired.Unix() || r.CertHost != "example.com" || !r.CertObserved || r.CertError == "" {
		t.Fatal(r)
	}
	good, pool := tlsFixture(t, time.Now().Add(30*24*time.Hour))
	p = certificateProber(good, pool)
	r = p.check(context.Background(), Site{URL: "https://first.example.com/"}, time.Second)
	if r.HTTP != 404 || r.CertHost != "first.example.com" || r.CertExpires == 0 || r.OK {
		t.Fatal(r)
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://first.example.com/", 302) }))
	defer plain.Close()
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		target := good.Listener.Addr().String()
		if strings.HasSuffix(address, ":80") {
			target = plain.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	r = p.check(context.Background(), Site{URL: "http://example.com/"}, time.Second)
	if r.CertHost != "first.example.com" || r.CertExpires == 0 {
		t.Fatal(r)
	}
}

func TestRestoreLimitAndTamperedBackup(t *testing.T) {
	m := testMonitor(t)
	ctx := context.Background()
	tx, e := m.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 1000; i++ {
		if _, e = tx.Exec("INSERT INTO websites(name,url) VALUES(?,?)", fmt.Sprint(i), fmt.Sprintf("https://site%d.example.com/", i)); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	doc := BackupDocument{1, time.Now().UTC().Format(time.RFC3339), []SiteConfig{{Name: "extra", URL: "https://extra.example.com/"}}}
	b := makeBackup(t, m, doc)
	if _, e = m.preview(ctx, doc, b); e == nil {
		t.Fatal("merge limit ignored")
	}
	os.WriteFile(filepath.Join(m.backupDir(), b.ID+".json"), []byte("{}"), 0600)
	if _, _, e = m.loadBackup(ctx, b.ID); e == nil {
		t.Fatal("corrupt backup accepted")
	}
}

func TestKnownCertificateCrossesExpiryDuringNetworkFailure(t *testing.T) {
	m := testMonitor(t)
	s := insertSite(t, m, "network-cert")
	ctx := context.Background()
	now := time.Now().Unix()
	if e := m.apply(ctx, s, Result{Time: now, OK: true, CertExpires: now + 10, CertHost: "example.com", CertChecked: now, CertObserved: true}); e != nil {
		t.Fatal(e)
	}
	if e := m.apply(ctx, s, Result{Time: now + 11, OK: false, Reason: "网络失败"}); e != nil {
		t.Fatal(e)
	}
	st := stateFor(t, m, s.ID)
	if !st.CertExpired || st.Last.CertChecked != now {
		t.Fatal("known expiry lost")
	}
	var text string
	var n int
	m.DB.QueryRow("SELECT count(*) FROM website_outbox WHERE kind='certificate'").Scan(&n)
	m.DB.QueryRow("SELECT message FROM website_outbox WHERE kind='certificate' ORDER BY id DESC LIMIT 1").Scan(&text)
	if n != 2 || !strings.Contains(text, "最近一次") {
		t.Fatal(n, text)
	}
}

func TestManualBackupSupportsAllSitesBeyondImportLimit(t *testing.T) {
	m := testMonitor(t)
	doc := BackupDocument{1, time.Now().UTC().Format(time.RFC3339), []SiteConfig{}}
	for i := 0; i < 1000; i++ {
		doc.Sites = append(doc.Sites, SiteConfig{Name: fmt.Sprint(i), URL: fmt.Sprintf("https://site%d.example.com/?q=", i) + strings.Repeat("x", 1900), Keyword: strings.Repeat("字", 200)})
	}
	raw := common.JSON(doc)
	if len(raw) <= backupLimit {
		t.Fatal("fixture too small")
	}
	if _, e := parseBackup(raw); e == nil {
		t.Fatal("untrusted import exceeded limit")
	}
	b := makeBackup(t, m, doc)
	loaded, _, e := m.loadBackup(context.Background(), b.ID)
	if e != nil || len(loaded.Sites) != 1000 {
		t.Fatal("complete server backup failed", e)
	}
}
