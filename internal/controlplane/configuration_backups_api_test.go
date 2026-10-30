package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigurationBackupTransportTrust(t *testing.T) {
	for _, tc := range []struct {
		name, peer, proto string
		proxies           []string
		tls, want         bool
	}{
		{"direct TLS", "192.0.2.1:1234", "", nil, true, true},
		{"plain", "127.0.0.1:1234", "", nil, false, false},
		{"local is not implicitly trusted", "127.0.0.1:1234", "https", nil, false, false},
		{"forged header", "192.0.2.5:1234", "https", []string{"127.0.0.1"}, false, false},
		{"trusted exact", "127.0.0.1:1234", "https", []string{"127.0.0.1"}, false, true},
		{"trusted subnet", "192.0.2.5:1234", "https", []string{"192.0.2.0/24"}, false, true},
		{"outside subnet", "192.0.3.5:1234", "https", []string{"192.0.2.0/24"}, false, false},
		{"trusted IPv6", "[::1]:1234", "https", []string{"::1"}, false, true},
		{"mapped IPv4", "[::ffff:127.0.0.1]:1234", "https", []string{"127.0.0.1"}, false, true},
		{"ambiguous chain", "127.0.0.1:1234", "https,http", []string{"127.0.0.1"}, false, false},
		{"plain proxy", "127.0.0.1:1234", "http", []string{"127.0.0.1"}, false, false},
		{"no broad trust", "192.0.2.1:1234", "https", []string{"0.0.0.0/0"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &API{}
			a.Config.Central.TrustedProxies = tc.proxies
			r := httptest.NewRequest("POST", "/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-Proto", tc.proto)
			r.Header.Set("Forwarded", "proto=https")
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := a.configurationSecureTransport(r); got != tc.want {
				t.Fatalf("transport trust=%v want %v", got, tc.want)
			}
			r.Header.Add("X-Forwarded-Proto", "https")
			if !tc.tls && a.configurationSecureTransport(r) {
				t.Fatal("duplicate forwarding headers trusted")
			}
		})
	}
	for _, raw := range []string{"0.0.0.0/0", "::/0", "localhost", "127.0.0.1:80", "192.0.2.1,127.0.0.1", "fe80::1%eth0"} {
		c := configurationBootstrapFixture(t)
		c.Central.TrustedProxies = []string{raw}
		if c.Validate() == nil {
			t.Fatalf("accepted invalid proxy %q", raw)
		}
	}
}

func configurationAPIFixture(t *testing.T) (*API, *Vault, map[string]string) {
	t.Helper()
	s, _, c := configurationBackupStoreFixture(t)
	v, keyPath := testVault(t)
	c.DeploymentTrust = DeploymentTrustConfig{VaultKeyFile: keyPath,
		PublicKeyFile: "/test/release.pub", ManifestFile: "/test/release.json",
		SignatureFile: "/test/release.sig", HelperFile: "/test/helper", NativeBundleFile: "/test/native.tar"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	a := NewAPI(s, c)
	// The private bootstrap must never contain this transient lease identity.
	a.Config.Central.Instance = "runtime-only-lease-owner"
	sessions := map[string]string{}
	for _, user := range []string{"admin", "operator", "viewer"} {
		value := token()
		mustHistoryExec(t, s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,$2,1,'configuration-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(value)), user)
		sessions[user] = value
	}
	return a, v, sessions
}

func configurationAPICall(a *API, method, path string, body io.Reader, session, csrf, key string, secure bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v3/configuration-backups"+path, body)
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Idempotency-Key", key)
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestConfigurationBackupAPIAuthenticationSnapshotAndRedaction(t *testing.T) {
	a, v, sessions := configurationAPIFixture(t)
	call := func(method, path, body, user, csrf, key string) *httptest.ResponseRecorder {
		return configurationAPICall(a, method, path, strings.NewReader(body), sessions[user], csrf, key, false)
	}
	for _, user := range []string{"", "operator", "viewer"} {
		want := 403
		if user == "" {
			want = 401
		}
		for _, method := range []string{"GET", "POST"} {
			if w := call(method, "", "{}", user, "configuration-csrf", "create"); w.Code != want {
				t.Fatalf("authorization %q %s=%d", user, method, w.Code)
			}
		}
	}
	if w := call("POST", "", "{}", "admin", "", "create"); w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	if w := call("POST", "", "{}", "admin", "configuration-csrf", ""); w.Code != 400 {
		t.Fatal("missing idempotency key accepted", w.Code)
	}
	w := call("POST", "", "{}", "admin", "configuration-csrf", "create")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	id := configurationBackupReceiptID(t, w.Body.Bytes(), nil)
	again := call("POST", "", "{}", "admin", "configuration-csrf", "create")
	if again.Code != 200 || canonicalBackupResponse(t, again.Body.Bytes()) != canonicalBackupResponse(t, w.Body.Bytes()) {
		t.Fatal("create replay changed receipt")
	}
	doc := readPrivateConfigurationBackup(t, a.Store, v, id)
	if doc.Bootstrap["central"].(map[string]any)["instance_id"] == "runtime-only-lease-owner" {
		t.Fatal("captured runtime lease identity")
	}
	w = call("GET", "?limit=1", "", "admin", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"restore_available":false`) || strings.Contains(w.Body.String(), "private-") {
		t.Fatal("unsafe or incomplete list", w.Code, w.Body.String())
	}
	w = call("GET", "/"+id+"/export", "", "admin", "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "private-stored") || !strings.Contains(w.Header().Get("Content-Disposition"), ".yaml") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("redacted export failed", w.Code)
	}
	if _, err := parseConfigurationDocument(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if count := tableCount(t, a.Store, "v3_configuration_backups"); count != 1 {
		t.Fatal("bad create count", count)
	}
	// Neither import mode accepts spoofed HTTPS, even when public_url is HTTPS.
	for _, path := range []string{"/import", "/import-age", "/" + id + "/export-age"} {
		r := httptest.NewRequest("POST", "/api/v3/configuration-backups"+path, strings.NewReader(`{}`))
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-CSRF-Token", "configuration-csrf")
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "https_required") {
			t.Fatal("insecure secret operation accepted", path, w.Code)
		}
	}
	if tableCount(t, a.Store, "v3_login_attempts") != 0 {
		t.Fatal("untrusted transport reached crypto admission")
	}
}

func TestConfigurationBackupAPIAgeRoundtripAndImportOnly(t *testing.T) {
	a, v, sessions := configurationAPIFixture(t)
	call := func(method, path string, body io.Reader, key string) *httptest.ResponseRecorder {
		return configurationAPICall(a, method, path, body, sessions["admin"], "configuration-csrf", key, true)
	}
	w := call("POST", "", strings.NewReader("{}"), "create")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	id := configurationBackupReceiptID(t, w.Body.Bytes(), nil)
	for _, input := range []string{`{"password":"short","confirm":"short"}`, `{"password":"isolated-backup-password","confirm":"different"}`} {
		if got := call("POST", "/"+id+"/export-age", strings.NewReader(input), ""); got.Code != 400 {
			t.Fatal("invalid password accepted", got.Code)
		}
	}
	const password = "isolated-backup-password"
	w = call("POST", "/"+id+"/export-age", strings.NewReader(`{"password":"`+password+`","confirm":"`+password+`"}`), "")
	if w.Code != 200 || !bytes.HasPrefix(w.Body.Bytes(), []byte("age-encryption.org/v1")) || strings.Contains(w.Body.String(), "private-stored") {
		t.Fatal("age export failed", w.Code)
	}
	encrypted := append([]byte{}, w.Body.Bytes()...)
	if _, err := decryptConfigurationDocument(encrypted, password); err != nil {
		t.Fatal("download isn't standard age", err)
	}
	for _, pw := range []string{"incorrect-backup-password", password} {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		file, _ := writer.CreateFormFile("file", "ignored-local-name.age")
		file.Write(encrypted)
		writer.WriteField("password", pw)
		writer.Close()
		r := httptest.NewRequest("POST", "/api/v3/configuration-backups/import-age", &body)
		r.Header.Set("Content-Type", writer.FormDataContentType())
		r.Header.Set("X-CSRF-Token", "configuration-csrf")
		r.Header.Set("Idempotency-Key", "import-"+pw)
		r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: sessions["admin"]})
		r.TLS = &tls.ConnectionState{}
		w = httptest.NewRecorder()
		a.ServeHTTP(w, r)
		want := 200
		if pw != password {
			want = 400
		}
		if w.Code != want || strings.Contains(w.Body.String(), password) || strings.Contains(w.Body.String(), "private-stored") {
			t.Fatal("import status/privacy", w.Code, want)
		}
		if pw == password {
			newID := configurationBackupReceiptID(t, w.Body.Bytes(), nil)
			if readPrivateConfigurationBackup(t, a.Store, v, newID).SettingsVersion != 5 {
				t.Fatal("imported payload changed")
			}
		}
	}
	redacted := call("GET", "/"+id+"/export", nil, "")
	w = call("POST", "/import", bytes.NewReader(redacted.Body.Bytes()), "import-public")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"needs_completion":true`) {
		t.Fatal("redacted import", w.Code, w.Body.String())
	}
	var version int
	a.Store.DB.QueryRow("SELECT version FROM v3_settings").Scan(&version)
	if version != 5 || tableCount(t, a.Store, "v3_nodes") != 1 || tableCount(t, a.Store, "v3_deployment_jobs") != 0 || tableCount(t, a.Store, "v3_notifications") != 0 {
		t.Fatal("import applied configuration")
	}
	var audit, receipts []byte
	if err := a.Store.DB.QueryRow(`SELECT COALESCE(json_agg(result)::text,'[]') FROM v3_audit`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.DB.QueryRow(`SELECT COALESCE(json_agg(response)::text,'[]') FROM v3_requests`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{audit, receipts} {
		if bytes.Contains(raw, []byte(password)) || bytes.Contains(raw, []byte("private-stored")) {
			t.Fatal("password/payload entered audit or receipts")
		}
	}
}

func TestConfigurationBackupCryptoAdmissionAcrossInstancesAndCancellation(t *testing.T) {
	s, _, _ := configurationBackupStoreFixture(t)
	ctx := context.Background()
	first, err := s.admitConfigurationCrypto(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	ctx2, cancel := context.WithCancel(ctx)
	second, err := (&Store{DB: s.DB}).admitConfigurationCrypto(ctx2, "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer second()
	if _, err = s.admitConfigurationCrypto(ctx, "admin"); !errors.Is(err, errConfigurationCryptoBusy) {
		t.Fatal("third crypto worker admitted", err)
	}
	cancel()
	if _, err = s.admitConfigurationCrypto(ctx, "admin"); !errors.Is(err, errConfigurationCryptoBusy) {
		t.Fatal("request cancellation freed a slot before synchronous crypto returned", err)
	}
	second()
	third, err := s.admitConfigurationCrypto(ctx, "admin")
	if err != nil {
		t.Fatal("cancelled operation leaked lock", err)
	}
	third()
	first()
	mustHistoryExec(t, s.DB, `UPDATE v3_login_attempts SET count=10 WHERE key='configuration-crypto:user:admin'`)
	if _, err = s.admitConfigurationCrypto(ctx, "admin"); !errors.Is(err, errConfigurationCryptoRate) {
		t.Fatal("persistent per-user limit failed", err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_login_attempts SET expires_at=clock_timestamp()-interval '1 second'`)
	release, err := s.admitConfigurationCrypto(ctx, "admin")
	if err != nil {
		t.Fatal("expired limit didn't reset", err)
	}
	release()
	mustHistoryExec(t, s.DB, `UPDATE v3_login_attempts SET count=60 WHERE key='configuration-crypto:global'`)
	if _, err = s.admitConfigurationCrypto(ctx, "admin"); !errors.Is(err, errConfigurationCryptoRate) {
		t.Fatal("global crypto limit failed", err)
	}
	var before, after int
	s.DB.QueryRow("SELECT sum(count) FROM v3_login_attempts").Scan(&before)
	if _, err = s.admitConfigurationCrypto(ctx, "operator"); !errors.Is(err, ErrConfigurationBackupPermission) {
		t.Fatal("operator reached crypto gate", err)
	}
	s.DB.QueryRow("SELECT sum(count) FROM v3_login_attempts").Scan(&after)
	if before != after {
		t.Fatal("denied actor changed counters")
	}
	// Reconstructing an API must not clear the persistent rate window.
	a := NewAPI(s, Config{})
	if _, err = a.Store.admitConfigurationCrypto(ctx, "admin"); !errors.Is(err, errConfigurationCryptoRate) {
		t.Fatal("restart cleared rate window", err)
	}
}

func TestConfigurationBackupCryptoSmallPoolKeepsBusinessConnection(t *testing.T) {
	s, v, c := configurationBackupStoreFixture(t)
	s.DB.SetMaxOpenConns(2)
	ctx := context.Background()
	release, err := s.admitConfigurationCrypto(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := s.admitConfigurationCrypto(ctx, "admin"); !errors.Is(err, errConfigurationCryptoBusy) {
		t.Fatal("second crypto operation consumed business connection", err)
	}
	raw, err := s.createConfigurationBackup(ctx, v, c, "admin", "small-pool-backup")
	id := configurationBackupReceiptID(t, raw, err)
	if _, err := s.exportEncryptedConfigurationBackup(ctx, v, "admin", id, "isolated-test-password", "isolated-test-password"); err != nil {
		t.Fatal("business operation failed under crypto admission", err)
	}
}

func TestConfigurationBackupMultipartRejectsAmbiguousAndOversizedFields(t *testing.T) {
	for _, fields := range [][]string{{"file"}, {"password"}, {"file", "file", "password"}, {"file", "password", "unknown"}, {"file", "password", "password"}} {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		for _, field := range fields {
			writer.WriteField(field, strings.Repeat("x", 12))
		}
		writer.Close()
		r := httptest.NewRequest("POST", "/", &body)
		r.Header.Set("Content-Type", writer.FormDataContentType())
		if _, _, err := readConfigurationAgeImport(httptest.NewRecorder(), r); err == nil {
			t.Fatal("accepted ambiguous multipart", fields)
		}
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	writer.WriteField("file", "synthetic-age")
	writer.WriteField("password", strings.Repeat("x", 1025))
	writer.Close()
	r := httptest.NewRequest("POST", "/", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	if _, _, err := readConfigurationAgeImport(httptest.NewRecorder(), r); err == nil {
		t.Fatal("oversized password accepted")
	}
}
