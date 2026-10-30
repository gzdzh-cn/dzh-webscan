package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func fingerprintServer(t *testing.T) (int, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				c, _, _, e := ssh.NewServerConn(conn, config)
				if e == nil {
					c.Close()
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(signer.PublicKey())
}

type webDeploymentFixture struct {
	provisioningFixture
	api         *API
	worker      *webDeploymentWorker
	sessions    map[string]string
	port        int
	fingerprint string
}

func webDeployFixture(t *testing.T) webDeploymentFixture {
	t.Helper()
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	f.c.Executor.RulesFile = f.in.RulesFile
	mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET endpoint='127.0.0.1:19100' WHERE id=$1", f.in.Node)
	c := f.c
	c.Executor.Mode = "external"
	c.Executor.ConfigurationDirectory = ""
	c.Executor.RulesFile = ""
	c.NodePKI = NodePKIConfig{}
	c.DeploymentTrust.HelperFile = ""
	c.DeploymentTrust.NativeBundleFile = ""
	c.DeploymentTrust.ImageArchiveFile = ""
	a := NewAPI(f.s, c)
	sessions := map[string]string{}
	for _, user := range []string{"admin", "viewer"} {
		sessions[user] = token()
		mustHistoryExec(t, f.s.DB, `INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at) VALUES($1,$2,1,'web-csrf',clock_timestamp()+interval '1 hour')`, digest([]byte(sessions[user])), user)
	}
	w := &webDeploymentWorker{store: f.s, config: f.c, trust: f.t, instance: "web-test-executor"}
	for _, role := range []string{"executor", "deployment-preparations"} {
		mustHistoryExec(t, f.s.DB, `INSERT INTO v3_role_status(role,instance,heartbeat,details) VALUES($1,$2,clock_timestamp(),jsonb_build_object('manifest',$3::text,'vault',$4::text,'issuer',true,'rules',true))`, role, w.instance, f.t.release.SHA256(), f.t.vault.active)
	}
	port, fp := fingerprintServer(t)
	return webDeploymentFixture{f, a, w, sessions, port, fp}
}
func webCall(a *API, method, path, body, session, key string, secure bool, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "webscan_v3_session", Value: session})
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Idempotency-Key", key)
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	out := httptest.NewRecorder()
	a.ServeHTTP(out, r)
	return out
}
func (f webDeploymentFixture) call(method, path string, input any, key string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(input)
	return webCall(f.api, method, path, string(raw), f.sessions["admin"], key, true, "web-csrf")
}
func (f webDeploymentFixture) complete(t *testing.T, response *httptest.ResponseRecorder) deploymentPreparation {
	t.Helper()
	if response.Code != 202 {
		t.Fatal(response.Code, response.Body.String())
	}
	var p deploymentPreparation
	if json.Unmarshal(response.Body.Bytes(), &p) != nil {
		t.Fatal("bad receipt")
	}
	j, err := f.worker.claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if j.ID != p.ID {
		t.Fatal("wrong work claimed")
	}
	f.worker.execute(context.Background(), j)
	result, err := f.s.preparation(context.Background(), f.t.vault, "admin", p.ID)
	if err != nil || result.Status != "succeeded" {
		t.Fatal("preparation failed", result.Kind, result.Status, result.ErrorCode, err)
	}
	return result
}
func (f webDeploymentFixture) saveCredential(t *testing.T) deploymentPreparation {
	pin := f.complete(t, f.call("POST", "/api/v3/servers/node-a/ssh-fingerprint", map[string]any{"expected_version": 1, "ssh_port": f.port}, "fingerprint"))
	if pin.Result.Fingerprint != f.fingerprint {
		t.Fatal("wrong fingerprint")
	}
	return f.complete(t, f.call("POST", "/api/v3/servers/node-a/ssh-credential", webDeploymentInput{Expected: 1, SSHPort: f.port, Password: "never-log-this-password", FingerprintPreparation: pin.ID, FingerprintToken: pin.Result.FingerprintToken}, "credential"))
}
func TestWebDeploymentExternalAPIToDurableWorkerToJob(t *testing.T) {
	f := webDeployFixture(t)
	ctx := context.Background()
	if !f.api.deploymentAvailability(ctx).Available {
		t.Fatal("healthy external executor unavailable")
	}
	if f.api.Config.Executor.embedded() {
		t.Fatal("API starts embedded executor")
	}
	if f.api.Config.NodePKI.Enabled || f.api.Config.DeploymentTrust.HelperFile != "" {
		t.Fatal("private host artifacts in API")
	}
	f.saveCredential(t)
	body := map[string]any{"expected_version": 1, "kind": "install"}
	response := f.call("POST", "/api/v3/servers/node-a/deployment-preview", body, "prepare")
	if tableCount(t, f.s, "v3_deployment_jobs") != 0 {
		t.Fatal("preparation started service change")
	}
	prepared := f.complete(t, response)
	if prepared.Result.Preview == nil || prepared.Result.Preview.Target.Mode != "native" {
		t.Fatal("missing preview")
	}
	if len(prepared.Result.Preview.Token) != 64 || prepared.Result.Preview.Version != 1 {
		t.Fatal("unbound preview")
	}
	// Submission replay returns the same durable receipt, not a second worker run.
	replay := f.call("POST", "/api/v3/servers/node-a/deployment-preview", body, "prepare")
	if replay.Code != 202 || !sameProvisioningResponse(replay.Body.Bytes(), response.Body.Bytes()) {
		t.Fatal("prepare receipt replay", replay.Code, replay.Body.String())
	}
	in := webDeploymentInput{Expected: 1, Preparation: prepared.ID, PreviewToken: prepared.Result.Preview.Token}
	confirm := f.call("POST", "/api/v3/deployments", in, "confirm")
	result := f.complete(t, confirm)
	if result.Result.Job == "" || tableCount(t, f.s, "v3_deployment_jobs") != 1 {
		t.Fatal("missing actual job")
	}
	job, err := f.s.Deployment(ctx, result.Result.Job)
	if err != nil || job.Plan.BeforeBackup == "" || job.Plan.Request.RuntimeArtifact == nil {
		t.Fatal("missing protected immutable plan", err)
	}
	// A lost final response can be retried with the same key after job creation.
	replay = f.call("POST", "/api/v3/deployments", in, "confirm")
	if replay.Code != 202 || !sameProvisioningResponse(confirm.Body.Bytes(), replay.Body.Bytes()) {
		t.Fatal("confirm replay", replay.Code, replay.Body.String())
	}
	for _, table := range []string{"v3_deployment_preparations", "v3_deployment_private_inputs", "v3_deployment_jobs", "v3_deployment_logs", "v3_requests", "v3_audit"} {
		rows, err := f.s.DB.Query("SELECT row_to_json(t)::text FROM " + table + " t")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var text string
			if err = rows.Scan(&text); err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"never-log-this-password", prepared.Result.Preview.Token, "PRIVATE KEY"} {
				if strings.Contains(text, secret) {
					t.Fatal("secret in " + table)
				}
			}
		}
		rows.Close()
	}
}
func TestWebDeploymentStrictBoundaryAndReadiness(t *testing.T) {
	f := webDeployFixture(t)
	path := "/api/v3/servers/node-a/ssh-fingerprint"
	for _, tc := range []struct {
		name, session, body, csrf, key string
		secure                         bool
		want                           int
	}{
		{"anonymous", "", `{"expected_version":1}`, "web-csrf", "k", true, 401},
		{"viewer", f.sessions["viewer"], `{"expected_version":1}`, "web-csrf", "k", true, 403},
		{"csrf", f.sessions["admin"], `{"expected_version":1}`, "wrong", "k", true, 403},
		{"http", f.sessions["admin"], `{"expected_version":1}`, "web-csrf", "k", false, 403},
		{"key", f.sessions["admin"], `{"expected_version":1}`, "web-csrf", "", true, 400},
		{"command", f.sessions["admin"], `{"expected_version":1,"command":"whoami"}`, "web-csrf", "k", true, 400},
		{"duplicate", f.sessions["admin"], `{"expected_version":1,"expected_version":2}`, "web-csrf", "k", true, 400},
		{"alias", f.sessions["admin"], `{"Expected_version":1}`, "web-csrf", "k", true, 400},
		{"arbitrary target", f.sessions["admin"], `{"expected_version":1,"host":"example.test"}`, "web-csrf", "k", true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := webCall(f.api, "POST", path, tc.body, tc.session, tc.key, tc.secure, tc.csrf)
			if w.Code != tc.want {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	if tableCount(t, f.s, "v3_deployment_preparations") != 0 {
		t.Fatal("rejected input queued")
	}
	mustHistoryExec(t, f.s.DB, "UPDATE v3_role_status SET heartbeat=clock_timestamp()-interval '20 seconds'")
	if f.api.deploymentAvailability(context.Background()).Available {
		t.Fatal("stale worker reported available")
	}
	if w := f.call("POST", path, map[string]any{"expected_version": 1}, "stale"); w.Code != 503 {
		t.Fatal(w.Code)
	}
}
func TestWebDeploymentFingerprintExpiryChangedAndAccountBinding(t *testing.T) {
	for _, condition := range []string{"expiry", "revision", "wrong-token", "wrong-port", "changed"} {
		t.Run(condition, func(t *testing.T) {
			f := webDeployFixture(t)
			pin := f.complete(t, f.call("POST", "/api/v3/servers/node-a/ssh-fingerprint", map[string]any{"expected_version": 1, "ssh_port": f.port}, "pin"))
			in := webDeploymentInput{Expected: 1, SSHPort: f.port, Password: "not-a-real-password", FingerprintPreparation: pin.ID, FingerprintToken: pin.Result.FingerprintToken}
			switch condition {
			case "expiry":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_preparations SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", pin.ID)
			case "revision":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_accounts SET revision=revision+1 WHERE username='admin';UPDATE v3_sessions SET revision=revision+1 WHERE username='admin'")
			case "wrong-token":
				in.FingerprintToken = strings.Repeat("a", 64)
			case "wrong-port":
				in.SSHPort++
			case "changed":
				id, _, err := f.s.latestWebCredential(context.Background(), f.t.vault, "node-a")
				if err != nil {
					t.Fatal(err)
				}
				_ = id
				_, err = f.s.AddCredential(context.Background(), f.t.vault, "admin", "pin-changed", "node-a", 1, SSHCredential{Host: "127.0.0.1", Port: f.port, Fingerprint: "SHA256:" + strings.Repeat("A", 43), Password: "old"})
				if err != nil {
					t.Fatal(err)
				}
			}
			response := f.call("POST", "/api/v3/servers/node-a/ssh-credential", in, "replace")
			if response.Code != 202 {
				t.Fatal(response.Code, response.Body.String())
			}
			p, err := f.worker.claim(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			f.worker.execute(context.Background(), p)
			var status string
			if err = f.s.DB.QueryRow("SELECT status FROM v3_deployment_preparations WHERE id=$1", p.ID).Scan(&status); err != nil || status != "failed" {
				t.Fatal("invalid pin accepted", status, err)
			}
		})
	}
}
func TestWebDeploymentPreparationTakeoverAndBackupRestore(t *testing.T) {
	f := webDeployFixture(t)
	f.saveCredential(t)
	response := f.call("POST", "/api/v3/servers/node-a/deployment-preview", map[string]any{"expected_version": 1, "kind": "install"}, "takeover")
	if response.Code != 202 {
		t.Fatal(response.Code, response.Body.String())
	}
	p, err := f.worker.claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, "UPDATE v3_deployment_preparations SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", p.ID)
	other := *f.worker
	other.instance = "new-executor"
	next, err := other.claim(context.Background())
	if err != nil || next.Epoch <= p.Epoch {
		t.Fatal("takeover", err)
	}
	if f.worker.stage(context.Background(), p, "stale-worker") == nil {
		t.Fatal("stale writer accepted")
	}
	other.execute(context.Background(), next)
	result, err := f.s.preparation(context.Background(), f.t.vault, "admin", p.ID)
	if err != nil || result.Status != "succeeded" {
		t.Fatal("takeover result", result.ErrorCode, err)
	}
	backup, err := f.s.BackupPostgres(context.Background(), privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, restored, "v3_deployment_private_inputs") != 0 {
		t.Fatal("restored old capability")
	}
	var status string
	if err = restored.DB.QueryRow("SELECT status FROM v3_deployment_preparations WHERE id=$1", p.ID).Scan(&status); err != nil || status != "expired" {
		t.Fatal(status, err)
	}
}
func TestWebDeploymentSharedVaultMissingWrongPermissionsAndLegacyPaths(t *testing.T) {
	f := webDeployFixture(t)
	ctx := context.Background()
	for _, change := range []string{"missing", "wrong", "mode"} {
		t.Run(change, func(t *testing.T) {
			c := f.api.Config
			file := filepath.Join(privateTestDir(t), "vault.key")
			if change != "missing" {
				if err := os.WriteFile(file, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if change == "mode" {
				os.Chmod(file, 0644)
			}
			c.DeploymentTrust.VaultKeyFile = file
			a := NewAPI(f.s, c)
			if a.deploymentAvailability(ctx).Available {
				t.Fatal("bad Vault accepted")
			}
			w := webCall(a, "GET", "/api/v3/settings", "", f.sessions["admin"], "", true, "web-csrf")
			if w.Code != 503 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	root := privateTestDir(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(root, "key")
	if err = os.WriteFile(p, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	c := ExecutorConfig{SSHKeyDirectories: []string{root}}
	if _, err = controlledSSHKey(c, p); err == nil {
		t.Fatal("invalid key accepted")
	}
	if err = os.WriteFile(p, pem.EncodeToMemory(keyBlock), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = controlledSSHKey(c, p); err != nil {
		t.Fatal("valid controlled key refused", err)
	}
	if err = os.Chmod(p, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = controlledSSHKey(c, p); err == nil {
		t.Fatal("public key permissions accepted")
	}
	os.Remove(p)
	if err = os.Symlink(f.c.DeploymentTrust.VaultKeyFile, p); err != nil {
		t.Fatal(err)
	}
	if _, err = controlledSSHKey(c, p); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err = controlledSSHKey(c, "/etc/passwd"); err == nil {
		t.Fatal("outside directory read")
	}
}
