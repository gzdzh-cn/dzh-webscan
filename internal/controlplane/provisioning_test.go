package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

type provisioningFixture struct {
	s         *Store
	c         Config
	t         *deploymentTrust
	in        deploymentPreparationInput
	ca        *nodepki.Authority
	collector nodepki.Bundle
	node      nodepki.Bundle
	crl       []byte
}

func localProvisioningFixture(t *testing.T, authorityStart ...time.Time) provisioningFixture {
	t.Helper()
	s := testStore(t)
	f := newTrustToolFixture(t)
	c := configurationBootstrapFixture(t)
	c.DeploymentTrust = f.config()
	c.Executor = ExecutorConfig{Enabled: true, ConfigurationDirectory: filepath.Join(f.root, "configurations")}
	if err := os.Mkdir(c.Executor.ConfigurationDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	trust, err := loadDeploymentTrust(context.Background(), c.DeploymentTrust)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	caNow := now
	if len(authorityStart) != 0 {
		caNow = authorityStart[0]
	}
	ca, err := nodepki.NewAuthority(caNow, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	n := nodeFixture("node-a")
	if err := s.PutNode(context.Background(), n, 0, 256); err != nil {
		t.Fatal(err)
	}
	node, err := ca.Issue(nodepki.Node, n.ID, []string{n.ServerName}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := ca.Issue(nodepki.Collector, "collector-a", nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ca.Revoke(nil, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Join(f.root, "node-identity")
	if err := os.Mkdir(identityDir, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		filepath.Join(identityDir, "ca.crt"):       node.CA,
		filepath.Join(identityDir, "identity.crt"): node.Certificate,
		filepath.Join(identityDir, "identity.key"): node.Key,
		filepath.Join(f.root, "collector.crt"):     collector.Certificate,
		filepath.Join(f.root, "collector.key"):     collector.Key,
		filepath.Join(f.root, "ca.crt"):            collector.CA,
		filepath.Join(f.root, "ca.crl"):            crl,
		filepath.Join(f.root, "rules.yar"):         []byte("rule isolated { condition: false }"),
	}
	for path, raw := range files {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c.Collector.CAFile = filepath.Join(f.root, "ca.crt")
	c.Collector.CertFile = filepath.Join(f.root, "collector.crt")
	c.Collector.KeyFile = filepath.Join(f.root, "collector.key")
	c.Collector.RevocationFile = filepath.Join(f.root, "ca.crl")
	c.Collector.RevocationStateDirectory = filepath.Join(f.root, "revocation-floor")
	mustHistoryExec(t, s.DB, "INSERT INTO v3_accounts(username,password_hash,role) VALUES('admin','test-only-hash','admin'),('viewer','test-only-hash','viewer')")
	id := addCredential(t, s, trust.vault, n.ID)
	in := deploymentPreparationInput{Node: n.ID, Expected: 1, Kind: "install", Credential: id, IdentityDirectory: identityDir, Collectors: []string{"collector-a"}, RulesFile: filepath.Join(f.root, "rules.yar")}
	return provisioningFixture{s, c, trust, in, ca, collector, node, crl}
}

func writeProvisioningInput(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func sameProvisioningResponse(a, b []byte) bool {
	var first, second any
	return json.Unmarshal(a, &first) == nil && json.Unmarshal(b, &second) == nil && reflect.DeepEqual(first, second)
}

func TestLocalProvisioningPrivateInputValidation(t *testing.T) {
	root := privateTestDir(t)
	path := filepath.Join(root, "request.json")
	for _, raw := range []string{
		`{"node":"a","node":"b"}`, `{"node":"a","unknown":"secret"}`, `{"node":"a"} {}`,
		`{"credential":{"password":"a","password":"b"}}`, `{"node":`,
		strings.Repeat("[", 34) + strings.Repeat("]", 34), strings.Repeat("x", (128<<10)+1),
	} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		var in credentialFileInput
		if err := provisioningInput(path, &in); !errors.Is(err, errProvisioning) {
			t.Fatal("invalid input accepted")
		}
	}
	writeProvisioningInput(t, path, credentialFileInput{Node: "node-a", Expected: 1, Credential: credentialFixture()})
	var in credentialFileInput
	if err := provisioningInput(path, &in); err != nil || in.Credential.Password != credentialFixture().Password {
		t.Fatal("valid private input refused", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := provisioningInput(path, &in); err == nil {
		t.Fatal("public credential input accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := provisioningInput(link, &in); err == nil {
		t.Fatal("symlink input accepted")
	}
}

func TestLocalProvisioningPrepareQueueAndCredentialReplay(t *testing.T) {
	f := localProvisioningFixture(t)
	ctx := context.Background()
	path := filepath.Join(filepath.Dir(f.c.Executor.ConfigurationDirectory), "request.json")
	writeProvisioningInput(t, path, credentialFileInput{Node: f.in.Node, Expected: 1, Credential: credentialFixture()})
	op := Options{Action: "store-ssh-credential", Username: "admin", RequestKey: "local-credential", Source: path}
	var first, replay bytes.Buffer
	if err := f.s.localProvisioningCommand(ctx, f.c, op, &first); err != nil {
		t.Fatal(err)
	}
	if err := f.s.localProvisioningCommand(ctx, f.c, op, &replay); err != nil || !sameProvisioningResponse(first.Bytes(), replay.Bytes()) {
		t.Fatal("credential replay changed identity", err)
	}
	var cred struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(first.Bytes(), &cred); err != nil || cred.ID == "" {
		t.Fatal("missing credential receipt", err)
	}
	f.in.Credential = cred.ID
	writeProvisioningInput(t, path, f.in)
	var out bytes.Buffer
	if err := f.s.localProvisioningCommand(ctx, f.c, Options{Action: "prepare-deployment", Username: "admin", Source: path}, &out); err != nil {
		t.Fatal(err)
	}
	var request DeploymentRequest
	if err := json.Unmarshal(out.Bytes(), &request); err != nil {
		t.Fatal(err)
	}
	if request.ManifestSHA256 != f.t.release.SHA256() || request.RuntimeArtifact == nil || tableCount(t, f.s, "v3_deployment_jobs") != 0 {
		t.Fatal("preparation created a task or lost release binding")
	}
	writeProvisioningInput(t, path, request)
	op = Options{Action: "queue-deployment", Username: "admin", RequestKey: "local-install", Source: path}
	first.Reset()
	replay.Reset()
	if err := f.s.localProvisioningCommand(ctx, f.c, op, &first); err != nil {
		t.Fatal(err)
	}
	if err := f.s.localProvisioningCommand(ctx, f.c, op, &replay); err != nil || !sameProvisioningResponse(first.Bytes(), replay.Bytes()) {
		t.Fatal("deployment replay changed task", err)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 1 {
		t.Fatal("duplicate task")
	}
	var plan, audit string
	if err := f.s.DB.QueryRow("SELECT plan::text FROM v3_deployment_jobs").Scan(&plan); err != nil {
		t.Fatal(err)
	}
	if err := f.s.DB.QueryRow("SELECT coalesce(string_agg(result::text,''),'') FROM v3_audit").Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{out.String(), first.String(), plan, audit} {
		for _, secret := range []string{credentialFixture().Password, "PRIVATE KEY", f.in.IdentityDirectory, f.in.RulesFile} {
			if strings.Contains(raw, secret) {
				t.Fatal("private material leaked")
			}
		}
	}
	var applied int
	if err := f.s.DB.QueryRow("SELECT applied_version FROM v3_nodes WHERE id=$1", f.in.Node).Scan(&applied); err != nil || applied != 0 {
		t.Fatal("queue marked deployment applied", err)
	}
	// Only enqueue; no executor or SSH service was started by these commands.
	var status string
	if err := f.s.DB.QueryRow("SELECT status FROM v3_deployment_jobs").Scan(&status); err != nil || status != "queued" {
		t.Fatal("queue executed deployment", err)
	}
}

func TestLocalProvisioningRejectsUntrustedAndChangedInputs(t *testing.T) {
	for _, name := range []string{"unrelated-ca", "collector-not-allowed", "wrong-node", "revoked-node", "revoked-collector", "bad-collector-key", "outdated-version"} {
		t.Run(name, func(t *testing.T) {
			f := localProvisioningFixture(t)
			now := time.Now().UTC().Truncate(time.Second)
			switch name {
			case "unrelated-ca":
				ca, err := nodepki.NewAuthority(now, 365*24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				b, err := ca.Issue(nodepki.Node, f.in.Node, []string{"192.0.2.1"}, now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				for name, raw := range map[string][]byte{"ca.crt": b.CA, "identity.crt": b.Certificate, "identity.key": b.Key} {
					if err := os.WriteFile(filepath.Join(f.in.IdentityDirectory, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "collector-not-allowed":
				f.in.Collectors = []string{"other-collector"}
			case "wrong-node":
				b, err := f.ca.Issue(nodepki.Node, "other-node", []string{"192.0.2.1"}, now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				for name, raw := range map[string][]byte{"identity.crt": b.Certificate, "identity.key": b.Key} {
					if err := os.WriteFile(filepath.Join(f.in.IdentityDirectory, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "revoked-node", "revoked-collector":
				cert := f.node.Certificate
				if name == "revoked-collector" {
					cert = f.collector.Certificate
				}
				crl, err := f.ca.Revoke(f.crl, [][]byte{cert}, now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.c.Collector.RevocationFile, crl, 0600); err != nil {
					t.Fatal(err)
				}
			case "bad-collector-key":
				if err := os.WriteFile(f.c.Collector.KeyFile, f.node.Key, 0600); err != nil {
					t.Fatal(err)
				}
			case "outdated-version":
				f.in.Expected = 2
			}
			if _, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, f.in); err == nil {
				t.Fatal("unsafe preparation accepted")
			}
			entries, err := os.ReadDir(f.c.Executor.ConfigurationDirectory)
			if err != nil || len(entries) != 0 {
				t.Fatal("failed preparation published private package", err)
			}
			if tableCount(t, f.s, "v3_deployment_jobs") != 0 {
				t.Fatal("failed preparation created task")
			}
		})
	}
}

func TestLocalProvisioningQueueRevalidatesArtifactsAndState(t *testing.T) {
	for _, name := range []string{"node-version", "settings", "manifest", "target", "tampered-file", "missing-artifact", "wrong-credential", "viewer", "disabled-executor", "migration", "new-crl", "rollback-crl", "changed-material"} {
		t.Run(name, func(t *testing.T) {
			f := localProvisioningFixture(t)
			ctx := context.Background()
			request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
			if err != nil {
				t.Fatal(err)
			}
			user := "admin"
			path := filepath.Join(f.c.Executor.ConfigurationDirectory, request.RuntimeArtifact.SHA256, "node.json")
			switch name {
			case "node-version":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET version=version+1 WHERE id=$1", f.in.Node)
			case "settings":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config='{"probe_seconds":120}' WHERE id=$1`, f.in.Node)
			case "manifest":
				request.ManifestSHA256 = strings.Repeat("c", 64)
			case "target":
				request.SHA256 = strings.Repeat("c", 64)
			case "tampered-file":
				if err := os.WriteFile(path, []byte("modified"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-artifact":
				request.RuntimeArtifact = nil
			case "wrong-credential":
				request.Credential = "unregistered-credential"
			case "viewer":
				user = "viewer"
			case "disabled-executor":
				f.c.Executor.Enabled = false
			case "migration":
				mustHistoryExec(t, f.s.DB, "INSERT INTO v3_migration_domains(domain,source) VALUES('fixture',$1)", strings.Repeat("a", 64))
			case "new-crl", "rollback-crl":
				newCRL, err := f.ca.Revoke(f.crl, nil, time.Now().UTC().Truncate(time.Second), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.c.Collector.RevocationFile, newCRL, 0600); err != nil {
					t.Fatal(err)
				}
				if name == "rollback-crl" {
					if _, err := nodepki.NewPersistentFileTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, f.c.Collector.RevocationStateDirectory, time.Now()); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(f.c.Collector.RevocationFile, f.crl, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "changed-material":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				m, err := nodeconfig.Decode(raw, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				m.Settings.ProbeSeconds = 120
				raw, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				a := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
				if _, err := writeNodeConfiguration(f.c.Executor.ConfigurationDirectory, a, raw); err != nil {
					t.Fatal(err)
				}
				request.RuntimeArtifact = &a
			}
			if _, err := f.s.queueLocalDeployment(ctx, f.c, f.t, user, "refused-task", request); err == nil {
				t.Fatal("unsafe task queued")
			}
			if tableCount(t, f.s, "v3_deployment_jobs") != 0 {
				t.Fatal("refused submission persisted task")
			}
		})
	}
}

func TestLocalProvisioningDockerTargetComesFromSignedManifest(t *testing.T) {
	f := localProvisioningFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET mode='docker' WHERE id=$1", f.in.Node)
	request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	if request.SHA256 != f.t.release.manifest.Image[len(f.t.release.manifest.Image)-64:] || request.SHA256 == f.t.release.manifest.Native.SHA256 {
		t.Fatal("Docker target was not bound to signed image")
	}
	if _, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "docker-install", request); err != nil {
		t.Fatal(err)
	}
	var plan string
	if err := f.s.DB.QueryRow("SELECT plan::text FROM v3_deployment_jobs").Scan(&plan); err != nil {
		t.Fatal(err)
	}
	var p DeploymentPlan
	if json.Unmarshal([]byte(plan), &p) != nil || p.Node.Mode != "docker" {
		t.Fatal("wrong deployment mode")
	}
	// Role revocation also blocks an idempotent receipt, not only new tasks.
	mustHistoryExec(t, f.s.DB, "UPDATE v3_accounts SET role='viewer' WHERE username='admin'")
	if _, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "docker-install", request); err == nil {
		t.Fatal("demoted account replayed task")
	}
}

func TestLocalProvisioningCommandsRequireAdminAndRequestKey(t *testing.T) {
	f := localProvisioningFixture(t)
	path := filepath.Join(filepath.Dir(f.c.Executor.ConfigurationDirectory), "credential.json")
	writeProvisioningInput(t, path, credentialFileInput{Node: f.in.Node, Expected: 1, Credential: credentialFixture()})
	for _, op := range []Options{
		{Action: "store-ssh-credential", Username: "viewer", RequestKey: "viewer-key", Source: path},
		{Action: "store-ssh-credential", Username: "unknown", RequestKey: "unknown-key", Source: path},
		{Action: "store-ssh-credential", Username: "admin", Source: path},
		{Action: "queue-deployment", Username: "admin", Source: path},
	} {
		var out bytes.Buffer
		if err := f.s.localProvisioningCommand(context.Background(), f.c, op, &out); err == nil || out.Len() != 0 {
			t.Fatal("unauthorized request accepted or produced output")
		}
	}
	if tableCount(t, f.s, "v3_credentials") != 1 || tableCount(t, f.s, "v3_deployment_jobs") != 0 {
		t.Fatal("rejected command mutated credentials or jobs")
	}
}

func TestLocalProvisioningConcurrentQueueCreatesOneTask(t *testing.T) {
	f := localProvisioningFixture(t)
	ctx := context.Background()
	request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan json.RawMessage, 12)
	errors := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "concurrent-install", request)
			if err != nil {
				errors <- err
				return
			}
			results <- raw
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal("concurrent queue failed", err)
	}
	var previous json.RawMessage
	for raw := range results {
		if previous != nil && !sameProvisioningResponse(previous, raw) {
			t.Fatal("different task receipts")
		}
		previous = raw
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 1 {
		t.Fatal("duplicate tasks")
	}
}

func TestLocalProvisioningCommandLoadsConfigAndConfirms(t *testing.T) {
	f := localProvisioningFixture(t)
	ctx := context.Background()
	root := filepath.Dir(f.c.Executor.ConfigurationDirectory)
	var schema string
	if err := f.s.DB.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if err != nil || (dsn.Scheme != "postgres" && dsn.Scheme != "postgresql") {
		t.Fatal("CLI test requires a PostgreSQL URL DSN")
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	f.c.Version = 3
	f.c.Central.Instance = "isolated-local-provisioner"
	f.c.Central.PublicURL = "https://control.example.test"
	f.c.Database.DSNFile = filepath.Join(root, "dsn")
	f.c.Metrics.WriteURL = "http://127.0.0.1:1"
	f.c.Metrics.QueryURL = "http://127.0.0.1:1"
	if err := os.WriteFile(f.c.Database.DSNFile, []byte(dsn.String()), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(f.c)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "control.yaml")
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "prepare.json")
	writeProvisioningInput(t, source, f.in)
	var out bytes.Buffer
	if err := Command(ctx, Options{Config: config, Action: "prepare-deployment", Username: "admin", Source: source}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	var request DeploymentRequest
	if err := json.Unmarshal(out.Bytes(), &request); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(root, "queue.json")
	writeProvisioningInput(t, requestPath, request)
	out.Reset()
	if binary := os.Getenv("WEBSCAN_V3_TEST_CLI"); binary != "" {
		cmd := exec.CommandContext(ctx, binary, "control-v3", "--config", config, "--action", "preview-deployment", "--username", "admin", "--source", requestPath)
		result, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal("actual preview CLI failed", err)
		}
		out.Write(result)
	} else if err := Command(ctx, Options{Config: config, Action: "preview-deployment", Username: "admin", Source: requestPath}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	var preview DeploymentPreview
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil || preview.Token == "" {
		t.Fatal("missing preview", err)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 0 {
		t.Fatal("preview created task")
	}
	confirmPath := filepath.Join(root, "confirm.json")
	writeProvisioningInput(t, confirmPath, deploymentConfirmationInput{Token: preview.Token})
	out.Reset()
	if err := Command(ctx, Options{Config: config, Action: "confirm-deployment", Username: "admin", Source: confirmPath, RequestKey: "cli-install"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, f.s, "v3_deployment_jobs") != 1 || tableCount(t, f.s, "v3_workers") != 0 {
		t.Fatal("CLI started workers or lost task")
	}
	if binary := os.Getenv("WEBSCAN_V3_TEST_CLI"); binary != "" {
		// Replay through the actual binary also verifies strict flag registration.
		cmd := exec.CommandContext(ctx, binary, "control-v3", "--config", config, "--action", "confirm-deployment", "--username", "admin", "--source", confirmPath, "--request-key", "cli-install")
		result, err := cmd.CombinedOutput()
		if err != nil || !sameProvisioningResponse(out.Bytes(), result) {
			t.Fatal("actual CLI replay failed", err)
		}
		t.Log("actual CLI flags, config, private input and account-bound preview and idempotent confirmation verified")
	}
}
