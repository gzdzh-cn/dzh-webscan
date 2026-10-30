package controlplane

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

func enableRegistryIssuer(t *testing.T, f *provisioningFixture) {
	t.Helper()
	root := filepath.Dir(f.c.Executor.ConfigurationDirectory)
	dir := filepath.Join(root, "authority")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "crls"), 0700); err != nil {
		t.Fatal(err)
	}
	b, err := f.ca.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	for name, raw := range map[string][]byte{"ca.crt": b.CA, "ca.key": b.Key, "ca.crl": f.crl, "crls/1.pem": f.crl} {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.c.NodePKI = NodePKIConfig{Enabled: true, AuthorityDirectory: dir}
}

func issuedNode(t *testing.T, f provisioningFixture, key string) NodeCertificateRecord {
	t.Helper()
	raw, err := f.s.IssueNodeCertificate(context.Background(), f.c, f.t.vault, "admin", key, NodeCertificateInput{Node: f.in.Node, Expected: 1, LifetimeHours: 24})
	if err != nil {
		t.Fatal(err)
	}
	var record NodeCertificateRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.ID == "" {
		t.Fatal("missing certificate receipt", err)
	}
	return record
}

func TestPKIRegistryIssueReplayAndPrepareWithoutPlaintextKey(t *testing.T) {
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	ctx := context.Background()
	record := issuedNode(t, f, "node-issue")
	replay := issuedNode(t, f, "node-issue")
	if record.ID != replay.ID || tableCount(t, f.s, "v3_node_certificates") != 1 || tableCount(t, f.s, "v3_pki_authorities") != 1 {
		t.Fatal("duplicate certificate issued")
	}
	b, err := f.s.readNodeIdentity(ctx, f.c, f.t.vault, record.ID, f.in.Node)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	cert, err := provisioningCertificate(b.Certificate)
	if err != nil || digest(cert.Raw) != record.SHA256 || cert.SerialNumber.Text(16) != record.Serial || cert.VerifyHostname("192.0.2.1") != nil {
		t.Fatal("incorrect signed identity")
	}
	f.in.IdentityDirectory = ""
	f.in.IdentityID = record.ID
	request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "issued-install", request); err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	if err := f.s.DB.QueryRow("SELECT ciphertext FROM v3_node_certificates WHERE id=$1", record.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, b.Key) || bytes.Contains(encrypted, []byte("PRIVATE KEY")) {
		t.Fatal("plaintext node key in registry")
	}
	var audit, plan string
	if err := f.s.DB.QueryRow("SELECT string_agg(result::text,'') FROM v3_audit").Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if err := f.s.DB.QueryRow("SELECT plan::text FROM v3_deployment_jobs").Scan(&plan); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(record)
	for _, raw := range []string{audit, plan, string(metadata)} {
		for _, secret := range []string{"PRIVATE KEY", string(b.Key), f.c.NodePKI.AuthorityDirectory, f.in.RulesFile} {
			if strings.Contains(raw, secret) {
				t.Fatal("private key or local path leaked")
			}
		}
	}
	if _, err := f.s.readNodeIdentity(ctx, f.c, f.t.vault, record.ID, "other-node"); err == nil {
		t.Fatal("cross-node identity read")
	}
	_, newKeyFile := testVault(t)
	wrong, err := OpenVault(newKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.readNodeIdentity(ctx, f.c, wrong, record.ID, f.in.Node); err == nil {
		t.Fatal("wrong vault key opened identity")
	}
	rotated, err := OpenVault(newKeyFile, f.c.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.s.readNodeIdentity(ctx, f.c, rotated, record.ID, f.in.Node)
	if err != nil || !bytes.Equal(read.Key, b.Key) {
		t.Fatal("previous vault key could not read issued identity", err)
	}
	clear(read.Key)
	if err := f.s.RewrapNodeCertificate(ctx, rotated, record.ID, f.in.Node); err != nil {
		t.Fatal(err)
	}
	read, err = f.s.readNodeIdentity(ctx, f.c, wrong, record.ID, f.in.Node)
	if err != nil || !bytes.Equal(read.Key, b.Key) {
		t.Fatal("rewrapped identity still depends on old active vault key", err)
	}
	clear(read.Key)
}

func TestPKIRegistryConcurrentIssuersCommitOneCertificate(t *testing.T) {
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	var wg sync.WaitGroup
	results := make(chan json.RawMessage, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := f.s.IssueNodeCertificate(context.Background(), f.c, f.t.vault, "admin", "concurrent-cert", NodeCertificateInput{Node: f.in.Node, Expected: 1})
			if err != nil {
				failures <- err
			} else {
				results <- raw
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var previous json.RawMessage
	for raw := range results {
		if previous != nil && !sameProvisioningResponse(previous, raw) {
			t.Fatal("different issuance receipts")
		}
		previous = raw
	}
	if tableCount(t, f.s, "v3_node_certificates") != 1 {
		t.Fatal("duplicate leaf issued")
	}
	var audits int
	if err := f.s.DB.QueryRow("SELECT count(*) FROM v3_audit WHERE kind='issue-node-certificate'").Scan(&audits); err != nil || audits != 1 {
		t.Fatal("duplicate/missing issue audit", err)
	}
}

func TestPKIRegistryInvalidRequestsLeaveNoIssuerOrCertificate(t *testing.T) {
	for _, name := range []string{"disabled", "outdated", "viewer", "disabled-node", "invalid-hours", "wrong-ca", "ca-symlink", "invalid-key", "expired-crl", "migration", "database-failure"} {
		t.Run(name, func(t *testing.T) {
			f := localProvisioningFixture(t)
			enableRegistryIssuer(t, &f)
			in := NodeCertificateInput{Node: f.in.Node, Expected: 1}
			user := "admin"
			switch name {
			case "disabled":
				f.c.NodePKI.Enabled = false
			case "outdated":
				in.Expected = 2
			case "viewer":
				user = "viewer"
			case "disabled-node":
				mustHistoryExec(t, f.s.DB, "UPDATE v3_nodes SET enabled=false WHERE id=$1", f.in.Node)
			case "invalid-hours":
				in.LifetimeHours = 2161
			case "wrong-ca":
				other, err := nodepki.NewAuthority(time.Now(), 365*24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				b, err := other.Export()
				if err != nil {
					t.Fatal(err)
				}
				defer clear(b.Key)
				for name, raw := range map[string][]byte{"ca.crt": b.CA, "ca.key": b.Key} {
					if err := os.WriteFile(filepath.Join(f.c.NodePKI.AuthorityDirectory, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "ca-symlink":
				path := filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")
				link := filepath.Join(filepath.Dir(f.c.NodePKI.AuthorityDirectory), "key-copy")
				if err := os.Rename(path, link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(link, path); err != nil {
					t.Fatal(err)
				}
			case "invalid-key":
				if err := os.WriteFile(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key"), []byte("invalid-private-key"), 0600); err != nil {
					t.Fatal(err)
				}
			case "expired-crl":
				b, err := f.ca.Export()
				if err != nil {
					t.Fatal(err)
				}
				defer clear(b.Key)
				block, _ := pem.Decode(b.Key)
				key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				root, err := provisioningCertificate(b.CA)
				if err != nil {
					t.Fatal(err)
				}
				oldTime := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
				der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: oldTime, NextUpdate: oldTime.Add(time.Hour)}, root, key.(crypto.Signer))
				if err != nil {
					t.Fatal(err)
				}
				old := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
				for _, p := range []string{filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), filepath.Join(f.c.NodePKI.AuthorityDirectory, "crls/1.pem"), f.c.Collector.RevocationFile} {
					if err := os.WriteFile(p, old, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "migration":
				mustHistoryExec(t, f.s.DB, "INSERT INTO v3_migration_domains(domain,source) VALUES('fixture',$1)", strings.Repeat("a", 64))
			case "database-failure":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_node_certificate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated registry write failure'; END $$`)
				mustHistoryExec(t, f.s.DB, `CREATE TRIGGER reject_node_certificate BEFORE INSERT ON v3_node_certificates FOR EACH ROW EXECUTE FUNCTION reject_node_certificate()`)
			}
			if _, err := f.s.IssueNodeCertificate(context.Background(), f.c, f.t.vault, user, "refused-issue", in); err == nil {
				t.Fatal("invalid certificate request accepted")
			}
			if tableCount(t, f.s, "v3_node_certificates") != 0 || tableCount(t, f.s, "v3_pki_authorities") != 0 || tableCount(t, f.s, "v3_deployment_jobs") != 0 {
				t.Fatal("failed issuance left records or tasks")
			}
		})
	}
}

func TestPKIRegistryFloorRejectsIndependentStaleIssuerAndPreparedTask(t *testing.T) {
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	f.c.Collector.RevocationStateDirectory = "" // Prove database floor independently.
	record := issuedNode(t, f, "initial-issue")
	f.in.IdentityDirectory = ""
	f.in.IdentityID = record.ID
	request, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	crl, err := f.ca.Revoke(f.crl, nil, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), filepath.Join(f.c.NodePKI.AuthorityDirectory, "crls/2.pem"), f.c.Collector.RevocationFile} {
		if err := os.WriteFile(p, crl, 0600); err != nil {
			t.Fatal(err)
		}
	}
	issuedNode(t, f, "new-floor-issue")
	// Simulate a separate issuer with the same CA but an older local history.
	stale := filepath.Join(filepath.Dir(f.c.NodePKI.AuthorityDirectory), "stale-authority")
	if err := os.Mkdir(stale, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stale, "crls"), 0700); err != nil {
		t.Fatal(err)
	}
	ca, err := f.ca.Export()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ca.Key)
	for name, raw := range map[string][]byte{"ca.crt": ca.CA, "ca.key": ca.Key, "ca.crl": f.crl, "crls/1.pem": f.crl} {
		if err := os.WriteFile(filepath.Join(stale, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.c.NodePKI.AuthorityDirectory = stale
	if err := os.WriteFile(f.c.Collector.RevocationFile, f.crl, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.IssueNodeCertificate(context.Background(), f.c, f.t.vault, "admin", "stale-issuer", NodeCertificateInput{Node: f.in.Node, Expected: 1}); err == nil {
		t.Fatal("stale independent issuer lowered registry floor")
	}
	if _, err := f.s.queueLocalDeployment(context.Background(), f.c, f.t, "admin", "stale-task", request); err == nil {
		t.Fatal("stale task bypassed shared issuer floor")
	}
	if _, err := f.s.readNodeIdentity(context.Background(), f.c, f.t.vault, record.ID, f.in.Node); err == nil {
		t.Fatal("stale files bypassed registry read floor")
	}
	if tableCount(t, f.s, "v3_node_certificates") != 2 || tableCount(t, f.s, "v3_deployment_jobs") != 0 {
		t.Fatal("stale issuer changed durable state")
	}
}

func TestPKIRegistryPrivatePreparationAutoIssuesAndReusesCertificate(t *testing.T) {
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	f.in.IdentityDirectory = ""
	path := filepath.Join(filepath.Dir(f.c.Executor.ConfigurationDirectory), "prepare.json")
	writeProvisioningInput(t, path, f.in)
	op := Options{Action: "prepare-deployment", Username: "admin", Source: path, RequestKey: "auto-identity"}
	var first, replay bytes.Buffer
	if err := f.s.localProvisioningCommand(context.Background(), f.c, op, &first); err != nil {
		t.Fatal(err)
	}
	if err := f.s.localProvisioningCommand(context.Background(), f.c, op, &replay); err != nil || !sameProvisioningResponse(first.Bytes(), replay.Bytes()) {
		t.Fatal("auto issue preparation not repeatable", err)
	}
	if tableCount(t, f.s, "v3_node_certificates") != 1 || tableCount(t, f.s, "v3_deployment_jobs") != 0 {
		t.Fatal("preparation duplicated identity or deployed service")
	}
	var request DeploymentRequest
	if json.Unmarshal(first.Bytes(), &request) != nil || request.RuntimeArtifact == nil {
		t.Fatal("missing immutable package reference")
	}
	raw, err := os.ReadFile(filepath.Join(f.c.Executor.ConfigurationDirectory, request.RuntimeArtifact.SHA256, "node.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	m, err := nodeconfig.Decode(raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := provisioningCertificate(m.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("192.0.2.1"); err != nil {
		t.Fatal("auto identity does not match saved node")
	}
	op.RequestKey = ""
	if err := f.s.localProvisioningCommand(context.Background(), f.c, op, &bytes.Buffer{}); err == nil {
		t.Fatal("automatic issuance without stable request key")
	}
}

func TestPKIRegistryConfiguredExecutorRechecksTrustBeforeRemotePhase(t *testing.T) {
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	f.c.Central.Instance = "pki-executor-test"
	record := issuedNode(t, f, "executor-certificate")
	f.in.IdentityDirectory = ""
	f.in.IdentityID = record.ID
	ctx := context.Background()
	request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "executor-certificate-task", request); err != nil {
		t.Fatal(err)
	}
	job := claimDeployment(t, f.s, "pki-executor")
	runner, err := newDeploymentExecutor(ctx, f.s, f.c)
	if err != nil {
		t.Fatal(err)
	}
	runtime := runner.Runtime.(*SSHNodeRuntime)
	if _, err := runtime.request(ctx, job, "inspect"); err != nil {
		t.Fatal("valid registry task refused", err)
	}
	// Rotate revocation evidence after enqueueing; the old task must stop
	// before any SSH phase, even if its immutable artifact still hashes well.
	crl, err := f.ca.Revoke(f.crl, nil, time.Now().UTC().Truncate(time.Second), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.c.Collector.RevocationFile, crl, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.request(ctx, job, "inspect"); err == nil {
		t.Fatal("queued task ignored changed live trust")
	}
	if latest := reloadDeployment(t, f.s, job.ID); latest.Step != 0 || latest.Status != "running" {
		t.Fatal("validation advanced remote phase")
	}
}

func TestPKIRegistryBackupRestoreAndSchema11Migration(t *testing.T) {
	t.Run("registered-identity", func(t *testing.T) {
		f := localProvisioningFixture(t)
		enableRegistryIssuer(t, &f)
		record := issuedNode(t, f, "backup-identity")
		path, err := f.s.BackupPostgres(context.Background(), privateTestDir(t))
		if err != nil {
			t.Fatal(err)
		}
		restored := emptyTestStore(t)
		if err := restored.RestorePostgres(context.Background(), path); err != nil {
			t.Fatal(err)
		}
		b, err := restored.readNodeIdentity(context.Background(), f.c, f.t.vault, record.ID, f.in.Node)
		if err != nil {
			t.Fatal(err)
		}
		clear(b.Key)
		if tableCount(t, restored, "v3_node_certificates") != 1 || tableCount(t, restored, "v3_credentials") != 1 || tableCount(t, restored, "v3_accounts") != 2 {
			t.Fatal("backup omitted identity or existing business data")
		}
	})
	t.Run("schema11-backup-required", func(t *testing.T) {
		f := localProvisioningFixture(t)
		dropConfigurationBackupsForTest(t, f.s)
		mustHistoryExec(t, f.s.DB, "DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_deployment_previews;DROP INDEX v3_deployment_node_history;DROP TABLE v3_node_certificates;DROP TABLE v3_pki_authorities;DELETE FROM v3_schema WHERE version>=12")
		if err := f.s.Migrate(context.Background()); err == nil {
			t.Fatal("upgraded schema11 without backup")
		}
		bad := filepath.Join(privateTestDir(t), "not-a-directory")
		if err := os.WriteFile(bad, []byte("file"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := f.s.Upgrade(context.Background(), bad); err == nil {
			t.Fatal("backup failure allowed schema change")
		}
		if version, err := currentSchema(context.Background(), f.s.DB); err != nil || version != 11 {
			t.Fatal("failed upgrade changed schema")
		}
		dir := privateTestDir(t)
		if err := f.s.Upgrade(context.Background(), dir); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatal("missing consistent migration backup", err)
		}
		header, err := inspectPGBackup(filepath.Join(dir, entries[0].Name()))
		if err != nil || header.Version != 11 {
			t.Fatal("backup does not precede migration", err)
		}
		if version, err := currentSchema(context.Background(), f.s.DB); err != nil || version != SchemaVersion {
			t.Fatal("migration did not reach schema12", err)
		}
		if tableCount(t, f.s, "v3_accounts") != 2 || tableCount(t, f.s, "v3_credentials") != 1 || tableCount(t, f.s, "v3_nodes") != 1 {
			t.Fatal("migration changed existing records")
		}
		old := emptyTestStore(t)
		if err := old.RestorePostgres(context.Background(), filepath.Join(dir, entries[0].Name())); err != nil {
			t.Fatal(err)
		}
		if _, err := old.ReadCredential(context.Background(), f.t.vault, f.in.Credential, f.in.Node); err != nil {
			t.Fatal("old backup lost encrypted credential", err)
		}
	})
}

func TestPKIRegistryConfigurationAndAuthenticationBinding(t *testing.T) {
	for _, c := range []NodePKIConfig{{Enabled: true}, {Enabled: true, AuthorityDirectory: "relative"}, {AuthorityDirectory: "/"}, {AuthorityDirectory: "/tmp/../bad"}} {
		if c.validate() == nil {
			t.Fatal("invalid issuer config accepted")
		}
	}
	if err := (NodePKIConfig{}).validate(); err != nil {
		t.Fatal(err)
	}
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	record := issuedNode(t, f, "bound-key")
	mustHistoryExec(t, f.s.DB, "UPDATE v3_node_certificates SET id='rebound-certificate' WHERE id=$1", record.ID)
	if _, err := f.s.readNodeIdentity(context.Background(), f.c, f.t.vault, "rebound-certificate", f.in.Node); !errors.Is(err, errNodeIdentity) {
		t.Fatal("ciphertext was not bound to record identity", err)
	}
}

func TestPKIRegistryCommandIssuesAndPreparesFromPrivateConfig(t *testing.T) {
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	ctx := context.Background()
	root := filepath.Dir(f.c.Executor.ConfigurationDirectory)
	var schema string
	if err := f.s.DB.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if err != nil || (dsn.Scheme != "postgres" && dsn.Scheme != "postgresql") {
		t.Fatal("CLI test requires isolated PostgreSQL URL")
	}
	q := dsn.Query()
	q.Set("search_path", schema)
	dsn.RawQuery = q.Encode()
	f.c.Version = 3
	f.c.Central.Instance = "isolated-pki-cli"
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
	config := filepath.Join(root, "issuer.yaml")
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "issue.json")
	writeProvisioningInput(t, source, NodeCertificateInput{Node: f.in.Node, Expected: 1})
	op := Options{Config: config, Action: "issue-node-certificate", Username: "admin", Source: source, RequestKey: "cli-node-identity"}
	var out bytes.Buffer
	if err := Command(ctx, op, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if binary := os.Getenv("WEBSCAN_V3_TEST_CLI"); binary != "" {
		cmd := exec.CommandContext(ctx, binary, "control-v3", "--config", config, "--action", op.Action, "--username", "admin", "--source", source, "--request-key", op.RequestKey)
		result, err := cmd.CombinedOutput()
		if err != nil || !sameProvisioningResponse(out.Bytes(), result) {
			t.Fatal("actual CLI issuance replay failed", err)
		}
		t.Log("actual CLI issued/replayed registered identity using private config")
	}
	f.in.IdentityDirectory = ""
	writeProvisioningInput(t, source, f.in)
	op.Action = "prepare-deployment"
	out.Reset()
	if err := Command(ctx, op, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if binary := os.Getenv("WEBSCAN_V3_TEST_CLI"); binary != "" {
		cmd := exec.CommandContext(ctx, binary, "control-v3", "--config", config, "--action", op.Action, "--username", "admin", "--source", source, "--request-key", op.RequestKey)
		result, err := cmd.CombinedOutput()
		if err != nil || !sameProvisioningResponse(out.Bytes(), result) {
			t.Fatal("actual CLI automatic preparation replay failed", err)
		}
		t.Log("actual CLI automatically reused issued identity and immutable package")
	}
	if tableCount(t, f.s, "v3_node_certificates") != 1 || tableCount(t, f.s, "v3_deployment_jobs") != 0 || tableCount(t, f.s, "v3_workers") != 0 {
		t.Fatal("CLI duplicated identity or started deployment")
	}
}

func TestPKIRegistryRejectsImplicitAuthorityReplacement(t *testing.T) {
	f := localProvisioningFixture(t)
	enableRegistryIssuer(t, &f)
	issuedNode(t, f, "pin-authority")
	other := localProvisioningFixture(t)
	enableRegistryIssuer(t, &other)
	// Separate server-side files match one another, but must not replace this
	// cluster's already pinned root. Keep the original node and vault identity.
	other.s = f.s
	other.t.vault = f.t.vault
	if _, err := f.s.IssueNodeCertificate(context.Background(), other.c, f.t.vault, "admin", "replace-authority", NodeCertificateInput{Node: f.in.Node, Expected: 1}); err == nil {
		t.Fatal("different issuer root silently replaced cluster authority")
	}
	if tableCount(t, f.s, "v3_pki_authorities") != 1 || tableCount(t, f.s, "v3_node_certificates") != 1 {
		t.Fatal("failed root replacement changed registry")
	}
	if err := checkIssuerFloor(context.Background(), f.s.DB, nodeconfig.Material{CA: other.node.CA, CRL: other.crl}); err == nil {
		t.Fatal("offline identity bypassed pinned cluster root")
	}
}
