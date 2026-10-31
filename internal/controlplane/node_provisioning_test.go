package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"webscan/internal/common"
)

func nodeProvisioningFixture(t *testing.T) (*Store, configurationLocalFixture, *deploymentTrust, nodeProvisioningInput) {
	t.Helper()
	s, f := newSavedConfigurationStore(t)
	ctx := context.Background()
	n := nodeFixture("prepared-node")
	if _, err := s.SaveNode(ctx, "admin", "preparation-node", n, 0, f.c.Collector.Shards); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.c.NodePKI.AuthorityDirectory, "crls"), 0700); err != nil {
		t.Fatal(err)
	}
	localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "crls", "1.pem"), f.crl)
	credential := addCredential(t, s, f.v, n.ID)
	raw, err := s.IssueNodeCertificate(ctx, f.c, f.v, "admin", "preparation-certificate", NodeCertificateInput{Node: n.ID, Expected: 1})
	var identity NodeCertificateRecord
	if err != nil || json.Unmarshal(raw, &identity) != nil {
		t.Fatal("certificate", err)
	}
	rules := filepath.Join(f.f.root, "private-rules.yar")
	localWrite(t, rules, []byte("rule private_preparation_rule { condition: false }"))
	trust, err := loadDeploymentTrust(ctx, f.c.DeploymentTrust)
	if err != nil {
		t.Fatal(err)
	}
	in := nodeProvisioningInput{Node: n.ID, Expected: 1, Credential: credential, Identity: identity.ID, Collectors: []string{"collector-local"}, RulesFile: rules}
	return s, f, trust, in
}

func bindProvisioningForTest(t *testing.T, s *Store, f configurationLocalFixture, trust *deploymentTrust, in nodeProvisioningInput, key string) nodeProvisioningReceipt {
	t.Helper()
	raw, err := s.bindNodeProvisioning(context.Background(), f.c, trust, "admin", key, in)
	var r nodeProvisioningReceipt
	if err != nil || json.Unmarshal(raw, &r) != nil || !r.Configured || r.Node != in.Node || r.Generation != in.Generation+1 {
		t.Fatal("bind", err)
	}
	return r
}

func TestNodeProvisioningAtomicEncryptedBindingAndReplay(t *testing.T) {
	s, f, trust, in := nodeProvisioningFixture(t)
	r := bindProvisioningForTest(t, s, f, trust, in, "binding")
	replay := bindProvisioningForTest(t, s, f, trust, in, "binding")
	if replay != r || tableCount(t, s, "v3_node_provisioning") != 1 {
		t.Fatal("duplicate binding")
	}
	var db, audit string
	if err := s.DB.QueryRow(`SELECT row_to_json(p)::text FROM v3_node_provisioning p`).Scan(&db); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT string_agg(result::text,'') FROM v3_audit WHERE kind='bind-node-provisioning'`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	response, _ := json.Marshal(r)
	for _, raw := range []string{db, audit, string(response)} {
		for _, secret := range []string{in.Credential, in.Identity, in.RulesFile, "private_preparation_rule", credentialFixture().Password, "PRIVATE KEY"} {
			if strings.Contains(raw, secret) {
				t.Fatal("binding exposed private material")
			}
		}
	}
	if _, err := json.Marshal(nodeProvisioningMaterial{}); err == nil {
		t.Fatal("private material serializable")
	}
	before := r
	localWrite(t, in.RulesFile, []byte("rule replacement_rule { condition: true }"))
	if _, err := s.bindNodeProvisioning(context.Background(), f.c, trust, "admin", "binding", in); !errors.Is(err, ErrRequestConflict) {
		t.Fatal("replayed key accepted different material", err)
	}
	if _, err := s.bindNodeProvisioning(context.Background(), f.c, trust, "admin", "stale-binding", in); !errors.Is(err, ErrConflict) {
		t.Fatal("stale generation overwrote binding", err)
	}
	in.Generation = r.Generation
	r = bindProvisioningForTest(t, s, f, trust, in, "replace-binding")
	if r.ID == before.ID || r.Generation != 2 {
		t.Fatal("replacement did not rotate binding identity")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
	if _, err := s.bindNodeProvisioning(context.Background(), f.c, trust, "admin", "replace-binding", in); err == nil {
		t.Fatal("demoted administrator replayed binding")
	}
}

func TestNodeProvisioningValidationAndAtomicFailures(t *testing.T) {
	for _, kind := range []string{"wrong-node-credential", "wrong-node-identity", "collector", "rules-empty", "rules-large", "rules-symlink", "node-version", "generation", "audit", "binding-write", "migration"} {
		t.Run(kind, func(t *testing.T) {
			s, f, trust, in := nodeProvisioningFixture(t)
			switch kind {
			case "wrong-node-credential":
				in.Credential = "not-this-node"
			case "wrong-node-identity":
				in.Identity = "not-this-node"
			case "collector":
				in.Collectors = []string{"not-the-current-collector"}
			case "rules-empty":
				localWrite(t, in.RulesFile, nil)
			case "rules-large":
				localWrite(t, in.RulesFile, bytes.Repeat([]byte("x"), (512<<10)+1))
			case "rules-symlink":
				link := in.RulesFile + ".link"
				if err := os.Symlink(in.RulesFile, link); err != nil {
					t.Fatal(err)
				}
				in.RulesFile = link
			case "node-version":
				in.Expected++
			case "generation":
				in.Generation++
			case "audit":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_provisioning() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='bind-node-provisioning' THEN RAISE EXCEPTION 'isolated failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_provisioning BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_provisioning()`)
			case "binding-write":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_provisioning() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated failure';END$$;CREATE TRIGGER fail_provisioning BEFORE INSERT ON v3_node_provisioning FOR EACH ROW EXECUTE FUNCTION fail_provisioning()`)
			case "migration":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('fixture',$1)`, strings.Repeat("a", 64))
			}
			if _, err := s.bindNodeProvisioning(context.Background(), f.c, trust, "admin", "rejected-binding", in); err == nil {
				t.Fatal("invalid binding accepted")
			}
			var requests int
			if err := s.DB.QueryRow(`SELECT count(*) FROM v3_requests WHERE key='rejected-binding'`).Scan(&requests); err != nil || requests != 0 || tableCount(t, s, "v3_node_provisioning") != 0 {
				t.Fatal("failed binding left a partial commit", err)
			}
		})
	}
}

func TestNodeProvisioningConcurrentGenerationAndKeyRotation(t *testing.T) {
	s, f, trust, in := nodeProvisioningFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, key := range []string{"parallel-one", "parallel-two"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			_, err := s.bindNodeProvisioning(context.Background(), f.c, trust, "admin", key, in)
			errs <- err
		}(key)
	}
	wg.Wait()
	close(errs)
	passed := 0
	for err := range errs {
		if err == nil {
			passed++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal("concurrent binding", err)
		}
	}
	if passed != 1 {
		t.Fatal("generation did not fence concurrent replacement", passed)
	}
	_, keyFile := testVault(t)
	rotated, err := OpenVault(keyFile, f.c.DeploymentTrust.VaultKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, private, err := readNodeProvisioningTx(context.Background(), tx, rotated, in.Node)
	if err != nil || string(private.Rules) != "rule private_preparation_rule { condition: false }" {
		t.Fatal("retained key could not read binding", err)
	}
	clear(private.Rules)
	wrong, err := OpenVault(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = readNodeProvisioningTx(context.Background(), tx, wrong, in.Node); err == nil {
		t.Fatal("missing old key read binding")
	}
}

func TestNodeProvisioningSchema26BackupAndDisasterRestore(t *testing.T) {
	s, f, trust, in := nodeProvisioningFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, nodeHistoryRetirementTestDrop+`DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE IF EXISTS v3_deployment_recoveries;DROP TABLE v3_deployment_installations;DROP TABLE v3_node_provisioning;DELETE FROM v3_schema WHERE version>=27`)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema 26 upgraded without backup")
	}
	bad := filepath.Join(privateTestDir(t), "not-directory")
	localWrite(t, bad, []byte("test"))
	if err := s.Upgrade(ctx, bad); err == nil {
		t.Fatal("failed backup allowed migration")
	}
	if v, err := currentSchema(ctx, s.DB); err != nil || v != 26 {
		t.Fatal("failed migration changed schema", err)
	}
	if err := s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	r := bindProvisioningForTest(t, s, f, trust, in, "before-backup")
	path, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err = target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	tx, err := target.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	copy, material, err := readNodeProvisioningTx(ctx, tx, f.v, in.Node)
	if err != nil || copy != r || !bytes.Contains(material.Rules, []byte("private_preparation_rule")) {
		t.Fatal("disaster restore lost authenticated binding", err)
	}
	clear(material.Rules)
	var plain string
	if err = target.DB.QueryRow(`SELECT result::text FROM v3_audit WHERE kind='bind-node-provisioning'`).Scan(&plain); err != nil || common.S(common.M(mustCommonMap([]byte(plain)))["node"]) != in.Node {
		t.Fatal("binding audit not restored", err)
	}
}
