package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/nodeconfig"
)

// Actual SQL, registry issuance, vault, saved source and artifact preparation.
// An explicitly synthetic preceding environment checkpoint selects the node
// phase. Tests using readinessFixtureRuntime also synthesize remote actions
// and collector observations, and do not attest real SSH installation.
func applicationPreparationFixture(t *testing.T, mode string, installed bool) (*Store, configurationLocalFixture, *deploymentTrust, privateConfigurationApplication, nodeProvisioningInput) {
	t.Helper()
	s, f, trust, p, in := applicationPreparationEnvironmentFixture(t, mode, installed)
	if _, err := s.checkpointConfigurationApplication(context.Background(), f.v, p, applicationComplete(p)); err != nil {
		t.Fatal(err)
	}
	p = claimApplicationForTest(t, s, f, "preparation-worker")
	p, err := s.armConfigurationApplication(context.Background(), f.v, p)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, trust, p, in
}

func applicationPreparationEnvironmentFixture(t *testing.T, mode string, installed bool) (*Store, configurationLocalFixture, *deploymentTrust, privateConfigurationApplication, nodeProvisioningInput) {
	t.Helper()
	s, f, trust, in := nodeProvisioningFixture(t)
	ctx := context.Background()
	n := nodeFixture(in.Node)
	if mode != "native" && mode != "disabled" {
		n.Mode = mode
		if _, err := s.SaveNode(ctx, "admin", "preparation-mode", n, 1, f.c.Collector.Shards); err != nil {
			t.Fatal(err)
		}
	}
	n, err := scanNode(s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, in.Node))
	if err != nil {
		t.Fatal(err)
	}
	if installed {
		if err = s.PutNode(ctx, n, n.Version, f.c.Collector.Shards); err != nil {
			t.Fatal(err)
		}
		mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET applied_version=version WHERE id=$1`, n.ID)
		mustHistoryExec(t, s.DB, `UPDATE v3_node_runtime r SET delivered_version=c.version FROM v3_node_configurations c WHERE r.node=$1 AND c.node=r.node AND c.id=r.snapshot`, n.ID)
		n, err = scanNode(s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, n.ID))
		if err != nil {
			t.Fatal(err)
		}
	}
	in.Expected = n.Version
	_ = bindProvisioningForTest(t, s, f, trust, in, "application-binding")
	n.Name = "new-saved-node-name"
	if mode == "disabled" {
		n.Enabled = false
	}
	doc, err := newConfigurationDocument(f.c, []byte(`{}`), 1, []Node{n}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stage, revision := savedRestoreFromDocument(t, s, f, doc)
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "preparation-save", stage.ID, revision.Generation)
	_ = savedReceipt(t, raw, err)
	raw, err = s.queueConfigurationApplication(ctx, f.v, f.c, "admin", "preparation-queue", stage.ID, revision.Generation)
	_ = applicationReceipt(t, raw, err)
	p := claimApplicationForTest(t, s, f, "preparation-environment")
	return s, f, trust, p, in
}

func TestConfigurationApplicationPreparationSavedModesAndArtifactReuse(t *testing.T) {
	for _, mode := range []string{"native", "docker"} {
		for _, installed := range []bool{false, true} {
			name := mode + "/install"
			if installed {
				name = mode + "/upgrade"
			}
			t.Run(name, func(t *testing.T) {
				s, f, trust, p, binding := applicationPreparationFixture(t, mode, installed)
				provider := configurationNodePreparer{s, f.c, trust}
				if err := os.Remove(binding.RulesFile); err != nil {
					t.Fatal(err)
				}
				first, err := provider.Prepare(context.Background(), p, binding.Node)
				if err != nil {
					t.Fatal("prepare without temporary source paths", err)
				}
				second, err := provider.Prepare(context.Background(), p, binding.Node)
				if err != nil || !sameDeploymentRequest(first, second) {
					t.Fatal("retry changed prepared artifact", err)
				}
				wantKind := "install"
				if installed {
					wantKind = "upgrade"
				}
				if first.Kind != wantKind || first.Node != binding.Node || first.Expected <= binding.Expected || first.Credential != binding.Credential || first.RuntimeArtifact == nil {
					t.Fatal("not the saved target", first.Kind, first.Expected)
				}
				wantSHA := trust.release.manifest.Native.SHA256
				if mode == "docker" {
					wantSHA = trust.release.manifest.Image[len(trust.release.manifest.Image)-64:]
				}
				if first.SHA256 != wantSHA || first.ManifestSHA256 != trust.release.SHA256() {
					t.Fatal("untrusted target")
				}
				path := filepath.Join(f.c.Executor.ConfigurationDirectory, first.RuntimeArtifact.SHA256, "node.json")
				raw, err := readTrustData(path, true, nodeconfig.MaxBytes)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(raw)
				m, err := nodeconfig.Decode(raw, time.Now())
				defer clear(m.Key)
				if err != nil || m.Node != binding.Node || m.Mode != mode || m.Version != first.Expected || !bytes.Contains(m.YARA, []byte("private_preparation_rule")) {
					t.Fatal("artifact lost material", err)
				}
				st, err := os.Stat(path)
				if err != nil || st.Mode().Perm() != 0600 {
					t.Fatal("unsafe artifact permissions", err)
				}
				if tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
					t.Fatal("preparation queued work or notifications")
				}
			})
		}
	}
}

func TestConfigurationApplicationPreparationFencesPublicationAgainstChanges(t *testing.T) {
	for _, kind := range []string{"lease", "epoch", "account", "source", "binding", "migration", "credential", "identity", "revoked", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, f, trust, p, in := applicationPreparationFixture(t, "native", false)
			provider := configurationNodePreparer{s, f.c, trust}
			first, err := provider.read(context.Background(), p, in.Node)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(first.material.Key)
			defer clear(first.material.YARA)
			switch kind {
			case "credential":
				credential := credentialFixture()
				credential.Password = "changed-after-private-write"
				key, nonce, sealed, err := trust.vault.seal(in.Credential, in.Node, 2, credential)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, s.DB, `UPDATE v3_credentials SET revision=2,key_id=$1,nonce=$2,ciphertext=$3 WHERE id=$4`, key, nonce, sealed, in.Credential)
			case "identity":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_certificates SET certificate='broken'::bytea WHERE id=$1`, in.Identity)
			case "revoked":
				crl, err := f.authority.Revoke(f.crl, [][]byte{first.material.Certificate}, time.Now().UTC().Truncate(time.Second), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				localWrite(t, f.c.Collector.RevocationFile, crl)
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := provider.publish(ctx, p, in.Node, first); err == nil {
					t.Fatal("cancelled publication accepted")
				}
				return
			case "lease":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, p.ID)
			case "epoch":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, p.ID)
				_ = claimApplicationForTest(t, s, f, "replacement-worker")
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "source":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET name='unapproved-change' WHERE id=$1`, in.Node)
			case "binding":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_provisioning SET generation=generation+1 WHERE node=$1`, in.Node)
			case "migration":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('fixture',$1)`, strings.Repeat("a", 64))
			}
			if request, err := provider.publish(context.Background(), p, in.Node, first); err == nil || request.RuntimeArtifact != nil {
				t.Fatal("stale read authorized an artifact", err)
			}
			files, err := filepath.Glob(filepath.Join(f.c.Executor.ConfigurationDirectory, "*", "node.json"))
			if err != nil || len(files) != 1 {
				t.Fatal("test did not reach post-I/O boundary", err)
			}
			if tableCount(t, s, "v3_deployment_jobs") != 0 {
				t.Fatal("failed preparation started child")
			}
		})
	}
}

func TestConfigurationApplicationPreparationRejectsChangedMaterialBeforeWriting(t *testing.T) {
	for _, kind := range []string{"missing-binding", "ciphertext", "nonce", "id", "credential", "identity", "revoked", "directory", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			s, f, trust, p, in := applicationPreparationFixture(t, "native", false)
			provider := configurationNodePreparer{s, f.c, trust}
			switch kind {
			case "missing-binding":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_node_provisioning`)
			case "ciphertext":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_provisioning SET ciphertext='broken'::bytea`)
			case "nonce":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_provisioning SET nonce='broken'::bytea`)
			case "id":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_provisioning SET id=$1`, token())
			case "credential":
				credential := credentialFixture()
				credential.Password = "replacement-private-password"
				key, nonce, sealed, err := trust.vault.seal(in.Credential, in.Node, 2, credential)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, s.DB, `UPDATE v3_credentials SET revision=2,key_id=$1,nonce=$2,ciphertext=$3 WHERE id=$4`, key, nonce, sealed, in.Credential)
			case "identity":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_certificates SET certificate='broken'::bytea WHERE id=$1`, in.Identity)
			case "revoked":
				identity, err := s.readNodeIdentity(context.Background(), f.c, f.v, in.Identity, in.Node)
				if err != nil {
					t.Fatal(err)
				}
				clear(identity.Key)
				crl, err := f.authority.Revoke(f.crl, [][]byte{identity.Certificate}, time.Now().UTC().Truncate(time.Second), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				localWrite(t, f.c.Collector.RevocationFile, crl)
			case "directory":
				if err := os.Chmod(f.c.Executor.ConfigurationDirectory, 0755); err != nil {
					t.Fatal(err)
				}
			case "rollback":
				p = rollbackApplicationNodesForTest(t, s, f, p)
			}
			if _, err := provider.Prepare(context.Background(), p, in.Node); err == nil {
				t.Fatal("invalid preparation accepted")
			}
			files, _ := filepath.Glob(filepath.Join(f.c.Executor.ConfigurationDirectory, "*", "node.json"))
			if len(files) != 0 {
				t.Fatal("invalid source wrote an artifact")
			}
		})
	}
}

func TestConfigurationApplicationPreparationDrivesChildAndReusesOriginalRollback(t *testing.T) {
	s, f, trust, p, in := applicationPreparationFixture(t, "native", false)
	ctx := context.Background()
	remote := &fakeDeploymentRuntime{}
	provider := configurationNodePreparer{s, f.c, trust}
	r := configurationNodesRuntime{store: s, vault: f.v, bootstrap: f.c, trust: trust, runtime: readinessFixtureRuntime{remote, t, s}, prepare: provider.Prepare}
	if _, err := r.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal("real provider did not drive child", err)
	}
	if tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("missing child")
	}
	if _, err := provider.Prepare(ctx, p, in.Node); err == nil {
		t.Fatal("linked child could be replaced by a newly prepared request")
	}
	if _, err := s.bindNodeProvisioning(ctx, f.c, trust, "admin", "blocked-rebind", in); !errors.Is(err, errConfigurationApplicationBusy) {
		t.Fatal("binding changed during application", err)
	}
	// Demonstrate that rollback uses the child plan/artifact, not newly read
	// provisioning. Simulated SQL removal is deliberately not a public action.
	mustHistoryExec(t, s.DB, `DELETE FROM v3_node_provisioning`)
	p = rollbackApplicationNodesForTest(t, s, f, p)
	r.prepare = nil
	if _, err := r.ApplyConfigurationPhase(ctx, p); err != nil {
		t.Fatal("rollback depended on mutable provisioning", err)
	}
	if tableCount(t, s, "v3_deployment_jobs") != 1 {
		t.Fatal("rollback created replacement child")
	}
}

func TestNodeProvisioningLocalCommandAndRuntimeFactory(t *testing.T) {
	s, f, trust, in := nodeProvisioningFixture(t)
	ctx := context.Background()
	path := filepath.Join(f.f.root, "bind.json")
	writeProvisioningInput(t, path, in)
	localWrite(t, f.c.Database.DSNFile, environmentDSN(t, s))
	config := filepath.Join(f.f.root, "control.yaml")
	raw, err := yaml.Marshal(f.c)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, config, raw)
	options := Options{Config: config, Action: "bind-node-provisioning", Username: "admin", RequestKey: "cli-binding", Source: path}
	var first, replay bytes.Buffer
	if err := Command(ctx, options, strings.NewReader(""), &first); err != nil {
		t.Fatal("command", err)
	}
	if err := Command(ctx, options, strings.NewReader(""), &replay); err != nil || !sameProvisioningResponse(first.Bytes(), replay.Bytes()) {
		t.Fatal("command replay", err)
	}
	if strings.Contains(first.String(), in.RulesFile) || strings.Contains(first.String(), in.Credential) || strings.Contains(first.String(), in.Identity) {
		t.Fatal("CLI leaked local material")
	}
	r, err := newConfigurationCompositeRuntime(ctx, s, trust.vault, f.c, f.c, []string{"all"}, &fakeDeploymentRuntime{})
	if err != nil || !r.valid() {
		t.Fatal("automatic runtime factory", err)
	}
	if _, err = newConfigurationCompositeRuntime(ctx, s, trust.vault, f.c, f.c, []string{"all"}, nil); err == nil {
		t.Fatal("incomplete runtime accepted")
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_configuration_applications") != 0 {
		t.Fatal("local bind or factory started deployment")
	}
}

func TestConfigurationApplicationPreparationEnvironmentBeforeRecovery(t *testing.T) {
	for _, kind := range []string{"bound", "missing", "credential", "lease", "disabled", "unchanged"} {
		t.Run(kind, func(t *testing.T) {
			mode := "native"
			if kind == "disabled" {
				mode = "disabled"
			}
			s, f, trust, p, in := applicationPreparationEnvironmentFixture(t, mode, false)
			provider := configurationNodePreparer{s, f.c, trust}
			switch kind {
			case "missing":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_node_provisioning`)
			case "credential":
				mustHistoryExec(t, s.DB, `UPDATE v3_credentials SET ciphertext='broken'::bytea WHERE id=$1`, in.Credential)
			case "lease":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_applications SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, p.ID)
			case "unchanged":
				// Explicitly synthetic existing application, not remote acceptance.
				tx, err := s.DB.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				snapshot, err := captureSavedNodeTx(context.Background(), tx, in.Node)
				if err != nil {
					t.Fatal(err)
				}
				if err = publishNodeRuntimeTx(context.Background(), tx, in.Node, snapshot, in.Expected+1); err != nil {
					t.Fatal(err)
				}
				if _, err = tx.Exec(`UPDATE v3_nodes SET applied_version=version WHERE id=$1`, in.Node); err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, s.DB, `DELETE FROM v3_node_provisioning`)
			case "disabled":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_node_provisioning`)
			}
			err := provider.checkEnvironment(context.Background(), p)
			wantOK := kind == "bound" || kind == "unchanged" || kind == "disabled"
			if (err == nil) != wantOK {
				t.Fatal("unexpected preparation preflight", kind, err)
			}
			if kind == "missing" || kind == "credential" {
				runtime, err := newConfigurationCompositeRuntime(context.Background(), s, f.v, f.c, f.c, []string{"all"}, &fakeDeploymentRuntime{})
				if err != nil {
					t.Fatal(err)
				}
				if err = s.executeConfigurationApplication(context.Background(), f.v, p, runtime); err == nil {
					t.Fatal("incomplete materials passed composition")
				}
				after := privateApplicationForTest(t, s, f.v, p.ID)
				if after.Status != "failed" || after.RecoveryRequired || after.ErrorCode != "environment-failed" || after.step != 0 {
					t.Fatal("preflight failure armed or advanced recovery")
				}
			}
			files, _ := filepath.Glob(filepath.Join(f.c.Executor.ConfigurationDirectory, "*", "node.json"))
			if len(files) != 0 || tableCount(t, s, "v3_deployment_jobs") != 0 {
				t.Fatal("environment preflight wrote artifacts or queued remote work")
			}
		})
	}
}

func TestConfigurationApplicationPreparationCredentialRewrapPreservesMaterial(t *testing.T) {
	s, f, trust, p, in := applicationPreparationFixture(t, "native", false)
	provider := configurationNodePreparer{s, f.c, trust}
	first, err := provider.read(context.Background(), p, in.Node)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first.material.Key)
	defer clear(first.material.YARA)
	key, nonce, sealed, err := trust.vault.seal(in.Credential, in.Node, 2, credentialFixture())
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_credentials SET revision=2,key_id=$1,nonce=$2,ciphertext=$3 WHERE id=$4`, key, nonce, sealed, in.Credential)
	if _, err = provider.publish(context.Background(), p, in.Node, first); err != nil {
		t.Fatal("same credential rewrapped under a new revision invalidated material", err)
	}
}
