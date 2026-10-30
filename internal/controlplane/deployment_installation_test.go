package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/nodeops"
)

// SQL/lease/transaction evidence is real; remote installation digests here are
// synthetic. Real service lifecycle acceptance is recorded separately.
func installationFixture(t *testing.T, vaults ...*Vault) (*Store, *Vault, DeploymentJob, RemoteDeploymentCheckpoint) {
	t.Helper()
	return installationFixtureMode(t, "native", vaults...)
}

func installationFixtureMode(t *testing.T, mode string, vaults ...*Vault) (*Store, *Vault, DeploymentJob, RemoteDeploymentCheckpoint) {
	t.Helper()
	s := testStore(t)
	v, _ := testVault(t)
	if len(vaults) != 0 {
		v = vaults[0]
	}
	in := deploymentFixture(t, s)
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET mode=$2,config='{"monitor":{"roots":["/custom-monitor"]},"scan":{"clamav":{"enabled":true}}}' WHERE id=$1`, in.Node, mode)
	if mode == "docker" {
		in.SHA256 = strings.Repeat("c", 64)
	}
	in.ManifestSHA256 = strings.Repeat("c", 64)
	in.RuntimeArtifact = &ReleaseArtifact{SHA256: strings.Repeat("d", 64), Bytes: 2048}
	createDeployment(t, s, in, "installation-proof-job")
	j := claimDeployment(t, s, "installation-executor")
	ctx := context.Background()
	for j.Phase() != "finalize" {
		if j.Phase() == "backup" {
			if err := s.ArmDeploymentRecovery(ctx, j); err != nil {
				t.Fatal(err)
			}
		}
		if j.Phase() == "verify" {
			recordDeploymentReady(t, s, j)
		}
		if err := s.CompleteDeploymentPhase(ctx, j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, s, j.ID)
	}
	recordDeploymentReady(t, s, j)
	var configuration []byte
	if err := s.DB.QueryRow(`SELECT config FROM v3_node_configurations WHERE node=$1 AND id=$2`, j.Node, j.Plan.TargetRuntime).Scan(&configuration); err != nil {
		t.Fatal(err)
	}
	settings, err := nodeRuntimeSettings(configuration)
	if err != nil {
		t.Fatal(err)
	}
	spec := &nodeops.Spec{Mode: mode, MetricsPort: 19100, MonitorDirectories: settings.Monitor.Roots, ClamAV: settings.Scan.ClamAV.Enabled, ArtifactBytes: 1024, Release: in.Release, BundleSHA256: strings.Repeat("a", 64), RuntimeSHA256: in.RuntimeArtifact.SHA256, RuntimeBytes: in.RuntimeArtifact.Bytes, ConfigVersion: j.NodeVersion, ConfigSourceSHA256: j.Plan.ConfigDigest, ServerName: j.Plan.Node.ServerName}
	if mode == "docker" {
		spec.AgentImage = "docker.io/gzdzh/webscan-agent@sha256:" + in.SHA256
	}
	proof := checkpoint(j, "complete")
	proof.Spec, proof.Installation = spec, &nodeops.InstallationEvidence{CaptureSHA256: strings.Repeat("a", 64), ActiveSHA256: strings.Repeat("b", 64)}
	return s, v, j, proof
}

func TestDeploymentInstallationDockerBindsImmutableImage(t *testing.T) {
	for _, image := range []string{"valid", "tag", "different-digest", "native-fields"} {
		t.Run(image, func(t *testing.T) {
			s, v, j, proof := installationFixtureMode(t, "docker")
			switch image {
			case "tag":
				proof.Spec.AgentImage = "docker.io/gzdzh/webscan-agent:latest"
			case "different-digest":
				proof.Spec.AgentImage = "docker.io/gzdzh/webscan-agent@sha256:" + strings.Repeat("e", 64)
			case "native-fields":
				proof.Spec.Mode, proof.Spec.AgentImage = "native", ""
			}
			err := s.completeDeploymentPhase(context.Background(), j, v, &proof)
			if image == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := installationRow(t, s, v, j); err != nil {
					t.Fatal("Docker recovery evidence unreadable", err)
				}
			} else if err == nil || tableCount(t, s, "v3_deployment_installations") != 0 {
				t.Fatal("wrong image committed installation proof", err)
			}
		})
	}
}

func TestDeploymentInstallationLocksCollectorLeaseBeforeEvidenceForeignKey(t *testing.T) {
	s, v, j, proof := installationFixture(t)
	assertDeploymentLocksCollectorLeaseBeforeNode(t, s, j, func(ctx context.Context) error {
		return s.completeDeploymentPhase(ctx, j, v, &proof)
	})
	if _, err := installationRow(t, s, v, j); err != nil {
		t.Fatal("serialized finalization lost evidence", err)
	}
}

func installationRow(t *testing.T, s *Store, v *Vault, j DeploymentJob) (deploymentInstallation, error) {
	t.Helper()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	return readDeploymentInstallationTx(context.Background(), tx, v, j)
}

func TestDeploymentInstallationAtomicFinalizationAndAuthentication(t *testing.T) {
	s, v, j, proof := installationFixture(t)
	if err := s.completeDeploymentPhase(context.Background(), j, v, &proof); err != nil {
		t.Fatal(err)
	}
	row, err := installationRow(t, s, v, j)
	if err != nil || row.Evidence != *proof.Installation || row.Epoch != j.Epoch {
		t.Fatal("installation evidence missing", err)
	}
	if current := reloadDeployment(t, s, j.ID); current.Status != "succeeded" || current.RecoveryRequired {
		t.Fatal("not finalized atomically")
	}
	var applied, audits int64
	if err = s.DB.QueryRow(`SELECT applied_version FROM v3_nodes WHERE id=$1`, j.Node).Scan(&applied); err != nil || applied != j.NodeVersion {
		t.Fatal("applied version", applied, err)
	}
	if err = s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='deployment-installation-recorded' AND resource=$1`, j.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("audit missing", audits, err)
	}
	wrong, _ := testVault(t)
	if _, err = installationRow(t, s, wrong, j); !errors.Is(err, errDeploymentInstallation) {
		t.Fatal("wrong independent key accepted", err)
	}
	// Current saved intent may change; source proof remains bound to the old plan.
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET config='{"private":{"changed":true}}',version=version+1 WHERE id=$1`, j.Node)
	if _, err = installationRow(t, s, v, j); err != nil {
		t.Fatal("source proof depended on new draft", err)
	}
	path, err := s.BackupPostgres(context.Background(), privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if _, err = installationRow(t, restored, v, j); err != nil {
		t.Fatal("restored recovery proof invalid", err)
	}
}

func TestDeploymentInstallationFailureRollsBackEvidenceAuditAndSuccess(t *testing.T) {
	for _, failure := range []string{"record", "audit", "terminal", "not-ready", "lease", "lease-during-write"} {
		t.Run(failure, func(t *testing.T) {
			s, v, j, proof := installationFixture(t)
			switch failure {
			case "record":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_installation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic'; END$$;CREATE TRIGGER fail_installation BEFORE INSERT ON v3_deployment_installations FOR EACH ROW EXECUTE FUNCTION reject_installation()`)
			case "audit":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_installation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='deployment-installation-recorded' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END$$;CREATE TRIGGER fail_installation BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION reject_installation()`)
			case "terminal":
				mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_installation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.status='succeeded' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END$$;CREATE TRIGGER fail_installation BEFORE UPDATE ON v3_deployment_jobs FOR EACH ROW EXECUTE FUNCTION reject_installation()`)
			case "not-ready":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_node_readiness`)
			case "lease":
				mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, j.ID)
			case "lease-during-write":
				// The first fence succeeds; revoke its time window only after
				// proof insertion begins, before terminal/applied writes commit.
				mustHistoryExec(t, s.DB, `CREATE FUNCTION expire_installation_lease() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=NEW.job; RETURN NEW; END$$;CREATE TRIGGER expire_installation BEFORE INSERT ON v3_deployment_installations FOR EACH ROW EXECUTE FUNCTION expire_installation_lease()`)
			}
			if err := s.completeDeploymentPhase(context.Background(), j, v, &proof); err == nil {
				t.Fatal("failed write marked successful")
			} else if failure == "lease-during-write" && !errors.Is(err, ErrLeaseLost) {
				t.Fatal("final fence did not reject lease expiration during proof write", err)
			}
			if tableCount(t, s, "v3_deployment_installations") != 0 {
				t.Fatal("partial installation proof committed")
			}
			current := reloadDeployment(t, s, j.ID)
			if current.Status != "running" || current.Phase() != "finalize" || !current.RecoveryRequired {
				t.Fatal("partial terminal commit")
			}
			var n int
			if err := s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='deployment-installation-recorded'`).Scan(&n); err != nil || n != 0 {
				t.Fatal("partial audit", n, err)
			}
		})
	}
}

func TestDeploymentInstallationRejectsChangedReceipt(t *testing.T) {
	for _, change := range []string{"epoch", "phase", "job", "mode", "runtime", "roots", "source", "capture", "missing-spec", "missing-key"} {
		t.Run(change, func(t *testing.T) {
			s, v, j, proof := installationFixture(t)
			switch change {
			case "epoch":
				proof.Epoch++
			case "phase":
				proof.Phase = "verify"
			case "job":
				proof.Job = "other-task"
			case "mode":
				proof.Spec.Mode = "docker"
			case "runtime":
				proof.Spec.RuntimeSHA256 = strings.Repeat("e", 64)
			case "roots":
				proof.Spec.MonitorDirectories = []string{"/other"}
			case "source":
				proof.Spec.ConfigSourceSHA256 = strings.Repeat("e", 64)
			case "capture":
				proof.Installation.CaptureSHA256 = "invalid"
			case "missing-spec":
				proof.Spec = nil
			case "missing-key":
				v = nil
			}
			if err := s.completeDeploymentPhase(context.Background(), j, v, &proof); err == nil {
				t.Fatal("mismatched receipt committed")
			}
			if tableCount(t, s, "v3_deployment_installations") != 0 || reloadDeployment(t, s, j.ID).Status != "running" {
				t.Fatal("rejected receipt changed state")
			}
		})
	}
}

func TestDeploymentInstallationRejectsStoredEvidenceDrift(t *testing.T) {
	for _, damage := range []string{"capture_sha256", "active_sha256", "plan_digest", "proof", "spec", "recorded_epoch", "node"} {
		t.Run(damage, func(t *testing.T) {
			s, v, j, proof := installationFixture(t)
			if err := s.completeDeploymentPhase(context.Background(), j, v, &proof); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "spec":
				mustHistoryExec(t, s.DB, `UPDATE v3_deployment_installations SET spec=spec||'{"unknown":true}'::jsonb`)
			case "recorded_epoch":
				mustHistoryExec(t, s.DB, `UPDATE v3_deployment_installations SET recorded_epoch=recorded_epoch+1`)
			case "node":
				if err := s.PutNode(context.Background(), nodeFixture("other-node"), 0, 256); err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, s.DB, `UPDATE v3_deployment_installations SET node='other-node'`)
			default:
				mustHistoryExec(t, s.DB, `UPDATE v3_deployment_installations SET `+damage+`=repeat('f',64)`)
			}
			if _, err := installationRow(t, s, v, j); !errors.Is(err, errDeploymentInstallation) {
				t.Fatal("stored drift accepted", err)
			}
		})
	}
}

func TestDeploymentInstallationSchema27UpgradeNeedsConsistentBackup(t *testing.T) {
	s := testStore(t)
	mustHistoryExec(t, s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE IF EXISTS v3_deployment_recoveries;DROP TABLE v3_deployment_installations;DELETE FROM v3_schema WHERE version>=28`)
	if err := s.Migrate(context.Background()); err == nil {
		t.Fatal("upgraded without backup")
	}
	blocked := filepath.Join(privateTestDir(t), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(context.Background(), blocked); err == nil {
		t.Fatal("upgraded after backup failure")
	}
	if version, err := currentSchema(context.Background(), s.DB); err != nil || version != 27 {
		t.Fatal("failed backup changed schema", version, err)
	}
	if err := s.Upgrade(context.Background(), privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if version, err := currentSchema(context.Background(), s.DB); err != nil || version != SchemaVersion {
		t.Fatal(version, err)
	}
	if tableCount(t, s, "v3_deployment_installations") != 0 {
		t.Fatal("invented legacy installation proof")
	}
	if _, err := installationRow(t, s, nil, DeploymentJob{ID: "unknown"}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
}

func TestDeploymentInstallationRejectsImmutableSnapshotDrift(t *testing.T) {
	for _, change := range []string{"config", "endpoint", "name"} {
		t.Run(change, func(t *testing.T) {
			s, v, j, proof := installationFixture(t)
			if err := s.completeDeploymentPhase(context.Background(), j, v, &proof); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "config":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_configurations SET config='{}' WHERE id=$1`, j.Plan.TargetRuntime)
			case "endpoint":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_configurations SET endpoint='192.0.2.3:19100' WHERE id=$1`, j.Plan.TargetRuntime)
			case "name":
				mustHistoryExec(t, s.DB, `UPDATE v3_node_configurations SET name='changed' WHERE id=$1`, j.Plan.TargetRuntime)
			}
			if _, err := installationRow(t, s, v, j); !errors.Is(err, errDeploymentInstallation) {
				t.Fatal("changed immutable source snapshot accepted", err)
			}
		})
	}
}

func TestDeploymentInstallationReplayAndKeyRotation(t *testing.T) {
	v, oldPath := testVault(t)
	s, v, j, proof := installationFixture(t, v)
	ctx := context.Background()
	// An exact duplicate inside a transaction is harmless; changed proof must
	// fail without overwriting the authenticated first receipt.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = recordDeploymentInstallationTx(ctx, tx, v, j, proof); err != nil {
		t.Fatal(err)
	}
	if err = recordDeploymentInstallationTx(ctx, tx, v, j, proof); err != nil {
		t.Fatal("exact replay rejected", err)
	}
	changed := proof
	changed.Installation = &nodeops.InstallationEvidence{CaptureSHA256: strings.Repeat("e", 64), ActiveSHA256: proof.Installation.ActiveSHA256}
	if err = recordDeploymentInstallationTx(ctx, tx, v, j, changed); !errors.Is(err, errDeploymentInstallation) {
		t.Fatal("conflicting replay accepted", err)
	}
	var audits int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_audit WHERE kind='deployment-installation-recorded'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("duplicate audit", audits, err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_, nextPath := testVault(t)
	// Keep the old verification key while new tasks use a new active key.
	next, err := OpenVault(nextPath, oldPath)
	if err != nil {
		t.Fatal(err)
	}
	withoutOld, err := OpenVault(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = installationRow(t, s, next, j); err != nil {
		t.Fatal("rotation rejected retained verification key", err)
	}
	if _, err = installationRow(t, s, withoutOld, j); !errors.Is(err, errDeploymentInstallation) {
		t.Fatal("removed verification key accepted", err)
	}
	if err = s.completeDeploymentPhase(ctx, j, next, &proof); err != nil {
		t.Fatal("exact proof could not finalize after key rotation", err)
	}
}
