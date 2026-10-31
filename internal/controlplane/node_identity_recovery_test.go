package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"webscan/internal/nodepki"
)

type identityRecoveryFixture struct {
	provisioningFixture
	input    nodeIdentityRecoveryInput
	job      nodeIdentityRecoveryJob
	identity string
	request  nodepki.NodeRecoveryRequest
	lease    Lease
}

func newIdentityRecoveryFixture(t *testing.T, credentials ...SSHCredential) identityRecoveryFixture {
	return identityRecoveryFixtureAt(t, "", credentials...)
}

func identityRecoveryFixtureAt(t *testing.T, endpoint string, credentials ...SSHCredential) identityRecoveryFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	f := localProvisioningFixture(t, now.Add(-72*time.Hour))
	if endpoint != "" {
		mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET endpoint=$2 WHERE id=$1`, f.in.Node, endpoint)
		mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET endpoint=$2 WHERE node=$1`, f.in.Node, endpoint)
	}
	if len(credentials) > 0 {
		raw, err := f.s.AddCredential(ctx, f.t.vault, "admin", "recovery-pinned-ssh", f.in.Node, 1, credentials[0])
		if err != nil {
			t.Fatal(err)
		}
		var ref struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &ref) != nil {
			t.Fatal("missing credential reference")
		}
		f.in.Credential = ref.ID
	}
	enableRegistryIssuer(t, &f)
	seed := issuedNode(t, f, "recovery-seed")
	past := now.Add(-36 * time.Hour)
	expired, err := f.ca.Issue(nodepki.Node, f.in.Node, []string{"192.0.2.1"}, past, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(expired.Key)
	leaf, _ := provisioningCertificate(expired.Certificate)
	// The original encrypted seed is deliberately no longer decryptable under
	// this historical public leaf binding. Recovery may not read its key.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificates SET certificate=$2,serial=$3,not_before=$4,not_after=$5 WHERE id=$1`, seed.ID, expired.Certificate, leaf.SerialNumber.Text(16), leaf.NotBefore, leaf.NotAfter)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET applied_version=version WHERE id=$1`, f.in.Node)
	dir := filepath.Join(filepath.Dir(f.c.Collector.CAFile), "expired-active")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "active.pem")
	if _, err := nodepki.PublishIdentity(ctx, f.c.Collector.CAFile, file, nodepki.Node, f.in.Node, "", expired, past); err != nil {
		t.Fatal(err)
	}
	root, _ := provisioningCertificate(expired.CA)
	in := nodeIdentityRecoveryInput{Node: f.in.Node, Expected: 1, Credential: f.in.Credential, AuthoritySHA256: digest(root.Raw), ParentSHA256: digest(leaf.Raw), LifetimeHours: 72, Certificate: expired.Certificate}
	j, err := f.s.prepareNodeIdentityRecovery(ctx, f.c, f.t.vault, "admin", "recover-identity", in)
	if err != nil {
		t.Fatal("prepare recovery", err)
	}
	r, err := nodepki.PrepareNodeRecovery(ctx, f.c.Collector.CAFile, file, f.crl, j.Intent, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	l, err := f.s.Acquire(ctx, nodeRenewalResource(in.Node), "ssh-recovery-a")
	if err != nil {
		t.Fatal(err)
	}
	return identityRecoveryFixture{f, in, j, file, r, l}
}

func admitRecoveryFixture(t *testing.T, f identityRecoveryFixture) nodeIdentityRecoveryJob {
	t.Helper()
	raw, _ := json.Marshal(f.request)
	j, err := f.s.admitNodeIdentityRecovery(context.Background(), f.t.vault, f.lease, f.job.ID, raw)
	if err != nil {
		t.Fatal("admit public SSH response", err)
	}
	return j
}

func TestNodeIdentityRecoveryDurableRequestSigningAndReplay(t *testing.T) {
	f := newIdentityRecoveryFixture(t)
	ctx := context.Background()
	retry, err := f.s.prepareNodeIdentityRecovery(ctx, f.c, f.t.vault, "admin", "recover-identity", f.input)
	if err != nil || retry.ID != f.job.ID || retry.Intent.Challenge != f.job.Intent.Challenge || tableCount(t, f.s, "v3_node_identity_recoveries") != 1 {
		t.Fatal("preparation replay regenerated intent", err)
	}
	admitRecoveryFixture(t, f)
	if err := f.s.RewrapCredential(ctx, f.t.vault, f.in.Credential, f.in.Node); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan signedNodeRenewal, 4)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				errs <- err
			} else {
				results <- out
			}
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var first signedNodeRenewal
	for out := range results {
		if first.Receipt.Node == "" {
			first = out
		}
		if out.Receipt != first.Receipt || !bytes.Equal(out.Certificate, first.Certificate) {
			t.Fatal("response loss or concurrent retry signed another certificate")
		}
	}
	if first.Receipt.Node != f.in.Node || first.Receipt.RequestSHA256 != f.request.Renewal.SHA256() || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("missing shared public issuance")
	}
	if err := os.Rename(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key"), filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key.offline")); err != nil {
		t.Fatal(err)
	}
	replayed, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil || !bytes.Equal(first.Certificate, replayed.Certificate) {
		t.Fatal("receipt replay required a CA private key", err)
	}
	stored, err := f.s.nodeIdentityRecovery(ctx, f.t.vault, f.job.ID)
	if err != nil || stored.Status != "signed" {
		t.Fatal("signed state not durable", err)
	}
	var audit int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='recover-node-certificate'`).Scan(&audit); err != nil || audit != 1 {
		t.Fatal("recovery issuance audit duplicated", err)
	}
	// Ordinary signing cannot reuse this receipt with an expired parent.
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, nodeRenewalSigningInput{Snapshot: f.job.Snapshot, RuntimeEpoch: f.job.RuntimeEpoch, LifetimeHours: f.job.LifetimeHours, Request: f.request.Renewal})
	requireEmptyRenewalFailure(t, out, err)
	var material []byte
	if err := f.s.DB.QueryRow(`SELECT to_jsonb(j)::text FROM v3_node_identity_recoveries j`).Scan(&material); err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("PRIVATE KEY"), []byte(f.identity), []byte(credentialFixture().Password)} {
		if bytes.Contains(material, secret) {
			t.Fatal("private material in recovery task")
		}
	}
	// The committed public certificate activates only the key held by the
	// node. Confirmation in this storage test is supplied directly; this is
	// not claimed as actual SSH/mTLS readiness orchestration.
	trustDir := filepath.Join(filepath.Dir(f.identity), "trust")
	if _, err := nodepki.NewReceiverTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, trustDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ActivateNodeRecovery(ctx, f.c.Collector.CAFile, f.identity, trustDir, f.request, f.job.Intent, first.Certificate, time.Now()); err != nil {
		t.Fatal("committed recovery did not activate local key", err)
	}
	peer, _ := provisioningCertificate(first.Certificate)
	for i := 0; i < 2; i++ {
		if err := f.s.confirmNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID, peer); err != nil {
			t.Fatal("recovery confirmation not idempotent", err)
		}
	}
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='complete-node-identity-recovery'`).Scan(&audit); err != nil || audit != 1 {
		t.Fatal("completion audit duplicated", err)
	}
	stored, err = f.s.nodeIdentityRecovery(ctx, f.t.vault, f.job.ID)
	if err != nil || stored.Status != "completed" {
		t.Fatal("completed recovery was not durable", err)
	}
	out, err = f.s.signNodeRenewal(ctx, f.c, f.lease, nodeRenewalSigningInput{Snapshot: f.job.Snapshot, RuntimeEpoch: f.job.RuntimeEpoch, LifetimeHours: f.job.LifetimeHours, Request: f.request.Renewal})
	requireEmptyRenewalFailure(t, out, err)
}

func TestNodeIdentityRecoveryRejectsStaleAuthorizationAndLease(t *testing.T) {
	for _, scenario := range []string{"viewer", "account-version", "node-version", "config-digest", "runtime-epoch", "runtime-snapshot", "expired-task", "lease-expired", "lease-resource", "credential-damage", "parent-revoked", "crl-rollback", "changed-request", "canceled-task"} {
		t.Run(scenario, func(t *testing.T) {
			f := newIdentityRecoveryFixture(t)
			admitRecoveryFixture(t, f)
			l := f.lease
			switch scenario {
			case "viewer":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			case "account-version":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "node-version":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET version=version+1 WHERE id=$1`, f.in.Node)
			case "config-digest":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config='{"changed":true}' WHERE id=$1`, f.in.Node)
			case "runtime-epoch":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, f.in.Node)
			case "runtime-snapshot":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET enabled=false`)
			case "expired-task":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_identity_recoveries SET expires_at=clock_timestamp()-interval '1 second'`)
			case "lease-expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
			case "lease-resource":
				l.Resource = "wrong-resource"
			case "credential-damage":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_credentials SET ciphertext=decode('deadbeef','hex')`)
			case "parent-revoked":
				crl, err := f.ca.Revoke(f.crl, [][]byte{f.request.Renewal.Certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), crl)
			case "crl-rollback":
				crl, err := f.ca.Revoke(f.crl, nil, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, crl)
			case "changed-request":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_identity_recoveries SET request_sha256=repeat('f',64)`)
			case "canceled-task":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_identity_recoveries SET status='canceled'`)
			}
			out, err := f.s.signNodeIdentityRecovery(context.Background(), f.c, f.t.vault, l, f.job.ID)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("invalid task left a committed certificate")
			}
		})
	}
}

func TestNodeIdentityRecoveryBackupRestoreAndMigration(t *testing.T) {
	f := newIdentityRecoveryFixture(t)
	ctx := context.Background()
	admitRecoveryFixture(t, f)
	out, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := f.s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, backup); err != nil {
		t.Fatal("backup lost recovery dependencies", err)
	}
	j, err := target.nodeIdentityRecovery(ctx, f.t.vault, f.job.ID)
	if err != nil || j.Status != "signed" || j.Intent.Challenge != f.job.Intent.Challenge || !bytes.Equal(j.Request, f.requestBytes(t)) {
		t.Fatal("recovery task changed across restore", err)
	}
	// A different worker must wait for the restored old owner's lease, just
	// as it would after a process crash. Do not silently steal a live lease.
	mustHistoryExec(t, target.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
	lease, err := target.Acquire(ctx, f.lease.Resource, "restored-recovery")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := target.signNodeIdentityRecovery(ctx, f.c, f.t.vault, lease, f.job.ID)
	if err != nil || out.Receipt != replayed.Receipt || !bytes.Equal(out.Certificate, replayed.Certificate) {
		t.Fatal("restored recovery issued another successor", err)
	}
	stale, err := target.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	requireEmptyRenewalFailure(t, stale, err)
	mustHistoryExec(t, f.s.DB, nodeHistoryRetirementTestDrop+`DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE v3_node_name_prunings;DROP TABLE v3_node_name_changes;ALTER TABLE v3_node_certificate_renewals DROP COLUMN request_kind;DROP TABLE v3_node_identity_recoveries;DELETE FROM v3_schema WHERE version>=32`)
	if err := f.s.Migrate(ctx); err == nil {
		t.Fatal("schema 31 advanced without consistent backup")
	}
	badBackup := filepath.Join(privateTestDir(t), "not-a-directory")
	if err := os.WriteFile(badBackup, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Upgrade(ctx, badBackup); err == nil {
		t.Fatal("migration proceeded after backup failure")
	}
	if version, err := currentSchema(ctx, f.s.DB); err != nil || version != 31 {
		t.Fatal("backup failure advanced schema", version, err)
	}
	if err := f.s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if version, err := currentSchema(ctx, f.s.DB); err != nil || version != SchemaVersion || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("migration lost the shared issuance ledger", version, err)
	}
}

func (f identityRecoveryFixture) requestBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNodeIdentityRecoveryCommitFailureAndLateExpiry(t *testing.T) {
	for _, kind := range []string{"commit", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			f := newIdentityRecoveryFixture(t)
			admitRecoveryFixture(t, f)
			if kind == "commit" {
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_recovery_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic deferred commit failure'; END$$; CREATE CONSTRAINT TRIGGER fail_recovery_commit AFTER UPDATE ON v3_node_identity_recoveries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_recovery_commit()`)
			} else {
				// Generate a genuinely countersigned short-lived intent, rather
				// than corrupting a signature and accidentally testing rejection
				// before the INSERT. Sequences survive rollback and prove that
				// issuance reached the deliberately delayed database write.
				intent := f.job.Intent
				intent.ExpiresAt = time.Now().Add(500 * time.Millisecond).UTC().Truncate(time.Microsecond)
				r, err := nodepki.PrepareNodeRecovery(context.Background(), f.c.Collector.CAFile, f.identity, f.crl, intent, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				intentRaw, _ := json.Marshal(intent)
				raw, _ := json.Marshal(r)
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_identity_recoveries SET expires_at=$1,intent=$2,request=$3,request_sha256=$4`, intent.ExpiresAt, intentRaw, raw, r.SHA256())
				mustHistoryExec(t, f.s.DB, `CREATE SEQUENCE recovery_delay_observed; CREATE FUNCTION delay_recovery_issue() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('recovery_delay_observed'); PERFORM pg_sleep(1); RETURN NEW; END$$; CREATE TRIGGER delay_recovery_issue BEFORE INSERT ON v3_node_certificate_renewals FOR EACH ROW EXECUTE FUNCTION delay_recovery_issue()`)
			}
			out, err := f.s.signNodeIdentityRecovery(context.Background(), f.c, f.t.vault, f.lease, f.job.ID)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("failed commit/late expiry left a signed successor")
			}
			if kind == "expiry" {
				var called bool
				if err := f.s.DB.QueryRow(`SELECT is_called FROM recovery_delay_observed`).Scan(&called); err != nil || !called {
					t.Fatal("expiry occurred before the issuance write, not during it", err)
				}
			}
		})
	}
}

func TestNodeIdentityRecoveryCancelRetainsIssuanceAndReleasesNode(t *testing.T) {
	f := newIdentityRecoveryFixture(t)
	ctx := context.Background()
	admitRecoveryFixture(t, f)
	if _, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.cancelNodeIdentityRecovery(ctx, "viewer", "viewer-cancel", f.job.ID); err == nil {
		t.Fatal("viewer canceled recovery")
	}
	if _, err := f.s.cancelNodeIdentityRecovery(ctx, "admin", "admin-cancel", f.job.ID); err != nil {
		t.Fatal(err)
	}
	out, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	requireEmptyRenewalFailure(t, out, err)
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("cancel deleted already committed certificate")
	}
	n, err := scanNode(f.s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, f.in.Node))
	if err != nil {
		t.Fatal(err)
	}
	n.Name = "after cancellation"
	if _, err := f.s.SaveNode(ctx, "admin", "edit-after-cancel", n, n.Version, 256); err != nil {
		t.Fatal("cancel did not release saved node", err)
	}
}

func TestNodeIdentityRecoveryAdmissionRejectsForgedOrMismatchedIntent(t *testing.T) {
	f := newIdentityRecoveryFixture(t)
	for _, kind := range []string{"challenge", "proof", "node", "online", "oversized", "lease"} {
		t.Run(kind, func(t *testing.T) {
			r, l := f.request, f.lease
			switch kind {
			case "challenge":
				r.Intent.Challenge = r.Intent.AuthoritySHA256
			case "proof":
				r.Proof = nil
			case "node":
				r.Renewal.Node = "other"
			case "lease":
				l.Resource = "wrong"
			}
			raw, _ := json.Marshal(r)
			if kind == "online" {
				raw, _ = json.Marshal(r.Renewal)
			}
			if kind == "oversized" {
				raw = bytes.Repeat([]byte{'x'}, nodepki.MaxRenewalBytes+1)
			}
			if _, err := f.s.admitNodeIdentityRecovery(context.Background(), f.t.vault, l, f.job.ID, raw); err == nil {
				t.Fatal("untrusted public response admitted")
			}
		})
	}
	admitRecoveryFixture(t, f)
}

func TestNodeIdentityRecoveryReservesOnlyTargetNode(t *testing.T) {
	f := newIdentityRecoveryFixture(t)
	ctx := context.Background()
	n, err := scanNode(f.s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, f.in.Node))
	if err != nil {
		t.Fatal(err)
	}
	n.Name = "must not save"
	if _, err := f.s.SaveNode(ctx, "admin", "edit-during-recovery", n, n.Version, 256); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("active recovery did not reserve node configuration", err)
	}
	other := nodeFixture("node-b")
	if err := f.s.PutNode(ctx, other, 0, 256); err != nil {
		t.Fatal(err)
	}
	other.Name = "unrelated node remains editable"
	if _, err := f.s.SaveNode(ctx, "admin", "edit-other-during-recovery", other, 1, 256); err != nil {
		t.Fatal("recovery blocked unrelated node", err)
	}
	if _, err := f.s.CreateDeployment(ctx, "admin", "deploy-during-recovery", DeploymentRequest{Node: n.ID, Expected: n.Version, Kind: "upgrade", Credential: f.in.Credential, Release: "v3.0.0", SHA256: f.t.release.manifest.Native.SHA256}); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("active recovery did not reserve deployment", err)
	}
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := configurationRestoreDeployments(ctx, tx); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("restore ignored active identity recovery")
	}
}

func TestNodeIdentityRecoveryUsesPinnedSSHAndChecksBeforeConnect(t *testing.T) {
	rpc := startNodeRPC(t, func(_ string, _ ssh.Channel) { t.Error("connect must not execute a remote command") })
	f := newIdentityRecoveryFixture(t, rpc.credential)
	ctx := context.Background()
	remote, err := f.s.connectNodeIdentityRecoverySSH(ctx, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if remote.Fingerprint != rpc.credential.Fingerprint {
		t.Fatal("recovery connected without its verified host pin")
	}
	remote.Close()
	before := rpc.connections.Load()
	mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
	if remote, err := f.s.connectNodeIdentityRecoverySSH(ctx, f.t.vault, f.lease, f.job.ID); err == nil {
		remote.Close()
		t.Fatal("expired lease connected to SSH")
	}
	if rpc.connections.Load() != before {
		t.Fatal("stale task contacted remote SSH before its fence check")
	}
	wrong := rpc.credential
	wrong.Fingerprint = credentialFixture().Fingerprint
	g := newIdentityRecoveryFixture(t, wrong)
	if remote, err := g.s.connectNodeIdentityRecoverySSH(ctx, g.t.vault, g.lease, g.job.ID); err == nil {
		remote.Close()
		t.Fatal("wrong SSH host pin accepted")
	}
}

func TestNodeIdentityRecoveryFreshTaskReconcilesOriginalIssuanceAfterRuntimeChange(t *testing.T) {
	f := newIdentityRecoveryFixture(t)
	ctx := context.Background()
	admitRecoveryFixture(t, f)
	first, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.cancelNodeIdentityRecovery(ctx, "admin", "cancel-for-runtime", f.job.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE v3_nodes SET version=version+1,applied_version=version+1 WHERE id=$1`, f.in.Node); err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureSavedNodeTx(ctx, tx, f.in.Node)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishNodeRuntimeTx(ctx, tx, f.in.Node, snapshot, f.job.RuntimeEpoch); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	in := f.input
	in.Expected++
	j, err := f.s.prepareNodeIdentityRecovery(ctx, f.c, f.t.vault, "admin", "recover-new-runtime", in)
	if err != nil || j.Snapshot == f.job.Snapshot || j.RuntimeEpoch == f.job.RuntimeEpoch {
		t.Fatal("fresh task not bound to actual new runtime", err)
	}
	r, err := nodepki.PrepareNodeRecovery(ctx, f.c.Collector.CAFile, f.identity, f.crl, j.Intent, time.Now())
	if err != nil || r.Renewal.SHA256() != f.request.Renewal.SHA256() {
		t.Fatal("fresh intent replaced durable local CSR", err)
	}
	raw, _ := json.Marshal(r)
	if _, err := f.s.admitNodeIdentityRecovery(ctx, f.t.vault, f.lease, j.ID, raw); err != nil {
		t.Fatal(err)
	}
	replayed, err := f.s.signNodeIdentityRecovery(ctx, f.c, f.t.vault, f.lease, j.ID)
	if err != nil || !bytes.Equal(replayed.Certificate, first.Certificate) || replayed.Receipt != first.Receipt || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("new runtime caused duplicate issuance or destroyed original audit binding", err)
	}
}
