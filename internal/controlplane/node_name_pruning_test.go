package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

type namePruningRegistryFixture struct {
	renewalRegistryFixture
	input   nodeNamePruningInput
	job     nodeNamePruningJob
	request nodepki.NodeNamePruningRequest
	trust   string
}

func newNamePruningRegistryFixture(t *testing.T) namePruningRegistryFixture {
	t.Helper()
	f, _ := namePruningPolicyFixture(t)
	n := runtimeNodeForTest(t, f.s, f.in.Request.Node)
	b, err := f.ca.Issue(nodepki.Node, n.ID, []string{n.ServerName, "unused.example.test"}, time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	cert, err := provisioningCertificate(b.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit extra-SAN historical issuance fixture. The actual pruning
	// request, node-local key, signature and shared SQL issuance are real.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificates SET certificate=$1,serial=$2,not_before=$3,not_after=$4 WHERE id='pruning-policy-parent'`, b.Certificate, cert.SerialNumber.Text(16), cert.NotBefore, cert.NotAfter)
	if _, err := nodepki.PublishIdentity(context.Background(), f.c.Collector.CAFile, f.identity, nodepki.Node, n.ID, f.in.Request.CertificateSHA256, b, time.Now()); err != nil {
		t.Fatal(err)
	}
	in := nodeNamePruningInput{Node: n.ID, Credential: f.provisioningFixture.in.Credential, Expected: n.Version, LifetimeHours: 72, Certificate: b.Certificate}
	j, err := f.s.prepareNodeNamePruning(context.Background(), f.c, f.t.vault, "admin", "pruning-prepare", in)
	if err != nil {
		t.Fatal("prepare pruning task", err)
	}
	trust := filepath.Join(filepath.Dir(f.identity), "pruning-trust")
	if _, err := nodepki.NewReceiverTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, trust, time.Now()); err != nil {
		t.Fatal(err)
	}
	r, err := nodepki.PrepareNodeNamePruning(context.Background(), f.c.Collector.CAFile, f.identity, trust, j.Intent, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return namePruningRegistryFixture{f, in, j, r, trust}
}

func (f namePruningRegistryFixture) admit(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.admitNodeNamePruning(context.Background(), f.c, f.t.vault, f.lease, f.job.ID, raw); err != nil {
		t.Fatal("admit pruning request", err)
	}
}

func TestNodeNamePruningRegistryConcurrentReplayAndRenewal(t *testing.T) {
	f := newNamePruningRegistryFixture(t)
	ctx := context.Background()
	replayed, err := f.s.prepareNodeNamePruning(ctx, f.c, f.t.vault, "admin", "pruning-prepare", f.input)
	if err != nil || replayed.ID != f.job.ID || replayed.Intent.SHA256() != f.job.Intent.SHA256() {
		t.Fatal("idempotent preparation changed intent", err)
	}
	if _, err := f.s.prepareNodeNamePruning(ctx, f.c, f.t.vault, "admin", "second-pruning", f.input); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("parallel task admitted", err)
	}
	f.admit(t)
	f.admit(t)
	if err := f.s.RewrapCredential(ctx, f.t.vault, f.input.Credential, f.input.Node); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan signedNodeRenewal, 6)
	failures := make(chan error, 6)
	for range 6 {
		wg.Go(func() {
			out, err := f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				failures <- err
			} else {
				results <- out
			}
		})
	}
	wg.Wait()
	close(failures)
	close(results)
	for err := range failures {
		t.Fatal(err)
	}
	var first signedNodeRenewal
	for out := range results {
		if first.Receipt.Node == "" {
			first = out
		}
		if first.Receipt != out.Receipt || !bytes.Equal(first.Certificate, out.Certificate) {
			t.Fatal("parallel signing forked parent")
		}
	}
	if first.Receipt.RequestSHA256 != f.request.SHA256() || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("pruning bypassed shared issuance")
	}
	var kind, status string
	if err := f.s.DB.QueryRow(`SELECT request_kind FROM v3_node_certificate_renewals`).Scan(&kind); err != nil || kind != "name-pruning" {
		t.Fatal("wrong proof domain", err)
	}
	if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_prunings WHERE id=$1`, f.job.ID).Scan(&status); err != nil || status != "signed" {
		t.Fatal("task/issuance not committed together", err)
	}
	key := filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")
	if err := os.Rename(key, key+".offline"); err != nil {
		t.Fatal(err)
	}
	out, err := f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil || out.Receipt != first.Receipt || !bytes.Equal(out.Certificate, first.Certificate) {
		t.Fatal("replay required CA private key", err)
	}
	if err := os.Rename(key+".offline", key); err != nil {
		t.Fatal(err)
	}
	old, _ := provisioningCertificate(f.input.Certificate)
	if err := f.s.confirmNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID, old); err == nil {
		t.Fatal("old peer confirmed new identity")
	}
	record, err := nodepki.ActivateNodeNamePruning(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.request, f.job.Intent, first.Certificate, time.Now())
	if err != nil || record.CertificateSHA256 != first.Receipt.CertificateSHA256 {
		t.Fatal("committed receipt did not match local key", err)
	}
	leaf, _ := provisioningCertificate(first.Certificate)
	if leaf.VerifyHostname("unused.example.test") == nil || leaf.VerifyHostname(f.job.Plan.ActiveName) != nil {
		t.Fatal("pruning scope changed")
	}
	if err := f.s.confirmNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID, leaf); err != nil {
		t.Fatal("confirm exact public peer", err)
	}
	if err := f.s.confirmNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID, leaf); err != nil {
		t.Fatal("confirmation replay", err)
	}
	next, err := nodepki.PrepareNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, f.input.Node, record.CertificateSHA256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := f.s.signNodeRenewal(ctx, f.c, f.lease, nodeRenewalSigningInput{Snapshot: f.job.Snapshot, RuntimeEpoch: f.job.Plan.RuntimeEpoch, LifetimeHours: 96, Request: next})
	if err != nil || renewed.Receipt.ParentSHA256 != record.CertificateSHA256 {
		t.Fatal("normal renewal after pruning", err)
	}
	var completions, issuances int
	if err := f.s.DB.QueryRow(`SELECT count(*) FILTER(WHERE kind='complete-node-name-pruning'),count(*) FILTER(WHERE kind='prune-node-certificate-names') FROM v3_audit`).Scan(&completions, &issuances); err != nil || completions != 1 || issuances != 1 {
		t.Fatal("duplicate audit", err, completions, issuances)
	}
}

func TestNodeNamePruningRegistryRejectsStaleAuthority(t *testing.T) {
	for _, scenario := range []string{"actor", "role", "version", "config", "epoch", "credential", "intent", "request", "plan", "history-added", "history-changed", "expired", "lease-expired", "lease-resource", "canceled", "revoked", "crl-rollback", "deployment", "migration"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningRegistryFixture(t)
			f.admit(t)
			l := f.lease
			switch scenario {
			case "actor":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "role":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			case "version":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET version=version+1`)
			case "config":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config='{"changed":true}'`)
			case "epoch":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1`)
			case "credential":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_credentials SET ciphertext='invalid'`)
			case "intent":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_prunings SET intent=jsonb_set(intent,'{names}','["unused.example.test"]')`)
			case "request":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_prunings SET request_sha256=repeat('f',64)`)
			case "plan":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_prunings SET plan=jsonb_set(plan,'{DependenciesSHA256}','"changed"')`)
			case "history-added":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_configurations SELECT 'new-recovery',node,version,name,endpoint,'unused.example.test',false,mode,shard,config FROM v3_node_configurations WHERE id=$1`, f.job.Snapshot)
			case "history-changed":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_configurations SELECT 'new-same-name',node,version,name,endpoint,server_name,enabled,mode,shard,'{"historical":true}' FROM v3_node_configurations WHERE id=$1`, f.job.Snapshot)
			case "expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_prunings SET expires_at=clock_timestamp()-interval '1 second'`)
			case "lease-expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
			case "lease-resource":
				l.Resource = "other-resource"
			case "canceled":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_prunings SET status='canceled'`)
			case "revoked", "crl-rollback":
				var revoked [][]byte
				if scenario == "revoked" {
					revoked = [][]byte{f.input.Certificate}
				}
				crl, err := f.ca.Revoke(f.crl, revoked, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "revoked" {
					localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), crl)
				} else {
					mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, crl)
				}
			case "deployment":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_jobs(id,node,username,kind,node_version,credential,plan,plan_digest)VALUES('conflict','node-a','admin','upgrade',1,$1,'{}','fixture')`, f.input.Credential)
			case "migration":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_migration_domains(domain,source)VALUES('fixture',repeat('a',64))`)
			}
			out, err := f.s.signNodeNamePruning(context.Background(), f.c, f.t.vault, l, f.job.ID)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("stale task committed issuance")
			}
		})
	}
}

func TestNodeNamePruningRegistryNeverReturnsUncommittedLeaf(t *testing.T) {
	for _, scenario := range []string{"audit", "deferred", "context", "expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningRegistryFixture(t)
			f.admit(t)
			ctx := context.Background()
			switch scenario {
			case "audit":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_prune_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='prune-node-certificate-names' THEN RAISE EXCEPTION 'isolated failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_prune_audit BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_prune_audit()`)
			case "deferred":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_prune_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated deferred failure';END$$;CREATE CONSTRAINT TRIGGER fail_prune_commit AFTER UPDATE ON v3_node_name_prunings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_prune_commit()`)
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expiry":
				i := f.job.Intent
				i.ExpiresAt = time.Now().UTC().Add(1500 * time.Millisecond).Truncate(time.Microsecond)
				r, err := nodepki.PrepareNodeNamePruning(ctx, f.c.Collector.CAFile, f.identity, f.trust, i, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				intent, _ := json.Marshal(i)
				raw, _ := json.Marshal(r)
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_prunings SET intent=$1,expires_at=$2,request=$3,request_sha256=$4`, intent, i.ExpiresAt, raw, r.SHA256())
				mustHistoryExec(t, f.s.DB, `CREATE SEQUENCE prune_delay_observed;CREATE FUNCTION delay_prune_issue()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('prune_delay_observed');PERFORM pg_sleep(2);RETURN NEW;END$$;CREATE TRIGGER delay_prune_issue BEFORE INSERT ON v3_node_certificate_renewals FOR EACH ROW EXECUTE FUNCTION delay_prune_issue()`)
			}
			out, err := f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("failed transaction retained issuance")
			}
			if scenario == "expiry" {
				var observed bool
				if err := f.s.DB.QueryRow(`SELECT is_called FROM prune_delay_observed`).Scan(&observed); err != nil || !observed {
					t.Fatal("expiry test did not reach delayed insert", err)
				}
			}
		})
	}
}

func TestNodeNamePruningCannotForkOnlineRenewalOrAnotherIntent(t *testing.T) {
	f := newNamePruningRegistryFixture(t)
	ctx := context.Background()
	normal, err := nodepki.PrepareNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, f.input.Node, f.job.ParentSHA256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in := nodeRenewalSigningInput{Snapshot: f.job.Snapshot, RuntimeEpoch: f.job.Plan.RuntimeEpoch, LifetimeHours: 72, Request: normal}
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, in)
	requireEmptyRenewalFailure(t, out, err)
	// A request signed for a different administrator challenge is not authority.
	i, err := nodepki.NewNodeNamePruningIntent(f.input.Node, f.job.AuthoritySHA256, f.job.ParentSHA256, f.job.Plan.ConfigurationSHA256, f.job.Plan.RuntimeEpoch, f.job.Plan.ActiveName, f.job.Plan.Names, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r, err := nodepki.PrepareNodeNamePruning(ctx, f.c.Collector.CAFile, f.identity, f.trust, i, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	if _, err := f.s.admitNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID, raw); err == nil {
		t.Fatal("request self-authorized a new challenge")
	}
	f.admit(t)
	signed, err := f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.cancelNodeNamePruning(ctx, "admin", "cancel-prune", f.job.ID); err != nil {
		t.Fatal(err)
	}
	out, err = f.s.signNodeRenewal(ctx, f.c, f.lease, in)
	requireEmptyRenewalFailure(t, out, err)
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 || len(signed.Certificate) == 0 {
		t.Fatal("cancel removed issuance ancestry or renewal forked it")
	}
}

func TestNodeNamePruningPreparationReservesManagementOnlyForTarget(t *testing.T) {
	f := newNamePruningRegistryFixture(t)
	ctx := context.Background()
	n := runtimeNodeForTest(t, f.s, f.input.Node)
	if _, err := f.s.SaveNode(ctx, "admin", "blocked-pruning-save", n, n.Version, 256); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("pending pruning allowed target edit", err)
	}
	if busy, err := func() (bool, error) {
		tx, err := f.s.DB.BeginTx(ctx, nil)
		if err != nil {
			return false, err
		}
		defer tx.Rollback()
		return nodeIdentityRecoveryBusyTx(ctx, tx, n.ID, "")
	}(); err != nil || !busy {
		t.Fatal("identity exclusion missing", err)
	}
	other := nodeFixture("node-b")
	if _, err := f.s.SaveNode(ctx, "admin", "other-pruning-node", other, 0, 256); err != nil {
		t.Fatal("pruning blocked unrelated node", err)
	}
	if _, err := f.s.cancelNodeNamePruning(ctx, "viewer", "forbidden-pruning-cancel", f.job.ID); err == nil {
		t.Fatal("viewer canceled task")
	}
	if _, err := f.s.cancelNodeNamePruning(ctx, "admin", "pruning-cancel", f.job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SaveNode(ctx, "admin", "released-pruning-save", n, n.Version, 256); err != nil {
		t.Fatal("cancel did not release reservation", err)
	}
}

func TestNodeNamePruningBackupRevokesExecutionAndMigrationPreservesLedger(t *testing.T) {
	f := newNamePruningRegistryFixture(t)
	ctx := context.Background()
	f.admit(t)
	signed, err := f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	path, err := f.s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, path); err != nil {
		t.Fatal(err)
	}
	var status string
	var saved []byte
	if err := target.DB.QueryRow(`SELECT status FROM v3_node_name_prunings WHERE id=$1`, f.job.ID).Scan(&status); err != nil || status != "canceled" {
		t.Fatal("restore retained destructive authority", status, err)
	}
	if err := target.DB.QueryRow(`SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND parent_sha256=$2`, f.input.Node, f.job.ParentSHA256).Scan(&saved); err != nil || !bytes.Equal(saved, signed.Certificate) {
		t.Fatal("restore discarded public ancestry", err)
	}
	out, err := target.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	requireEmptyRenewalFailure(t, out, err)
	old := newRenewalRegistryFixture(t)
	prior, err := old.s.signNodeRenewal(ctx, old.c, old.lease, old.in)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, old.s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version>=35;DROP TABLE v3_node_name_prunings;ALTER TABLE v3_node_certificate_renewals DROP CONSTRAINT v3_node_certificate_renewals_request_kind_check;ALTER TABLE v3_node_certificate_renewals ADD CONSTRAINT v3_node_certificate_renewals_request_kind_check CHECK(request_kind IN ('renewal','name-change'));DELETE FROM v3_schema WHERE version=34`)
	if err := old.s.Migrate(ctx); err == nil {
		t.Fatal("migration skipped consistent backup")
	}
	bad := filepath.Join(privateTestDir(t), "not-directory")
	localWrite(t, bad, []byte("fixture"))
	if err := old.s.Upgrade(ctx, bad); err == nil {
		t.Fatal("backup failure did not stop migration")
	}
	if v, err := currentSchema(ctx, old.s.DB); err != nil || v != 33 {
		t.Fatal("failed migration changed schema", v, err)
	}
	if err := old.s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	replay, err := old.s.signNodeRenewal(ctx, old.c, old.lease, old.in)
	if err != nil || !bytes.Equal(replay.Certificate, prior.Certificate) {
		t.Fatal("migration rewrote prior issuance", err)
	}
}

func TestNodeNamePruningReplayRechecksRevocationAndLedger(t *testing.T) {
	for _, scenario := range []string{"revoked-parent", "revoked-successor", "floor-rollback", "wrong-kind", "wrong-request", "wrong-leaf", "expired-task", "dependency-change"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningRegistryFixture(t)
			f.admit(t)
			ctx := context.Background()
			first, err := f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "revoked-parent", "revoked-successor", "floor-rollback":
				var revoked [][]byte
				if scenario == "revoked-parent" {
					revoked = [][]byte{f.input.Certificate}
				} else if scenario == "revoked-successor" {
					revoked = [][]byte{first.Certificate}
				}
				crl, err := f.ca.Revoke(f.crl, revoked, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "floor-rollback" {
					mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, crl)
				} else {
					localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), crl)
				}
			case "wrong-kind":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET request_kind='renewal'`)
			case "wrong-request":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET request_sha256=repeat('f',64)`)
			case "wrong-leaf":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET certificate=$1`, f.input.Certificate)
			case "expired-task":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_prunings SET expires_at=clock_timestamp()-interval '1 second'`)
			case "dependency-change":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_configurations SELECT 'late-dependency',node,version,name,endpoint,server_name,enabled,mode,shard,config FROM v3_node_configurations WHERE id=$1`, f.job.Snapshot)
			}
			out, err := f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("failed replay created or deleted ledger rows")
			}
		})
	}
}

func TestNodeNamePruningCannotReplaceAlreadyIssuedOrdinarySuccessor(t *testing.T) {
	f := newNamePruningRegistryFixture(t)
	ctx := context.Background()
	if _, err := f.s.cancelNodeNamePruning(ctx, "admin", "cancel-before-normal", f.job.ID); err != nil {
		t.Fatal(err)
	}
	r, err := nodepki.PrepareNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, f.input.Node, f.job.ParentSHA256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, nodeRenewalSigningInput{Snapshot: f.job.Snapshot, RuntimeEpoch: f.job.Plan.RuntimeEpoch, LifetimeHours: 72, Request: r})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.prepareNodeNamePruning(ctx, f.c, f.t.vault, "admin", "pruning-after-normal", f.input); err == nil {
		t.Fatal("pruning forked already-issued ordinary renewal")
	}
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 || len(out.Certificate) == 0 {
		t.Fatal("parent ledger was replaced")
	}
}

func TestNodeNamePruningAdmissionAndCompletionAreAccountBound(t *testing.T) {
	f := newNamePruningRegistryFixture(t)
	ctx := context.Background()
	old, _ := provisioningCertificate(f.input.Certificate)
	if err := f.s.confirmNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID, old); err == nil {
		t.Fatal("prepared task completed before signing")
	}
	for _, scenario := range []string{"empty", "oversize", "wrong-kind", "proof", "unknown-field", "duplicate-field", "wrong-fence"} {
		t.Run(scenario, func(t *testing.T) {
			raw, _ := json.Marshal(f.request)
			l := f.lease
			switch scenario {
			case "empty":
				raw = nil
			case "oversize":
				raw = bytes.Repeat([]byte("x"), nodepki.MaxRenewalBytes+1)
			case "wrong-kind":
				r := f.request
				r.Kind = "ssh-node-name-change"
				raw, _ = json.Marshal(r)
			case "proof":
				r := f.request
				r.Proof = append([]byte(nil), r.Proof...)
				r.Proof[0] ^= 1
				raw, _ = json.Marshal(r)
			case "unknown-field":
				raw = append(raw[:len(raw)-1], []byte(`,"untrusted":true}`)...)
			case "duplicate-field":
				raw = append(raw[:len(raw)-1], []byte(`,"format":1}`)...)
			case "wrong-fence":
				l.Epoch++
			}
			if _, err := f.s.admitNodeNamePruning(ctx, f.c, f.t.vault, l, f.job.ID, raw); err == nil {
				t.Fatal("unauthorized request admitted")
			}
		})
	}
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_accounts(username,password_hash,role)VALUES('operator','test-only-hash','admin')`)
	if _, err := f.s.cancelNodeNamePruning(ctx, "operator", "other-admin-cancel", f.job.ID); err == nil {
		t.Fatal("another account canceled bound task")
	}
	f.admit(t)
	first, err := f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := provisioningCertificate(first.Certificate)
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_prune_complete() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.status='completed' THEN RAISE EXCEPTION 'isolated complete failure';END IF;RETURN NEW;END$$;CREATE CONSTRAINT TRIGGER fail_prune_complete AFTER UPDATE ON v3_node_name_prunings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_prune_complete()`)
	if err := f.s.confirmNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID, leaf); err == nil {
		t.Fatal("uncommitted completion reported success")
	}
	var status string
	if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_prunings WHERE id=$1`, f.job.ID).Scan(&status); err != nil || status != "signed" {
		t.Fatal("failed completion changed task", status, err)
	}
	var count int
	if err := f.s.DB.QueryRow(`SELECT count(*)FROM v3_audit WHERE kind='complete-node-name-pruning'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed completion left audit", err, count)
	}
}

func TestNodeIssuanceRechecksParentExpiryAfterSQLWait(t *testing.T) {
	for _, scenario := range []string{"pruning-issue", "ordinary-issue", "pruning-replay", "ordinary-replay"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNamePruningRegistryFixture(t)
			ctx := context.Background()
			if _, err := f.s.cancelNodeNamePruning(ctx, "admin", "cancel-long-parent", f.job.ID); err != nil {
				t.Fatal(err)
			}
			b, _, err := nodepki.ReadIdentity(f.c.Collector.CAFile, f.identity, nodepki.Node, f.input.Node, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer clear(b.Key)
			leaf, err := provisioningCertificate(b.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			ca, err := f.ca.Export()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(ca.Key)
			block, _ := pem.Decode(ca.Key)
			if block == nil {
				t.Fatal("fixture CA key missing")
			}
			defer clear(block.Bytes)
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			private := parsed.(ed25519.PrivateKey)
			defer clear(private)
			// A valid registered parent close to natural expiry. This private
			// fixture does not relax production lifetime or CSR validation.
			leaf.NotAfter = time.Now().Add(3 * time.Second).Truncate(time.Second)
			der, err := x509.CreateCertificate(rand.Reader, leaf, f.caCertificate(t), leaf.PublicKey, private)
			if err != nil {
				t.Fatal(err)
			}
			b.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			cert, err := provisioningCertificate(b.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificates SET certificate=$1,not_after=$2 WHERE id='pruning-policy-parent'`, b.Certificate, cert.NotAfter)
			f.identity = filepath.Join(filepath.Dir(f.identity), "short-parent.pem")
			record, err := nodepki.PublishIdentity(ctx, f.c.Collector.CAFile, f.identity, nodepki.Node, f.input.Node, "", b, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			pruning := scenario == "pruning-issue" || scenario == "pruning-replay"
			var input nodeRenewalSigningInput
			if pruning {
				f.input.Certificate = b.Certificate
				f.job, err = f.s.prepareNodeNamePruning(ctx, f.c, f.t.vault, "admin", "short-parent-pruning", f.input)
				if err != nil {
					t.Fatal(err)
				}
				f.request, err = nodepki.PrepareNodeNamePruning(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.job.Intent, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				f.admit(t)
			} else {
				r, err := nodepki.PrepareNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, f.input.Node, record.CertificateSHA256, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				input = nodeRenewalSigningInput{Snapshot: f.job.Snapshot, RuntimeEpoch: f.job.Plan.RuntimeEpoch, LifetimeHours: 72, Request: r}
			}
			sign := func() (signedNodeRenewal, error) {
				if pruning {
					return f.s.signNodeNamePruning(ctx, f.c, f.t.vault, f.lease, f.job.ID)
				}
				return f.s.signNodeRenewal(ctx, f.c, f.lease, input)
			}
			replay := scenario == "pruning-replay" || scenario == "ordinary-replay"
			if replay {
				if _, err := sign(); err != nil {
					t.Fatal("initial signing before expiry", err)
				}
			}
			trigger := `CREATE SEQUENCE parent_wait_observed;CREATE FUNCTION wait_parent_issue() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('parent_wait_observed');PERFORM pg_sleep(4);RETURN NEW;END$$;`
			if replay {
				trigger += `CREATE TRIGGER wait_parent_issue BEFORE UPDATE ON v3_pki_authorities FOR EACH ROW EXECUTE FUNCTION wait_parent_issue()`
			} else {
				trigger += `CREATE TRIGGER wait_parent_issue BEFORE INSERT ON v3_node_certificate_renewals FOR EACH ROW EXECUTE FUNCTION wait_parent_issue()`
			}
			mustHistoryExec(t, f.s.DB, trigger)
			out, err := sign()
			requireEmptyRenewalFailure(t, out, err)
			var observed bool
			if e := f.s.DB.QueryRow(`SELECT is_called FROM parent_wait_observed`).Scan(&observed); e != nil || !observed {
				t.Fatal("test did not reach live-parent SQL wait", e)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Fatal("parent expiry test only proved context timeout", err)
			}
			want := 0
			if replay {
				want = 1
			}
			if tableCount(t, f.s, "v3_node_certificate_renewals") != want {
				t.Fatal("expired parent altered committed ledger")
			}
		})
	}
}

func (f namePruningRegistryFixture) caCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(f.c.Collector.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := provisioningCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
