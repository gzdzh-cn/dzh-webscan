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

	"webscan/internal/nodepki"
)

type nameChangeRegistryFixture struct {
	renewalRegistryFixture
	input   nodeNameChangeInput
	job     nodeNameChangeJob
	request nodepki.NodeNameChangeRequest
	trust   string
}

func newNameChangeRegistryFixture(t *testing.T) nameChangeRegistryFixture {
	return nameChangeRegistryFixtureWith(t, nil)
}

func nameChangeRegistryFixtureWith(t *testing.T, configure func(*provisioningFixture)) nameChangeRegistryFixture {
	t.Helper()
	f := renewalRegistryFixtureWith(t, configure)
	ctx := context.Background()
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET applied_version=version WHERE id=$1`, f.in.Request.Node)
	n, err := scanNode(f.s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, f.in.Request.Node))
	if err != nil {
		t.Fatal(err)
	}
	n.ServerName = "new-agent.test"
	if _, err := f.s.SaveNode(ctx, "admin", "saved-name-change", n, n.Version, 256); err != nil {
		t.Fatal(err)
	}
	in := nodeNameChangeInput{Node: n.ID, Credential: f.provisioningFixture.in.Credential, AuthoritySHA256: f.in.Request.AuthoritySHA256, ParentSHA256: f.in.Request.CertificateSHA256, Expected: 2, LifetimeHours: 72, Certificate: f.in.Request.Certificate}
	j, err := f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "name-change", in)
	if err != nil {
		t.Fatal("prepare name change", err)
	}
	trust := filepath.Join(filepath.Dir(f.identity), "name-change-trust")
	if _, err := nodepki.NewReceiverTrust(f.c.Collector.CAFile, f.c.Collector.RevocationFile, trust, time.Now()); err != nil {
		t.Fatal(err)
	}
	r, err := nodepki.PrepareNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, trust, j.Intent, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return nameChangeRegistryFixture{f, in, j, r, trust}
}

func (f nameChangeRegistryFixture) requestBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f nameChangeRegistryFixture) admit(t *testing.T) {
	t.Helper()
	if _, err := f.s.admitNodeNameChange(context.Background(), f.t.vault, f.lease, f.job.ID, f.requestBytes(t)); err != nil {
		t.Fatal("admit name request", err)
	}
}

func TestNodeNameChangeRegistryConcurrentReplayAndNextRenewal(t *testing.T) {
	f := newNameChangeRegistryFixture(t)
	ctx := context.Background()
	retry, err := f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "name-change", f.input)
	if err != nil || retry.ID != f.job.ID || retry.Intent.SHA256() != f.job.Intent.SHA256() {
		t.Fatal("preparation replay changed authorization", err)
	}
	if _, err := f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "second-name-change", f.input); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("parallel task was admitted", err)
	}
	f.admit(t)
	f.admit(t)
	if err := f.s.RewrapCredential(ctx, f.t.vault, f.input.Credential, f.input.Node); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan signedNodeRenewal, 4)
	failures := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				failures <- err
			} else {
				results <- out
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var first signedNodeRenewal
	for out := range results {
		if first.Receipt.Node == "" {
			first = out
		}
		if out.Receipt != first.Receipt || !bytes.Equal(out.Certificate, first.Certificate) {
			t.Fatal("response loss signed a second successor")
		}
	}
	if first.Receipt.RequestSHA256 != f.request.SHA256() || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("name change bypassed shared issuance ledger")
	}
	var kind, status string
	if err := f.s.DB.QueryRow(`SELECT request_kind FROM v3_node_certificate_renewals`).Scan(&kind); err != nil || kind != "name-change" {
		t.Fatal("wrong request domain", err)
	}
	if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes`).Scan(&status); err != nil || status != "signed" {
		t.Fatal("signing did not advance durable task", err)
	}
	key := filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")
	if err := os.Rename(key, key+".offline"); err != nil {
		t.Fatal(err)
	}
	replay, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil || replay.Receipt != first.Receipt || !bytes.Equal(replay.Certificate, first.Certificate) {
		t.Fatal("replay required issuer private key", err)
	}
	if err := os.Rename(key+".offline", key); err != nil {
		t.Fatal(err)
	}
	if _, err := nodepki.ActivateNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, f.request, f.job.Intent, first.Certificate, time.Now()); err != nil {
		t.Fatal("SQL-committed receipt not usable with local CSR", err)
	}
	leaf, _ := provisioningCertificate(first.Certificate)
	if leaf.VerifyHostname(f.job.SourceName) != nil || leaf.VerifyHostname(f.job.TargetName) != nil {
		t.Fatal("source/target overlap missing")
	}
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	requireEmptyRenewalFailure(t, out, err)
	original, _ := provisioningCertificate(f.request.Certificate)
	if err := f.s.confirmNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID, original); err == nil {
		t.Fatal("original identity confirmed a name change")
	}
	// Store-layer test only: the host transport that obtains this peer still
	// needs integration with a fresh actual Agent connection.
	for i := 0; i < 2; i++ {
		if err := f.s.confirmNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID, leaf); err != nil {
			t.Fatal("confirmation replay", err)
		}
	}
	var completions int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='complete-node-name-change'`).Scan(&completions); err != nil || completions != 1 {
		t.Fatal("completion audit duplicated", err)
	}
	if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes`).Scan(&status); err != nil || status != "completed" {
		t.Fatal("completion not durable", err)
	}
	if _, err := f.s.cancelNodeNameChange(ctx, "admin", "cancel-completed-name-change", f.job.ID); err != nil {
		t.Fatal(err)
	}
	// Completion releases management exclusion, but may not fork the same
	// parent through the ordinary online renewal protocol.
	out, err = f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	requireEmptyRenewalFailure(t, out, err)
	// A public-only committed name successor is valid ancestry for subsequent
	// normal renewal, which must preserve both authorized SANs.
	next := f.in
	next.Request, err = nodepki.PrepareNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, f.input.Node, first.Receipt.CertificateSHA256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next.LifetimeHours = 96
	out, err = f.s.signNodeRenewal(ctx, f.c, f.lease, next)
	if err != nil || out.Receipt.ParentSHA256 != first.Receipt.CertificateSHA256 || tableCount(t, f.s, "v3_node_certificate_renewals") != 2 {
		t.Fatal("normal renewal of name successor failed", err)
	}
	for _, table := range []string{"v3_node_name_changes", "v3_node_certificate_renewals", "v3_audit"} {
		var stored string
		if err := f.s.DB.QueryRow(`SELECT COALESCE(string_agg(to_jsonb(t)::text,''),'') FROM ` + table + ` t`).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains([]byte(stored), []byte("PRIVATE KEY")) || bytes.Contains([]byte(stored), []byte(f.identity)) || bytes.Contains([]byte(stored), []byte(credentialFixture().Password)) {
			t.Fatal("private material leaked to task/ledger/audit", table)
		}
	}
}

func TestNodeNameChangeRegistryRejectsStaleAuthorization(t *testing.T) {
	for _, scenario := range []string{"viewer", "actor-revision", "node-version", "saved-config", "saved-endpoint", "saved-name", "source-name", "target-snapshot", "epoch", "snapshot", "expired", "lease-expired", "lease-resource", "credential", "request", "intent", "canceled", "revoked", "crl-rollback", "busy", "migration"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			f.admit(t)
			l := f.lease
			switch scenario {
			case "viewer":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			case "actor-revision":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "node-version":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET version=version+1`)
			case "saved-config":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config='{"changed":true}'`)
			case "saved-endpoint":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET endpoint='other.test:19100'`)
			case "saved-name":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET server_name='other.test'`)
			case "source-name":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET server_name='other.test' WHERE id=$1`, f.job.Snapshot)
			case "target-snapshot":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET endpoint='other.test:19100' WHERE id=$1`, f.job.TargetSnapshot)
			case "epoch":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1`)
			case "snapshot":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_runtime SET snapshot=$1`, f.job.TargetSnapshot)
			case "expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET expires_at=clock_timestamp()-interval '1 second'`)
			case "lease-expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
			case "lease-resource":
				l.Resource = "wrong-resource"
			case "credential":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_credentials SET ciphertext=decode('deadbeef','hex')`)
			case "request":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET request_sha256=repeat('f',64)`)
			case "intent":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET intent=jsonb_set(intent,'{server_name}','"extra.test"')`)
			case "canceled":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET status='canceled'`)
			case "revoked", "crl-rollback":
				var revoked [][]byte
				if scenario == "revoked" {
					revoked = [][]byte{f.request.Certificate}
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
			case "busy":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_jobs(id,node,username,kind,node_version,credential,plan,plan_digest) VALUES('busy','node-a','admin','upgrade',2,$1,'{}','test')`, f.input.Credential)
			case "migration":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_migration_domains(domain,source) VALUES('fixture',repeat('a',64))`)
			}
			out, err := f.s.signNodeNameChange(context.Background(), f.c, f.t.vault, l, f.job.ID)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("stale authorization committed issuance")
			}
		})
	}
}

func TestNodeNameChangeRegistryBackupRestoreAndUpgrade(t *testing.T) {
	f := newNameChangeRegistryFixture(t)
	f.admit(t)
	ctx := context.Background()
	first, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := f.s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, backup); err != nil {
		t.Fatal(err)
	}
	j, err := target.nodeNameChange(ctx, f.t.vault, f.job.ID)
	if err != nil || j.Intent.SHA256() != f.job.Intent.SHA256() || j.TargetSnapshot != f.job.TargetSnapshot || j.Status != "signed" {
		t.Fatal("backup changed durable authorization", err)
	}
	mustHistoryExec(t, target.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
	l, err := target.Acquire(ctx, f.lease.Resource, "restored-name-change")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := target.signNodeNameChange(ctx, f.c, f.t.vault, l, f.job.ID)
	if err != nil || replay.Receipt != first.Receipt || !bytes.Equal(replay.Certificate, first.Certificate) {
		t.Fatal("restore forked a public-only issuance", err)
	}
	stale, err := target.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
	requireEmptyRenewalFailure(t, stale, err)
	// Simulate a schema-32 database with its existing shared ledger intact.
	old := newRenewalRegistryFixture(t)
	prior, err := old.s.signNodeRenewal(ctx, old.c, old.lease, old.in)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, old.s.DB, `DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE v3_node_name_prunings;DROP TABLE v3_node_name_changes;ALTER TABLE v3_node_certificate_renewals DROP COLUMN request_kind;DELETE FROM v3_schema WHERE version>=33`)
	if err := old.s.Migrate(ctx); err == nil {
		t.Fatal("upgrade skipped consistent backup")
	}
	bad := filepath.Join(privateTestDir(t), "not-a-directory")
	localWrite(t, bad, []byte("fixture"))
	if err := old.s.Upgrade(ctx, bad); err == nil {
		t.Fatal("upgrade ignored backup failure")
	}
	if version, err := currentSchema(ctx, old.s.DB); err != nil || version != 32 {
		t.Fatal("backup failure changed schema", version, err)
	}
	if err := old.s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if version, err := currentSchema(ctx, old.s.DB); err != nil || version != SchemaVersion || tableCount(t, old.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("upgrade lost prior public issuance", version, err)
	}
	var kind string
	if err := old.s.DB.QueryRow(`SELECT request_kind FROM v3_node_certificate_renewals`).Scan(&kind); err != nil || kind != "renewal" {
		t.Fatal("legacy issuance was assigned a different request domain", err)
	}
	replayed, err := old.s.signNodeRenewal(ctx, old.c, old.lease, old.in)
	if err != nil || !bytes.Equal(prior.Certificate, replayed.Certificate) {
		t.Fatal("schema upgrade changed the original issuance receipt", err)
	}
}

func TestNodeNameChangeRegistryNeverReturnsUncommittedCertificate(t *testing.T) {
	for _, scenario := range []string{"audit", "deferred-commit", "context", "expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			f.admit(t)
			ctx := context.Background()
			switch scenario {
			case "audit":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_name_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='change-node-certificate-name' THEN RAISE EXCEPTION 'isolated failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_name_audit BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_name_audit()`)
			case "deferred-commit":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_name_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated deferred failure';END$$;CREATE CONSTRAINT TRIGGER fail_name_commit AFTER UPDATE ON v3_node_name_changes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_name_commit()`)
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expiry":
				// Preserve a genuine proof: shorten the task/intent before local
				// preparation, then delay issuance beyond that exact authorization.
				i := f.job.Intent
				i.ExpiresAt = time.Now().UTC().Add(1500 * time.Millisecond).Truncate(time.Microsecond)
				r, err := nodepki.PrepareNodeNameChange(ctx, f.c.Collector.CAFile, f.identity, f.trust, i, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(r)
				intent, _ := json.Marshal(i)
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET intent=$1,expires_at=$2,request=$3,request_sha256=$4`, intent, i.ExpiresAt, raw, r.SHA256())
				mustHistoryExec(t, f.s.DB, `CREATE SEQUENCE name_delay_observed;CREATE FUNCTION delay_name_issue() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('name_delay_observed');PERFORM pg_sleep(2);RETURN NEW;END$$;CREATE TRIGGER delay_name_issue BEFORE INSERT ON v3_node_certificate_renewals FOR EACH ROW EXECUTE FUNCTION delay_name_issue()`)
			}
			out, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("failed transaction retained issuance")
			}
			if scenario == "expiry" {
				var observed bool
				if err := f.s.DB.QueryRow(`SELECT is_called FROM name_delay_observed`).Scan(&observed); err != nil || !observed {
					t.Fatal("expiry test did not reach the delayed issuance", err)
				}
			}
		})
	}
}

func TestNodeNameChangeRegistryRejectsUnboundRequest(t *testing.T) {
	for _, scenario := range []string{"ordinary-request", "forged-proof", "other-name", "other-challenge", "oversize", "noncanonical", "wrong-lease", "not-admitted"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			r := f.request
			l := f.lease
			var raw []byte
			switch scenario {
			case "ordinary-request":
				raw, _ = json.Marshal(f.in.Request)
			case "forged-proof":
				r.Proof = append([]byte(nil), r.Proof...)
				r.Proof[0] ^= 1
			case "other-name":
				r.Intent.ServerName = "another.test"
			case "other-challenge":
				r.Intent.Challenge = digest([]byte("unbound"))
			case "oversize":
				raw = bytes.Repeat([]byte("x"), nodepki.MaxRenewalBytes+1)
			case "noncanonical":
				raw = append(f.requestBytes(t), '\n')
			case "wrong-lease":
				l.Resource = "wrong-resource"
			case "not-admitted":
				out, err := f.s.signNodeNameChange(context.Background(), f.c, f.t.vault, l, f.job.ID)
				requireEmptyRenewalFailure(t, out, err)
				return
			}
			if raw == nil {
				raw, _ = json.Marshal(r)
			}
			if _, err := f.s.admitNodeNameChange(context.Background(), f.t.vault, l, f.job.ID, raw); err == nil {
				t.Fatal("unbound SSH response admitted")
			}
			var status string
			if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes`).Scan(&status); err != nil || status != "prepared" || tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("rejection left partial progress", err)
			}
		})
	}
}

func TestNodeNameChangeCannotForkOrdinaryIssuanceOrEscalateOnline(t *testing.T) {
	for _, scenario := range []string{"ordinary-first", "online-scope-expansion"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			ctx := context.Background()
			if _, err := f.s.cancelNodeNameChange(ctx, "admin", "release-name-task", f.job.ID); err != nil {
				t.Fatal(err)
			}
			if scenario == "ordinary-first" {
				first, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "new-name-task", f.input); err == nil {
					t.Fatal("ordinary successor allowed a new name-change task")
				}
				if tableCount(t, f.s, "v3_node_name_changes") != 1 {
					t.Fatal("conflicting preparation created a task")
				}
				var receipt string
				if err := f.s.DB.QueryRow(`SELECT certificate_sha256 FROM v3_node_certificate_renewals`).Scan(&receipt); err != nil || receipt != first.Receipt.CertificateSHA256 || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
					t.Fatal("name issuance overwrote ordinary successor", err)
				}
			} else {
				in := f.in
				in.Request.CSR, in.Request.Proof = f.request.CSR, f.request.Proof
				out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, in)
				requireEmptyRenewalFailure(t, out, err)
				if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
					t.Fatal("online renewal added a hostname")
				}
			}
		})
	}
}

func TestNodeNameChangeReservesManagementAndRenewalOnlyForTarget(t *testing.T) {
	f := newNameChangeRegistryFixture(t)
	ctx := context.Background()
	n, err := scanNode(f.s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, f.input.Node))
	if err != nil {
		t.Fatal(err)
	}
	n.Name = "must not change"
	if _, err := f.s.SaveNode(ctx, "admin", "edit-during-name-change", n, n.Version, 256); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("active name task did not reserve saved configuration", err)
	}
	other := nodeFixture("node-b")
	if err := f.s.PutNode(ctx, other, 0, 256); err != nil {
		t.Fatal(err)
	}
	other.Name = "unrelated node remains editable"
	if _, err := f.s.SaveNode(ctx, "admin", "edit-other-name-change", other, 1, 256); err != nil {
		t.Fatal("name task blocked unrelated node", err)
	}
	request := DeploymentRequest{Node: n.ID, Expected: n.Version, Kind: "upgrade", Credential: f.input.Credential, Release: "v3.0.0", SHA256: f.t.release.manifest.Native.SHA256}
	if _, err := f.s.CreateDeployment(ctx, "admin", "deploy-during-name-change", request); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("deployment ignored name task", err)
	}
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configurationRestoreDeployments(ctx, tx); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("restore ignored name task", err)
	}
	if _, _, _, err := deploymentPreviewState(ctx, tx, n, request); !errors.Is(err, ErrDeploymentBusy) {
		t.Fatal("deployment preview ignored name task", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	active, err := scanActiveNode(f.s.DB.QueryRow(`SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, f.input.Node))
	if err != nil {
		t.Fatal(err)
	}
	shard, err := f.s.Acquire(ctx, shardResource(active.Shard), "name-task-collector")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.in.Request)
	if _, err := f.s.queueNodeRenewal(ctx, active, shard, raw, f.in.LifetimeHours); !errors.Is(err, errNodeRenewalPaused) {
		t.Fatal("collector admitted renewal during name task", err)
	}
	if _, err := f.s.cancelNodeNameChange(ctx, "viewer", "viewer-cancel-name", f.job.ID); err == nil {
		t.Fatal("viewer canceled administrator task")
	}
	if _, err := f.s.cancelNodeNameChange(ctx, "admin", "admin-cancel-name", f.job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SaveNode(ctx, "admin", "edit-after-name-cancel", n, n.Version, 256); err != nil {
		t.Fatal("cancellation did not release management exclusion", err)
	}
}

func TestNodeNameChangeReplayRechecksCurrentRevocationAndRequestDomain(t *testing.T) {
	for _, scenario := range []string{"parent-revoked", "successor-revoked", "crl-rollback", "request-domain", "task-expired", "actor-revision"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			ctx := context.Background()
			f.admit(t)
			first, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "parent-revoked", "successor-revoked", "crl-rollback":
				var revoked [][]byte
				if scenario == "parent-revoked" {
					revoked = [][]byte{f.request.Certificate}
				} else if scenario == "successor-revoked" {
					revoked = [][]byte{first.Certificate}
				}
				crl, err := f.ca.Revoke(f.crl, revoked, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "crl-rollback" {
					mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, crl)
				} else {
					localWrite(t, filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), crl)
				}
			case "request-domain":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET request_kind='renewal'`)
			case "task-expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET expires_at=clock_timestamp()-interval '1 second'`)
			case "actor-revision":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			}
			out, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("replay changed already committed issuance")
			}
		})
	}
}

func TestNodeNameChangeCompletionRechecksAuthorizationAndCommit(t *testing.T) {
	for _, scenario := range []string{"nil-peer", "original-peer", "lease", "expired", "actor", "target", "revoked", "commit"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNameChangeRegistryFixture(t)
			f.admit(t)
			ctx := context.Background()
			out, err := f.s.signNodeNameChange(ctx, f.c, f.t.vault, f.lease, f.job.ID)
			if err != nil {
				t.Fatal(err)
			}
			peer, _ := provisioningCertificate(out.Certificate)
			l := f.lease
			switch scenario {
			case "nil-peer":
				peer = nil
			case "original-peer":
				peer, _ = provisioningCertificate(f.request.Certificate)
			case "lease":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
			case "expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_name_changes SET expires_at=clock_timestamp()-interval '1 second'`)
			case "actor":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "target":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET server_name='other.test'`)
			case "revoked":
				crl, err := f.ca.Revoke(f.crl, [][]byte{out.Certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				localWrite(t, f.c.Collector.RevocationFile, crl)
			case "commit":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_name_completion() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.status='completed' THEN RAISE EXCEPTION 'isolated deferred completion failure';END IF;RETURN NEW;END$$;CREATE CONSTRAINT TRIGGER fail_name_completion AFTER UPDATE ON v3_node_name_changes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_name_completion()`)
			}
			if err := f.s.confirmNodeNameChange(ctx, f.c, f.t.vault, l, f.job.ID, peer); err == nil {
				t.Fatal("unverified or uncommitted completion accepted")
			}
			var status string
			var count int
			if err := f.s.DB.QueryRow(`SELECT status FROM v3_node_name_changes`).Scan(&status); err != nil || status != "signed" {
				t.Fatal("failed confirmation changed task", err)
			}
			if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='complete-node-name-change'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed confirmation retained completion audit", err)
			}
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
				t.Fatal("failed confirmation deleted committed issuance")
			}
		})
	}
}
