package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

type renewalRegistryFixture struct {
	provisioningFixture
	in       nodeRenewalSigningInput
	lease    Lease
	identity string
}

func renewalPendingForTest(t *testing.T, f provisioningFixture, b nodepki.Bundle, name string) (string, nodepki.NodeRenewalRequest) {
	t.Helper()
	dir := filepath.Join(filepath.Dir(f.c.Collector.CAFile), name)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "active.pem")
	now := time.Now()
	record, err := nodepki.PublishIdentity(context.Background(), f.c.Collector.CAFile, file, nodepki.Node, f.in.Node, "", b, now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := nodepki.PrepareNodeRenewal(context.Background(), f.c.Collector.CAFile, file, f.in.Node, record.CertificateSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	return file, r
}

func newRenewalRegistryFixture(t *testing.T) renewalRegistryFixture {
	return renewalRegistryFixtureWith(t, nil)
}

func renewalRegistryFixtureWith(t *testing.T, configure func(*provisioningFixture)) renewalRegistryFixture {
	t.Helper()
	f := localProvisioningFixture(t)
	if configure != nil {
		configure(&f)
	}
	enableRegistryIssuer(t, &f)
	record := issuedNode(t, f, "renewal-seed")
	b, err := f.s.readNodeIdentity(context.Background(), f.c, f.t.vault, record.ID, f.in.Node)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	file, request := renewalPendingForTest(t, f, b, "local-node")
	in := nodeRenewalSigningInput{RuntimeEpoch: 1, LifetimeHours: 72, Request: request}
	if err := f.s.DB.QueryRow(`SELECT snapshot FROM v3_node_runtime WHERE node=$1`, f.in.Node).Scan(&in.Snapshot); err != nil {
		t.Fatal(err)
	}
	l, err := f.s.Acquire(context.Background(), nodeRenewalResource(f.in.Node), "issuer-a")
	if err != nil {
		t.Fatal(err)
	}
	return renewalRegistryFixture{f, in, l, file}
}

func requireEmptyRenewalFailure(t *testing.T, out signedNodeRenewal, err error) {
	t.Helper()
	if err == nil || len(out.Certificate) != 0 || len(out.CRL) != 0 || out.Receipt.Node != "" {
		t.Fatal("failed operation returned an uncommitted certificate", err)
	}
}

func TestNodeRenewalRegistryCommitReplayAndLocalKeyChain(t *testing.T) {
	f := newRenewalRegistryFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan signedNodeRenewal, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
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
			t.Fatal("concurrent/retried CSR issued different certificates")
		}
	}
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 1 || tableCount(t, f.s, "v3_node_certificates") != 1 {
		t.Fatal("duplicate issuance or fabricated centrally held private key")
	}
	var audits int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='renew-node-certificate'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("missing/duplicate renewal audit", err)
	}
	trust, err := nodepki.NewTrust(f.node.CA, first.CRL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verify := func(cert *x509.Certificate) error {
		return trust.Verify(cert, nodepki.Node, f.in.Request.Node, time.Now())
	}
	record, err := nodepki.ActivateNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, f.in.Request.Node, f.in.Request.CertificateSHA256, f.in.Request.SHA256(), first.Certificate, time.Now(), verify)
	if err != nil || record.CertificateSHA256 != first.Receipt.CertificateSHA256 {
		t.Fatal("committed certificate did not match the node-local key", err)
	}
	// The successor is public-only in SQL, yet can become the next parent.
	next := f.in
	next.Request, err = nodepki.PrepareNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, f.in.Request.Node, record.CertificateSHA256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	next.LifetimeHours = 96
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, next)
	if err != nil || out.Receipt.ParentSHA256 != first.Receipt.CertificateSHA256 || tableCount(t, f.s, "v3_node_certificate_renewals") != 2 {
		t.Fatal("public-only renewal chain failed", err)
	}
	var stored string
	if err := f.s.DB.QueryRow(`SELECT string_agg(to_jsonb(r)::text,'') FROM v3_node_certificate_renewals r`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(stored), []byte("PRIVATE KEY")) || bytes.Contains([]byte(stored), []byte(f.identity)) {
		t.Fatal("local key or path leaked to registry")
	}
}

func TestNodeRenewalRegistryUsesActiveSnapshotAndRejectsConflicts(t *testing.T) {
	for _, scenario := range []string{"snapshot", "epoch", "lease-resource", "lease-expired", "lease-takeover", "runtime-mismatch", "disabled", "unregistered", "hostname", "busy", "disabled-issuer", "missing-ca-key", "forged-proof", "unknown-parent", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRenewalRegistryFixture(t)
			in, l, c := f.in, f.lease, f.c
			ctx := context.Background()
			switch scenario {
			case "snapshot":
				in.Snapshot = "other-snapshot"
			case "epoch":
				in.RuntimeEpoch++
			case "lease-resource":
				l.Resource = "other-resource"
			case "lease-expired", "lease-takeover":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second'`)
				if scenario == "lease-takeover" {
					if _, err := f.s.Acquire(ctx, l.Resource, "issuer-b"); err != nil {
						t.Fatal(err)
					}
				}
			case "runtime-mismatch":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1`)
			case "disabled":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET enabled=false`)
			case "unregistered":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_runtime`)
			case "hostname":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET server_name='other.test'`)
			case "busy":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_jobs(id,node,username,kind,node_version,credential,plan,plan_digest) SELECT 'busy','node-a','admin','upgrade',1,id,'{}','test' FROM v3_credentials WHERE node='node-a' LIMIT 1`)
			case "disabled-issuer":
				c.NodePKI.Enabled = false
			case "missing-ca-key":
				if err := os.Remove(filepath.Join(c.NodePKI.AuthorityDirectory, "ca.key")); err != nil {
					t.Fatal(err)
				}
			case "forged-proof":
				in.Request.Proof = append([]byte{}, in.Request.Proof...)
				in.Request.Proof[0] ^= 1
			case "unknown-parent":
				b, err := f.ca.Issue(nodepki.Node, "node-a", []string{"192.0.2.1"}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(b.Key)
				_, in.Request = renewalPendingForTest(t, f.provisioningFixture, b, "unregistered-identity")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			out, err := f.s.signNodeRenewal(ctx, c, l, in)
			requireEmptyRenewalFailure(t, out, err)
			if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
				t.Fatal("rejected request persisted a certificate")
			}
		})
	}
	t.Run("saved-draft-does-not-change-runtime", func(t *testing.T) {
		f := newRenewalRegistryFixture(t)
		mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET server_name='pending.test',endpoint='192.0.2.99:19100',version=version+1,enabled=false`)
		if _, err := f.s.signNodeRenewal(context.Background(), f.c, f.lease, f.in); err != nil {
			t.Fatal("saved draft influenced active renewal", err)
		}
	})
}

func TestNodeRenewalRegistryFailureRollsBackBeforeDelivery(t *testing.T) {
	f := newRenewalRegistryFixture(t)
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_renewal_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='renew-node-certificate' THEN RAISE EXCEPTION 'synthetic renewal persistence failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_renewal_audit BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_renewal_audit()`)
	out, err := f.s.signNodeRenewal(context.Background(), f.c, f.lease, f.in)
	requireEmptyRenewalFailure(t, out, err)
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
		t.Fatal("failed transaction persisted a partial receipt")
	}
	mustHistoryExec(t, f.s.DB, `DROP TRIGGER fail_renewal_audit ON v3_audit`)
	out, err = f.s.signNodeRenewal(context.Background(), f.c, f.lease, f.in)
	if err != nil || len(out.Certificate) == 0 {
		t.Fatal("retry after failed transaction did not succeed", err)
	}
	// Bind one successor to one parent even when a caller submits a second
	// valid CSR with possession of that same old private key.
	var id string
	if err := f.s.DB.QueryRow(`SELECT id FROM v3_node_certificates LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	b, err := f.s.readNodeIdentity(context.Background(), f.c, f.t.vault, id, f.in.Request.Node)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	_, different := renewalPendingForTest(t, f.provisioningFixture, b, "different-pending")
	changed := f.in
	changed.Request = different
	failed, err := f.s.signNodeRenewal(context.Background(), f.c, f.lease, changed)
	requireEmptyRenewalFailure(t, failed, err)
	changed = f.in
	changed.LifetimeHours++
	failed, err = f.s.signNodeRenewal(context.Background(), f.c, f.lease, changed)
	requireEmptyRenewalFailure(t, failed, err)
	// Replays need no node key, Vault or CA private key. New signing still does.
	keyPath := filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")
	if err := os.Rename(keyPath, keyPath+".offline"); err != nil {
		t.Fatal(err)
	}
	replayed, err := f.s.signNodeRenewal(context.Background(), f.c, f.lease, f.in)
	if err != nil || !bytes.Equal(replayed.Certificate, out.Certificate) {
		t.Fatal("committed receipt could not be replayed without signing key", err)
	}
}

func TestNodeRenewalRegistryCommitFailureDoesNotDeliverCertificate(t *testing.T) {
	f := newRenewalRegistryFixture(t)
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_renewal_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic deferred commit failure';END$$; CREATE CONSTRAINT TRIGGER fail_renewal_commit AFTER INSERT ON v3_node_certificate_renewals DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_renewal_commit()`)
	out, err := f.s.signNodeRenewal(context.Background(), f.c, f.lease, f.in)
	requireEmptyRenewalFailure(t, out, err)
	if tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
		t.Fatal("failed commit left a durable successor")
	}
	mustHistoryExec(t, f.s.DB, `DROP TRIGGER fail_renewal_commit ON v3_node_certificate_renewals`)
	if _, err := f.s.signNodeRenewal(context.Background(), f.c, f.lease, f.in); err != nil {
		t.Fatal("failed commit could not be safely retried", err)
	}
}

func TestNodeRenewalRegistryReplayChecksSharedRevocationFloor(t *testing.T) {
	f := newRenewalRegistryFixture(t)
	ctx := context.Background()
	if _, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	newCRL, err := f.ca.Revoke(f.crl, [][]byte{f.in.Request.Certificate}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, newCRL)
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	requireEmptyRenewalFailure(t, out, err)
	if err := os.WriteFile(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.crl"), newCRL, 0600); err != nil {
		t.Fatal(err)
	}
	out, err = f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	requireEmptyRenewalFailure(t, out, err)
}

func TestNodeRenewalRegistryMigrationRequiresConsistentBackup(t *testing.T) {
	f := newRenewalRegistryFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, f.s.DB, nodeHistoryRetirementTestDrop+`DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE v3_node_renewal_jobs;DROP TABLE v3_node_certificate_renewals;DELETE FROM v3_schema WHERE version>=30`)
	if err := f.s.Migrate(ctx); err == nil {
		t.Fatal("existing schema upgraded without backup")
	}
	if err := f.s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if version, err := currentSchema(ctx, f.s.DB); err != nil || version != SchemaVersion {
		t.Fatal(version, err)
	}
	if tableCount(t, f.s, "v3_node_certificates") != 1 || tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
		t.Fatal("migration lost installation identities or fabricated renewals")
	}
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	if err != nil || out.Receipt.Node != f.in.Request.Node {
		t.Fatal("migrated registry unusable", err)
	}
	// Verify the generic backup includes public renewal rows as well.
	file, err := f.s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil || !bytes.Contains(raw, []byte("v3_node_certificate_renewals")) {
		t.Fatal("renewal rows absent from consistent backup", err)
	}
	metadata, _ := json.Marshal(out.Receipt)
	if bytes.Contains(metadata, []byte("PRIVATE KEY")) {
		t.Fatal("private material in audit receipt")
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, file); err != nil {
		t.Fatal("consistent backup did not restore renewal dependencies", err)
	}
	lease, err := target.Acquire(ctx, f.lease.Resource, f.lease.Owner)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := target.signNodeRenewal(ctx, f.c, lease, f.in)
	if err != nil || restored.Receipt != out.Receipt || !bytes.Equal(restored.Certificate, out.Certificate) || tableCount(t, target, "v3_node_certificate_renewals") != 1 {
		t.Fatal("restored renewal ledger issued a different successor", err)
	}
}

func TestNodeRenewalRegistryConcurrentInitialIssuanceUsesConsistentLockOrder(t *testing.T) {
	f := newRenewalRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.s.PutNode(ctx, nodeFixture("node-b"), 0, 256); err != nil {
		t.Fatal(err)
	}
	errors := make(chan error, 12)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
			errors <- err
		}()
		go func() {
			defer wg.Done()
			_, err := f.s.IssueNodeCertificate(ctx, f.c, f.t.vault, "admin", "other-node-initial", NodeCertificateInput{Node: "node-b", Expected: 1})
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal("initial and renewed issuance blocked or failed", err)
		}
	}
}

func TestNodeRenewalRegistryLeaseExpiryDuringIssuanceDoesNotCommit(t *testing.T) {
	f := newRenewalRegistryFixture(t)
	// The final fence must use PostgreSQL time, not the caller's Expires field.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()+interval '0.15 seconds'`)
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION delay_renewal() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(0.25); RETURN NEW; END$$; CREATE TRIGGER delay_renewal BEFORE INSERT ON v3_node_certificate_renewals FOR EACH ROW EXECUTE FUNCTION delay_renewal()`)
	out, err := f.s.signNodeRenewal(context.Background(), f.c, f.lease, f.in)
	requireEmptyRenewalFailure(t, out, err)
	if !errors.Is(err, ErrLeaseLost) || tableCount(t, f.s, "v3_node_certificate_renewals") != 0 {
		t.Fatal("expired lease committed a certificate", err)
	}
}
