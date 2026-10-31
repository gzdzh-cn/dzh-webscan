package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

func renewalRelayFixture(t *testing.T) (renewalRegistryFixture, Node, Lease, []byte) {
	t.Helper()
	f := newRenewalRegistryFixture(t)
	n, err := scanActiveNode(f.s.DB.QueryRow(`SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, f.in.Request.Node))
	if err != nil {
		t.Fatal(err)
	}
	l, err := f.s.Acquire(context.Background(), shardResource(n.Shard), "relay-a")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.in.Request)
	return f, n, l, raw
}

func changeRenewalRuntime(t *testing.T, f renewalRegistryFixture, hostname string) Node {
	t.Helper()
	ctx := context.Background()
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE v3_nodes SET version=version+1,server_name=$2 WHERE id=$1`, f.in.Request.Node, hostname); err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureSavedNodeTx(ctx, tx, f.in.Request.Node)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishNodeRuntimeTx(ctx, tx, f.in.Request.Node, snapshot, 1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	n, err := scanActiveNode(f.s.DB.QueryRow(`SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, f.in.Request.Node))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNodeRenewalQueueConcurrentPublicRoundTrip(t *testing.T) {
	f, n, l, raw := renewalRelayFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.s.queueNodeRenewal(ctx, n, l, raw, f.in.LifetimeHours)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if tableCount(t, f.s, "v3_node_renewal_jobs") != 1 {
		t.Fatal("duplicate public requests")
	}
	jobs, err := f.s.pendingNodeRenewals(ctx, 100)
	if err != nil || len(jobs) != 1 || !bytes.Equal(jobs[0].Request, raw) {
		t.Fatal("public request unavailable to isolated host", jobs, err)
	}
	if _, err := f.s.nodeRenewalDelivery(ctx, n, l, f.in.Request.CertificateSHA256, f.in.Request.SHA256()); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("unsigned request became deliverable", err)
	}
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err = f.s.pendingNodeRenewals(ctx, 100)
	if err != nil || len(jobs) != 0 {
		t.Fatal("committed issuance was queued for repeated signing", err)
	}
	// Replay/delivery still works with no CA private key or Vault access.
	if err := os.Rename(filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key"), filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key.offline")); err != nil {
		t.Fatal(err)
	}
	delivery, err := f.s.nodeRenewalDelivery(ctx, n, l, f.in.Request.CertificateSHA256, f.in.Request.SHA256())
	if err != nil || delivery.Receipt != out.Receipt || !bytes.Equal(delivery.Certificate, out.Certificate) {
		t.Fatal("committed public receipt not delivered", err)
	}
	trust, err := nodepki.NewTrust(f.node.CA, delivery.CRL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := provisioningCertificate(delivery.Certificate)
	record, err := nodepki.ActivateNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, n.ID, f.in.Request.CertificateSHA256, f.in.Request.SHA256(), delivery.Certificate, time.Now(), func(_cert *x509.Certificate) error { return trust.Verify(_cert, nodepki.Node, n.ID, time.Now()) })
	if err != nil || record.CertificateSHA256 != out.Receipt.CertificateSHA256 {
		t.Fatal("local pending key not usable with queued receipt", err)
	}
	for i := 0; i < 2; i++ {
		if err := f.s.confirmNodeRenewal(ctx, n, l, record.CertificateSHA256, cert.NotAfter.Unix()); err != nil {
			t.Fatal("lost activation response reconciliation failed", err)
		}
	}
	var activated bool
	var audits int
	if err := f.s.DB.QueryRow(`SELECT activated_at IS NOT NULL FROM v3_node_renewal_jobs`).Scan(&activated); err != nil || !activated {
		t.Fatal("activation not durable", err)
	}
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='activate-node-certificate'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("activation audit duplicated", audits, err)
	}
	var stored []byte
	if err := f.s.DB.QueryRow(`SELECT to_jsonb(j)::text FROM v3_node_renewal_jobs j`).Scan(&stored); err != nil || bytes.Contains(stored, []byte("PRIVATE KEY")) || bytes.Contains(stored, []byte(f.identity)) {
		t.Fatal("private state in public queue", err)
	}
}

func TestNodeRenewalQueueRebindsDeliveryWithoutReissuing(t *testing.T) {
	f, n, l, raw := renewalRelayFixture(t)
	ctx := context.Background()
	if _, err := f.s.queueNodeRenewal(ctx, n, l, raw, f.in.LifetimeHours); err != nil {
		t.Fatal(err)
	}
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	if err != nil {
		t.Fatal(err)
	}
	next := changeRenewalRuntime(t, f, n.ServerName)
	if _, err := f.s.nodeRenewalDelivery(ctx, n, l, f.in.Request.CertificateSHA256, f.in.Request.SHA256()); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale collector delivered certificate", err)
	}
	if _, err := f.s.nodeRenewalDelivery(ctx, next, l, f.in.Request.CertificateSHA256, f.in.Request.SHA256()); !errors.Is(err, ErrConflict) {
		t.Fatal("new collector did not rebind before delivery", err)
	}
	j, err := f.s.queueNodeRenewal(ctx, next, l, raw, f.in.LifetimeHours)
	if err != nil || j.RuntimeEpoch != next.RuntimeEpoch || j.Snapshot == f.in.Snapshot {
		t.Fatal("same request failed current-runtime rebind", err)
	}
	delivery, err := f.s.nodeRenewalDelivery(ctx, next, l, j.ParentSHA256, j.RequestSHA256)
	if err != nil || delivery.Receipt != out.Receipt || !bytes.Equal(delivery.Certificate, out.Certificate) || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("harmless runtime change stranded/reissued successor", err)
	}
	if err := f.s.confirmNodeRenewal(ctx, next, l, out.Receipt.CertificateSHA256, out.Receipt.ExpiresAt.Unix()); err != nil {
		t.Fatal(err)
	}
	changed := changeRenewalRuntime(t, f, "not-covered.example.test")
	if _, err := f.s.queueNodeRenewal(ctx, changed, l, raw, f.in.LifetimeHours); err == nil {
		t.Fatal("hostname transition reused invalid identity")
	}
	if err := f.s.confirmNodeRenewal(ctx, changed, l, out.Receipt.CertificateSHA256, out.Receipt.ExpiresAt.Unix()); err == nil {
		t.Fatal("hostname mismatch incorrectly confirmed")
	}
}

func TestNodeRenewalQueueRejectsInvalidWorkAndFences(t *testing.T) {
	for _, scenario := range []string{"bad-json", "wrong-node", "forged-proof", "unknown-parent", "revoked", "expired-crl", "hours", "busy", "wrong-shard", "lease-expired", "stale-runtime", "disabled", "draft-only", "request-conflict"} {
		t.Run(scenario, func(t *testing.T) {
			f, n, l, raw := renewalRelayFixture(t)
			hours := f.in.LifetimeHours
			switch scenario {
			case "bad-json":
				raw = append(raw, '\n')
			case "wrong-node", "forged-proof":
				r := f.in.Request
				if scenario == "wrong-node" {
					r.Node = "other"
				} else {
					r.Proof = append([]byte{}, r.Proof...)
					r.Proof[0] ^= 1
				}
				raw, _ = json.Marshal(r)
			case "unknown-parent":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_certificates`)
			case "revoked":
				crl, err := f.ca.Revoke(f.crl, [][]byte{f.in.Request.Certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, crl)
			case "expired-crl":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, []byte("invalid"))
			case "hours":
				hours = 2161
			case "busy":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_jobs(id,node,username,kind,node_version,credential,plan,plan_digest) SELECT 'busy','node-a','admin','upgrade',1,id,'{}','test' FROM v3_credentials WHERE node='node-a' LIMIT 1`)
			case "wrong-shard":
				l.Resource = "shard:other"
			case "lease-expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE resource=$1`, l.Resource)
			case "stale-runtime":
				n.RuntimeEpoch++
			case "disabled":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET enabled=false`)
			case "draft-only":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_runtime`)
			case "request-conflict":
				if _, err := f.s.queueNodeRenewal(context.Background(), n, l, raw, hours); err != nil {
					t.Fatal(err)
				}
				hours++
			}
			j, err := f.s.queueNodeRenewal(context.Background(), n, l, raw, hours)
			if err == nil || j.Node != "" {
				t.Fatal("invalid queue operation succeeded", err)
			}
			if scenario != "request-conflict" && tableCount(t, f.s, "v3_node_renewal_jobs") != 0 {
				t.Fatal("rejected request created work")
			}
		})
	}
}

func TestNodeRenewalQueueDeliveryRechecksTrustAndExactReceipt(t *testing.T) {
	for _, scenario := range []string{"request", "certificate", "expiry", "revocation", "audit-failure"} {
		t.Run(scenario, func(t *testing.T) {
			f, n, l, raw := renewalRelayFixture(t)
			ctx := context.Background()
			if _, err := f.s.queueNodeRenewal(ctx, n, l, raw, f.in.LifetimeHours); err != nil {
				t.Fatal(err)
			}
			out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
			if err != nil {
				t.Fatal(err)
			}
			request, cert, expiry := f.in.Request.SHA256(), out.Receipt.CertificateSHA256, out.Receipt.ExpiresAt.Unix()
			switch scenario {
			case "request":
				request = digest([]byte("other"))
			case "certificate":
				cert = digest([]byte("other"))
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET certificate_sha256=$1`, cert)
			case "expiry":
				expiry++
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET not_after=not_after+interval '1 second'`)
			case "revocation":
				crl, err := f.ca.Revoke(out.CRL, [][]byte{out.Certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, crl)
			case "audit-failure":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_activation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='activate-node-certificate' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_activation BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_activation()`)
			}
			if scenario != "audit-failure" {
				delivery, err := f.s.nodeRenewalDelivery(ctx, n, l, f.in.Request.CertificateSHA256, request)
				if err == nil || len(delivery.Certificate) != 0 {
					t.Fatal("invalid receipt delivered", err)
				}
			} else if err := f.s.confirmNodeRenewal(ctx, n, l, cert, expiry); err == nil {
				t.Fatal("activation committed without audit")
			}
			if scenario != "request" && scenario != "audit-failure" {
				if err := f.s.confirmNodeRenewal(ctx, n, l, cert, expiry); err == nil {
					t.Fatal("invalid activation was recorded")
				}
			}
			var activated bool
			if err := f.s.DB.QueryRow(`SELECT activated_at IS NOT NULL FROM v3_node_renewal_jobs`).Scan(&activated); err != nil || activated {
				t.Fatal("failed confirmation marked activated", err)
			}
		})
	}
}

func TestNodeRenewalQueueMigrationBackupAndRestore(t *testing.T) {
	f, n, l, raw := renewalRelayFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, f.s.DB, nodeHistoryRetirementTestDrop+`DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;ALTER TABLE v3_node_certificate_renewals DROP COLUMN request_kind;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE v3_node_renewal_jobs;DELETE FROM v3_schema WHERE version>=31`)
	if err := f.s.Migrate(ctx); err == nil {
		t.Fatal("schema 30 upgraded without backup")
	}
	if err := f.s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.queueNodeRenewal(ctx, n, l, raw, f.in.LifetimeHours); err != nil {
		t.Fatal(err)
	}
	file, err := f.s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	target := emptyTestStore(t)
	if err := target.RestorePostgres(ctx, file); err != nil {
		t.Fatal(err)
	}
	jobs, err := target.pendingNodeRenewals(ctx, 100)
	if err != nil || len(jobs) != 1 || !bytes.Equal(jobs[0].Request, raw) {
		t.Fatal("pending request lost in backup/restart", err)
	}
	if version, err := currentSchema(ctx, target.DB); err != nil || version != SchemaVersion {
		t.Fatal("restored incorrect schema", version, err)
	}
	if _, err := target.pendingNodeRenewals(ctx, 1001); err == nil {
		t.Fatal("unbounded signer batch accepted")
	}
}

func TestNodeRenewalQueueCommitFailureAndExpiryReturnNoSuccess(t *testing.T) {
	for _, scenario := range []string{"commit", "lease-expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f, n, l, raw := renewalRelayFixture(t)
			if scenario == "commit" {
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_queue_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic commit failure'; END$$; CREATE CONSTRAINT TRIGGER fail_queue_commit AFTER INSERT ON v3_node_renewal_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_queue_commit()`)
			} else {
				mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET expires_at=clock_timestamp()+interval '0.15 seconds' WHERE resource=$1`, l.Resource)
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION delay_queue_insert() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(0.25); RETURN NEW; END$$; CREATE TRIGGER delay_queue_insert BEFORE INSERT ON v3_node_renewal_jobs FOR EACH ROW EXECUTE FUNCTION delay_queue_insert()`)
			}
			out, err := f.s.queueNodeRenewal(context.Background(), n, l, raw, f.in.LifetimeHours)
			if err == nil || out.Node != "" || tableCount(t, f.s, "v3_node_renewal_jobs") != 0 {
				t.Fatal("uncommitted/unfenced work escaped", err)
			}
		})
	}
	f, n, l, raw := renewalRelayFixture(t)
	ctx := context.Background()
	if _, err := f.s.queueNodeRenewal(ctx, n, l, raw, f.in.LifetimeHours); err != nil {
		t.Fatal(err)
	}
	out, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, `CREATE FUNCTION fail_activation_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic activation commit failure'; END$$; CREATE CONSTRAINT TRIGGER fail_activation_commit AFTER UPDATE ON v3_node_renewal_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_activation_commit()`)
	if err := f.s.confirmNodeRenewal(ctx, n, l, out.Receipt.CertificateSHA256, out.Receipt.ExpiresAt.Unix()); err == nil {
		t.Fatal("activation reported success before commit")
	}
	var activated bool
	if err := f.s.DB.QueryRow(`SELECT activated_at IS NOT NULL FROM v3_node_renewal_jobs`).Scan(&activated); err != nil || activated {
		t.Fatal("failed commit changed durable activation", err)
	}
	var audits int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='activate-node-certificate'`).Scan(&audits); err != nil || audits != 0 {
		t.Fatal("activation audit not rolled back", err)
	}
}
