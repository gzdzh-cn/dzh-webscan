//go:build linux

package controlplane

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

// Only called after the outer real-kernel test's strict isolation guard. The
// fixtures deliberately install signed near-expiry/expired leaves; production
// publication correctly refuses shortening an installed certificate. All
// renewal/recovery/name maintenance afterwards uses the real host task, pinned
// SSH helper, live service and freshly authenticated mTLS observations.
func webKernelMaintenance(t *testing.T, ctx context.Context, f webDeploymentFixture, mode, site string, version *int64, wait func(func() bool, string), apply func(string), unchanged func()) {
	t.Helper()
	const active = "/var/lib/webscan-v1/pki-identity/active.pem"
	const anchor = "/var/lib/webscan-v1/pki-identity/ca.crt"
	const floor = "/var/lib/webscan-v1/pki-trust"
	read := func() nodepki.Bundle {
		t.Helper()
		b, _, err := nodepki.ReadIdentityWithRootState(anchor, active, floor, nodepki.Node, "node-a", time.Now())
		if err != nil {
			t.Fatal("actual maintained leaf", err)
		}
		clear(b.Key)
		return b
	}
	seed := func(at time.Time, lifetime time.Duration) nodepki.Bundle {
		t.Helper()
		b, err := f.ca.Issue(nodepki.Node, "node-a", []string{"127.0.0.1"}, at, lifetime)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(b.Key)
		cert, _ := provisioningCertificate(b.Certificate)
		root, _ := provisioningCertificate(b.CA)
		id := token()
		key, nonce, ciphertext, err := f.t.vault.sealNodeKey(id, "node-a", digest(root.Raw), digest(cert.Raw), b.Key)
		if err != nil {
			t.Fatal(err)
		}
		mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_certificates(id,node,authority,node_version,server_name,serial,certificate,key_id,nonce,ciphertext,not_before,not_after) VALUES($1,'node-a',$2,$3,'127.0.0.1',$4,$5,$6,$7,$8,$9,$10)`, id, digest(root.Raw), *version, cert.SerialNumber.Text(16), b.Certificate, key, nonce, ciphertext, cert.NotBefore, cert.NotAfter)
		temporary := filepath.Join(filepath.Dir(active), ".kernel-expiry-fixture")
		material := append(append([]byte{}, b.Certificate...), b.Key...)
		defer clear(material)
		if err := os.WriteFile(temporary, material, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temporary, active); err != nil {
			t.Fatal(err)
		}
		return nodepki.Bundle{CA: b.CA, Certificate: b.Certificate}
	}
	near := seed(time.Now().UTC().Truncate(time.Second), 96*time.Hour)
	parent, _ := provisioningCertificate(near.Certificate)
	wait(func() bool {
		result, err := f.s.processNodeRenewalQueue(ctx, f.c, "kernel-maintenance-signer", 8)
		if err != nil || result.Failed != 0 {
			t.Fatal("actual host renewal signer", err)
		}
		var activated bool
		return f.s.DB.QueryRowContext(ctx, `SELECT activated_at IS NOT NULL FROM v3_node_renewal_jobs WHERE node='node-a' AND parent_sha256=$1`, digest(parent.Raw)).Scan(&activated) == nil && activated
	}, "real Agent renewal queue, host signing and collector confirmation")
	unchanged()

	// The expired leaf blocks normal RPCs, but the Agent keeps its SQLite
	// queue. Recovery must authenticate over SSH and retain this actual event.
	expired := seed(time.Now().UTC().Add(-36*time.Hour).Truncate(time.Second), 24*time.Hour)
	cert, _ := provisioningCertificate(expired.Certificate)
	root, _ := provisioningCertificate(expired.CA)
	path := site + "/expired-identity-pending.php"
	if err := os.WriteFile(path, []byte("<?php echo 'pending while TLS expired';"), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:/var/lib/webscan-v1/agent.sqlite3?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var pendingEvent string
	wait(func() bool {
		return db.QueryRowContext(ctx, `SELECT id FROM events WHERE json_extract(payload,'$.path')=? AND accepted IS NULL ORDER BY created,id LIMIT 1`, path).Scan(&pendingEvent) == nil && pendingEvent != ""
	}, "actual SQLite pending event during expired identity")
	credential, _, err := f.s.latestWebCredential(ctx, f.t.vault, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := f.s.prepareNodeIdentityRecovery(ctx, f.c, f.t.vault, "admin", "kernel-expired-recovery", nodeIdentityRecoveryInput{Node: "node-a", Credential: credential, AuthoritySHA256: digest(root.Raw), ParentSHA256: digest(cert.Raw), Expected: *version, LifetimeHours: 30 * 24, Certificate: expired.Certificate})
	if err != nil {
		t.Fatal("actual expired recovery authorization", err)
	}
	runtime := &sshNodeIdentityRecovery{store: f.s, vault: f.t.vault, config: f.c, release: f.t.release, localHelper: f.t.config.HelperFile}
	worker := nodeIdentityRecoveryRunner{store: f.s, vault: f.t.vault, runtime: runtime}
	if err := worker.run(ctx, "admin", recovery.ID, func(p identityRecoveryProgress) error { t.Log("actual recovery", p.Phase, p.Status); return nil }); err != nil {
		t.Fatal("actual expired identity SSH recovery", err)
	}
	wait(func() bool {
		var count int
		var accepted sql.NullFloat64
		// A single file write can legitimately emit create and modify events.
		// De-duplication is by immutable event ID, not by filesystem path.
		return f.s.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_events WHERE node='node-a' AND id=$1 AND payload->>'path'=$2`, pendingEvent, path).Scan(&count) == nil && count == 1 &&
			db.QueryRowContext(ctx, `SELECT accepted FROM events WHERE id=?`, pendingEvent).Scan(&accepted) == nil && accepted.Valid
	}, "pending event persisted once after actual identity recovery")
	unchanged()

	b := read()
	cert, _ = provisioningCertificate(b.Certificate)
	n, err := scanNode(f.s.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id='node-a'"))
	if err != nil {
		t.Fatal(err)
	}
	n.ServerName = "kernel-node-next.example.test"
	if _, err := f.s.SaveNode(ctx, "admin", "kernel-save-new-tls-name", n, *version, 1); err != nil {
		t.Fatal(err)
	}
	*version++
	changeInput := nodeNameChangeInput{Node: "node-a", Credential: credential, AuthoritySHA256: digest(root.Raw), ParentSHA256: digest(cert.Raw), Expected: *version, LifetimeHours: 30 * 24, Certificate: b.Certificate}
	change, err := f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "kernel-name-overlap", changeInput)
	if err != nil {
		t.Fatal(err)
	}
	nameRuntime := &sshNodeNameChange{store: f.s, vault: f.t.vault, config: f.c, release: f.t.release, localHelper: f.t.config.HelperFile}
	// Cancel after the real remote activation, then explicitly reauthorize the
	// same receipt. This exercises continuation without another issuance.
	lease, err := f.s.Acquire(ctx, nodeRenewalResource("node-a"), "kernel-name-interrupted")
	if err != nil {
		t.Fatal(err)
	}
	if err := withRecoveryHeartbeat(ctx, change.ExpiresAt, 10*time.Second, 3*time.Second, func(op context.Context) error {
		return f.s.renewNodeNameChangeLease(op, f.t.vault, lease, change.ID)
	}, func(op context.Context) error {
		if _, err := nameRuntime.prepare(op, lease, change.ID); err != nil {
			return err
		}
		return nameRuntime.activate(op, lease, change.ID)
	}); err != nil {
		t.Fatal("real interrupted name activation", err)
	}
	if err := f.s.Release(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.cancelNodeNameChange(ctx, "admin", "kernel-cancel-name-authorization", change.ID); err != nil {
		t.Fatal(err)
	}
	change, err = f.s.prepareNodeNameChange(ctx, f.c, f.t.vault, "admin", "kernel-name-reauthorized", changeInput)
	if err != nil {
		t.Fatal(err)
	}
	nameWorker := nodeNameChangeRunner{store: f.s, vault: f.t.vault, runtime: nameRuntime}
	if err := nameWorker.run(ctx, "admin", change.ID, func(p nameChangeProgress) error { t.Log("actual name overlap", p.Phase, p.Status); return nil }); err != nil {
		t.Fatal("actual name authorization continuation", err)
	}
	apply("kernel-apply-new-tls-name")
	// Retire only exact nonactive snapshots, preserving records and audits.
	rows, err := f.s.DB.QueryContext(ctx, `SELECT c.id FROM v3_node_configurations c JOIN v3_node_runtime r ON r.node=c.node WHERE c.node='node-a' AND c.id<>r.snapshot ORDER BY c.id`)
	if err != nil {
		t.Fatal(err)
	}
	retire := nodeHistoryRetirementInput{Node: "node-a", Expected: *version}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		retire.Snapshots = append(retire.Snapshots, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(retire.Snapshots) == 0 {
		t.Fatal("historical snapshots unavailable", err)
	}
	preview, err := f.s.previewNodeHistoryRetirement(ctx, "admin", retire)
	if err != nil {
		t.Fatal(err)
	}
	retire.Confirm, retire.PreviewSHA256 = true, preview.PreviewSHA256
	if _, err := f.s.retireNodeHistory(ctx, "admin", "kernel-retire-old-name", retire); err != nil {
		t.Fatal(err)
	}
	b = read()
	prune, err := f.s.prepareNodeNamePruning(ctx, f.c, f.t.vault, "admin", "kernel-prune-old-name", nodeNamePruningInput{Node: "node-a", Credential: credential, Expected: *version, LifetimeHours: 30 * 24, Certificate: b.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	pruneRuntime := &sshNodeNamePruning{store: f.s, vault: f.t.vault, config: f.c, release: f.t.release, localHelper: f.t.config.HelperFile}
	pruneWorker := nodeNamePruningRunner{store: f.s, vault: f.t.vault, config: f.c, runtime: pruneRuntime}
	if err := pruneWorker.run(ctx, "admin", prune.ID, func(p namePruningProgress) error { t.Log("actual name pruning", p.Phase, p.Status); return nil }); err != nil {
		t.Fatal("actual old name pruning", err)
	}
	b = read()
	cert, _ = provisioningCertificate(b.Certificate)
	if cert.VerifyHostname(n.ServerName) != nil || cert.VerifyHostname("127.0.0.1") == nil {
		t.Fatal("actual Agent did not prune old TLS name")
	}
	var kept int
	if err := f.s.DB.QueryRowContext(ctx, `SELECT count(*) FROM v3_node_history_retirements WHERE node='node-a'`).Scan(&kept); err != nil || kept != len(retire.Snapshots) {
		t.Fatal("retirement evidence missing", err)
	}
	unchanged()
	t.Logf("real %s Agent automatic renewal, expired SSH recovery, reauthorization, name overlap, public config apply, explicit history retirement and name pruning passed; prior event persisted once", mode)
}
