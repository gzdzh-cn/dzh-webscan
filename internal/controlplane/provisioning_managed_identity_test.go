package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

func committedManagedUpgradeFixture(t *testing.T) (renewalRegistryFixture, DeploymentRequest) {
	t.Helper()
	f := newRenewalRegistryFixture(t)
	if _, err := f.s.signNodeRenewal(context.Background(), f.c, f.lease, f.in); err != nil {
		t.Fatal(err)
	}
	// The registry fixture creates a synthetic active runtime; a real upgrade
	// additionally has a successfully applied installation version.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET applied_version=version WHERE id=$1`, f.in.Request.Node)
	in := f.provisioningFixture.in
	in.Kind, in.IdentityDirectory = "upgrade", ""
	if err := f.s.DB.QueryRow(`SELECT id FROM v3_node_certificates WHERE node=$1`, in.Node).Scan(&in.IdentityID); err != nil {
		t.Fatal(err)
	}
	f.provisioningFixture.in = in
	request, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, in)
	if err != nil {
		t.Fatal(err)
	}
	return f, request
}

func readPreparedManagedMaterial(t *testing.T, f provisioningFixture, in DeploymentRequest) nodeconfig.Material {
	t.Helper()
	path := filepath.Join(f.c.Executor.ConfigurationDirectory, in.RuntimeArtifact.SHA256, "node.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := nodeconfig.Decode(raw, time.Now())
	if err != nil || m.Format != 3 || len(m.Key) != 0 || len(m.Certificate) != 0 || bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("upgrade is not keyless", err)
	}
	return m
}

func TestManagedUpgradeUsesCommittedLocalRenewalWithoutSeedKey(t *testing.T) {
	f, first := committedManagedUpgradeFixture(t)
	ctx := context.Background()
	readPreparedManagedMaterial(t, f.provisioningFixture, first)
	// The activation response may be lost; committed issuance is sufficient
	// for selection, while the node still verifies its actual live identity.
	if tableCount(t, f.s, "v3_node_renewal_jobs") != 0 {
		t.Fatal("fixture unexpectedly depends on a collector activation receipt")
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificates SET ciphertext='unavailable-seed-key'::bytea`)
	if _, err := f.s.readNodeIdentity(ctx, f.c, f.t.vault, f.provisioningFixture.in.IdentityID, first.Node); err == nil {
		t.Fatal("seed reader unexpectedly accepted unavailable private key")
	}
	second, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.provisioningFixture.in)
	if err != nil || !sameDeploymentRequest(first, second) {
		t.Fatal("private seed still required after local renewal", err)
	}
	preview, err := f.s.previewLocalDeployment(ctx, f.c, f.t, "admin", second)
	if err != nil {
		t.Fatal("keyless upgrade preview", err)
	}
	if _, err := f.s.confirmLocalDeployment(ctx, f.c, f.t, "admin", "keyless-upgrade", preview.Token); err != nil {
		t.Fatal("keyless upgrade queue", err)
	}
	if tableCount(t, f.s, "v3_node_certificates") != 1 || tableCount(t, f.s, "v3_node_certificate_renewals") != 1 {
		t.Fatal("upgrade fabricated a new seed/key")
	}
}

func TestManagedUpgradeCLIAndSavedBindingDoNotReissueOrDecrypt(t *testing.T) {
	f, _ := committedManagedUpgradeFixture(t)
	ctx := context.Background()
	in := f.provisioningFixture.in
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificates SET ciphertext='unavailable-seed-key'::bytea`)
	binding := nodeProvisioningInput{Node: in.Node, Expected: in.Expected, Credential: in.Credential, Identity: in.IdentityID, Collectors: in.Collectors, RulesFile: in.RulesFile}
	raw, err := f.s.bindNodeProvisioning(ctx, f.c, f.t, "admin", "bind-managed-upgrade", binding)
	if err != nil {
		t.Fatal("historical binding still decrypts seed", err)
	}
	var receipt nodeProvisioningReceipt
	if json.Unmarshal(raw, &receipt) != nil || !receipt.Configured {
		t.Fatal("missing binding")
	}
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, in.Node))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := (configurationNodePreparer{f.s, f.c, f.t}).materialTx(ctx, tx, n)
	if err != nil || prepared.kind != "upgrade" || prepared.material.Format != 3 || len(prepared.material.Key) != 0 {
		t.Fatal("saved configuration application still uses seed", err)
	}
	tx.Rollback()
	in.IdentityID = ""
	path := filepath.Join(filepath.Dir(f.c.Executor.ConfigurationDirectory), "keyless-prepare.json")
	writeProvisioningInput(t, path, in)
	var out bytes.Buffer
	if err := f.s.localProvisioningCommand(ctx, f.c, Options{Action: "prepare-deployment", Username: "admin", Source: path}, &out); err != nil {
		t.Fatal("CLI tried issuing unnecessary seed", err)
	}
	if tableCount(t, f.s, "v3_node_certificates") != 1 {
		t.Fatal("CLI minted another installation key")
	}
}

func TestManagedUpgradeSurvivesRenewalBetweenPreparationAndQueue(t *testing.T) {
	f, before := committedManagedUpgradeFixture(t)
	ctx := context.Background()
	signed, err := f.s.signNodeRenewal(ctx, f.c, f.lease, f.in)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := nodepki.NewTrust(f.node.CA, signed.CRL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	active, err := nodepki.ActivateNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, before.Node, f.in.Request.CertificateSHA256, f.in.Request.SHA256(), signed.Certificate, time.Now(), func(cert *x509.Certificate) error { return trust.Verify(cert, nodepki.Node, before.Node, time.Now()) })
	if err != nil {
		t.Fatal(err)
	}
	request, err := nodepki.PrepareNodeRenewal(ctx, f.c.Collector.CAFile, f.identity, before.Node, active.CertificateSHA256, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in := f.in
	in.Request, in.LifetimeHours = request, 96
	if _, err := f.s.signNodeRenewal(ctx, f.c, f.lease, in); err != nil {
		t.Fatal(err)
	}
	after, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, f.provisioningFixture.in)
	if err != nil || !sameDeploymentRequest(before, after) {
		t.Fatal("live leaf rotation changed immutable upgrade artifact", err)
	}
	if _, err := f.s.previewLocalDeployment(ctx, f.c, f.t, "admin", before); err != nil {
		t.Fatal("rotation invalidated keyless preview", err)
	}
	if _, err := f.s.queueLocalDeployment(ctx, f.c, f.t, "admin", "queue-after-local-renewal", before); err != nil {
		t.Fatal("rotation stranded prepared upgrade", err)
	}
}

func TestManagedUpgradeRejectsForgedMissingOrRevokedRenewalEvidence(t *testing.T) {
	for _, scenario := range []string{"install-kind", "missing-evidence", "wrong-node", "wrong-root", "wrong-digest", "broken-certificate", "revoked", "wrong-host"} {
		t.Run(scenario, func(t *testing.T) {
			f, request := committedManagedUpgradeFixture(t)
			switch scenario {
			case "install-kind":
				request.Kind = "install"
			case "missing-evidence":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_certificate_renewals`)
			case "wrong-node":
				other, err := f.ca.Issue(nodepki.Node, "other-node", []string{"192.0.2.1"}, time.Now(), 72*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				cert, err := provisioningCertificate(other.Certificate)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET certificate=$1,certificate_sha256=$2`, other.Certificate, digest(cert.Raw))
			case "wrong-root":
				foreign := localProvisioningFixture(t)
				localWrite(t, f.c.Collector.CAFile, foreign.node.CA)
			case "wrong-digest":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET certificate_sha256=repeat('f',64)`)
			case "broken-certificate":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificate_renewals SET certificate='broken'::bytea`)
			case "revoked":
				var cert []byte
				if err := f.s.DB.QueryRow(`SELECT certificate FROM v3_node_certificate_renewals`).Scan(&cert); err != nil {
					t.Fatal(err)
				}
				crl, err := f.ca.Revoke(f.crl, [][]byte{cert}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				localWrite(t, f.c.Collector.RevocationFile, crl)
			case "wrong-host":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET server_name='other.example.test' WHERE id=$1`, request.Node)
			}
			if _, err := f.s.queueLocalDeployment(context.Background(), f.c, f.t, "admin", "reject-keyless", request); err == nil {
				t.Fatal("invalid keyless upgrade accepted", scenario)
			}
			if tableCount(t, f.s, "v3_deployment_jobs") != 0 {
				t.Fatal("failed validation created deployment")
			}
		})
	}
}

func TestManagedUpgradeHistoricalSeedCanExpireAndBeRevoked(t *testing.T) {
	// Record an older, genuinely expired same-node issuance alongside a real
	// committed renewal. This is historical registry setup, not time travel of
	// the online issuer: current online authentication remains strict.
	f := localProvisioningFixture(t, time.Now().Add(-48*time.Hour))
	enableRegistryIssuer(t, &f)
	ctx := context.Background()
	record := issuedNode(t, f, "current-seed")
	b, err := f.s.readNodeIdentity(ctx, f.c, f.t.vault, record.ID, f.in.Node)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	_, request := renewalPendingForTest(t, f, b, "managed-expiry-node")
	var snapshot string
	if err := f.s.DB.QueryRow(`SELECT snapshot FROM v3_node_runtime WHERE node=$1`, f.in.Node).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	l, err := f.s.Acquire(ctx, nodeRenewalResource(f.in.Node), "expiry-issuer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.signNodeRenewal(ctx, f.c, l, nodeRenewalSigningInput{Snapshot: snapshot, RuntimeEpoch: 1, LifetimeHours: 72, Request: request}); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Truncate(time.Second).Add(-36 * time.Hour)
	old, err := f.ca.Issue(nodepki.Node, f.in.Node, []string{"192.0.2.1"}, past, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(old.Key)
	cert, err := provisioningCertificate(old.Certificate)
	root, rootErr := provisioningCertificate(old.CA)
	if err != nil || rootErr != nil {
		t.Fatal(err, rootErr)
	}
	id := "historical-expired-seed"
	key, nonce, sealed, err := f.t.vault.sealNodeKey(id, f.in.Node, digest(root.Raw), digest(cert.Raw), old.Key)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_certificates(id,node,authority,node_version,server_name,serial,certificate,key_id,nonce,ciphertext,not_before,not_after) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11)`, id, f.in.Node, digest(root.Raw), "192.0.2.1", cert.SerialNumber.Text(16), old.Certificate, key, nonce, sealed, cert.NotBefore, cert.NotAfter)
	crl, err := f.ca.Revoke(f.crl, [][]byte{old.Certificate}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	localWrite(t, f.c.Collector.RevocationFile, crl)
	if _, err := f.s.readNodeIdentity(ctx, f.c, f.t.vault, id, f.in.Node); err == nil {
		t.Fatal("ordinary seed reader accepted expired/revoked identity")
	}
	in := f.in
	in.Kind, in.IdentityDirectory, in.IdentityID = "upgrade", "", id
	prepared, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, in)
	if err != nil {
		t.Fatal("expired historical seed stranded valid managed successor", err)
	}
	readPreparedManagedMaterial(t, f, prepared)
	if _, err := f.s.bindNodeProvisioning(ctx, f.c, f.t, "admin", "bind-expired-seed", nodeProvisioningInput{Node: in.Node, Expected: in.Expected, Credential: in.Credential, Identity: id, Collectors: in.Collectors, RulesFile: in.RulesFile}); err != nil {
		t.Fatal("expired reference prevented saved binding", err)
	}
}
