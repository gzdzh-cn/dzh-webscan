package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"webscan/internal/nodepki"
)

func TestRootCompletedProvisioningUsesSuccessorAndPreservesRotatedAnchor(t *testing.T) {
	w, runtime, j := newRootRunnerFixture(t)
	ctx := context.Background()
	report := func(rootRotationProgress) error { return nil }
	if err := w.run(ctx, "admin", j.ID, false, report); err != nil {
		t.Fatal(err)
	}
	if err := w.run(ctx, "admin", j.ID, true, report); err != nil {
		t.Fatal(err)
	}
	f := runtime.f
	// A rolled existing installation upgrades without the historical private
	// seed and without replacing the immutable original anchor.
	var seed string
	if err := f.s.DB.QueryRow(`SELECT id FROM v3_node_certificates WHERE node=$1 LIMIT 1`, f.provisioningFixture.in.Node).Scan(&seed); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_certificates SET ciphertext='unavailable-historical-key'::bytea`)
	in := f.provisioningFixture.in
	in.Kind, in.IdentityID, in.IdentityDirectory = "upgrade", seed, ""
	request, err := f.s.prepareLocalDeployment(ctx, f.c, f.t, in)
	if err != nil {
		t.Fatal("rotated upgrade preparation", err)
	}
	m := readPreparedManagedMaterial(t, f.provisioningFixture, request)
	if !bytes.Equal(m.CA, j.Anchor) {
		t.Fatal("rotated upgrade changed anchor")
	}
	if _, err := f.s.previewLocalDeployment(ctx, f.c, f.t, "admin", request); err != nil {
		t.Fatal("rotated upgrade preview", err)
	}
	// A genuinely new node pins the successor directly, with existing format 2.
	n, err := scanNode(f.s.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, in.Node))
	if err != nil {
		t.Fatal(err)
	}
	n.ID, n.Version, n.AppliedVersion = "node-after-root", 0, 0
	if err := f.s.PutNode(ctx, n, 0, f.c.Collector.Shards); err != nil {
		t.Fatal(err)
	}
	in.Node, in.Expected, in.Kind = n.ID, 1, "install"
	in.Credential = addCredential(t, f.s, f.t.vault, n.ID)
	raw, err := f.s.IssueNodeCertificate(ctx, f.c, f.t.vault, "admin", "successor-new-node", NodeCertificateInput{Node: n.ID, Expected: 1, LifetimeHours: 24})
	if err != nil {
		t.Fatal("successor issuance", err)
	}
	var issued NodeCertificateRecord
	if err := json.Unmarshal(raw, &issued); err != nil {
		t.Fatal(err)
	}
	final, _, err := f.s.readRootTask(ctx, f.t.vault, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	sha, _ := nodepki.RootFingerprint(final.Roots.Dual.NewCA)
	if issued.Authority != sha {
		t.Fatal("new node signed by retired root")
	}
	in.IdentityID = issued.ID
	b, err := f.s.readNodeIdentity(ctx, f.c, f.t.vault, issued.ID, n.ID)
	defer clear(b.Key)
	if err != nil || !bytes.Equal(b.CA, final.Roots.Dual.NewCA) {
		t.Fatal("new node identity", err)
	}
	request, err = f.s.prepareLocalDeployment(ctx, f.c, f.t, in)
	if err != nil {
		t.Fatal("new node preparation", err)
	}
	artifact, err := os.ReadFile(filepath.Join(f.c.Executor.ConfigurationDirectory, request.RuntimeArtifact.SHA256, "node.json"))
	if err != nil {
		t.Fatal(err)
	}
	material, err := decodeProvisioningMaterial(f.c, artifact, time.Now())
	defer clear(material.Key)
	if err != nil || material.Format != 2 || !bytes.Equal(material.CA, final.Roots.Dual.NewCA) {
		t.Fatal("new node anchor", err)
	}
	if validateProvisioningTrust(f.c, material, time.Now()) != nil {
		t.Fatal("new node collector trust")
	}
	if _, err := f.s.previewLocalDeployment(ctx, f.c, f.t, "admin", request); err != nil {
		t.Fatal("successor preview", err)
	}
}
