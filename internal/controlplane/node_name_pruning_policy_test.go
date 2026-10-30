package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Real isolated PG transactions and public certificate validation, with stored
// applied-version/extra-SAN evidence as explicit fixtures. No remote service is
// installed or observed, and a plan does not authorize signing or activation.
func namePruningPolicyFixture(t *testing.T) (renewalRegistryFixture, []byte) {
	t.Helper()
	f := newRenewalRegistryFixture(t)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET applied_version=version WHERE id=$1`, f.in.Request.Node)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_runtime SET delivered_version=1 WHERE node=$1`, f.in.Request.Node)
	n := runtimeNodeForTest(t, f.s, f.in.Request.Node)
	b, err := f.ca.Issue("node", n.ID, []string{n.ServerName, "unused.example.test"}, time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Key)
	cert, err := provisioningCertificate(b.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	// Public-only historical fixture. No usable centrally stored key is needed
	// for planning; the original seed remains unchanged.
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_certificates(id,node,authority,node_version,server_name,serial,certificate,key_id,nonce,ciphertext,not_before,not_after) VALUES('pruning-policy-parent',$1,$2,1,$3,$4,$5,'unavailable-seed','x','unavailable-key',$6,$7)`, n.ID, f.in.Request.AuthoritySHA256, n.ServerName, cert.SerialNumber.Text(16), b.Certificate, cert.NotBefore, cert.NotAfter)
	return f, b.Certificate
}

func TestNodeNamePruningPolicyUsesAppliedStateAndPreservesAllSnapshots(t *testing.T) {
	f, certificate := namePruningPolicyFixture(t)
	ctx := context.Background()
	n := runtimeNodeForTest(t, f.s, f.in.Request.Node)
	key := filepath.Join(f.c.NodePKI.AuthorityDirectory, "ca.key")
	if err := os.Rename(key, key+".offline"); err != nil {
		t.Fatal(err)
	}
	before := tableCount(t, f.s, "v3_audit")
	p, err := f.s.planNodeNamePruning(ctx, f.c, "admin", n.ID, n.Version, certificate)
	if err != nil {
		t.Fatal(err)
	}
	if p.ActiveName != n.ServerName || p.RuntimeEpoch != n.RuntimeEpoch || p.NodeVersion != n.Version || p.ActorRevision < 1 || !reflect.DeepEqual(p.Names, []string{n.ServerName}) || !reflect.DeepEqual(p.RemovableNames, []string{"unused.example.test"}) || p.ConfigurationSHA256 != digest(n.Config) || p.DependenciesSHA256 == "" {
		t.Fatal("incorrect applied-state plan", p)
	}
	repeated, err := f.s.planNodeNamePruning(ctx, f.c, "admin", n.ID, n.Version, certificate)
	if err != nil || !reflect.DeepEqual(p, repeated) {
		t.Fatal("read-only plan changed without source changes", err)
	}
	if tableCount(t, f.s, "v3_audit") != before {
		t.Fatal("planning mutated audit or prepared authorization")
	}
	// Even a disabled historical snapshot protects its name; a caller cannot
	// drop it merely because the current configuration uses a different name.
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_configurations SELECT 'protected-old',node,version,name,endpoint,'unused.example.test',false,mode,shard,config FROM v3_node_configurations WHERE id=$1`, p.Snapshot)
	protected, err := f.s.planNodeNamePruning(ctx, f.c, "admin", n.ID, n.Version, certificate)
	if err != nil || len(protected.RemovableNames) != 0 || !reflect.DeepEqual(protected.Names, []string{n.ServerName, "unused.example.test"}) || protected.DependenciesSHA256 == p.DependenciesSHA256 {
		t.Fatal("historical recovery name was silently retired", protected, err)
	}
	// All snapshot bytes are bound, not just the set of names. There is no
	// execution token here; a later durable task must recheck this dependency.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_node_configurations SET config='{"changed":true}' WHERE id='protected-old'`)
	changed, err := f.s.planNodeNamePruning(ctx, f.c, "admin", n.ID, n.Version, certificate)
	if err != nil || changed.DependenciesSHA256 == protected.DependenciesSHA256 {
		t.Fatal("changed recovery config did not invalidate dependency hash", err)
	}
}

func TestNodeNamePruningPolicyRejectsStaleUnappliedOrUnknownState(t *testing.T) {
	for _, scenario := range []string{"viewer", "unknown-user", "version", "pending-edit", "disabled", "undelivered", "runtime-generation", "active-config", "active-shard", "active-display-name", "unknown-parent", "revoked-parent", "pending-renewal", "missing-snapshot", "uncovered-history", "existing-successor"} {
		t.Run(scenario, func(t *testing.T) {
			f, certificate := namePruningPolicyFixture(t)
			ctx := context.Background()
			n := runtimeNodeForTest(t, f.s, f.in.Request.Node)
			user, expected := "admin", n.Version
			switch scenario {
			case "viewer":
				user = "viewer"
			case "unknown-user":
				user = "unknown"
			case "version":
				expected++
			case "pending-edit":
				n.Name = "saved-but-unapplied"
				if _, err := f.s.SaveNode(ctx, "admin", "pending-pruning", n, n.Version, 256); err != nil {
					t.Fatal(err)
				}
				expected++
			case "disabled":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET enabled=false WHERE id=$1`, n.ID)
			case "undelivered":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_node_runtime SET delivered_version=0 WHERE node=$1`, n.ID)
			case "runtime-generation":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, n.ID)
			case "active-config":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET config='{"pending":true}' WHERE id=$1`, n.ID)
			case "active-shard":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET shard=(shard+1)%256 WHERE id=$1`, n.ID)
			case "active-display-name":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET name='unregistered-change' WHERE id=$1`, n.ID)
			case "unknown-parent":
				certificate = f.node.Certificate
			case "revoked-parent":
				crl, err := f.ca.Revoke(f.crl, [][]byte{certificate}, time.Now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `UPDATE v3_pki_authorities SET crl=$1`, crl)
			case "pending-renewal":
				raw, err := json.Marshal(f.in.Request)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_renewal_jobs(node,parent_sha256,request_sha256,request,snapshot,runtime_epoch,lifetime_hours) VALUES($1,$2,$3,$4,$5,$6,72)`, n.ID, f.in.Request.CertificateSHA256, f.in.Request.SHA256(), raw, f.in.Snapshot, n.RuntimeEpoch)
			case "missing-snapshot":
				mustHistoryExec(t, f.s.DB, `DELETE FROM v3_node_runtime WHERE node=$1`, n.ID)
			case "uncovered-history":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_configurations SELECT 'unknown-history',node,version,name,endpoint,'not-covered.example.test',true,mode,shard,config FROM v3_node_configurations WHERE id=$1`, f.in.Snapshot)
			case "existing-successor":
				cert, err := provisioningCertificate(certificate)
				if err != nil {
					t.Fatal(err)
				}
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_certificate_renewals(node,authority,parent_sha256,request_sha256,snapshot,runtime_epoch,lifetime_hours,certificate,certificate_sha256,serial,not_after) VALUES($1,$2,$3,$3,$4,$5,72,$6,$3,'fixture-successor',$7)`, n.ID, f.in.Request.AuthoritySHA256, digest(cert.Raw), f.in.Snapshot, n.RuntimeEpoch, certificate, cert.NotAfter)
			}
			p, err := f.s.planNodeNamePruning(ctx, f.c, user, n.ID, expected, certificate)
			if err == nil || p.Node != "" || len(p.RemovableNames) > 0 {
				t.Fatal("unsafe plan escaped validation", scenario, p, err)
			}
		})
	}
}

func TestNodeNamePruningPolicyKeepsNameApplicationRollbackPossible(t *testing.T) {
	f, j, certificate := nameChangeApplicationFixture(t)
	j = advanceNameApplication(t, f, j, "verify")
	for j.Phase() != "complete" {
		recordDeploymentReady(t, f.s, j)
		if err := f.s.CompleteDeploymentPhase(context.Background(), j); err != nil {
			t.Fatal(err)
		}
		j = reloadDeployment(t, f.s, j.ID)
	}
	p, err := f.s.planNodeNamePruning(context.Background(), f.c, "admin", j.Node, j.NodeVersion, certificate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Names, []string{f.job.SourceName, f.job.TargetName}) || len(p.RemovableNames) != 0 {
		t.Fatal("successful target application silently disabled source rollback", p)
	}
}
