package controlplane

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDeploymentHistoryReadCursorRoleAndBoundedDecoration(t *testing.T) {
	f := newDeploymentHistoryFixture(t)
	// Synthetic historical rows exercise page bounds; they are not evidence of
	// additional remote installations or a capacity benchmark.
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_jobs SELECT (jsonb_populate_record(NULL::v3_deployment_jobs,to_jsonb(d)||jsonb_build_object('id','page-'||lpad(g::text,3,'0')))).* FROM v3_deployment_jobs d CROSS JOIN generate_series(1,201) g WHERE d.id=$1`, f.old.ID)
	seen := map[string]bool{}
	var before time.Time
	beforeID := ""
	for page := 0; page < 2; page++ {
		items, err := f.s.publicDeployments(context.Background(), before, beforeID, "", 200, true)
		if err != nil {
			t.Fatal(err)
		}
		if page == 0 && len(items) != 200 || page == 1 && len(items) != 3 {
			t.Fatal("public cursor page lost bounded rows", page, len(items))
		}
		for _, item := range items {
			if seen[item.ID] || item.RecordKey != "deployment-job:"+item.ID || item.CanDelete != (item.DeleteReason == "") {
				t.Fatal("duplicate or undecorated public task", item.ID)
			}
			if item.ID == f.latest.ID && item.CanDelete {
				t.Fatal("latest task lost protection")
			}
			seen[item.ID] = true
		}
		last := items[len(items)-1]
		before, beforeID = last.CreatedAt, last.ID
	}
	viewer, err := f.s.publicDeployment(context.Background(), f.old.ID, false)
	if err != nil || viewer.CanDelete || viewer.DeleteReason != "需要管理员权限" {
		t.Fatal("viewer received deletion permission", err)
	}
	raw, err := json.Marshal(viewer)
	if err != nil || strings.Contains(string(raw), `"plan":`) || strings.Contains(string(raw), `"credential":`) || strings.Contains(string(raw), `"lease_owner":`) {
		t.Fatal("private journal leaked into public wrapper", err)
	}
}

func TestDeploymentHistoryReadProtectionReferences(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testing.T, deploymentHistoryFixture)
	}{
		{"recent", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET finished_at=clock_timestamp() WHERE id=$1`, f.old.ID)
		}},
		{"unknown-finish", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET finished_at=NULL WHERE id=$1`, f.old.ID)
		}},
		{"latest", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET created_at=clock_timestamp()+interval '1 hour' WHERE id=$1`, f.old.ID)
		}},
		{"success-baseline", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET status='rolled_back',direction='rollback' WHERE id=$1`, f.latest.ID)
		}},
		{"active-runtime", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `UPDATE v3_node_runtime SET snapshot=$2,epoch=epoch+1 WHERE node=$1`, f.old.Node, f.old.Plan.TargetRuntime)
			mustHistoryExec(t, f.s.DB, `UPDATE v3_nodes SET runtime_generation=runtime_generation+1 WHERE id=$1`, f.old.Node)
		}},
		{"valid-consumed-preview", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_previews(token_hash,username,account_revision,node,request,request_digest,state_digest,credential_revision,job) VALUES('fixture-preview','admin',1,$1,'{}','fixture','fixture',1,$2)`, f.old.Node, f.old.ID)
		}},
		{"node-preview", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_previews(token_hash,username,account_revision,node,request,request_digest,state_digest,credential_revision) VALUES('fixture-preview','admin',1,$1,'{}','fixture','fixture',1)`, f.old.Node)
		}},
		{"preparation", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_preparations(id,node,username,account_revision,node_version,manifest_sha256,kind) VALUES('fixture-preparation',$1,'admin',1,1,$2,'prepare')`, f.old.Node, strings.Repeat("c", 64))
		}},
		{"uninstall-source", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_uninstalls(job,source,key_id,proof) VALUES($1,$2,'fixture','fixture')`, f.latest.ID, f.old.ID)
		}},
		{"lifecycle-authorization", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_lifecycle_authorizations(job,source,key_id,proof) VALUES($1,$2,'fixture','fixture')`, f.latest.ID, f.old.ID)
		}},
		{"lifecycle-receipt", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_lifecycle_receipts(job,kind,evidence,recorded_epoch,key_id,proof) VALUES($1,'removal','{}',1,'fixture','fixture')`, f.old.ID)
		}},
		{"node-lifecycle", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_lifecycle(node,job,state,body,key_id,proof) VALUES($1,$2,'uninstalled','{}','fixture','fixture')`, f.old.Node, f.old.ID)
		}},
		{"uninstall-credential", func(t *testing.T, f deploymentHistoryFixture) {
			mustHistoryExec(t, f.s.DB, `INSERT INTO v3_web_uninstall_credentials(node,source,credential) VALUES($1,$2,$3)`, f.old.Node, f.old.ID, f.request.Credential)
		}},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			f := newDeploymentHistoryFixture(t)
			before, err := f.s.publicDeployment(context.Background(), f.old.ID, true)
			if err != nil || !before.CanDelete {
				t.Fatal("fixture task not eligible before reference", before.DeleteReason, err)
			}
			scenario.edit(t, f)
			after, err := f.s.publicDeployment(context.Background(), f.old.ID, true)
			if err != nil || after.CanDelete || after.DeleteReason == "" {
				t.Fatal("live reference not protected", scenario.name, err)
			}
			p := historyDeletionPreview(t, f, f.old.ID)
			if p.Eligible != 0 || p.Protected != 1 {
				t.Fatal("preview protection disagrees with public read", scenario.name)
			}
		})
	}
}

func TestDeploymentHistoryReadProtectsMonitoringReservationBeforeChild(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	old := claimlessLatestHistoryJob(t, f.s, f.in.Node)
	// Add a second persistent runner journal, so the original installation is
	// no longer latest/current and becomes a genuine deletion candidate.
	next := publicMonitoringNode(t, f.s, f.in.Node)
	next.Name = "history-before-monitoring"
	if err := f.s.PutNode(context.Background(), next, 1, 256); err != nil {
		t.Fatal(err)
	}
	f.in.Kind, f.in.Expected = "upgrade", 2
	f.request.Nodes[0].Expected = 2
	request, err := f.s.prepareLocalDeployment(context.Background(), f.c, f.t, f.in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.queueLocalDeployment(context.Background(), f.c, f.t, "admin", "history-before-monitoring", request); err != nil {
		t.Fatal(err)
	}
	if err := (&DeploymentRunner{Store: f.s, Vault: f.t.vault, Runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, f.s}}).Execute(context.Background(), claimDeployment(t, f.s, "history-before-monitoring")); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET created_at=clock_timestamp()-interval '3 days',updated_at=clock_timestamp()-interval '2 days',finished_at=clock_timestamp()-interval '2 days' WHERE id=$1`, old.ID)
	before, err := f.s.publicDeployment(context.Background(), old.ID, true)
	if err != nil || !before.CanDelete {
		t.Fatal("old installation not eligible before monitoring reservation", before.DeleteReason, err)
	}
	p := f.confirmed(t)
	var children int
	if err = f.s.DB.QueryRow(`SELECT count(*) FROM v3_monitoring_application_nodes WHERE application=$1 AND child IS NOT NULL`, p.ID).Scan(&children); err != nil || children != 0 {
		t.Fatal("fixture unexpectedly has child", err)
	}
	after, err := f.s.publicDeployment(context.Background(), old.ID, true)
	if err != nil || after.CanDelete || !strings.Contains(after.DeleteReason, "公共监控规则") {
		t.Fatal("durable reservation without child was ignored", after.DeleteReason, err)
	}
}

func claimlessLatestHistoryJob(t *testing.T, s *Store, node string) DeploymentJob {
	t.Helper()
	var id string
	if err := s.DB.QueryRow(`SELECT id FROM v3_deployment_jobs WHERE node=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, node).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return reloadDeployment(t, s, id)
}
