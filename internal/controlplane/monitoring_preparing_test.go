package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Reproduce interruption after the signed target-save checkpoint, before a
// child deployment exists. The displayed recovery action must be executable.
// PostgreSQL is real; remote service operations use the existing test adapter.
func TestMonitoringApplicationPreparingSelectedResume(t *testing.T) {
	f := newMonitoringApplicationFixture(t)
	ctx := context.Background()
	p := f.confirmed(t)
	scoped := monitoringNodeContext(ctx, f.t.vault, p, f.in.Node, "")
	prepared, err := f.s.prepareMonitoringNode(scoped, f.c, f.t, p, f.in.Node)
	if err != nil {
		t.Fatal("prepare signed node checkpoint", err)
	}
	if prepared.Version != 2 {
		t.Fatal("fixture did not save target exactly once", prepared.Version)
	}
	jobs := tableCount(t, f.s, "v3_deployment_jobs")
	if jobs != 1 {
		t.Fatal("preparation unexpectedly created a child deployment", jobs)
	}
	tx, err := f.s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	p, err = lockMonitoringParentTx(ctx, tx, f.t.vault, p)
	if err != nil {
		t.Fatal(err)
	}
	p.Status = "paused"
	p.Owner = sql.NullString{}
	p.Lease = sql.NullTime{}
	if err = updateMonitoringApplicationTx(ctx, tx, f.t.vault, &p); err != nil {
		t.Fatal("pause with authentic parent state", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	api := NewAPI(f.s, f.c)
	req := httptest.NewRequest(http.MethodGet, "https://local/api/v3/monitoring/applications/"+p.ID, nil)
	response := httptest.NewRecorder()
	if !api.monitoringApplicationRoutes(response, req, identity{Username: "admin", Role: "admin"}) || response.Code != http.StatusOK {
		t.Fatal("GET paused application failed", response.Code, response.Body.String())
	}
	var paused monitoringApplication
	if err = json.Unmarshal(response.Body.Bytes(), &paused); err != nil {
		t.Fatal(err)
	}
	if paused.Status != "paused" || !paused.CanResume || len(paused.Nodes) != 1 || paused.Nodes[0].State != "preparing" || !paused.Nodes[0].CanResume || paused.Nodes[0].Job != "" {
		t.Fatal("GET lost authentic preparing checkpoint or resume permission", paused.Status, paused.CanResume, paused.Nodes)
	}
	if _, err = f.s.recoverMonitoringApplication(ctx, f.t.vault, "admin", "resume-preparing-selected", p.ID, paused.Expected, "forward", f.in.Node); err != nil {
		t.Fatal("GET-advertised selected preparing resume was rejected", err)
	}
	queued, err := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if err != nil || queued.Status != "queued" || queued.Selected != f.in.Node {
		t.Fatal("selected resume was not queued", queued.Status, queued.Selected, err)
	}
	p, err = f.worker.claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.worker.execute(ctx, p)
	partial, err := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if err != nil || partial.Status != "paused" || len(partial.Nodes) != 1 || partial.Nodes[0].State != "succeeded" || partial.Nodes[0].Job == "" {
		t.Fatal("selected preparing node did not resume through original runner", partial.Status, partial.Error, err)
	}
	child := reloadDeployment(t, f.s, partial.Nodes[0].Job)
	if child.Status != "succeeded" || child.Kind != "upgrade" || child.Plan.Node.Version != prepared.Version || child.Plan.Request.Release != f.t.release.manifest.Release || tableCount(t, f.s, "v3_deployment_jobs") != jobs+1 {
		t.Fatal("resume did not create exactly one pinned original-flow upgrade")
	}
	after := publicMonitoringNode(t, f.s, f.in.Node)
	if after.Version != prepared.Version || after.AppliedVersion != prepared.Version || !configurationJSONEqual(after.Config, prepared.Config) {
		t.Fatal("resume rewrote the already saved target or lost applied version", after.Version, after.AppliedVersion)
	}
	if _, err = f.s.recoverMonitoringApplication(ctx, f.t.vault, "admin", "finish-preparing-parent", p.ID, partial.Expected, "forward"); err != nil {
		t.Fatal(err)
	}
	p, err = f.worker.claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.worker.execute(ctx, p)
	done, err := f.s.monitoringApplication(ctx, f.t.vault, "admin", p.ID)
	if err != nil || done.Status != "succeeded" || tableCount(t, f.s, "v3_deployment_jobs") != jobs+1 {
		t.Fatal("parent could not finalize without duplicate deployment", done.Status, done.Error, err)
	}
}
