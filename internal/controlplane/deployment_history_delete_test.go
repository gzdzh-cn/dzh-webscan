package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type deploymentHistoryFixture struct {
	s           *Store
	old, latest DeploymentJob
	request     DeploymentRequest
}

// Real PostgreSQL and the real persistent runner; remote service and collector
// operations are explicit local adapters, not a Linux lifecycle certification.
func newDeploymentHistoryFixture(t *testing.T) deploymentHistoryFixture {
	t.Helper()
	s := testStore(t)
	if err := s.Provision(context.Background(), "admin", "isolated-history-password"); err != nil {
		t.Fatal(err)
	}
	in := deploymentFixture(t, s)
	old := createDeployment(t, s, in, "history-original")
	runner := &DeploymentRunner{Store: s, Runtime: readinessFixtureRuntime{&fakeDeploymentRuntime{}, t, s}}
	if err := runner.Execute(context.Background(), claimDeployment(t, s, "history-first")); err != nil {
		t.Fatal(err)
	}
	nextNode := publicMonitoringNode(t, s, in.Node)
	nextNode.Name = "history-upgraded-node"
	if err := s.PutNode(context.Background(), nextNode, 1, 256); err != nil {
		t.Fatal(err)
	}
	upgrade := in
	upgrade.Kind, upgrade.Release, upgrade.SHA256 = "upgrade", "v3.0.1", strings.Repeat("b", 64)
	upgrade.Expected = 2
	latest := createDeployment(t, s, upgrade, "history-latest")
	if err := runner.Execute(context.Background(), claimDeployment(t, s, "history-second")); err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_deployment_jobs SET created_at=clock_timestamp()-interval '3 days',updated_at=clock_timestamp()-interval '2 days',finished_at=clock_timestamp()-interval '2 days' WHERE id=$1`, old.ID)
	return deploymentHistoryFixture{s, reloadDeployment(t, s, old.ID), reloadDeployment(t, s, latest.ID), in}
}

func historyDeletionPreview(t *testing.T, f deploymentHistoryFixture, ids ...string) deploymentHistoryDeletePreview {
	t.Helper()
	records := make([]string, len(ids))
	for i, id := range ids {
		records[i] = "deployment-job:" + id
	}
	p, err := f.s.previewDeploymentHistoryDelete(context.Background(), "admin", "preview-"+token()[:24], records)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func historyDeletionQueue(t *testing.T, f deploymentHistoryFixture, p deploymentHistoryDeletePreview) deploymentHistoryDeleteJob {
	t.Helper()
	raw, err := f.s.submitDeploymentHistoryDelete(context.Background(), "admin", "delete-"+token()[:24], p.Token, true)
	if err != nil {
		t.Fatal(err)
	}
	var j deploymentHistoryDeleteJob
	if json.Unmarshal(raw, &j) != nil || j.ID == "" {
		t.Fatal("missing deletion receipt")
	}
	return j
}

func historyDeletionFinish(t *testing.T, f deploymentHistoryFixture, j deploymentHistoryDeleteJob) deploymentHistoryDeleteJob {
	t.Helper()
	lease := historyLease(t, f.s)
	defer f.s.Release(context.Background(), lease)
	for i := 0; i < 205 && (j.Status == "queued" || j.Status == "running"); i++ {
		var err error
		j, err = f.s.deploymentHistoryDeleteBatch(context.Background(), lease, j.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if j.Status == "queued" || j.Status == "running" {
		t.Fatal("delete task did not finish")
	}
	return j
}

func deploymentHistoryRaw(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var raw []byte
	if err := s.DB.QueryRow(`SELECT to_jsonb(d) FROM v3_deployment_jobs d WHERE id=$1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDeploymentHistoryDeletePreservesJournalsAndOriginalIdempotency(t *testing.T) {
	f := newDeploymentHistoryFixture(t)
	before := deploymentHistoryRaw(t, f.s, f.old.ID)
	var logs int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_deployment_logs WHERE job=$1`, f.old.ID).Scan(&logs); err != nil || logs < 1 {
		t.Fatal("fixture lacks actual runner logs", err)
	}
	p := historyDeletionPreview(t, f, f.old.ID, f.latest.ID, "missing-task")
	if p.Eligible != 1 || p.Protected != 2 {
		t.Fatal("incorrect preview protection", p.Items)
	}
	j := historyDeletionFinish(t, f, historyDeletionQueue(t, f, p))
	if j.Status != "partial" || j.Deleted != 1 || j.Skipped != 2 || j.Failed != 0 {
		t.Fatal("incorrect delete result", j)
	}
	if !bytes.Equal(before, deploymentHistoryRaw(t, f.s, f.old.ID)) {
		t.Fatal("archival changed original immutable task or journal checkpoint")
	}
	if _, err := f.s.Deployment(context.Background(), f.old.ID); err != nil {
		t.Fatal("internal task disappeared", err)
	}
	if _, err := f.s.publicDeployment(context.Background(), f.old.ID, true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("archived public detail remains visible", err)
	}
	if _, _, err := f.s.publicDeploymentLogs(context.Background(), f.old.ID, 0, 100, true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("archived logs remain public", err)
	}
	var deleted int
	if err := f.s.DB.QueryRow(`SELECT deleted_logs FROM v3_deployment_history_archives WHERE deployment=$1`, f.old.ID).Scan(&deleted); err != nil || deleted != logs {
		t.Fatal("removed log count not committed with archive", deleted, err)
	}
	remaining, err := f.s.DeploymentLogs(context.Background(), f.old.ID, 0, 100)
	if err != nil || len(remaining) != 0 {
		t.Fatal("logs were not deleted", err)
	}
	replay := createDeployment(t, f.s, f.request, "history-original")
	if replay.ID != f.old.ID || tableCount(t, f.s, "v3_deployment_jobs") != 2 {
		t.Fatal("archiving bypassed original deployment idempotency")
	}
	detail, err := f.s.deploymentHistoryDeleteJob(context.Background(), "admin", j.ID)
	if err != nil || len(detail.Items) != 3 {
		t.Fatal("missing per-item outcomes", err)
	}
	var audit string
	if err = f.s.DB.QueryRow(`SELECT string_agg(result::text,' ') FROM v3_audit WHERE kind LIKE 'deployment-history-delete%'`).Scan(&audit); err != nil || strings.Contains(audit, p.Token) {
		t.Fatal("preview capability leaked into audit", err)
	}
}

func TestDeploymentHistoryDeletePreviewBindingsAndReplays(t *testing.T) {
	for _, scenario := range []string{"expired", "account", "settings", "draft", "gate", "owner", "used", "confirm"} {
		t.Run(scenario, func(t *testing.T) {
			f := newDeploymentHistoryFixture(t)
			p := historyDeletionPreview(t, f, f.old.ID)
			user, confirm := "admin", true
			switch scenario {
			case "expired":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_history_delete_previews SET expires_at=clock_timestamp()-interval '1 second'`)
			case "account":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "settings":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_settings SET version=version+1`)
			case "draft":
				mustHistoryExec(t, f.s.DB, `INSERT INTO v3_settings_drafts(id,generation,applied_generation,runtime_version,payload,proof,runtime_digest) SELECT 1,1,0,version,payload,'','' FROM v3_settings`)
			case "gate":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_configuration_operation_gate SET generation=generation+1`)
			case "owner":
				if err := f.s.Provision(context.Background(), "other", "isolated-other-password"); err != nil {
					t.Fatal(err)
				}
				user = "other"
			case "used":
				historyDeletionQueue(t, f, p)
			case "confirm":
				confirm = false
			}
			if _, err := f.s.submitDeploymentHistoryDelete(context.Background(), user, "stale-confirm", p.Token, confirm); err == nil {
				t.Fatal("stale or unauthorized capability accepted")
			}
			if tableCount(t, f.s, "v3_deployment_history_archives") != 0 {
				t.Fatal("rejected confirmation hid history")
			}
		})
	}
	f := newDeploymentHistoryFixture(t)
	records := []string{"deployment-job:" + f.old.ID}
	one, err := f.s.previewDeploymentHistoryDelete(context.Background(), "admin", "same-preview", records)
	if err != nil {
		t.Fatal(err)
	}
	two, err := f.s.previewDeploymentHistoryDelete(context.Background(), "admin", "same-preview", records)
	if err != nil || one.Token != two.Token {
		t.Fatal("preview response loss did not replay original capability", err)
	}
	first, err := f.s.submitDeploymentHistoryDelete(context.Background(), "admin", "same-confirm", one.Token, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.s.submitDeploymentHistoryDelete(context.Background(), "admin", "same-confirm", one.Token, true)
	if err != nil || !sameJSON(first, second) || tableCount(t, f.s, "v3_deployment_history_delete_jobs") != 1 {
		t.Fatal("confirmation response loss duplicated task", err)
	}
}

func TestDeploymentHistoryDeleteProtectionChangesAndWorkerRevocation(t *testing.T) {
	for _, scenario := range []string{"raw-recovery", "live-lease", "new-log", "account", "demoted", "settings", "failure"} {
		t.Run(scenario, func(t *testing.T) {
			f := newDeploymentHistoryFixture(t)
			j := historyDeletionQueue(t, f, historyDeletionPreview(t, f, f.old.ID))
			switch scenario {
			case "raw-recovery":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET recovery_required=true WHERE id=$1`, f.old.ID)
			case "live-lease":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()+interval '1 hour' WHERE id=$1`, f.old.ID)
			case "new-log":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET log_cursor=log_cursor+1 WHERE id=$1`, f.old.ID)
			case "account":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "demoted":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			case "settings":
				mustHistoryExec(t, f.s.DB, `UPDATE v3_settings SET version=version+1`)
			case "failure":
				mustHistoryExec(t, f.s.DB, `CREATE FUNCTION reject_history_archive() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'PRIVATE provider credential'; END $$; CREATE TRIGGER reject_history_archive BEFORE INSERT ON v3_deployment_history_archives FOR EACH ROW EXECUTE FUNCTION reject_history_archive()`)
			}
			before := deploymentHistoryRaw(t, f.s, f.old.ID)
			var logs int
			if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_deployment_logs WHERE job=$1`, f.old.ID).Scan(&logs); err != nil {
				t.Fatal(err)
			}
			result := historyDeletionFinish(t, f, j)
			if result.Deleted != 0 || result.Skipped+result.Failed != 1 || tableCount(t, f.s, "v3_deployment_history_archives") != 0 {
				t.Fatal("changed state or error deleted history", result)
			}
			if !bytes.Equal(before, deploymentHistoryRaw(t, f.s, f.old.ID)) {
				t.Fatal("failed cleanup changed original job")
			}
			var remaining int
			if err := f.s.DB.QueryRow(`SELECT count(*) FROM v3_deployment_logs WHERE job=$1`, f.old.ID).Scan(&remaining); err != nil || remaining != logs {
				t.Fatal("failed archive did not atomically retain logs", err)
			}
			if strings.Contains(fmt.Sprint(result), "PRIVATE") {
				t.Fatal("raw failure leaked")
			}
		})
	}
}

func TestDeploymentHistoryDeleteConcurrentSelectionAndFence(t *testing.T) {
	f := newDeploymentHistoryFixture(t)
	p := historyDeletionPreview(t, f, f.old.ID)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.s.submitDeploymentHistoryDelete(context.Background(), "admin", fmt.Sprintf("same-capability-%d", i), p.Token, true)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, errDeploymentHistoryDeletePreview) {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || tableCount(t, f.s, "v3_deployment_history_delete_jobs") != 1 {
		t.Fatal("capability confirmed more than once")
	}
	var id string
	if err := f.s.DB.QueryRow(`SELECT id FROM v3_deployment_history_delete_jobs`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	lease := historyLease(t, f.s)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_leases SET epoch=epoch+1 WHERE resource='retention'`)
	if _, err := f.s.deploymentHistoryDeleteBatch(context.Background(), lease, id); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale lease deleted history", err)
	}
	if tableCount(t, f.s, "v3_deployment_history_archives") != 0 {
		t.Fatal("stale worker created archive")
	}
}

func TestDeploymentHistoryDeleteSelectionValidation(t *testing.T) {
	for _, records := range [][]string{nil, {}, {"deployment-job:"}, {"deployment-job:a", "deployment-job:a"}, {"event:abc"}, {"deployment-job:bad/id"}, make([]string, 201)} {
		if _, err := deploymentHistoryDeleteRecords(records); err == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	// Keep this literal-only test independent from optional PostgreSQL setup.
	if _, err := deploymentHistoryDeleteRecords([]string{"deployment-job:valid-task"}); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentHistoryDeleteNeverPromotesProtectedSelection(t *testing.T) {
	f := newDeploymentHistoryFixture(t)
	mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET lease_until=clock_timestamp()+interval '1 hour' WHERE id=$1`, f.old.ID)
	p := historyDeletionPreview(t, f, f.old.ID)
	if p.Eligible != 0 || p.Protected != 1 {
		t.Fatal("live lease was not protected in preview")
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_deployment_jobs SET lease_until=NULL WHERE id=$1`, f.old.ID)
	available, err := f.s.publicDeployment(context.Background(), f.old.ID, true)
	if err != nil || !available.CanDelete {
		t.Fatal("fixture did not become eligible", available.DeleteReason, err)
	}
	finished := historyDeletionFinish(t, f, historyDeletionQueue(t, f, p))
	if finished.Skipped != 1 || finished.Deleted != 0 || tableCount(t, f.s, "v3_deployment_history_archives") != 0 {
		t.Fatal("worker promoted a record never authorized by preview", finished.Status)
	}
}

func TestDeploymentHistoryDeleteRestartResumesCommittedItems(t *testing.T) {
	f := newDeploymentHistoryFixture(t)
	const second = "history-second-archivable"
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_jobs SELECT (jsonb_populate_record(NULL::v3_deployment_jobs,to_jsonb(d)||jsonb_build_object('id',$2::text))).* FROM v3_deployment_jobs d WHERE d.id=$1`, f.old.ID, second)
	j := historyDeletionQueue(t, f, historyDeletionPreview(t, f, f.old.ID, second))
	lease := historyLease(t, f.s)
	partial, err := f.s.deploymentHistoryDeleteBatch(context.Background(), lease, j.ID)
	if err != nil || partial.Deleted != 1 || partial.Status != "running" {
		t.Fatal("first item was not checkpointed", partial.Status, err)
	}
	if err = f.s.Release(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	// Reopen through a new Store instance over the same real PostgreSQL pool:
	// no worker-local state or request memory is available to the replacement.
	restarted := *f.s
	f.s = &restarted
	finished := historyDeletionFinish(t, f, j)
	if finished.Status != "succeeded" || finished.Deleted != 2 || finished.Skipped != 0 || tableCount(t, f.s, "v3_deployment_history_archives") != 2 {
		t.Fatal("restart repeated or skipped committed deletion", finished.Status)
	}
	var progress int
	if err = f.s.DB.QueryRow(`SELECT count(*) FROM v3_audit WHERE kind='deployment-history-delete-progress' AND resource=$1`, j.ID).Scan(&progress); err != nil || progress != 2 {
		t.Fatal("restart repeated a completed item", progress, err)
	}
}
