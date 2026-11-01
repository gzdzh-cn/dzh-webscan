package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDeploymentHistoryBackupRetainsArchivesAndRevokesPendingDeletion(t *testing.T) {
	f := newDeploymentHistoryFixture(t)
	completed := historyDeletionFinish(t, f, historyDeletionQueue(t, f, historyDeletionPreview(t, f, f.old.ID)))
	if completed.Status != "succeeded" {
		t.Fatal("fixture archive failed", completed.Status)
	}
	// Relational restore fixture only: historical lifecycle proof rows may still
	// refer to an archived original journal. Their signature verification belongs
	// to lifecycle tests; backup must retain their bytes and FK ordering.
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_uninstalls(job,source,key_id,proof) VALUES($1,$2,'fixture','fixture')`, f.latest.ID, f.old.ID)
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_lifecycle_authorizations(job,source,key_id,proof) VALUES($1,$2,'fixture','fixture')`, f.latest.ID, f.old.ID)
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_lifecycle_receipts(job,kind,evidence,recorded_epoch,key_id,proof) VALUES($1,'removal','{}',1,'fixture','fixture')`, f.old.ID)
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_node_lifecycle(node,job,state,body,key_id,proof) VALUES($1,$2,'uninstalled','{}','fixture','fixture')`, f.old.Node, f.old.ID)
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_web_uninstall_credentials(node,source,credential) VALUES($1,$2,$3)`, f.old.Node, f.old.ID, f.request.Credential)
	const pendingID = "history-pending-fixture"
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_deployment_jobs SELECT (jsonb_populate_record(NULL::v3_deployment_jobs,to_jsonb(d)||jsonb_build_object('id',$2::text))).* FROM v3_deployment_jobs d WHERE d.id=$1`, f.old.ID, pendingID)
	p := historyDeletionPreview(t, f, pendingID, f.latest.ID)
	if p.Eligible != 1 || p.Protected != 1 {
		t.Fatal("pending restore fixture lacks mixed eligibility")
	}
	pending := historyDeletionQueue(t, f, p)
	before := deploymentHistoryRaw(t, f.s, f.old.ID)
	path, err := f.s.BackupPostgres(context.Background(), privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(context.Background(), path); err != nil {
		t.Fatal("full backup could not restore FK-ordered history tables", err)
	}
	if !bytes.Equal(before, deploymentHistoryRaw(t, restored, f.old.ID)) || tableCount(t, restored, "v3_deployment_history_archives") != 1 {
		t.Fatal("restore changed original job or lost tombstone")
	}
	for _, table := range []string{"v3_deployment_uninstalls", "v3_deployment_lifecycle_authorizations", "v3_deployment_lifecycle_receipts", "v3_node_lifecycle", "v3_web_uninstall_credentials"} {
		if tableCount(t, restored, table) != 1 {
			t.Fatal("restore lost archived journal lifecycle evidence", table)
		}
	}
	if _, err = restored.publicDeployment(context.Background(), f.old.ID, true); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("restore resurrected deleted public history", err)
	}
	job, err := restored.deploymentHistoryDeleteJob(context.Background(), "admin", pending.ID)
	if err != nil || job.Status != "cancelled" || job.Skipped != 2 || job.Deleted != 0 || job.Failed != 0 || len(job.Items) != 2 {
		t.Fatal("restore revived deletion authority or lost counters", job, err)
	}
	for _, item := range job.Items {
		if item.Status != "skipped" {
			t.Fatal("restore left pending destructive item", item.Status)
		}
	}
	if _, err = restored.submitDeploymentHistoryDelete(context.Background(), "admin", "old-restore-capability", p.Token, true); err == nil {
		t.Fatal("restored preview still authorized deletion")
	}
	if err = restored.runDeploymentHistoryDeleteRound(context.Background(), historyLease(t, restored)); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, restored, "v3_deployment_history_archives") != 1 {
		t.Fatal("restored worker silently continued pending deletion")
	}
	if _, err = restored.publicDeployment(context.Background(), pendingID, true); err != nil {
		t.Fatal("pending record was hidden by restore", err)
	}
}

func TestDeploymentHistorySchemaUpgradeBacksUpAndFailureStops(t *testing.T) {
	f := newDeploymentHistoryFixture(t)
	// Deliberately reconstruct the immediately preceding schema in this
	// isolated fixture. No data-bearing production database is downgraded.
	mustHistoryExec(t, f.s.DB, postMonitoringMigrationsTestDrop+`ALTER TABLE v3_deployment_jobs DROP CONSTRAINT v3_deployment_jobs_kind_check;
ALTER TABLE v3_deployment_jobs ADD CONSTRAINT v3_deployment_jobs_kind_check CHECK(kind IN ('install','upgrade','recover'));
DELETE FROM v3_schema WHERE version>=40`)
	before := deploymentHistoryRaw(t, f.s, f.old.ID)
	unsafeDirectory := privateTestDir(t)
	if err := os.Chmod(unsafeDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Upgrade(context.Background(), unsafeDirectory); err == nil {
		t.Fatal("migration proceeded after backup permission failure")
	}
	version, err := currentSchema(context.Background(), f.s.DB)
	if err != nil || version != 39 || !bytes.Equal(before, deploymentHistoryRaw(t, f.s, f.old.ID)) {
		t.Fatal("failed backup changed schema or original journal", version, err)
	}
	directory := privateTestDir(t)
	if err = f.s.Upgrade(context.Background(), directory); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(directory, "postgres-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatal("schema upgrade lacked one consistent pre-upgrade archive", err)
	}
	header, err := inspectPGBackup(files[0])
	if err != nil || header.Version != 39 {
		t.Fatal("upgrade backup was not the old schema snapshot", err)
	}
	if version, err = currentSchema(context.Background(), f.s.DB); err != nil || version != SchemaVersion || !bytes.Equal(before, deploymentHistoryRaw(t, f.s, f.old.ID)) {
		t.Fatal("upgrade lost journal or failed to install current schema", version, err)
	}
	if tableCount(t, f.s, "v3_deployment_history_archives") != 0 {
		t.Fatal("migration automatically archived existing history")
	}
}
