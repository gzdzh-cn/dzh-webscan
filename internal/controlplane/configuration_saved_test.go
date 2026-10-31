package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"webscan/internal/common"
)

func dropConfigurationSavedForTest(t *testing.T, s *Store) {
	t.Helper()
	dropBootstrapRuntimeForTest(t, s)
	mustHistoryExec(t, s.DB, nodeHistoryRetirementTestDrop+`DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_configuration_application_settings;DELETE FROM v3_schema WHERE version>=23`)
	mustHistoryExec(t, s.DB, nodeHistoryRetirementTestDrop+`DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_configuration_application_logs;DROP TABLE v3_configuration_applications;DELETE FROM v3_schema WHERE version>=22`)
	mustHistoryExec(t, s.DB, `DROP TABLE v3_configuration_restore_commits;DROP TABLE v3_bootstrap_drafts;
 ALTER TABLE v3_configuration_restore_stages DROP CONSTRAINT v3_configuration_restore_stages_status_check,DROP CONSTRAINT v3_configuration_restore_stages_check1;
 ALTER TABLE v3_configuration_restore_stages ADD CONSTRAINT v3_configuration_restore_stages_status_check CHECK(status IN ('pending_validation','pending_application','cancelled')),ADD CONSTRAINT v3_configuration_restore_stages_check1 CHECK((status IN ('pending_validation','pending_application') AND finished_at IS NULL) OR (status='cancelled' AND finished_at IS NOT NULL));
 ALTER TABLE v3_configuration_revisions DROP CONSTRAINT v3_configuration_revisions_status_check,DROP CONSTRAINT v3_configuration_revisions_check;
 ALTER TABLE v3_configuration_revisions ADD CONSTRAINT v3_configuration_revisions_status_check CHECK(status IN ('pending_application','cancelled')),ADD CONSTRAINT v3_configuration_revisions_check CHECK((status='pending_application' AND finished_at IS NULL) OR (status='cancelled' AND finished_at IS NOT NULL));
 DELETE FROM v3_schema WHERE version>=21`)
}

func commitSavedFixture(t *testing.T) (*Store, configurationLocalFixture, configurationRestoreStage, configurationRevision) {
	t.Helper()
	s, f, stage := configurationRevisionFixture(t, false)
	raw, err := s.saveConfigurationRestorePending(context.Background(), f.v, f.c, "admin", "save-candidate", stage.ID)
	return s, f, stage, configurationRevisionReceipt(t, raw, err)
}

func savedReceipt(t *testing.T, raw []byte, err error) configurationSavedReceipt {
	t.Helper()
	var r configurationSavedReceipt
	if err != nil || json.Unmarshal(raw, &r) != nil || r.Status != "saved_pending_application" {
		t.Fatal("invalid saved restore receipt", err)
	}
	return r
}

func savedStateForTest(s *Store, f configurationLocalFixture, stage string, current bool) (configurationSavedReceipt, configurationDocument, error) {
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return configurationSavedReceipt{}, configurationDocument{}, err
	}
	defer tx.Rollback()
	return loadSavedConfigurationTx(ctx, tx, f.v, f.c, "admin", stage, current)
}

func TestConfigurationSavedCommitChangesDesiredAndPreservesRuntime(t *testing.T) {
	s, f, stage, r := commitSavedFixture(t)
	ctx := context.Background()
	active := runtimeNodeForTest(t, s, "revision-node")
	files := localTree(t, f.f.root)
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "commit-saved", stage.ID, r.Generation)
	saved := savedReceipt(t, raw, err)
	if saved.NodesChanged != 1 || !saved.Settings.Pending || saved.Settings.RuntimeVersion != 6 || saved.RequiresCenterRestart {
		t.Fatal("saved state misreported application")
	}
	var n Node
	n, err = scanNode(s.DB.QueryRow(`SELECT ` + nodeColumns + ` FROM v3_nodes WHERE id='revision-node'`))
	if err != nil || n.Name != "backup-node-name" || n.Version != 8 || n.AppliedVersion != 4 {
		t.Fatal("desired restore lost versions or metadata", err)
	}
	if got := runtimeNodeForTest(t, s, n.ID); !reflect.DeepEqual(active, got) {
		t.Fatal("restore changed runtime registration, epoch or applied state")
	}
	policy, err := s.RetentionPolicy(ctx)
	if err != nil || policy.Policy.Events != 90 || policy.Version != 6 {
		t.Fatal("restore applied pending retention", err)
	}
	d := settingsStateForTest(t, s)
	var desired common.Map
	if json.Unmarshal(d.Desired, &desired) != nil || common.I(common.M(desired["retention"])["sqlite_events_days"]) != 30 {
		t.Fatal("saved settings were not materialized")
	}
	if !reflect.DeepEqual(files, localTree(t, f.f.root)) {
		t.Fatal("restore wrote local materials")
	}
	if _, _, err = savedStateForTest(s, f, stage.ID, true); err != nil {
		t.Fatal("cannot revalidate materialized state", err)
	}
	phase, _, err := s.configurationRestoreStage(ctx, "admin", stage.ID)
	if err != nil || phase.Status != "saved" || phase.Finished == nil {
		t.Fatal("restore stage not closed as saved", err)
	}
	var pins int
	if err = s.DB.QueryRow(`SELECT count(*) FROM v3_configuration_backup_pins WHERE kind='rollback' AND reference IN($1,$2)`, "restore:"+stage.ID+":source", "restore:"+stage.ID+":before").Scan(&pins); err != nil || pins != 2 {
		t.Fatal("saved restore lost recovery archives", err)
	}
	if tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("restore started deployment or notifications")
	}
	for _, key := range []string{"commit-saved", "new-key-same-stage"} {
		again, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", key, stage.ID, r.Generation)
		if err != nil || canonicalBackupResponse(t, again) != canonicalBackupResponse(t, raw) {
			t.Fatal("saved restore replay changed receipt", err)
		}
	}
	if tableCount(t, s, "v3_configuration_restore_commits") != 1 {
		t.Fatal("replay duplicated commits")
	}
	for _, secret := range []string{"private-revision-password", f.f.root, "backup-node-name", "dsn_file"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("saved receipt leaked configuration")
		}
	}
}

func TestConfigurationSavedCommitIsAtomicAndRetryable(t *testing.T) {
	for _, failure := range []string{"node", "snapshot", "settings", "commit", "stage", "audit", "pins"} {
		t.Run(failure, func(t *testing.T) {
			s, f, stage, r := commitSavedFixture(t)
			before := settingsStateForTest(t, s)
			active := runtimeNodeForTest(t, s, "revision-node")
			target := map[string]string{"node": "v3_nodes", "snapshot": "v3_node_configurations", "settings": "v3_settings_drafts", "commit": "v3_configuration_restore_commits", "stage": "v3_configuration_restore_stages", "audit": "v3_audit", "pins": "v3_configuration_backup_pins"}[failure]
			condition := "TRUE"
			if failure == "audit" {
				condition = "NEW.kind='configuration-restore-commit'"
			}
			if failure == "stage" {
				condition = "NEW.status='saved'"
			}
			mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_saved_commit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF `+condition+` THEN RAISE EXCEPTION 'isolated save failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_saved_commit BEFORE INSERT OR UPDATE ON `+target+` FOR EACH ROW EXECUTE FUNCTION fail_saved_commit()`)
			if _, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "atomic-commit", stage.ID, r.Generation); err == nil {
				t.Fatal("injected failure ignored")
			}
			if tableCount(t, s, "v3_configuration_restore_commits") != 0 || settingsStateForTest(t, s).Generation != before.Generation || !reflect.DeepEqual(active, runtimeNodeForTest(t, s, "revision-node")) {
				t.Fatal("failed commit partially changed state")
			}
			var name string
			var version int64
			if err := s.DB.QueryRow(`SELECT name,version FROM v3_nodes WHERE id='revision-node'`).Scan(&name, &version); err != nil || name != "live-node-name" || version != 7 {
				t.Fatal("failed commit saved partial nodes", err)
			}
			mustHistoryExec(t, s.DB, `DROP TRIGGER fail_saved_commit ON `+target)
			raw, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "atomic-commit", stage.ID, r.Generation)
			_ = savedReceipt(t, raw, err)
		})
	}
}

func TestConfigurationSavedCommitRejectsStaleOrUnauthorizedInputs(t *testing.T) {
	for _, kind := range []string{"generation", "node", "settings", "bootstrap", "account", "other-admin", "local-key", "candidate", "busy"} {
		t.Run(kind, func(t *testing.T) {
			s, f, stage, r := commitSavedFixture(t)
			generation := r.Generation
			user := "admin"
			switch kind {
			case "generation":
				generation++
			case "node":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET version=version+1`)
			case "settings":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
			case "bootstrap":
				f.c.Collector.Concurrency++
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "other-admin":
				user = "other-admin"
			case "local-key":
				localWrite(t, f.c.Collector.KeyFile, []byte("damaged"))
			case "candidate":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revision_parts SET payload=set_byte(payload,0,get_byte(payload,0)#1)`)
			case "busy":
				cred, err := s.AddCredential(context.Background(), f.v, "admin", "busy-credential", "revision-node", 7, credentialFixture())
				if err != nil {
					t.Fatal(err)
				}
				var id struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(cred, &id) != nil {
					t.Fatal("invalid fixture credential")
				}
				_ = createDeployment(t, s, DeploymentRequest{Node: "revision-node", Kind: "upgrade", Expected: 7, Credential: id.ID, Release: "v3.0.0", SHA256: digest([]byte("synthetic-target"))}, "blocking")
			}
			if _, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, user, "must-reject", stage.ID, generation); err == nil {
				t.Fatal("stale restore materialized", kind)
			}
			if tableCount(t, s, "v3_configuration_restore_commits") != 0 || settingsStateForTest(t, s).Generation != 0 {
				t.Fatal("rejected commit left partial changes")
			}
		})
	}
}

func TestConfigurationSavedReceiptSurvivesLaterEditsWithoutAuthorizingThem(t *testing.T) {
	s, f, stage, r := commitSavedFixture(t)
	ctx := context.Background()
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "save-before-edit", stage.ID, r.Generation)
	_ = savedReceipt(t, raw, err)
	mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET name='later-edit',version=version+1`)
	if _, _, err := savedStateForTest(s, f, stage.ID, true); !errors.Is(err, errConfigurationSaved) {
		t.Fatal("old saved proof authorized later config", err)
	}
	if _, _, err := savedStateForTest(s, f, stage.ID, false); err != nil {
		t.Fatal("historical receipt lost after later edits", err)
	}
}

func savedRestoreFromDocument(t *testing.T, s *Store, f configurationLocalFixture, doc configurationDocument) (configurationRestoreStage, configurationRevision) {
	t.Helper()
	return savedRestoreFromDocumentOptions(t, s, f, doc, configurationRestoreOptions{})
}

func savedRestoreFromDocumentOptions(t *testing.T, s *Store, f configurationLocalFixture, doc configurationDocument, options configurationRestoreOptions) (configurationRestoreStage, configurationRevision) {
	t.Helper()
	ctx := context.Background()
	body, err := marshalConfigurationDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.importConfigurationBackup(ctx, f.v, "admin", "import-"+token()[:16], body)
	id := configurationBackupReceiptID(t, raw, err)
	p, err := s.previewConfigurationRestore(ctx, f.v, f.c, "admin", id, options)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = s.stageConfigurationRestore(ctx, f.v, f.c, "admin", "stage-"+token()[:16], p.Token)
	stage := configurationStageReceipt(t, raw, err)
	raw, err = s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "candidate-"+token()[:16], stage.ID)
	return stage, configurationRevisionReceipt(t, raw, err)
}

func newSavedConfigurationStore(t *testing.T) (*Store, configurationLocalFixture) {
	t.Helper()
	s := testStore(t)
	f := newConfigurationLocalFixture(t)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('admin','not-a-login','admin')`)
	return s, f
}

func TestConfigurationSavedBootstrapRemainsPendingAndCanRestoreOriginal(t *testing.T) {
	s, f := newSavedConfigurationStore(t)
	ctx := context.Background()
	doc, err := newConfigurationDocument(f.c, []byte(`{}`), 1, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	common.M(doc.Bootstrap["collector"])["concurrency"] = 32
	stage, r := savedRestoreFromDocument(t, s, f, doc)
	files := localTree(t, f.f.root)
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "root-save", stage.ID, r.Generation)
	saved := savedReceipt(t, raw, err)
	if !saved.Bootstrap.Pending || !saved.RequiresCenterRestart || saved.Bootstrap.Generation < 1 || saved.NodesChanged != 0 {
		t.Fatal("startup draft is not pending")
	}
	captured, err := s.captureConfigurationDocument(ctx, f.c)
	if err != nil || captured.BootstrapGeneration != saved.Bootstrap.Generation || common.I(common.M(captured.Bootstrap["collector"])["concurrency"]) != 32 || f.c.Collector.Concurrency == 32 {
		t.Fatal("saved startup configuration was lost or activated", err)
	}
	if _, _, err = savedStateForTest(s, f, stage.ID, true); err != nil {
		t.Fatal("saved startup proof failed", err)
	}
	if !reflect.DeepEqual(files, localTree(t, f.f.root)) {
		t.Fatal("startup save wrote local YAML or files")
	}
	// Startup drafts are scoped to the original stable member identity.
	other := f.c
	other.Central.Instance = "other-center"
	otherDoc, err := s.captureConfigurationDocument(ctx, other)
	if err != nil || otherDoc.BootstrapGeneration != 0 || common.I(common.M(otherDoc.Bootstrap["collector"])["concurrency"]) != f.c.Collector.Concurrency {
		t.Fatal("member inherited another member's pending startup configuration", err)
	}
	before := readPrivateConfigurationBackup(t, s, f.v, stage.BeforeBackup)
	stage2, r2 := savedRestoreFromDocument(t, s, f, before)
	raw, err = s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "restore-original-root", stage2.ID, r2.Generation)
	restored := savedReceipt(t, raw, err)
	if restored.Bootstrap.Generation <= saved.Bootstrap.Generation || restored.Bootstrap.Pending || restored.RequiresCenterRestart {
		t.Fatal("restoring the actual startup baseline invented a required restart")
	}
	if _, _, err = savedStateForTest(s, f, stage2.ID, true); err != nil {
		t.Fatal("restored baseline proof failed", err)
	}
}

func TestConfigurationSavedCommitAndConcurrentRetryHasOneEffect(t *testing.T) {
	s, f, stage, r := commitSavedFixture(t)
	ctx := context.Background()
	errs := make(chan error, 6)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "one-commit", stage.ID, r.Generation)
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
	if tableCount(t, s, "v3_configuration_restore_commits") != 1 {
		t.Fatal("concurrent commit duplicated state")
	}
	var version int64
	if err := s.DB.QueryRow(`SELECT version FROM v3_nodes WHERE id='revision-node'`).Scan(&version); err != nil || version != 8 {
		t.Fatal("concurrent commit repeated node edit", err)
	}
}

func TestConfigurationSavedRejectsTamperedCommitEvidence(t *testing.T) {
	for _, kind := range []string{"receipt", "proof", "candidate", "summary", "deployment", "root-payload", "root-proof", "root-generation", "archive-list", "source-identity", "before-identity", "source-content", "before-content", "archive-proof", "source-pin", "before-pin", "pin-expiry", "account"} {
		t.Run(kind, func(t *testing.T) {
			s, f := newSavedConfigurationStore(t)
			doc, err := newConfigurationDocument(f.c, []byte(`{}`), 1, nil, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			common.M(doc.Bootstrap["collector"])["concurrency"] = 32
			stage, r := savedRestoreFromDocument(t, s, f, doc)
			raw, err := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "tamper-after", stage.ID, r.Generation)
			_ = savedReceipt(t, raw, err)
			switch kind {
			case "receipt":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET result=jsonb_set(result,'{nodes_changed}','99')`)
			case "proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET proof='bad'`)
			case "candidate":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revision_parts SET payload=set_byte(payload,0,get_byte(payload,0)#1)`)
			case "summary":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_stages SET summary=jsonb_set(summary,'{nodes}','[{"node":"missing","action":"update","fields":[]}]')`)
			case "deployment":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET deployments='["changed"]'`)
			case "root-payload":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_drafts SET payload=jsonb_set(payload,'{collector,concurrency}','64')`)
			case "root-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_drafts SET proof='bad'`)
			case "root-generation":
				mustHistoryExec(t, s.DB, `UPDATE v3_bootstrap_drafts SET generation=generation+1`)
			case "archive-list":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_commits SET archives=jsonb_build_array(archives->1,archives->0)`)
			case "source-identity":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_stages SET backup=before_backup`)
			case "before-identity":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_stages SET before_backup=backup`)
			case "source-content", "before-content":
				id := stage.Backup
				if kind == "before-content" {
					id = stage.BeforeBackup
				}
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_backup_parts SET payload=set_byte(payload,0,get_byte(payload,0)#1) WHERE backup=$1`, id)
			case "archive-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_stages SET archive_proof='bad'`)
			case "source-pin", "before-pin":
				suffix := ":source"
				if kind == "before-pin" {
					suffix = ":before"
				}
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins WHERE reference=$1`, "restore:"+stage.ID+suffix)
			case "pin-expiry":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_backup_pins SET expires_at=clock_timestamp()+interval '1 hour' WHERE kind='rollback'`)
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			}
			if _, _, err := savedStateForTest(s, f, stage.ID, true); err == nil {
				t.Fatal("corrupt saved configuration accepted", kind)
			}
		})
	}
}

func TestConfigurationSavedSchema20UpgradeAndDisasterRestore(t *testing.T) {
	s, f, stage, revision := commitSavedFixture(t)
	ctx := context.Background()
	dropConfigurationSavedForTest(t, s)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema 20 upgraded without backup")
	}
	unsafe := filepath.Join(privateTestDir(t), "unsafe")
	if err := os.Mkdir(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, unsafe); err == nil {
		t.Fatal("failed backup allowed schema 21")
	}
	if version, err := currentSchema(ctx, s.DB); err != nil || version != 20 {
		t.Fatal("failed migration changed schema", err)
	}
	dir := privateTestDir(t)
	if err := s.Upgrade(ctx, dir); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatal("schema 20 backup missing", err)
	}
	old := emptyTestStore(t)
	if err = old.RestorePostgres(ctx, files[0]); err != nil {
		t.Fatal("schema 20 backup restore failed", err)
	}
	if err = old.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal("schema 20 restored upgrade failed", err)
	}
	oldStage, _, err := old.configurationRestoreStage(ctx, "admin", stage.ID)
	if err != nil || oldStage.Status != "cancelled" {
		t.Fatal("disaster revived old pending intent", err)
	}
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "after-upgrade", stage.ID, revision.Generation)
	saved := savedReceipt(t, raw, err)
	// Also include a genuine pending startup draft in the disaster snapshot.
	cancelRaw, err := s.cancelConfigurationRestore(ctx, "admin", "cancel-saved", stage.ID)
	var unchanged configurationRestoreStage
	if err != nil || json.Unmarshal(cancelRaw, &unchanged) != nil || unchanged.Status != "saved" {
		t.Fatal("cancel changed an already saved materialization", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := captureConfigurationDocumentTx(ctx, tx, f.c, f.v)
	_ = tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	common.M(doc.Bootstrap["collector"])["concurrency"] = 32
	nextStage, next := savedRestoreFromDocument(t, s, f, doc)
	nextRaw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "save-bootstrap", nextStage.ID, next.Generation)
	nextSaved := savedReceipt(t, nextRaw, err)
	if !nextSaved.Bootstrap.Pending {
		t.Fatal("bootstrap change not pending")
	}
	archive, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, archive); err != nil {
		t.Fatal(err)
	}
	got, _, err := savedStateForTest(restored, f, nextStage.ID, true)
	if err != nil || got.Bootstrap.Generation != nextSaved.Bootstrap.Generation || !got.Bootstrap.Pending {
		t.Fatal("disaster lost saved bootstrap/proofs/recovery pins", err)
	}
	prior, _, err := savedStateForTest(restored, f, stage.ID, false)
	if err != nil || prior.Settings.Generation != saved.Settings.Generation {
		t.Fatal("disaster lost historical saved receipt", err)
	}
	policy, err := restored.RetentionPolicy(ctx)
	if err != nil || policy.Version != 6 || policy.Policy.Events != 90 || runtimeNodeForTest(t, restored, "revision-node").AppliedVersion != 4 {
		t.Fatal("disaster applied saved configuration", err)
	}
}

func TestConfigurationSavedTwentyThousandNodesBatchCommit(t *testing.T) {
	s, f := newSavedConfigurationStore(t)
	ctx := context.Background()
	existing := nodeFixture("existing-node")
	if err := s.PutNode(ctx, existing, 0, 256); err != nil {
		t.Fatal(err)
	}
	active := runtimeNodeForTest(t, s, existing.ID)
	existing.Name = "restored-existing"
	nodes := make([]Node, 0, 20000)
	nodes = append(nodes, existing)
	for i := 1; i < 20000; i++ {
		n := nodeFixture(fmt.Sprintf("bulk-node-%05d", i))
		n.Config = []byte(`{}`)
		nodes = append(nodes, n)
	}
	doc, err := newConfigurationDocument(f.c, []byte(`{}`), 1, nodes, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stage, r := savedRestoreFromDocument(t, s, f, doc)
	raw, err := s.commitConfigurationRestoreSaved(ctx, f.v, f.c, "admin", "bulk-commit", stage.ID, r.Generation)
	saved := savedReceipt(t, raw, err)
	if saved.NodesChanged != 20000 || tableCount(t, s, "v3_nodes") != 20000 {
		t.Fatal("batch restore truncated desired nodes")
	}
	var activeCount int
	if err := s.DB.QueryRow(`SELECT count(*) FROM v3_active_nodes`).Scan(&activeCount); err != nil || activeCount != 1 || !reflect.DeepEqual(active, runtimeNodeForTest(t, s, existing.ID)) {
		t.Fatal("batch restore published or disturbed runtime nodes", err)
	}
	if _, _, err = savedStateForTest(s, f, stage.ID, true); err != nil {
		t.Fatal("large saved state failed proof verification", err)
	}
}
