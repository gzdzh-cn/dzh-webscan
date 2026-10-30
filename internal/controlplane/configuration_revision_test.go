package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"webscan/internal/common"
)

func configurationRevisionFixture(t *testing.T, large bool) (*Store, configurationLocalFixture, configurationRestoreStage) {
	t.Helper()
	s := testStore(t)
	f := newConfigurationLocalFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('admin','not-a-login','admin'),('other-admin','not-a-login','admin'),('operator','not-a-login','operator'),('viewer','not-a-login','viewer')`)
	n := nodeFixture("revision-node")
	n.Name = "backup-node-name"
	if large {
		n.Config = common.JSON(common.Map{"private": common.Map{"opaque": strings.Repeat("private-large-fixture-", 65000), "counter": json.Number("9007199254740993"), "decimal": json.Number("1.234567890123456789")}})
	}
	if e := s.PutNode(ctx, n, 0, 256); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=5,payload='{"retention":{"sqlite_events_days":30},"email":{"enabled":false,"password":"private-revision-password"}}'`)
	raw, e := s.createConfigurationBackup(ctx, f.v, f.c, "admin", "revision-source")
	source := configurationBackupReceiptID(t, raw, e)
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=6,payload=jsonb_set(payload,'{retention,sqlite_events_days}','90');UPDATE v3_nodes SET name='live-node-name',version=7,applied_version=4`)
	p, e := s.previewConfigurationRestore(ctx, f.v, f.c, "admin", source, configurationRestoreOptions{})
	if e != nil {
		t.Fatal(e)
	}
	raw, e = s.stageConfigurationRestore(ctx, f.v, f.c, "admin", "revision-stage", p.Token)
	return s, f, configurationStageReceipt(t, raw, e)
}

func configurationRevisionReceipt(t *testing.T, raw []byte, e error) configurationRevision {
	t.Helper()
	var r configurationRevision
	if e != nil || json.Unmarshal(raw, &r) != nil || !validArchiveSource(r.ID) || r.Generation < 1 {
		t.Fatal("invalid pending revision", e)
	}
	return r
}

func readConfigurationRevisionForTest(t *testing.T, s *Store, v *Vault, stage string) (privateConfigurationRevision, configurationDocument, error) {
	t.Helper()
	tx, e := s.DB.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	return loadConfigurationRevisionTx(context.Background(), tx, v, stage)
}

func revalidateConfigurationStageForTest(t *testing.T, s *Store, v *Vault, c Config, stage string) (configurationRestorePlan, error) {
	t.Helper()
	tx, e := s.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	return revalidateConfigurationStageTx(context.Background(), tx, v, c, "admin", stage)
}

func TestConfigurationRevisionSavePersistsCandidateWithoutApplying(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, false)
	ctx := context.Background()
	beforeFiles := localTree(t, f.f.root)
	beforeNodes, e := s.Nodes(ctx, "", "", 20, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "save-pending", stage.ID)
	r := configurationRevisionReceipt(t, raw, e)
	if r.Status != "pending_application" || r.Stage != stage.ID || r.Username != "admin" || r.BaseSettingsVersion != 6 || r.Finished != nil {
		t.Fatal("pending state described as applied", r)
	}
	var encoded map[string]any
	if json.Unmarshal(raw, &encoded) != nil || encoded["generation"] != "1" {
		t.Fatal("generation is not lossless text")
	}
	stored, doc, e := readConfigurationRevisionForTest(t, s, f.v, stage.ID)
	if e != nil || stored.ID != r.ID || doc.SettingsVersion != 6 || common.F(common.M(doc.Settings["retention"])["sqlite_events_days"]) != 30 || common.M(doc.Settings["email"])["password"] != "private-revision-password" || doc.Nodes["revision-node"].Name != "backup-node-name" || doc.Nodes["revision-node"].Version != 7 {
		t.Fatal("candidate lost selected content or rewound versions", e)
	}
	policy, e := s.RetentionPolicy(ctx)
	if e != nil || policy.Version != 6 || policy.Policy.Events != 90 {
		t.Fatal("pending save applied retention", e)
	}
	afterNodes, e := s.Nodes(ctx, "", "", 20, nil)
	if e != nil || !reflect.DeepEqual(beforeNodes, afterNodes) {
		t.Fatal("pending save changed live node identity/config/applied version", e)
	}
	if !reflect.DeepEqual(beforeFiles, localTree(t, f.f.root)) {
		t.Fatal("pending save changed independent material")
	}
	if tableCount(t, s, "v3_configuration_backups") != 2 || tableCount(t, s, "v3_configuration_backup_pins") != 2 || tableCount(t, s, "v3_configuration_revisions") != 1 || tableCount(t, s, "v3_deployment_jobs") != 0 || tableCount(t, s, "v3_notifications") != 0 {
		t.Fatal("pending save created work or replaced original protection")
	}
	backups, e := s.configurationBackups(ctx, "admin", retentionCursor{}, 20)
	if e != nil || len(backups) != 2 || backups[0].CanDelete || backups[1].CanDelete {
		t.Fatal("pending save lost original backup protection", e)
	}
	current, _, e := s.configurationRestoreStage(ctx, "admin", stage.ID)
	if e != nil || current.Status != "pending_application" {
		t.Fatal("intent did not advance to pending application", e)
	}
	plan, e := revalidateConfigurationStageForTest(t, s, f.v, f.c, stage.ID)
	if e != nil || plan.Candidate.Created != doc.Created || common.F(common.M(plan.Candidate.Settings["retention"])["sqlite_events_days"]) != 30 {
		t.Fatal("saved candidate cannot be authenticated again", e)
	}
	// New Store/Vault objects do not rely on in-memory candidates or reports.
	v, e := OpenVault(f.c.DeploymentTrust.VaultKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	restarted := &Store{DB: s.DB}
	if _, e := revalidateConfigurationStageForTest(t, restarted, v, f.c, stage.ID); e != nil {
		t.Fatal("restart lost candidate", e)
	}
	for _, key := range []string{"save-pending", "another-save-key"} {
		again, e := s.saveConfigurationRestorePending(ctx, v, f.c, "admin", key, stage.ID)
		if e != nil || canonicalBackupResponse(t, again) != canonicalBackupResponse(t, raw) || tableCount(t, s, "v3_configuration_revisions") != 1 {
			t.Fatal("retry created a second candidate", e)
		}
	}
	var header, audit, parts []byte
	if e = s.DB.QueryRow(`SELECT row_to_json(r) FROM v3_configuration_revisions r`).Scan(&header); e != nil {
		t.Fatal(e)
	}
	if e = s.DB.QueryRow(`SELECT result FROM v3_audit WHERE kind='configuration-restore-save' ORDER BY id LIMIT 1`).Scan(&audit); e != nil {
		t.Fatal(e)
	}
	if e = s.DB.QueryRow(`SELECT payload FROM v3_configuration_revision_parts LIMIT 1`).Scan(&parts); e != nil {
		t.Fatal(e)
	}
	for _, data := range [][]byte{raw, header, audit, parts} {
		for _, secret := range []string{"private-revision-password", f.f.root, "backup-node-name", "dsn_file", "private_key"} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("pending version leaked plaintext")
			}
		}
	}
	if _, e = json.Marshal(stored); e == nil || strings.Contains(fmt.Sprintf("%v %#v", stored, stored), f.f.root) {
		t.Fatal("private metadata can be serialized or logged")
	}
	p, e := s.previewConfigurationRestore(ctx, f.v, f.c, "admin", stage.Backup, configurationRestoreOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.stageConfigurationRestore(ctx, f.v, f.c, "admin", "conflicting-stage", p.Token); !errors.Is(e, errConfigurationRestorePending) {
		t.Fatal("second active restore allowed after candidate save", e)
	}
}

func TestConfigurationRevisionLocalFailureDoesNotConsumeIntent(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, false)
	ctx := context.Background()
	dsn, e := os.ReadFile(f.c.Database.DSNFile)
	if e != nil {
		t.Fatal(e)
	}
	localWrite(t, f.c.Database.DSNFile, []byte(" "))
	_, e = s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "fix-and-retry", stage.ID)
	var failure configurationLocalFailure
	if !errors.As(e, &failure) || failure.Report.LocalChecksPassed || localReportCheck(t, failure.Report, "database_credentials").Status != "failed" {
		t.Fatal("local failure was not actionable and safe", e)
	}
	if tableCount(t, s, "v3_configuration_revisions") != 0 || tableCount(t, s, "v3_configuration_revision_parts") != 0 || tableCount(t, s, "v3_configuration_backup_pins") != 2 {
		t.Fatal("failed validation partially saved")
	}
	live, _, e := s.configurationRestoreStage(ctx, "admin", stage.ID)
	if e != nil || live.Status != "pending_validation" {
		t.Fatal("failed validation advanced intent", e)
	}
	localWrite(t, f.c.Database.DSNFile, dsn)
	raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "fix-and-retry", stage.ID)
	r := configurationRevisionReceipt(t, raw, e)
	// A new save must not trust a past report, even after the candidate exists.
	localWrite(t, f.c.Collector.KeyFile, []byte("damaged"))
	if _, e = s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "must-recheck", stage.ID); !errors.As(e, &failure) {
		t.Fatal("stale successful report bypassed recheck", e)
	}
	current, e := s.configurationRevision(ctx, "admin", r.ID)
	if e != nil || current.Status != "pending_application" || tableCount(t, s, "v3_configuration_revisions") != 1 {
		t.Fatal("failed repeated check destroyed candidate", e)
	}
}

func TestConfigurationRevisionSaveAtomicOnDatabaseFailure(t *testing.T) {
	for _, target := range []string{"header", "part", "stage", "audit"} {
		t.Run(target, func(t *testing.T) {
			s, f, stage := configurationRevisionFixture(t, false)
			ctx := context.Background()
			sqls := map[string]string{
				"header": `CREATE FUNCTION reject_pending() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated failure';END$$;CREATE TRIGGER reject_pending BEFORE INSERT ON v3_configuration_revisions FOR EACH ROW EXECUTE FUNCTION reject_pending()`,
				"part":   `CREATE FUNCTION reject_pending() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated failure';END$$;CREATE TRIGGER reject_pending BEFORE INSERT ON v3_configuration_revision_parts FOR EACH ROW EXECUTE FUNCTION reject_pending()`,
				"stage":  `CREATE FUNCTION reject_pending() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.status='pending_application' THEN RAISE EXCEPTION 'isolated failure';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_pending BEFORE UPDATE ON v3_configuration_restore_stages FOR EACH ROW EXECUTE FUNCTION reject_pending()`,
				"audit":  `CREATE FUNCTION reject_pending() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='configuration-restore-save' THEN RAISE EXCEPTION 'isolated failure';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_pending BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION reject_pending()`,
			}
			mustHistoryExec(t, s.DB, sqls[target])
			if _, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "atomic-save", stage.ID); e == nil {
				t.Fatal("injected failure accepted")
			}
			if tableCount(t, s, "v3_configuration_revisions") != 0 || tableCount(t, s, "v3_configuration_revision_parts") != 0 || tableCount(t, s, "v3_configuration_backups") != 2 || tableCount(t, s, "v3_configuration_backup_pins") != 2 {
				t.Fatal("save failed non-atomically")
			}
			live, _, e := s.configurationRestoreStage(ctx, "admin", stage.ID)
			if e != nil || live.Status != "pending_validation" {
				t.Fatal("failure consumed intent", e)
			}
			mustHistoryExec(t, s.DB, `DROP FUNCTION reject_pending() CASCADE`)
			raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "atomic-save", stage.ID)
			configurationRevisionReceipt(t, raw, e)
		})
	}
}

func TestConfigurationRevisionConcurrentSavesAndAccountBoundaries(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, false)
	ctx := context.Background()
	for _, user := range []string{"viewer", "operator", "missing", "other-admin"} {
		if _, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, user, "not-owner", stage.ID); e == nil {
			t.Fatal("non-owner saved pending candidate", user)
		}
	}
	var wg sync.WaitGroup
	results := make(chan configurationRevision, 4)
	errs := make(chan error, 4)
	for _, key := range []string{"concurrent", "concurrent", "other-key", "other-key"} {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", key, stage.ID)
			var r configurationRevision
			if e == nil {
				e = json.Unmarshal(raw, &r)
			}
			results <- r
			errs <- e
		}(key)
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal("concurrent save failed", e)
		}
	}
	var id string
	for r := range results {
		if id == "" {
			id = r.ID
		}
		if r.ID != id || r.Generation != 1 {
			t.Fatal("concurrent duplicate revision")
		}
	}
	if tableCount(t, s, "v3_configuration_revisions") != 1 {
		t.Fatal("concurrent saves duplicated storage")
	}
	for _, user := range []string{"viewer", "operator", "missing"} {
		if _, e := s.configurationRevision(ctx, user, id); !errors.Is(e, ErrConfigurationBackupPermission) {
			t.Fatal("unauthorized metadata access", user, e)
		}
	}
	if _, e := s.configurationRevision(ctx, "other-admin", id); e != nil {
		t.Fatal("other admin cannot inspect abandoned candidate", e)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
	if _, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "new-account-revision", stage.ID); e == nil {
		t.Fatal("changed account continued old restore")
	}
	// Cancellation is available to a current administrator and remains atomic.
	if _, e := s.cancelConfigurationRestore(ctx, "other-admin", "cancel-abandoned", stage.ID); e != nil {
		t.Fatal(e)
	}
	r, e := s.configurationRevision(ctx, "other-admin", id)
	if e != nil || r.Status != "cancelled" || r.Finished == nil || tableCount(t, s, "v3_configuration_backup_pins") != 0 {
		t.Fatal("cancel did not retire candidate and its references", e)
	}
	if _, e := revalidateConfigurationStageForTest(t, s, f.v, f.c, stage.ID); e == nil {
		t.Fatal("cancelled candidate can be applied")
	}
}

func TestConfigurationRevisionRevalidationRejectsChangedLiveState(t *testing.T) {
	for _, change := range []string{"settings", "node", "bootstrap", "source", "before", "pin", "account"} {
		t.Run(change, func(t *testing.T) {
			s, f, stage := configurationRevisionFixture(t, false)
			ctx := context.Background()
			raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "before-change", stage.ID)
			configurationRevisionReceipt(t, raw, e)
			switch change {
			case "settings":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{retention,sqlite_events_days}','91')`)
			case "node":
				mustHistoryExec(t, s.DB, `UPDATE v3_nodes SET endpoint='192.0.2.99:19100'`)
			case "bootstrap":
				f.c.Central.Listen = "127.0.0.1:29444"
			case "source":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_backup_parts SET payload=decode('00','hex') WHERE backup=$1`, stage.Backup)
			case "before":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_backup_parts SET payload=decode('00','hex') WHERE backup=$1`, stage.BeforeBackup)
			case "pin":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_backup_pins WHERE backup=$1`, stage.BeforeBackup)
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			}
			if _, e := revalidateConfigurationStageForTest(t, s, f.v, f.c, stage.ID); e == nil {
				t.Fatal("stale pending candidate can continue", change)
			}
		})
	}
}

func TestConfigurationRevisionTamperingAndCandidateSourceBinding(t *testing.T) {
	for _, change := range []string{"none", "display-only", "part", "missing-part", "generation", "owner", "account", "state-proof", "candidate-proof", "base-version", "document-time", "node-count", "key", "nonce", "cancelled", "authenticated-other-candidate"} {
		t.Run(change, func(t *testing.T) {
			s, f, stage := configurationRevisionFixture(t, false)
			ctx := context.Background()
			raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "tamper-base", stage.ID)
			configurationRevisionReceipt(t, raw, e)
			switch change {
			case "display-only":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_restore_stages SET summary='{"removed":1000}';UPDATE v3_configuration_revisions SET message='display-only message'`)
			case "part":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revision_parts SET payload=decode('00','hex')`)
			case "missing-part":
				mustHistoryExec(t, s.DB, `DELETE FROM v3_configuration_revision_parts`)
			case "generation":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET generation=generation+1`)
			case "owner":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET username='other-admin'`)
			case "account":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET account_revision=account_revision+1`)
			case "state-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET state_proof='changed'`)
			case "candidate-proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET candidate_proof='changed'`)
			case "base-version":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET base_settings_version=base_settings_version+1`)
			case "document-time":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET document_created_at='2000-01-01T00:00:00Z'`)
			case "node-count":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET node_count=node_count+1`)
			case "key":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET key_id='unknown-key'`)
			case "nonce":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET nonce=decode('00','hex')`)
			case "cancelled":
				mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET status='cancelled',finished_at=clock_timestamp()`)
			case "authenticated-other-candidate":
				replaceCandidateForTest(t, s, f.v, stage.ID)
			}
			plan, e := revalidateConfigurationStageForTest(t, s, f.v, f.c, stage.ID)
			if change == "none" || change == "display-only" {
				if e != nil || common.F(common.M(plan.Candidate.Settings["retention"])["sqlite_events_days"]) != 30 {
					t.Fatal("valid pending target failed", e)
				}
			} else if e == nil {
				t.Fatal("tampered candidate accepted", change)
			}
		})
	}
}

// Give the substituted body a valid AEAD and candidate HMAC using a test-only
// vault. It must still fail against the independently reconstructed source plan.
func replaceCandidateForTest(t *testing.T, s *Store, v *Vault, stage string) {
	t.Helper()
	ctx := context.Background()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	r, doc, e := loadConfigurationRevisionTx(ctx, tx, v, stage)
	if e != nil {
		t.Fatal(e)
	}
	common.M(doc.Settings["retention"])["sqlite_events_days"] = 44
	r.CandidateProof, e = configurationRestoreProof(v, v.active, "candidate", r.Username, r.AccountRevision, configurationRestoreOptions{}, doc, common.JSON([]any{r.ID, r.Stage, r.Generation}))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := marshalConfigurationDocument(doc)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(raw)
	if _, e = rand.Read(r.Nonce); e != nil {
		t.Fatal(e)
	}
	sealed := v.keys[r.KeyID].Seal(nil, r.Nonce, raw, configurationRevisionAAD(r))
	defer clear(sealed)
	if _, e = tx.ExecContext(ctx, `UPDATE v3_configuration_revisions SET candidate_proof=$1,nonce=$2,ciphertext_bytes=$3 WHERE id=$4`, r.CandidateProof, r.Nonce, len(sealed), r.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM v3_configuration_revision_parts WHERE revision=$1`, r.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_configuration_revision_parts(revision,part,payload) VALUES($1,0,$2)`, r.ID, sealed); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
}

func TestConfigurationRevisionCancellationFailureAndGarbageCollection(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, false)
	ctx := context.Background()
	raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "before-cancel", stage.ID)
	r := configurationRevisionReceipt(t, raw, e)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_revision_cancel() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.status='cancelled' THEN RAISE EXCEPTION 'isolated failure';END IF;RETURN NEW;END$$;CREATE TRIGGER reject_revision_cancel BEFORE UPDATE ON v3_configuration_revisions FOR EACH ROW EXECUTE FUNCTION reject_revision_cancel()`)
	if _, e := s.cancelConfigurationRestore(ctx, "admin", "cancel-once", stage.ID); e == nil {
		t.Fatal("injected cancellation failure accepted")
	}
	current, _, e := s.configurationRestoreStage(ctx, "admin", stage.ID)
	if e != nil || current.Status != "pending_application" || tableCount(t, s, "v3_configuration_backup_pins") != 2 {
		t.Fatal("cancel failed non-atomically", e)
	}
	mustHistoryExec(t, s.DB, `DROP FUNCTION reject_revision_cancel() CASCADE`)
	if _, e := s.cancelConfigurationRestore(ctx, "admin", "cancel-once", stage.ID); e != nil {
		t.Fatal(e)
	}
	if tableCount(t, s, "v3_configuration_revisions") != 1 || tableCount(t, s, "v3_configuration_revision_parts") == 0 || tableCount(t, s, "v3_configuration_backups") != 2 {
		t.Fatal("cancel destroyed candidate history or original archives")
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET finished_at=clock_timestamp()-interval '366 days';UPDATE v3_configuration_restore_stages SET finished_at=clock_timestamp()-interval '366 days'`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source,pending) VALUES('settings',repeat('a',64),true)`)
	if e := s.Housekeeping(ctx, "revision-gc"); e != nil {
		t.Fatal(e)
	}
	if tableCount(t, s, "v3_configuration_revisions") != 1 || tableCount(t, s, "v3_configuration_revision_parts") == 0 {
		t.Fatal("migration freeze did not preserve revision history")
	}
	mustHistoryExec(t, s.DB, `DELETE FROM v3_migration_domains WHERE domain='settings'`)
	if e := s.Housekeeping(ctx, "revision-gc"); e != nil {
		t.Fatal(e)
	}
	if tableCount(t, s, "v3_configuration_revisions") != 0 || tableCount(t, s, "v3_configuration_revision_parts") != 0 || tableCount(t, s, "v3_configuration_restore_stages") != 0 || tableCount(t, s, "v3_configuration_backups") != 2 {
		t.Fatal("terminal cleanup incomplete or deleted archives")
	}
	// The retained receipt cannot recreate work after evidence GC.
	again, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "before-cancel", stage.ID)
	if e != nil || canonicalBackupResponse(t, again) != canonicalBackupResponse(t, raw) || tableCount(t, s, "v3_configuration_revisions") != 0 {
		t.Fatal("old request revived removed history", e)
	}
	if _, e = s.configurationRevision(ctx, "admin", r.ID); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("collected status still present", e)
	}
}

func TestConfigurationRevisionLargeBackupDisasterRecoveryAndGeneration(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, true)
	ctx := context.Background()
	raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "before-disaster", stage.ID)
	r := configurationRevisionReceipt(t, raw, e)
	_, original, e := readConfigurationRevisionForTest(t, s, f.v, stage.ID)
	if e != nil {
		t.Fatal(e)
	}
	if tableCount(t, s, "v3_configuration_revision_parts") < 2 {
		t.Fatal("large candidate not split")
	}
	private := common.M(original.Profiles[original.Nodes["revision-node"].Profile].Config["private"])
	if fmt.Sprint(private["counter"]) != "9007199254740993" || fmt.Sprint(private["decimal"]) != "1.234567890123456789" {
		t.Fatal("pending snapshot lost numeric precision")
	}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_configuration_backup_pins(backup,kind,reference) VALUES($1,'rollback','unrelated-recovery')`, stage.BeforeBackup)
	path, e := s.BackupPostgres(ctx, privateTestDir(t))
	if e != nil {
		t.Fatal(e)
	}
	restored := emptyTestStore(t)
	if e := restored.RestorePostgres(ctx, path); e != nil {
		t.Fatal(e)
	}
	meta, doc, e := readConfigurationRevisionForTest(t, restored, f.v, stage.ID)
	if e != nil || meta.Status != "cancelled" || meta.Finished == nil {
		t.Fatal("restored candidate not safely cancelled", e)
	}
	a, _ := marshalConfigurationDocument(original)
	b, _ := marshalConfigurationDocument(doc)
	if !bytes.Equal(a, b) || tableCount(t, restored, "v3_configuration_backup_pins") != 1 || tableCount(t, restored, "v3_configuration_backups") != 2 {
		t.Fatal("disaster lost candidate contents or unrelated recovery evidence")
	}
	if _, e := revalidateConfigurationStageForTest(t, restored, f.v, f.c, stage.ID); e == nil {
		t.Fatal("disaster revived candidate authorization")
	}
	again, e := restored.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "before-disaster", stage.ID)
	if e != nil || canonicalBackupResponse(t, again) != canonicalBackupResponse(t, raw) {
		t.Fatal("disaster lost receipt", e)
	}
	live, e := restored.configurationRevision(ctx, "admin", r.ID)
	if e != nil || live.Status != "cancelled" {
		t.Fatal("receipt replay revived cancelled target", e)
	}
	policy, e := restored.RetentionPolicy(ctx)
	if e != nil || policy.Policy.Events != 90 || policy.Version != 6 {
		t.Fatal("disaster applied pending candidate", e)
	}
	// A fresh preview/intent can make a new candidate, with a later generation.
	p, e := restored.previewConfigurationRestore(ctx, f.v, f.c, "admin", stage.Backup, configurationRestoreOptions{})
	if e != nil {
		t.Fatal(e)
	}
	newRaw, e := restored.stageConfigurationRestore(ctx, f.v, f.c, "admin", "fresh-stage", p.Token)
	newStage := configurationStageReceipt(t, newRaw, e)
	newRaw, e = restored.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "fresh-save", newStage.ID)
	next := configurationRevisionReceipt(t, newRaw, e)
	if next.Generation <= r.Generation {
		t.Fatal("restored identity sequence reused generation")
	}
}

func TestConfigurationRevisionSchema17UpgradeBackupGate(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, false)
	ctx := context.Background()
	dropConfigurationRevisionsForTest(t, s)
	old := &Store{DB: s.DB}
	if e := old.Upgrade(ctx, ""); e == nil {
		t.Fatal("schema 17 upgraded without backup")
	}
	bad := filepath.Join(privateTestDir(t), "not-a-directory")
	localWrite(t, bad, []byte("file"))
	if e := old.Upgrade(ctx, bad); e == nil {
		t.Fatal("failed backup permitted migration")
	}
	var version int
	if e := s.DB.QueryRow(`SELECT max(version) FROM v3_schema`).Scan(&version); e != nil || version != 17 {
		t.Fatal("failed upgrade changed schema", e)
	}
	dir := privateTestDir(t)
	if e := old.Upgrade(ctx, dir); e != nil {
		t.Fatal(e)
	}
	files, e := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if e != nil || len(files) != 1 {
		t.Fatal("missing pre-upgrade archive", e)
	}
	if e := s.DB.QueryRow(`SELECT max(version) FROM v3_schema`).Scan(&version); e != nil || version != SchemaVersion {
		t.Fatal("upgrade did not finish", e)
	}
	restored := emptyTestStore(t)
	if e := restored.RestorePostgres(ctx, files[0]); e != nil {
		t.Fatal("schema 17 archive cannot restore", e)
	}
	if e := restored.Upgrade(ctx, privateTestDir(t)); e != nil {
		t.Fatal("restored schema 17 cannot upgrade", e)
	}
	state, _, e := restored.configurationRestoreStage(ctx, "admin", stage.ID)
	if e != nil || state.Status != "cancelled" {
		t.Fatal("old disaster revived intent", e)
	}
	if _, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "after-upgrade", stage.ID); e != nil {
		t.Fatal("upgrade lost original valid pending intent", e)
	}
}

func TestConfigurationRevisionSaveCancellationRaceDoesNotOrphanWork(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, false)
	ctx := context.Background()
	start := make(chan struct{})
	saved := make(chan error, 1)
	cancelled := make(chan error, 1)
	go func() {
		<-start
		_, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "save-race", stage.ID)
		saved <- e
	}()
	go func() {
		<-start
		_, e := s.cancelConfigurationRestore(ctx, "other-admin", "cancel-race", stage.ID)
		cancelled <- e
	}()
	close(start)
	if e := <-cancelled; e != nil {
		t.Fatal("cancellation lost race", e)
	}
	if e := <-saved; e != nil && !errors.Is(e, errConfigurationRestorePreview) {
		t.Fatal("unexpected save race result", e)
	}
	live, _, e := s.configurationRestoreStage(ctx, "admin", stage.ID)
	if e != nil || live.Status != "cancelled" || tableCount(t, s, "v3_configuration_backup_pins") != 0 {
		t.Fatal("race orphaned active intent or pins", e)
	}
	var pending int
	if e = s.DB.QueryRow(`SELECT count(*) FROM v3_configuration_revisions WHERE status='pending_application'`).Scan(&pending); e != nil || pending != 0 {
		t.Fatal("race left active orphan candidate", e)
	}
	policy, e := s.RetentionPolicy(ctx)
	if e != nil || policy.Version != 6 || policy.Policy.Events != 90 {
		t.Fatal("race applied configuration", e)
	}
}

func TestConfigurationRevisionPendingIsNotExpiredByHistoryMaintenance(t *testing.T) {
	s, f, stage := configurationRevisionFixture(t, false)
	ctx := context.Background()
	raw, e := s.saveConfigurationRestorePending(ctx, f.v, f.c, "admin", "pending-long", stage.ID)
	r := configurationRevisionReceipt(t, raw, e)
	mustHistoryExec(t, s.DB, `UPDATE v3_configuration_revisions SET created_at=clock_timestamp()-interval '400 days';UPDATE v3_configuration_restore_stages SET created_at=clock_timestamp()-interval '400 days'`)
	if e := s.Housekeeping(ctx, "pending-gc"); e != nil {
		t.Fatal(e)
	}
	current, e := s.configurationRevision(ctx, "admin", r.ID)
	if e != nil || current.Status != "pending_application" || tableCount(t, s, "v3_configuration_revision_parts") == 0 || tableCount(t, s, "v3_configuration_backup_pins") != 2 {
		t.Fatal("maintenance expired pending restore", e)
	}
	if _, e := revalidateConfigurationStageForTest(t, s, f.v, f.c, stage.ID); e != nil {
		t.Fatal("maintenance invalidated pending body", e)
	}
}
