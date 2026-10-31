package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"webscan/internal/common"
)

func dropSettingsDraftForTest(t *testing.T, s *Store) {
	t.Helper()
	dropConfigurationSavedForTest(t, s)
	mustHistoryExec(t, s.DB, nodeHistoryRetirementTestDrop+`DROP TABLE IF EXISTS v3_deployment_private_inputs;DROP TABLE IF EXISTS v3_deployment_preparations;DROP TABLE IF EXISTS v3_web_node_credentials;DELETE FROM v3_schema WHERE version=35;DROP TABLE IF EXISTS v3_node_name_prunings;DROP TABLE IF EXISTS v3_node_name_changes;DROP TABLE IF EXISTS v3_node_identity_recoveries;DROP TABLE IF EXISTS v3_node_renewal_jobs;DROP TABLE IF EXISTS v3_node_certificate_renewals;DROP TABLE v3_settings_drafts;DELETE FROM v3_schema WHERE version>=20`)
}

func settingsDraftFixture(t *testing.T) (*Store, *configurationEditBackup) {
	t.Helper()
	s, v, c := configurationBackupStoreFixture(t)
	return s, &configurationEditBackup{v, c}
}

func settingsStateForTest(t *testing.T, s *Store) privateSettingsDraft {
	t.Helper()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	d, err := readSettingsDraftTx(context.Background(), tx, false)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func saveSettingsForTest(t *testing.T, s *Store, b *configurationEditBackup, key string, raw []byte) settingsDraftState {
	t.Helper()
	d := settingsStateForTest(t, s)
	rawResponse, err := s.saveSettingsDraft(context.Background(), "admin", key, raw, d.Generation, d.RuntimeVersion, b)
	var state settingsDraftState
	if err != nil || json.Unmarshal(rawResponse, &state) != nil {
		t.Fatal("save draft failed", err)
	}
	return state
}

func TestSettingsDraftSaveDoesNotApplyAndApplyIsAtomic(t *testing.T) {
	s, b := settingsDraftFixture(t)
	ctx := context.Background()
	original := settingsStateForTest(t, s)
	target := []byte(`{"retention":{"sqlite_events_days":95},"email":{"enabled":false,"password":"private-draft-password"}}`)
	saved := saveSettingsForTest(t, s, b, "settings-save", target)
	d := settingsStateForTest(t, s)
	if !saved.Pending || saved.Generation < 1 || d.RuntimeVersion != original.RuntimeVersion || !configurationJSONEqual(original.Runtime, d.Runtime) || !configurationJSONEqual(target, d.Desired) {
		t.Fatal("save changed runtime or lost desired content")
	}
	var row, audit []byte
	if err := s.DB.QueryRow(`SELECT response FROM v3_requests WHERE key='settings-save'`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT jsonb_agg(result) FROM v3_audit`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(row, []byte("private-")) || bytes.Contains(audit, []byte("private-")) {
		t.Fatal("metadata leaked settings")
	}
	mustHistoryExec(t, s.DB, `CREATE FUNCTION fail_settings_apply() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.kind='settings-apply' THEN RAISE EXCEPTION 'synthetic apply failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_settings_apply BEFORE INSERT ON v3_audit FOR EACH ROW EXECUTE FUNCTION fail_settings_apply()`)
	if _, err := s.applySettingsDraft(ctx, "admin", "settings-apply", saved.Generation, d.RuntimeVersion, b); err == nil {
		t.Fatal("injected audit failure ignored")
	}
	failed := settingsStateForTest(t, s)
	if failed.RuntimeVersion != original.RuntimeVersion || !failed.Pending || !configurationJSONEqual(original.Runtime, failed.Runtime) {
		t.Fatal("failed apply partially published")
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER fail_settings_apply ON v3_audit`)
	raw, err := s.applySettingsDraft(ctx, "admin", "settings-apply", saved.Generation, d.RuntimeVersion, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.applySettingsDraft(ctx, "admin", "settings-apply", saved.Generation, d.RuntimeVersion, b); err != nil {
		t.Fatal("lost response was not idempotent", err)
	}
	var applied settingsDraftState
	if json.Unmarshal(raw, &applied) != nil || applied.Pending || applied.AppliedGeneration != saved.Generation {
		t.Fatal("apply did not publish generation")
	}
	d = settingsStateForTest(t, s)
	if d.RuntimeVersion != original.RuntimeVersion+1 || !configurationJSONEqual(d.Desired, d.Runtime) || checkSettingsDraftProof(b.vault, d) != nil {
		t.Fatal("published settings mismatch")
	}
}

func TestSettingsDraftRetentionAppliesOnlyRetention(t *testing.T) {
	s, b := settingsDraftFixture(t)
	ctx := context.Background()
	original := settingsStateForTest(t, s)
	saved := saveSettingsForTest(t, s, b, "pending-mail", []byte(`{"retention":{"sqlite_events_days":60},"email":{"enabled":false,"password":"private-unapplied-mail"}}`))
	p := RetentionPolicy{90, 100, 110, 120, 130}
	if _, err := s.saveRetentionPolicy(ctx, "admin", "retention-only", p, original.RuntimeVersion, b); err != nil {
		t.Fatal(err)
	}
	d := settingsStateForTest(t, s)
	if d.Generation <= saved.Generation || !d.Pending || d.BaseRuntime != original.RuntimeVersion+1 || checkSettingsDraftProof(b.vault, d) != nil {
		t.Fatal("retention failed to rebase draft")
	}
	if bytes.Contains(d.Runtime, []byte("private-unapplied-mail")) || !bytes.Contains(d.Desired, []byte("private-unapplied-mail")) {
		t.Fatal("retention implicitly applied pending SMTP credentials")
	}
	var desired common.Map
	if json.Unmarshal(d.Desired, &desired) != nil {
		t.Fatal("bad desired settings")
	}
	got, err := retentionPolicy(desired)
	if err != nil || got != p {
		t.Fatal("retention periods diverged", err)
	}
	if _, err = s.applySettingsDraft(ctx, "admin", "stale-apply", saved.Generation, original.RuntimeVersion, b); !errors.Is(err, errSettingsDraft) {
		t.Fatal("old confirmation survived retention edit", err)
	}
}

func TestSettingsDraftRejectsCorruptionRuntimeDriftAndWrongAccount(t *testing.T) {
	for _, kind := range []string{"payload", "generation", "baseline", "proof", "active", "active-payload", "wrong-account"} {
		t.Run(kind, func(t *testing.T) {
			s, b := settingsDraftFixture(t)
			saved := saveSettingsForTest(t, s, b, "save-settings", []byte(`{"email":{"enabled":false,"password":"private-pending"}}`))
			d := settingsStateForTest(t, s)
			switch kind {
			case "payload":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings_drafts SET payload='{}'`)
			case "generation":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings_drafts SET generation=generation+1`)
			case "baseline":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings_drafts SET runtime_version=runtime_version+1`)
			case "proof":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings_drafts SET proof='bad'`)
			case "active-payload":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload='{}'`)
			case "active":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
			case "wrong-account":
				mustHistoryExec(t, s.DB, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`)
			}
			if _, err := s.applySettingsDraft(context.Background(), "admin", "must-reject", saved.Generation, d.RuntimeVersion, b); err == nil {
				t.Fatal("invalid settings applied", kind)
			}
			if bytes.Contains(settingsStateForTest(t, s).Runtime, []byte("private-pending")) {
				t.Fatal("rejected apply changed runtime")
			}
		})
	}
}

func TestSettingsDraftConcurrentSaveHasOneReceiptAndPreservesGenerations(t *testing.T) {
	s, b := settingsDraftFixture(t)
	d := settingsStateForTest(t, s)
	raw := []byte(`{"email":{"enabled":false}}`)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.saveSettingsDraft(context.Background(), "admin", "same-save", raw, 0, d.RuntimeVersion, b)
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
	if tableCount(t, s, "v3_settings_drafts") != 1 || tableCount(t, s, "v3_requests") != 1 || tableCount(t, s, "v3_configuration_backups") != 1 {
		t.Fatal("concurrent save duplicated effects")
	}
	first := settingsStateForTest(t, s)
	second := saveSettingsForTest(t, s, b, "next-save", []byte(`{"email":{"enabled":false},"retention":{"sqlite_events_days":110}}`))
	if second.Generation <= first.Generation {
		t.Fatal("draft generation did not advance")
	}
}

func TestSettingsDraftRetentionPreservesUnknownLargeNumbers(t *testing.T) {
	s, b := settingsDraftFixture(t)
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=payload||'{"future":{"counter":9007199254740993}}'::jsonb`)
	raw := []byte(`{"future":{"counter":9007199254740993},"email":{"enabled":false,"password":"private-draft"}}`)
	saveSettingsForTest(t, s, b, "large-number-save", raw)
	d := settingsStateForTest(t, s)
	if _, err := s.saveRetentionPolicy(context.Background(), "admin", "large-number-retention", RetentionPolicy{35, 36, 37, 38, 39}, d.RuntimeVersion, b); err != nil {
		t.Fatal(err)
	}
	d = settingsStateForTest(t, s)
	if checkSettingsDraftProof(b.vault, d) != nil {
		t.Fatal("retention merge changed runtime bytes relative to proof")
	}
	for _, raw := range [][]byte{d.Desired, d.Runtime} {
		var values configurationValues
		if decodeConfigurationObject(raw, &values) != nil || common.M(values["future"])["counter"] != json.Number("9007199254740993") {
			t.Fatal("unknown numeric setting rounded")
		}
	}
}

func TestSettingsDraftPostgresNumberNormalizationKeepsValidProof(t *testing.T) {
	s, b := settingsDraftFixture(t)
	saved := saveSettingsForTest(t, s, b, "normalized-numbers", []byte(`{"future":{"counter":9007199254740993e0,"rate":1.25e2,"offset":-0}}`))
	d := settingsStateForTest(t, s)
	if err := checkSettingsDraftProof(b.vault, d); err != nil {
		t.Fatal("PostgreSQL numeric normalization invalidated the proof", err)
	}
	var values configurationValues
	if decodeConfigurationObject(d.Desired, &values) != nil || common.M(values["future"])["counter"] != json.Number("9007199254740993") {
		t.Fatal("PostgreSQL normalization rounded a large integer")
	}
	if _, err := s.applySettingsDraft(context.Background(), "admin", "apply-normalized", saved.Generation, saved.RuntimeVersion, b); err != nil {
		t.Fatal(err)
	}
	if err := checkSettingsDraftProof(b.vault, settingsStateForTest(t, s)); err != nil {
		t.Fatal("applied normalized settings have an invalid proof", err)
	}
}

func TestSettingsDraftBackupCapturesSavedIntentAndRejectsDrift(t *testing.T) {
	for _, drift := range []string{"none", "payload", "runtime-version"} {
		t.Run(drift, func(t *testing.T) {
			s, b := settingsDraftFixture(t)
			saved := saveSettingsForTest(t, s, b, "backup-draft", []byte(`{"email":{"enabled":false,"password":"private-pending-backup"}}`))
			before := tableCount(t, s, "v3_configuration_backups")
			switch drift {
			case "payload":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings_drafts SET payload='{}'`)
			case "runtime-version":
				mustHistoryExec(t, s.DB, `UPDATE v3_settings SET version=version+1`)
			}
			raw, err := s.createConfigurationBackup(context.Background(), b.vault, b.bootstrap, "admin", "capture-draft")
			if drift != "none" {
				if err == nil || tableCount(t, s, "v3_configuration_backups") != before {
					t.Fatal("invalid saved intent archived as valid")
				}
				return
			}
			id := configurationBackupReceiptID(t, raw, err)
			doc := readPrivateConfigurationBackup(t, s, b.vault, id)
			if doc.SettingsGeneration != saved.Generation || doc.SettingsVersion != saved.RuntimeVersion || common.M(doc.Settings["email"])["password"] != "private-pending-backup" {
				t.Fatal("archive lost saved settings or generation")
			}
			encoded, err := marshalConfigurationDocument(doc)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := parseConfigurationDocument(encoded)
			if err != nil || roundtrip.SettingsGeneration != saved.Generation {
				t.Fatal("configuration document lost generation", err)
			}
			if bytes.Contains(settingsStateForTest(t, s).Runtime, []byte("private-pending-backup")) {
				t.Fatal("archive applied saved settings")
			}
		})
	}
}

func TestSettingsDraftAppliedRetentionAndSameValueEdits(t *testing.T) {
	s, b := settingsDraftFixture(t)
	ctx := context.Background()
	saved := saveSettingsForTest(t, s, b, "same-settings", settingsStateForTest(t, s).Runtime)
	if _, err := s.applySettingsDraft(ctx, "admin", "apply-same", saved.Generation, saved.RuntimeVersion, b); err != nil {
		t.Fatal(err)
	}
	d := settingsStateForTest(t, s)
	policy, err := s.RetentionPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.saveRetentionPolicy(ctx, "admin", "same-retention", policy.Policy, d.RuntimeVersion, b); err != nil {
		t.Fatal(err)
	}
	after := settingsStateForTest(t, s)
	if after.Pending || after.Generation <= d.Generation || after.AppliedGeneration != after.Generation || checkSettingsDraftProof(b.vault, after) != nil {
		t.Fatal("period-only edit invented pending changes or invalidated live proof")
	}
	if _, err := s.applySettingsDraft(ctx, "admin", "already-applied", after.Generation, after.RuntimeVersion, b); err != nil {
		t.Fatal(err)
	}
	if settingsStateForTest(t, s).RuntimeVersion != after.RuntimeVersion {
		t.Fatal("already applied draft republished")
	}
}

func TestSettingsDraftVaultRotationAndUnavailableKeys(t *testing.T) {
	s, b := settingsDraftFixture(t)
	old, oldPath := testVault(t)
	b.vault = old
	saved := saveSettingsForTest(t, s, b, "old-key-save", []byte(`{"email":{"enabled":false,"password":"private-rotating"}}`))
	next, nextPath := testVault(t)
	rotated, err := OpenVault(nextPath, oldPath)
	if err != nil {
		t.Fatal(err)
	}
	b.vault = next
	if _, err := s.applySettingsDraft(context.Background(), "admin", "missing-old-key", saved.Generation, saved.RuntimeVersion, b); err == nil {
		t.Fatal("unavailable proof key accepted")
	}
	if _, err := s.saveRetentionPolicy(context.Background(), "admin", "no-key-retention", RetentionPolicy{30, 30, 30, 30, 30}, saved.RuntimeVersion, nil); err == nil {
		t.Fatal("low-level retention silently invalidated draft")
	}
	b.vault = rotated
	if _, err := s.applySettingsDraft(context.Background(), "admin", "rotated-apply", saved.Generation, saved.RuntimeVersion, b); err != nil {
		t.Fatal(err)
	}
	d := settingsStateForTest(t, s)
	if !strings.HasPrefix(d.Proof, next.active+":") || checkSettingsDraftProof(next, d) != nil {
		t.Fatal("applied draft not signed with current key")
	}
}

func TestSettingsDraftSchema19UpgradeAndDisasterRestore(t *testing.T) {
	s, b := settingsDraftFixture(t)
	ctx := context.Background()
	dropSettingsDraftForTest(t, s)
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("schema 19 upgraded without backup")
	}
	unsafe := filepath.Join(privateTestDir(t), "unsafe")
	if err := os.Mkdir(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if err := s.Upgrade(ctx, unsafe); err == nil {
		t.Fatal("failed backup did not block upgrade")
	}
	version, err := currentSchema(ctx, s.DB)
	if err != nil || version != 19 {
		t.Fatal("failed migration changed schema", err)
	}
	if err = s.Upgrade(ctx, privateTestDir(t)); err != nil {
		t.Fatal(err)
	}
	d := settingsStateForTest(t, s)
	if d.Generation != 0 || d.Pending || !configurationJSONEqual(d.Desired, d.Runtime) {
		t.Fatal("migration created fictitious pending settings")
	}
	saved := saveSettingsForTest(t, s, b, "before-disaster", []byte(`{"email":{"enabled":false,"password":"private-survive-disaster"}}`))
	archive, err := s.BackupPostgres(ctx, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	restored := emptyTestStore(t)
	if err = restored.RestorePostgres(ctx, archive); err != nil {
		t.Fatal(err)
	}
	d = settingsStateForTest(t, restored)
	if d.Generation != saved.Generation || !d.Pending || checkSettingsDraftProof(b.vault, d) != nil || bytes.Contains(d.Runtime, []byte("private-survive-disaster")) {
		t.Fatal("disaster restore changed pending/live settings")
	}
	next := saveSettingsForTest(t, restored, b, "after-disaster", []byte(`{"email":{"enabled":false}}`))
	if next.Generation <= saved.Generation {
		t.Fatal("restored generation reused")
	}
}

func TestSettingsDraftLiveReadersIgnoreSavedChanges(t *testing.T) {
	s, b := settingsDraftFixture(t)
	ctx := context.Background()
	saveSettingsForTest(t, s, b, "reader-isolation", []byte(`{"retention":{"sqlite_events_days":1},"monitoring":{"interval_seconds":90},"email":{"enabled":true,"smtp_host":"smtp.example.test","smtp_port":465,"tls_mode":"tls","timeout_seconds":10,"max_per_minute":60,"retry":{"initial_delay_seconds":2,"max_delay_seconds":60},"username":"fixture@example.test","password":"private-never-send","from_address":"fixture@example.test","recipients":["recipient@example.test"]}}`))
	policy, err := s.RetentionPolicy(ctx)
	if err != nil || policy.Policy.Events != 60 {
		t.Fatal("saved draft changed live retention", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	root, err := websiteNotificationSettings(ctx, tx)
	if err != nil || websiteNotificationsEnabled(root) {
		t.Fatal("saved channel settings activated website notifications", err)
	}
	health, version, err := healthSettings(ctx, tx)
	if err != nil || version != 5 || common.I(health["interval_seconds"]) != 30 {
		t.Fatal("saved settings changed health workers", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	// This only reserves a job. No notifier or external channel is started.
	if notification, err := s.claimNotification(ctx, "email", "fixture-reader"); err != nil || notification != nil {
		t.Fatal("unapplied email settings enabled delivery", err)
	}
}

func TestSettingsDraftBlocksLegacyInitializationOverPendingSettings(t *testing.T) {
	s := testStore(t)
	v, _ := testVault(t)
	b := &configurationEditBackup{v, configurationBootstrapFixture(t)}
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('admin','not-a-login-hash','admin')`)
	saveSettingsForTest(t, s, b, "pending-first", []byte(`{"email":{"enabled":false,"password":"private-before-migration"}}`))
	source := writeLegacySettings(t, legacySettingsFixture(t))
	if _, err := s.ImportLegacySettings(context.Background(), source, privateTestDir(t)); err == nil {
		t.Fatal("legacy initializer overwrote a pending draft baseline")
	}
	d := settingsStateForTest(t, s)
	if d.RuntimeVersion != 1 || !configurationJSONEqual(d.Runtime, []byte(`{}`)) || checkSettingsDraftProof(v, d) != nil {
		t.Fatal("rejected import changed draft/live settings")
	}
}
