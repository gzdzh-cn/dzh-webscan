package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSingleBackupRuntimePolicyStrictControlsAndLegacyCompatibility(t *testing.T) {
	legacy, err := singleBackupRuntimePolicyFromSettings(runtimeSettingsObject(t, `{"backup":{"include_sqlite":true}}`))
	if err != nil || legacy.configured || !legacy.Enabled {
		t.Fatal(legacy, err)
	}
	p, err := singleBackupRuntimePolicyFromSettings(runtimeSettingsObject(t, `{"backup":{"enabled":true}}`))
	if err != nil || !p.configured || p.Time != "03:00" || p.Timezone != "UTC" || p.KeepDays != 7 {
		t.Fatal(p, err)
	}
	p, err = singleBackupRuntimePolicyFromSettings(runtimeSettingsObject(t, `{"backup":{"enabled":false,"time":"22:45","timezone":"Asia/Shanghai","keep_days":3650}}`))
	if err != nil || p.Enabled || p.Time != "22:45" || p.location.String() != "Asia/Shanghai" || p.KeepDays != 3650 {
		t.Fatal(p, err)
	}
	for _, raw := range []string{
		`{"backup":null}`, `{"backup":[]}`, `{"backup":{"enabled":"true"}}`,
		`{"backup":{"time":"3:00"}}`, `{"backup":{"time":"24:00"}}`, `{"backup":{"time":"12:60"}}`, `{"backup":{"time":300}}`,
		`{"backup":{"timezone":"Local"}}`, `{"backup":{"timezone":"../etc/passwd"}}`, `{"backup":{"timezone":"invalid/timezone"}}`, `{"backup":{"timezone":""}}`,
		`{"backup":{"keep_days":0}}`, `{"backup":{"keep_days":3651}}`, `{"backup":{"keep_days":1.5}}`, `{"backup":{"keep_days":"7"}}`,
	} {
		if _, err := singleBackupRuntimePolicyFromSettings(runtimeSettingsObject(t, raw)); err == nil {
			t.Fatal("invalid backup runtime accepted", raw)
		}
	}
	for path, raw := range map[string]string{"backup.time": `"23:59"`, "backup.timezone": `"America/New_York"`, "backup.keep_days": `30`, "backup.enabled": `false`} {
		if _, _, err := editSettings(runtimeSettingsObject(t, `{}`), settingsEdit{Values: map[string]json.RawMessage{path: json.RawMessage(raw)}}); err != nil {
			t.Fatal("runtime editor cannot preview backup policy", path, err)
		}
	}
	if _, _, err := editSettings(runtimeSettingsObject(t, `{}`), settingsEdit{Values: map[string]json.RawMessage{"backup.timezone": json.RawMessage(`"not-an-iana-zone"`)}}); err == nil {
		t.Fatal("editor accepted an invalid timezone")
	}
}

func TestSingleBackupRuntimeDueUsesLocalDatesAcrossDSTAndTimezoneChanges(t *testing.T) {
	parse := func(raw string) time.Time {
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	policy := func(zone, clock string) singleBackupRuntimePolicy {
		p, err := singleBackupRuntimePolicyFromSettings(runtimeSettingsObject(t, `{"backup":{"time":"`+clock+`","timezone":"`+zone+`"}}`))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name, zone, clock, now, latest, date string
		due                                  bool
	}{
		{"spring-before-gap", "America/New_York", "02:30", "2026-03-08T06:59:00Z", "", "2026-03-08", false},
		{"spring-next-available-minute", "America/New_York", "02:30", "2026-03-08T07:00:00Z", "", "2026-03-08", true},
		{"fall-first-hour", "America/New_York", "01:30", "2026-11-01T05:30:00Z", "", "2026-11-01", true},
		{"fall-second-hour-no-repeat", "America/New_York", "01:30", "2026-11-01T06:30:00Z", "2026-11-01T05:31:00Z", "2026-11-01", false},
		{"next-day-shorter-than-24h", "America/New_York", "03:00", "2026-03-08T07:00:00Z", "2026-03-07T08:01:00Z", "2026-03-08", true},
		{"new-time-same-date", "UTC", "00:00", "2026-11-01T14:00:00Z", "2026-11-01T03:00:00Z", "2026-11-01", false},
		{"zone-forward-crosses-date", "Pacific/Kiritimati", "00:00", "2026-11-01T12:10:00Z", "2026-11-01T11:50:00Z", "2026-11-02", false},
		{"zone-backward-crosses-date", "America/Los_Angeles", "00:00", "2026-11-01T06:00:00Z", "2026-11-01T05:30:00Z", "2026-10-31", false},
		{"clock-moved-backward", "UTC", "00:00", "2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z", "2026-11-01", false},
		{"year-rollover", "Asia/Shanghai", "03:00", "2026-12-31T19:00:00Z", "2026-12-30T19:01:00Z", "2027-01-01", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			latest := sql.NullTime{}
			if tc.latest != "" {
				latest = sql.NullTime{Time: parse(tc.latest), Valid: true}
			}
			date, due := singleBackupRuntimeDue(policy(tc.zone, tc.clock), parse(tc.now), latest)
			if date != tc.date || due != tc.due {
				t.Fatal(date, due)
			}
		})
	}
	disabled := policy("UTC", "00:00")
	disabled.Enabled = false
	if _, due := singleBackupRuntimeDue(disabled, parse("2026-11-01T12:00:00Z"), sql.NullTime{}); due {
		t.Fatal("disabled policy is due")
	}
	for hour := 0; hour < 24; hour++ {
		at := time.Date(2026, time.November, 1, hour, 0, 0, 0, time.Local)
		if singleBackupLegacyTimerDue(at) != (hour >= 3) {
			t.Fatal("legacy host-local 03:00 changed", hour)
		}
	}
}

func setRuntimeBackupFixture(t *testing.T, s *Store, raw string) {
	t.Helper()
	mustHistoryExec(t, s.DB, `UPDATE v3_settings SET payload=$1,version=version+1`, raw)
}

func TestSingleBackupRuntimeAppliedPolicyDurableDailySlotAndHostRestart(t *testing.T) {
	s, p, plan, raw := singleBackupScheduleFixture(t)
	ctx := context.Background()
	setRuntimeBackupFixture(t, s, `{"backup":{"enabled":true,"time":"00:00","timezone":"UTC","keep_days":2}}`)
	mustHistoryExec(t, s.DB, `INSERT INTO v3_settings_drafts(id,runtime_version,runtime_digest,payload,proof) SELECT 1,version,'fixture','{"backup":{"enabled":false}}','pending-only' FROM v3_settings`)
	r, err := s.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || r.State != "captured" || r.Receipt == nil {
		t.Fatal(r, err)
	}
	var run, date string
	var completed bool
	if err := s.DB.QueryRow(`SELECT run_id,local_date::text,completed_at IS NOT NULL FROM v3_single_backup_slots`).Scan(&run, &date, &completed); err != nil || run != r.ID || !completed || date != time.Now().UTC().Format("2006-01-02") {
		t.Fatal(run, date, completed, err)
	}
	// A new service object has no process-local dedup state to rely on.
	restarted := &Store{DB: s.DB}
	next, err := restarted.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || next.State != "not-due" || tableCount(t, s, "v3_single_backup_runs") != 1 {
		t.Fatal("restart repeated completed daily backup", next, err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_single_backup_runs SET status='expired' WHERE id=$1`, r.ID)
	next, err = restarted.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || next.State != "not-due" || tableCount(t, s, "v3_single_backup_runs") != 1 {
		t.Fatal("expired archive erased durable daily success", next, err)
	}
	setRuntimeBackupFixture(t, s, `{"backup":{"enabled":true,"time":"00:00","timezone":"Pacific/Kiritimati","keep_days":3}}`)
	next, err = restarted.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || next.State != "not-due" || tableCount(t, s, "v3_single_backup_runs") != 1 {
		t.Fatal("timezone update repeated daily backup", next, err)
	}
	setRuntimeBackupFixture(t, s, `{"backup":{"enabled":false}}`)
	next, err = restarted.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || next.State != "disabled" || tableCount(t, s, "v3_single_backup_runs") != 1 {
		t.Fatal("disabled schedule ran", next, err)
	}
	var hash string
	var stored []byte
	if err := s.DB.QueryRow(`SELECT sha256,policy FROM v3_single_backup_policies`).Scan(&hash, &stored); err != nil || hash != digest(raw) {
		t.Fatal("runtime policy rewrote immutable archive binding", err)
	}
	var original singleBackupSchedule
	if json.Unmarshal(stored, &original) != nil || original.Spec.Keep != p.Spec.Keep {
		t.Fatal("runtime retention rewrote old keep count")
	}
	manual := plan
	manual.output = filepath.Join(p.Spec.Directory, "manual-backup")
	if _, err := s.backupSingle(ctx, manual); err != nil {
		t.Fatal("disabled automatic schedule blocked manual backup", err)
	}
}

func TestSingleBackupRuntimeFailureAndInterruptedHostRetrySameSlot(t *testing.T) {
	s, p, plan, raw := singleBackupScheduleFixture(t)
	ctx := context.Background()
	setRuntimeBackupFixture(t, s, `{"backup":{"time":"00:00","timezone":"UTC","keep_days":7}}`)
	broken := plan
	broken.metrics.URL = "http://127.0.0.1:1"
	failed, err := s.runSingleBackupSchedule(ctx, p, broken, raw)
	if err == nil || failed.State != "failed" {
		t.Fatal(failed, err)
	}
	var done bool
	if err := s.DB.QueryRow(`SELECT completed_at IS NOT NULL FROM v3_single_backup_slots`).Scan(&done); err != nil || done {
		t.Fatal("failed backup completed daily slot", done, err)
	}
	interruptedID := token()
	interruptedDirectory := filepath.Join(p.Spec.Directory, "backup-"+interruptedID)
	if err := os.Mkdir(interruptedDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	localWrite(t, filepath.Join(interruptedDirectory, "unfinished"), []byte("inspection required"))
	mustHistoryExec(t, s.DB, `INSERT INTO v3_single_backup_runs(id,instance,policy_sha256,status,directory) VALUES($1,$2,$3,'running',$4)`, interruptedID, plan.spec.Instance, digest(raw), interruptedDirectory)
	mustHistoryExec(t, s.DB, `UPDATE v3_single_backup_slots SET run_id=$1`, interruptedID)
	restarted := &Store{DB: s.DB}
	recovered, err := restarted.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || recovered.State != "captured" || recovered.ID == failed.ID {
		t.Fatal("interrupted service failed to retry", recovered, err)
	}
	var state, run string
	if err := s.DB.QueryRow(`SELECT status FROM v3_single_backup_runs WHERE id=$1`, interruptedID).Scan(&state); err != nil || state != "interrupted" {
		t.Fatal(state, err)
	}
	if err := s.DB.QueryRow(`SELECT run_id,completed_at IS NOT NULL FROM v3_single_backup_slots`).Scan(&run, &done); err != nil || run != recovered.ID || !done || tableCount(t, s, "v3_single_backup_slots") != 1 {
		t.Fatal(run, done, err)
	}
	if _, err := os.Stat(filepath.Join(interruptedDirectory, "unfinished")); err != nil {
		t.Fatal("interrupted archive was discarded", err)
	}
	again, err := restarted.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || again.State != "not-due" {
		t.Fatal("successful retry repeated", again, err)
	}
}

func TestSingleBackupRuntimeRetentionUsesAgeAndPreservesNewestSuccessfulArchive(t *testing.T) {
	s, p, plan, raw := singleBackupScheduleFixture(t)
	ctx := context.Background()
	first, err := s.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil {
		t.Fatal(err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_single_backup_runs SET created_at=clock_timestamp()-interval '5 days' WHERE id=$1`, first.ID)
	second, err := s.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || second.State != "captured" {
		t.Fatal(second, err)
	}
	foreign := filepath.Join(p.Spec.Directory, "foreign")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	localWrite(t, filepath.Join(foreign, "keep"), []byte("unrelated"))
	setRuntimeBackupFixture(t, s, `{"backup":{"keep_days":2}}`)
	if err := s.pruneSingleBackups(ctx, p, plan.spec.Instance, digest(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first.Receipt.Directory); !os.IsNotExist(err) {
		t.Fatal("old verified archive not expired by age", err)
	}
	if _, err := verifySingleBackup(ctx, second.Receipt.Directory, second.Receipt.ManifestSHA256); err != nil {
		t.Fatal("fresh retained archive damaged", err)
	}
	mustHistoryExec(t, s.DB, `UPDATE v3_single_backup_runs SET created_at=clock_timestamp()-interval '10 days' WHERE id=$1`, second.ID)
	if err := s.pruneSingleBackups(ctx, p, plan.spec.Instance, digest(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifySingleBackup(ctx, second.Receipt.Directory, second.Receipt.ManifestSHA256); err != nil {
		t.Fatal("last successful archive removed despite no replacement", err)
	}
	if _, err := os.Stat(filepath.Join(foreign, "keep")); err != nil {
		t.Fatal("foreign directory changed", err)
	}
}

func TestSingleBackupRuntimeCompletionFailurePreservesArchiveAndRetriesAtomically(t *testing.T) {
	s, p, plan, raw := singleBackupScheduleFixture(t)
	ctx := context.Background()
	setRuntimeBackupFixture(t, s, `{"backup":{"time":"00:00","timezone":"UTC","keep_days":7}}`)
	mustHistoryExec(t, s.DB, `CREATE FUNCTION reject_runtime_backup_completion() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.completed_at IS NOT NULL THEN RAISE EXCEPTION 'isolated completion failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER reject_runtime_backup_completion BEFORE UPDATE ON v3_single_backup_slots FOR EACH ROW EXECUTE FUNCTION reject_runtime_backup_completion()`)
	if _, err := s.runSingleBackupSchedule(ctx, p, plan, raw); err == nil {
		t.Fatal("slot completion failure was hidden")
	}
	var old, directory, state string
	var completed bool
	if err := s.DB.QueryRow(`SELECT r.id,r.directory,r.status,s.completed_at IS NOT NULL FROM v3_single_backup_runs r JOIN v3_single_backup_slots s ON s.run_id=r.id`).Scan(&old, &directory, &state, &completed); err != nil || state != "running" || completed {
		t.Fatal("run and slot completion were not atomic", state, completed, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "backup.json")); err != nil {
		t.Fatal("published archive lost after task commit failure", err)
	}
	mustHistoryExec(t, s.DB, `DROP TRIGGER reject_runtime_backup_completion ON v3_single_backup_slots;DROP FUNCTION reject_runtime_backup_completion()`)
	restarted := &Store{DB: s.DB}
	r, err := restarted.runSingleBackupSchedule(ctx, p, plan, raw)
	if err != nil || r.State != "captured" || r.ID == old {
		t.Fatal("atomic completion failure could not be retried", r, err)
	}
	if err := s.DB.QueryRow(`SELECT status FROM v3_single_backup_runs WHERE id=$1`, old).Scan(&state); err != nil || state != "interrupted" {
		t.Fatal(state, err)
	}
	if _, err := os.Stat(filepath.Join(directory, "backup.json")); err != nil {
		t.Fatal("uncommitted archive was discarded on retry", err)
	}
}
