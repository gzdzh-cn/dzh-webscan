package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func migrationTargetJournalFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s := migrationSessionTestStore(t)
	var exists bool
	if e := s.DB.QueryRow(`SELECT to_regclass('v3_migration_target_journals') IS NOT NULL`).Scan(&exists); e != nil {
		t.Fatal(e)
	}
	if !exists {
		if _, e := s.DB.Exec(migrationTargetJournalSchema); e != nil {
			t.Fatal(e)
		}
	}
	id := digest([]byte(t.Name()))
	if _, e := s.BeginMigrationSession(context.Background(), id, 0, []string{"central"}); e != nil {
		t.Fatal(e)
	}
	// The journal's unit boundary begins after the separately tested freeze.
	if _, e := s.DB.Exec(`UPDATE v3_migration_sessions SET phase='frozen',freeze_digest=repeat('a',64) WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	return s, id
}
func TestMigrationTargetJournalCapturesAllRowOperationsAndProtectsSealedWrites(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	if _, e := s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('synthetic','PRIVATE_SYNTHETIC_HASH','admin')`); e != nil {
		t.Fatal(e)
	}
	armed, e := s.ArmMigrationTargetJournal(ctx, id, 1)
	if e != nil || armed.State != "armed" || armed.Tables < 90 || armed.BaselineRows < 1 || !releaseDigest(armed.BaselineSHA256) {
		t.Fatal(armed, e)
	}
	if _, e = s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('new','PRIVATE_NEW_HASH','viewer'); UPDATE v3_accounts SET username='new-name',role='operator' WHERE username='new'; DELETE FROM v3_accounts WHERE username='new-name'`); e != nil {
		t.Fatal(e)
	}
	var add, update, deleted int
	if e = s.DB.QueryRow(`SELECT count(*) FILTER(WHERE operation='ADD'),count(*) FILTER(WHERE operation='UPDATE'),count(*) FILTER(WHERE operation='DELETE') FROM v3_migration_target_changes WHERE session=$1 AND table_name='v3_accounts'`, id).Scan(&add, &update, &deleted); e != nil || add != 1 || update != 1 || deleted != 1 {
		t.Fatal(add, update, deleted, e)
	}
	var before, after string
	if e = s.DB.QueryRow(`SELECT before_key->>'username',after_key->>'username' FROM v3_migration_target_changes WHERE session=$1 AND operation='UPDATE'`, id).Scan(&before, &after); e != nil || before != "new" || after != "new-name" {
		t.Fatal("primary key change lost", before, after, e)
	}
	if _, e = s.DB.Exec(`TRUNCATE v3_accounts CASCADE`); e == nil {
		t.Fatal("truncate discarded unjournaled rows")
	}
	if _, e = s.SealMigrationTargetJournal(ctx, id, 1); !errors.Is(e, ErrConflict) {
		t.Fatal("stale seal accepted", e)
	}
	sealed, e := s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion)
	if e != nil || sealed.State != "sealed" || sealed.Changes != 3 || !releaseDigest(sealed.SealSHA256) {
		t.Fatal(sealed, e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_accounts SET role='viewer' WHERE username='synthetic'`); e == nil {
		t.Fatal("sealed target accepted new write")
	}
	var hash string
	if e = s.DB.QueryRow(`SELECT password_hash FROM v3_accounts WHERE username='synthetic'`).Scan(&hash); e != nil || hash != "PRIVATE_SYNTHETIC_HASH" {
		t.Fatal("failed write changed target", e)
	}
	again, e := s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion)
	if e != nil || again.SealSHA256 != sealed.SealSHA256 {
		t.Fatal(again, e)
	}
}

func TestMigrationTargetJournalExcludesOnlyDerivedConfigurationGate(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	if _, err := s.DB.Exec(`CREATE TABLE v3_new_business_payload(id text PRIMARY KEY,value text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ArmMigrationTargetJournal(context.Background(), id, 1); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"v3_accounts", "v3_settings", "v3_nodes", "v3_new_business_payload"} {
		var present bool
		if err := s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM v3_migration_target_tables WHERE session=$1 AND table_name=$2)`, id, name).Scan(&present); err != nil || !present {
			t.Fatal("business table omitted", name, err)
		}
	}
	var present bool
	if err := s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM v3_migration_target_tables WHERE session=$1 AND table_name='v3_configuration_operation_gate')`, id).Scan(&present); err != nil || present {
		t.Fatal("derived mutex captured", err)
	}
	if _, err := s.DB.Exec(`INSERT INTO v3_new_business_payload VALUES('new','captured')`); err != nil {
		t.Fatal(err)
	}
	var changes int
	if err := s.DB.QueryRow(`SELECT count(*) FROM v3_migration_target_changes WHERE session=$1 AND table_name='v3_new_business_payload'`, id).Scan(&changes); err != nil || changes != 1 {
		t.Fatal("unknown business table not captured", err)
	}
}
func TestMigrationTargetJournalSealWaitsForUncommittedChangeAndDetectsTamper(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	armed, e := s.ArmMigrationTargetJournal(ctx, id, 1)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('in-flight','synthetic','viewer')`); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { _, e := s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion); result <- e }()
	select {
	case e := <-result:
		t.Fatal("seal did not wait for in-flight commit", e)
	case <-time.After(100 * time.Millisecond):
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("seal blocked after commit")
	}
	status, e := s.MigrationTargetJournal(ctx, id)
	if e != nil || status.Changes != 1 {
		t.Fatal(status, e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_target_changes SET change_digest=repeat('b',64) WHERE session=$1`, id); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SealMigrationTargetJournal(ctx, id, status.SessionVersion); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("tampered sealed journal accepted", e)
	}
}
func TestMigrationTargetJournalRejectsRestoreHoldAndSchemaDrift(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	armed, e := s.ArmMigrationTargetJournal(ctx, id, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`ALTER TABLE v3_accounts ADD COLUMN synthetic_new integer`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('schema-drift','x','viewer')`); e == nil {
		t.Fatal("unbound schema wrote without capture")
	}
	if _, e = s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("schema drift sealed", e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_sessions SET recovery_hold=true WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ArmMigrationTargetJournal(ctx, id, armed.SessionVersion); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("restore hold rearm", e)
	}
	if _, e = s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("restore hold seal", e)
	}
	if _, e = s.DB.Exec(`INSERT INTO v3_accounts(username,password_hash,role) VALUES('held','x','viewer')`); e == nil {
		t.Fatal("restore hold write captured")
	}
	if strings.Contains(ErrMigrationSession.Error(), "PRIVATE") {
		t.Fatal("unsafe failure")
	}
}

func TestMigrationTargetJournalPartitionChangesAndMissingCaptureCannotSeal(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	armed, e := s.ArmMigrationTargetJournal(ctx, id, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`CREATE TABLE v3_events_journal_test PARTITION OF v3_events FOR VALUES FROM ('2000-01-01') TO ('2001-01-01');INSERT INTO v3_events(node,id,received_at,operation,payload) VALUES('synthetic','partition-event','2000-06-01','modify','{}'),('synthetic','default-event',clock_timestamp(),'modify','{}');UPDATE v3_events SET received_at='2001-06-01' WHERE id='partition-event'`); e != nil {
		t.Fatal(e)
	}
	var events int
	if e = s.DB.QueryRow(`SELECT count(*) FROM v3_migration_target_changes WHERE session=$1 AND table_name='v3_events'`, id).Scan(&events); e != nil || events != 4 {
		t.Fatal("partition row changes missing", events, e)
	}
	sealed, e := s.SealMigrationTargetJournal(ctx, id, armed.SessionVersion)
	if e != nil || sealed.Changes != 4 {
		t.Fatal(sealed, e)
	}
	// A bypassed row trigger cannot produce a falsely complete finite input.
	if _, e = s.DB.Exec(`ALTER TABLE v3_accounts DISABLE TRIGGER v3_migration_target_capture;INSERT INTO v3_accounts(username,password_hash,role) VALUES('bypassed','synthetic','viewer');ALTER TABLE v3_accounts ENABLE ALWAYS TRIGGER v3_migration_target_capture`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.SealMigrationTargetJournal(ctx, id, sealed.SessionVersion); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("missed target write accepted", e)
	}
}

func TestMigrationTargetJournalActivationVerificationAndRearmRecheckCapture(t *testing.T) {
	s, id := migrationTargetJournalFixture(t)
	ctx := context.Background()
	armed, e := s.ArmMigrationTargetJournal(ctx, id, 1)
	if e != nil {
		t.Fatal(e)
	}
	verify := func() error {
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); e != nil {
			return e
		}
		if e = migrationSessionLock(ctx, tx, id); e != nil {
			return e
		}
		return verifyMigrationTargetArmedTx(ctx, tx, id)
	}
	if e = verify(); e != nil {
		t.Fatal("intact armed journal rejected", e)
	}
	if again, e := s.ArmMigrationTargetJournal(ctx, id, 1); e != nil || again.BaselineSHA256 != armed.BaselineSHA256 {
		t.Fatal("lost response rearm", e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_domains SET pending=false WHERE domain=$1`, "session:"+id); e != nil {
		t.Fatal(e)
	}
	if e = verify(); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("activation accepted missing session fence", e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_domains SET pending=true WHERE domain=$1`, "session:"+id); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec(`ALTER TABLE v3_accounts DISABLE TRIGGER v3_migration_target_capture`); e != nil {
		t.Fatal(e)
	}
	if e = verify(); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("activation accepted disabled capture", e)
	}
	if _, e = s.ArmMigrationTargetJournal(ctx, id, armed.SessionVersion); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("rearm accepted disabled capture", e)
	}
	if _, e = s.DB.Exec(`ALTER TABLE v3_accounts ENABLE ALWAYS TRIGGER v3_migration_target_capture;INSERT INTO v3_accounts(username,password_hash,role) VALUES('activation-test','synthetic','viewer')`); e != nil {
		t.Fatal(e)
	}
	if e = verify(); e != nil {
		t.Fatal("captured target change rejected", e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_migration_target_changes SET change_digest=repeat('b',64) WHERE session=$1`, id); e != nil {
		t.Fatal(e)
	}
	if e = verify(); !errors.Is(e, ErrMigrationSession) {
		t.Fatal("activation accepted altered change digest", e)
	}
}
