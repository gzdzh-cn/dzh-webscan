package controlplane

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"webscan/internal/persist"
)

func TestSQLiteConsistentArchivePreservesValuesAndSource(t *testing.T) {
	s := testStore(t)
	path := filepath.Join(t.TempDir(), "source.sqlite3")
	db, e := persist.OpenDB(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec("CREATE TABLE history(id INTEGER PRIMARY KEY,value TEXT,big INTEGER,raw BLOB); INSERT INTO history VALUES(1,'保留事件',9007199254740993,x'00FF')"); e != nil {
		t.Fatal(e)
	}
	report, e := s.ArchiveSQLite(context.Background(), path, filepath.Join(t.TempDir(), "archive"))
	if e != nil {
		t.Fatal(e)
	}
	if report.Archived != 1 || report.ReadyForCutover {
		t.Fatal(report)
	}
	var payload string
	if e = s.DB.QueryRow("SELECT payload FROM v3_legacy_records").Scan(&payload); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(payload, "9007199254740993") || !strings.Contains(payload, "保留事件") || !strings.Contains(payload, "AP8=") {
		t.Fatal("archive changed values", payload)
	}
	var value string
	if e = db.QueryRow("SELECT value FROM history").Scan(&value); e != nil || value != "保留事件" {
		t.Fatal(value, e)
	}
}

func TestArchiveResumesTheOriginalSnapshotAndPreservesNegativeKeys(t *testing.T) {
	s := testStore(t)
	path := filepath.Join(t.TempDir(), "source.sqlite3")
	db, err := persist.OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE history(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO history VALUES(-9223372036854775808,'minimum'),(-1,'negative'),(0,'zero'); WITH RECURSIVE n(i) AS(SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<1001) INSERT INTO history SELECT i,'old-'||i FROM n`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`CREATE FUNCTION interrupt_archive() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.record_key='501' THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER interrupt_archive BEFORE INSERT ON v3_legacy_records FOR EACH ROW EXECUTE FUNCTION interrupt_archive()`); err != nil {
		t.Fatal(err)
	}
	report, err := s.ArchiveSQLite(context.Background(), path, filepath.Join(t.TempDir(), "archive"))
	if err == nil || report.Snapshot == "" || report.WrittenThisRun != 500 {
		t.Fatal(report, err)
	}
	if _, err = s.DB.Exec("DROP TRIGGER interrupt_archive ON v3_legacy_records"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE history SET value='new-source' WHERE id=1;INSERT INTO history VALUES(1002,'after-snapshot')"); err != nil {
		t.Fatal(err)
	}
	resumed, err := s.ArchiveSnapshot(context.Background(), report.Snapshot)
	if err != nil || resumed.Source != report.Source || resumed.Archived != 1004 || resumed.WrittenThisRun != 504 || resumed.ReadyForCutover {
		t.Fatal(resumed, err)
	}
	var value string
	if err = s.DB.QueryRow("SELECT payload->'value'->>'value' FROM v3_legacy_records WHERE record_key='1'").Scan(&value); err != nil || value != "old-1" {
		t.Fatal(value, err)
	}
	for _, key := range []string{"-9223372036854775808", "-1", "0"} {
		if err = s.DB.QueryRow("SELECT record_key FROM v3_legacy_records WHERE record_key=$1", key).Scan(&value); err != nil {
			t.Fatal(fmt.Errorf("lost key %s: %w", key, err))
		}
	}
	again, err := s.ArchiveSnapshot(context.Background(), report.Snapshot)
	if err != nil || again.WrittenThisRun != 0 || again.Archived != 1004 {
		t.Fatal(again, err)
	}
}
