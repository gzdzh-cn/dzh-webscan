package persist

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteReservationAndCancelledRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	db, e := OpenDB(path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec("CREATE TABLE values_test(value INTEGER)"); e != nil {
		t.Fatal(e)
	}
	peer, e := OpenDB(path)
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	tx, e := BeginWrite(ctx, db)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "INSERT INTO values_test VALUES(1)"); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { _, err := peer.Exec("INSERT INTO values_test VALUES(2)"); result <- err }()
	select {
	case e = <-result:
		t.Fatalf("writer was not reserved: %v", e)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("rollback retained writer lock")
	}
	var count, value int
	if e = peer.QueryRow("SELECT count(*),max(value) FROM values_test").Scan(&count, &value); e != nil {
		t.Fatal(e)
	}
	if count != 1 || value != 2 {
		t.Fatal(count, value)
	}
}
