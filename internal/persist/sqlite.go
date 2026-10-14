package persist

import (
	"database/sql"
	"errors"
	"fmt"
	gfSQLite "github.com/gogf/gf/contrib/drivers/sqlite/v2"
	"github.com/gogf/gf/v2/database/gdb"
	"net/url"
	"os"
	"path/filepath"
)

func OpenDB(path string) (*sql.DB, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	d, e := (&gfSQLite.Driver{}).Open(&gdb.ConfigNode{Name: path, Extra: "busy_timeout=30000&journal_mode=WAL&synchronous=FULL&foreign_keys=ON"})
	if e != nil {
		return nil, e
	}
	d.SetMaxOpenConns(4)
	d.SetMaxIdleConns(4)
	if e = d.Ping(); e != nil {
		d.Close()
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		d.Close()
		return nil, e
	}
	return d, nil
}
func BackupDB(d *sql.DB, path string) error {
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		if e != nil {
			return e
		}
		return fmt.Errorf("backup target already exists")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".sqlite-backup-*")
	if e != nil {
		return e
	}
	temp := f.Name()
	f.Close()
	os.Remove(temp)
	defer os.Remove(temp)
	if _, e = d.Exec("VACUUM INTO ?", temp); e != nil {
		var code interface{ Code() int }
		if errors.As(e, &code) && code.Code()&255 == 13 {
			return errors.New("consistent_backup_disk_full")
		}
		return errors.New("consistent_database_backup_failed")
	}
	if e = os.Chmod(temp, 0600); e != nil {
		return e
	}
	f, e = os.Open(temp)
	if e != nil {
		return e
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		return e
	}
	// Link atomically refuses an existing or concurrently created destination.
	return os.Link(temp, path)
}

// OpenReadOnly is for deployment account discovery; no PRAGMA or permissions
// are changed, and a missing database is never created.
func OpenReadOnly(path string) (*sql.DB, error) {
	d, e := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=busy_timeout(30000)"}).String())
	if e != nil {
		return nil, e
	}
	d.SetMaxOpenConns(1)
	if e = d.Ping(); e != nil {
		d.Close()
		return nil, e
	}
	return d, nil
}
