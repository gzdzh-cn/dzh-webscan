package persist

import (
	"database/sql"
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
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	_, e := d.Exec("VACUUM INTO ?", path)
	if e != nil {
		return e
	}
	return os.Chmod(path, 0600)
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
