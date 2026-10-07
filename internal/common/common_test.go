package common

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"webscan/internal/persist"
)

func TestCanonicalPythonUnicodeAndNumbers(t *testing.T) {
	v := Map{"路径": "/中文/<at>\u2028.php", "float": 1.0, "small": 0.00001, "zero": -0.0, "n": json.Number("1234567890123456789"), "list": []any{nil, true, "\n"}}
	b, e := Canonical(v, false)
	if e != nil {
		t.Fatal(e)
	}
	want := "{\"float\":1.0,\"list\":[null,true,\"\\n\"],\"n\":1234567890123456789,\"small\":1e-05,\"zero\":0.0,\"路径\":\"/中文/<at>\u2028.php\"}"
	if string(b) != want {
		t.Fatalf("canonical mismatch: %s", b)
	}
}
func TestDatabaseDurableBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite3")
	d, e := persist.OpenDB(path)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if _, e = d.Exec("CREATE TABLE fixture(value TEXT); INSERT INTO fixture VALUES('original')"); e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(t.TempDir(), "copy.sqlite3")
	if e = persist.BackupDB(d, backup); e != nil {
		t.Fatal(e)
	}
	copy, e := persist.OpenDB(backup)
	if e != nil {
		t.Fatal(e)
	}
	defer copy.Close()
	var s string
	if e = copy.QueryRow("SELECT value FROM fixture").Scan(&s); e != nil || s != "original" {
		t.Fatal(e, s)
	}
	var mode string
	if e = d.QueryRow("PRAGMA journal_mode").Scan(&mode); e != nil || mode != "wal" {
		t.Fatal(e, mode)
	}
}
func TestAtomicReplaceAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime.json")
	if e := Atomic(path, []byte("old"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := Atomic(path, []byte("new"), 0600); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	if !bytes.Equal(b, []byte("new")) {
		t.Fatal(string(b))
	}
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if e := Atomic(link, []byte("bad"), 0600); e == nil {
		t.Fatal("symlink overwritten")
	}
}
func TestPolicyGlobAndProtectedFiles(t *testing.T) {
	m := Map{"roots": []string{"/www/wwwroot"}, "exclude_paths": []string{"/www/wwwroot/*/**/runtime/**/cache"}, "extensions": []string{".php"}, "important_filenames": []string{".user.ini"}, "critical_paths": []string{}}
	p, e := NewPolicy(m)
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/www/wwwroot/site/runtime/cache/a.php", "/www/wwwroot/site/data/runtime/foo/cache/nested/a.php", "/www/wwwroot/newsite/runtime/cache"} {
		if !p.Excluded(path) {
			t.Fatal("not excluded", path)
		}
	}
	for _, path := range []string{"/www/wwwroot/site/runtime/main.php", "/www/wwwroot/site/framework/cache.php", "/www/wwwroot/site/runtime/tmp/a.php"} {
		if !p.Tracked(path, "/probe") {
			t.Fatal("not tracked", path)
		}
	}
	if !p.Tracked("/probe/heartbeat.php", "/probe") {
		t.Fatal("probe disabled")
	}
	m["exclude_paths"] = []string{"/www/wwwroot"}
	if _, e = NewPolicy(m); e == nil {
		t.Fatal("root excluded")
	}
	m["exclude_paths"] = []string{"/www/wwwroot/*/runtime/cache"}
	m["critical_paths"] = []string{"/www/wwwroot/site/runtime/cache/critical.php"}
	if _, e = NewPolicy(m); e == nil {
		t.Fatal("critical excluded")
	}
}

func TestPythonFnmatchClasses(t *testing.T) {
	for _, tt := range []struct {
		pattern, path string
		want          bool
	}{
		{"/www/[!a]*/cache", "/www/bb/cache/sub", true},
		{"/www/[!a]*/cache", "/www/ab/cache", false},
		{"/www/a[b/cache", "/www/a[b/cache/x", true},
		{"/www/[a-c]/cache", "/www/b/cache", true},
	} {
		e, err := NewExclusion(tt.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := e.Matches(tt.path); got != tt.want {
			t.Fatalf("%s %s = %v", tt.pattern, tt.path, got)
		}
	}
}

func TestPythonCanonicalGolden(t *testing.T) {
	b, e := os.ReadFile("testdata/python-canonical.json")
	if e != nil {
		t.Fatal(e)
	}
	value, e := Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	for _, item := range A(value) {
		fixture := M(item)
		for _, spaced := range []bool{false, true} {
			key := "compact"
			if spaced {
				key = "spaced"
			}
			got, e := Canonical(fixture["input"], spaced)
			if e != nil {
				t.Fatal(e)
			}
			if string(got) != S(fixture[key]) {
				t.Fatalf("Python canonical mismatch\n%s\n%s", got, S(fixture[key]))
			}
		}
	}
}
