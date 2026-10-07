//go:build linux

package agent

import (
	"context"
	"database/sql"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func testAgent(t *testing.T) (*Agent, context.Context) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "www")
	os.MkdirAll(root, 0700)
	schema, _ := assets.Files.ReadFile("schema.yaml")
	var cfg common.Map
	yaml.Unmarshal(schema, &cfg)
	n := common.M(cfg["node_defaults"])
	m := common.Clone(common.M(n["monitor"]))
	m["roots"] = []string{root}
	m["critical_paths"] = []string{}
	m["exclude_paths"] = []string{}
	c := common.Map{"node_id": "test", "monitor": m, "scan": n["scan"], "transport": n["transport"], "data_dir": filepath.Join(base, "data"), "log_dir": filepath.Join(base, "logs"), "probe_directory": filepath.Join(base, "probe"), "metrics_file": filepath.Join(base, "textfile", "agent.prom"), "yara_rules": filepath.Join(base, "rules.yar"), "retention_days": 7, "probe_seconds": 30, "public_url": "https://127.0.0.1:19443", "central_ca_file": "", "token": "test"}
	yara, _ := assets.Files.ReadFile("php-webshell.yar")
	os.WriteFile(common.S(c["yara_rules"]), yara, 0600)
	p := filepath.Join(base, "runtime.json")
	common.AtomicJSON(p, c)
	a, e := New(c, p)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); wg.Wait(); a.Close() })
	if e = a.Reconcile(ctx, true, false, nil); e != nil {
		t.Fatal(e)
	}
	for _, fn := range []func(context.Context){a.listen, a.jobs} {
		wg.Add(1)
		go func(fn func(context.Context)) { defer wg.Done(); fn(ctx) }(fn)
	}
	return a, ctx
}
func await(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition timeout")
}
func operations(a *Agent, path string) []string {
	rows, e := a.DB.Query("SELECT payload FROM events ORDER BY created")
	if e != nil {
		return nil
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		rows.Scan(&p)
		v, _ := common.Decode([]byte(p))
		m := common.M(v)
		if common.S(m["path"]) == path {
			out = append(out, common.S(m["operation"]))
		}
	}
	return out
}
func count(a *Agent, table, path string) int {
	var n int
	a.DB.QueryRow("SELECT count(*) FROM "+table+" WHERE path=?", path).Scan(&n)
	return n
}
func root(a *Agent) string { return a.rules.Load().Policy.Roots[0] }
func TestInotifyFileLifecycle(t *testing.T) {
	a, _ := testAgent(t)
	path := filepath.Join(root(a), "中文 '$ 特殊.php")
	os.WriteFile(path, []byte("<?php /* first */"), 0600)
	await(t, func() bool { return common.Contains(operations(a, path), "create") })
	os.WriteFile(path, []byte("<?php /* second */"), 0600)
	await(t, func() bool { return common.Contains(operations(a, path), "modify") })
	tmp := path + ".new"
	os.WriteFile(tmp, []byte("<?php /* atomic */"), 0600)
	os.Rename(tmp, path)
	await(t, func() bool { return len(operations(a, path)) >= 3 })
	dest := filepath.Join(root(a), "renamed.php")
	os.Rename(path, dest)
	await(t, func() bool { return common.Contains(operations(a, dest), "move") })
	os.Remove(dest)
	await(t, func() bool { return common.Contains(operations(a, dest), "delete") })
	if count(a, "manifest", dest) != 0 {
		t.Fatal("deleted file retained")
	}
}
func TestDirectoryMovesAndNewWebsite(t *testing.T) {
	a, ctx := testAgent(t)
	site := filepath.Join(root(a), "new-site")
	os.MkdirAll(filepath.Join(site, "deep"), 0700)
	os.WriteFile(filepath.Join(site, "deep", "one.php"), []byte("<?php /* one */"), 0600)
	if e := a.Reconcile(ctx, false, false, nil); e != nil {
		t.Fatal(e)
	}
	old := filepath.Join(site, "deep", "one.php")
	await(t, func() bool { return count(a, "manifest", old) == 1 })
	dest := filepath.Join(root(a), "renamed-site")
	os.Rename(site, dest)
	file := filepath.Join(dest, "deep", "one.php")
	await(t, func() bool { return common.Contains(operations(a, file), "move") })
	// IN_MOVE_SELF must not permanently remove subtree watches.
	if e := a.Reconcile(ctx, false, false, nil); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(file, []byte("<?php /* after directory move */"), 0600)
	await(t, func() bool { return common.Contains(operations(a, file), "modify") })
	outside := filepath.Join(filepath.Dir(root(a)), "outside")
	os.MkdirAll(outside, 0700)
	os.WriteFile(filepath.Join(outside, "inside.php"), []byte("<?php /* moved in */"), 0600)
	incoming := filepath.Join(root(a), "incoming")
	os.Rename(outside, incoming)
	a.Reconcile(ctx, false, false, nil)
	await(t, func() bool { return count(a, "manifest", filepath.Join(incoming, "inside.php")) == 1 })
}
func rewrite(t *testing.T, a *Agent, change func(common.Map)) {
	t.Helper()
	c := common.Clone(a.C)
	change(c)
	if e := common.AtomicJSON(a.ConfigPath, c); e != nil {
		t.Fatal(e)
	}
}
func TestReloadIgnoreQuietReincludeInvalidAndSameInstance(t *testing.T) {
	a, ctx := testAgent(t)
	site := filepath.Join(root(a), "site", "runtime", "cache")
	os.MkdirAll(site, 0700)
	path := filepath.Join(site, "old.php")
	os.WriteFile(path, []byte("<?php /* initial */"), 0600)
	a.Reconcile(ctx, false, false, nil)
	await(t, func() bool { return count(a, "manifest", path) == 1 })
	instance := a.Instance
	oldVersion := a.rules.Load().Version
	rewrite(t, a, func(c common.Map) {
		common.M(c["monitor"])["exclude_paths"] = []string{root(a) + "/*/**/runtime/**/cache"}
	})
	if e := a.Reload(ctx); e != nil {
		t.Fatal(e)
	}
	version := a.rules.Load().Version
	if version == oldVersion {
		t.Fatal("unchanged version")
	}
	if count(a, "manifest", path) != 0 || count(a, "scans", path) != 0 {
		t.Fatal("excluded queued data retained")
	}
	prior := len(operations(a, path))
	os.WriteFile(path, []byte("<?php /* ignored */"), 0600)
	time.Sleep(500 * time.Millisecond)
	if len(operations(a, path)) != prior {
		t.Fatal("ignored change notified")
	}
	rewrite(t, a, func(c common.Map) { common.M(c["monitor"])["exclude_paths"] = []string{} })
	if e := a.Reload(ctx); e != nil {
		t.Fatal(e)
	}
	if count(a, "manifest", path) != 1 || len(operations(a, path)) != prior {
		t.Fatal("reinclude generated old-file alert")
	}
	os.WriteFile(path, []byte("<?php /* tracked again */"), 0600)
	await(t, func() bool { return len(operations(a, path)) > prior })
	active := a.rules.Load().Version
	rewrite(t, a, func(c common.Map) { common.M(c["monitor"])["exclude_paths"] = []string{root(a)} })
	if e := a.Reload(ctx); e == nil {
		t.Fatal("root ignore accepted")
	}
	if a.rules.Load().Version != active {
		t.Fatal("invalid rule replaced current")
	}
	rewrite(t, a, func(c common.Map) {})
	os.WriteFile(common.S(a.C["yara_rules"]), []byte("broken yara syntax"), 0600)
	if e := a.Reload(ctx); e == nil {
		t.Fatal("invalid yara accepted")
	}
	if a.rules.Load().Version != active || a.Instance != instance {
		t.Fatal("invalid candidate changed running instance")
	}
}
func TestYaraScanAndDurableJobs(t *testing.T) {
	a, ctx := testAgent(t)
	path := filepath.Join(root(a), "fixture.php")
	content := []byte("<?php /* eval( base64_decode( never executed */")
	os.WriteFile(path, content, 0600)
	await(t, func() bool { return count(a, "scans", path) > 0 })
	var task scanTask
	if e := a.DB.QueryRow("SELECT id,path,hash FROM scans WHERE path=? LIMIT 1", path).Scan(&task.ID, &task.Path, &task.Hash); e != nil {
		t.Fatal(e)
	}
	if e := a.Scan(ctx, task); e != nil {
		t.Fatal(e)
	}
	var payload string
	rows, e := a.DB.Query("SELECT payload FROM events WHERE payload LIKE '%matched%'")
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("YARA failed to match")
	}
	rows.Scan(&payload)
	if !strings.Contains(payload, "matched") {
		t.Fatal(payload)
	}
	task.ID = "missing-file"
	task.Path = path + ".missing"
	if e = a.Scan(ctx, task); e != nil {
		t.Fatal(e)
	}
	var value float64
	if e = a.counter("transport_errors_total", 42, true); e != nil {
		t.Fatal(e)
	}
	second, e := persist.OpenDB(filepath.Join(a.Data, "agent.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	if e = second.QueryRow("SELECT value FROM counters WHERE key='transport_errors_total'").Scan(&value); e != nil || value != 42 {
		t.Fatal("counter not durable", e, value)
	}
	if e = a.DB.QueryRow("SELECT id FROM jobs LIMIT 1").Scan(new(int)); e != nil && e != sql.ErrNoRows {
		t.Fatal(e)
	}
}

func TestFilterImportantCriticalProbeAndSnapshots(t *testing.T) {
	a, ctx := testAgent(t)
	for _, name := range []string{"ignored.txt", ".user.ini", "regular.php"} {
		path := filepath.Join(root(a), name)
		os.WriteFile(path, []byte("fixture"), 0600)
		if name == "ignored.txt" {
			time.Sleep(300 * time.Millisecond)
			if count(a, "manifest", path) != 0 {
				t.Fatal("untracked extension captured")
			}
		} else {
			await(t, func() bool { return count(a, "manifest", path) == 1 })
		}
	}
	probe := filepath.Join(a.Probe, "heartbeat.php")
	os.WriteFile(probe, []byte("probe"), 0600)
	await(t, func() bool { return common.Contains(operations(a, probe), "probe") })
	if count(a, "scans", probe) != 0 {
		t.Fatal("probe scanned")
	}
	critical := filepath.Join(root(a), "config.special")
	rewrite(t, a, func(c common.Map) { common.M(c["monitor"])["critical_paths"] = []string{critical} })
	if e := a.Reload(ctx); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(critical, []byte("config"), 0600)
	await(t, func() bool { return count(a, "manifest", critical) == 1 })
	link := filepath.Join(root(a), "linked.php")
	os.Symlink(critical, link)
	if _, _, e := a.snapshot(ctx, link, false); e == nil {
		t.Fatal("symlink followed")
	}
	// A copied legacy SQLite snapshot retains manifest, counters and pending scans.
	copyRoot := t.TempDir()
	copyDB := filepath.Join(copyRoot, "agent.sqlite3")
	if e := persist.BackupDB(a.DB, copyDB); e != nil {
		t.Fatal(e)
	}
	c := common.Clone(a.C)
	c["data_dir"] = copyRoot
	migrated, e := New(c, a.ConfigPath)
	if e != nil {
		t.Fatal(e)
	}
	defer migrated.Close()
	if count(migrated, "manifest", critical) != 1 {
		t.Fatal("manifest lost on reopen")
	}
}

func TestScanFailureProducesDurableEvent(t *testing.T) {
	a, ctx := testAgent(t)
	path := filepath.Join(root(a), "gone.php")
	if e := a.Scan(ctx, scanTask{ID: "scan-failure", Path: path, Hash: "expected"}); e != nil {
		t.Fatal(e)
	}
	var payload string
	if e := a.DB.QueryRow("SELECT payload FROM events WHERE payload LIKE '%scan-failure%'").Scan(&payload); e != nil {
		t.Fatal(e)
	}
	value, e := common.Decode([]byte(payload))
	if e != nil || common.S(common.M(common.M(value)["scan"])["status"]) != "error" {
		t.Fatal("scan failure was not recorded", e)
	}
}

func TestConcurrentPooledSnapshotsAndAggregateReadLimit(t *testing.T) {
	a, ctx := testAgent(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		content := strings.Repeat(string(rune('A'+i)), 64*1024)
		path := filepath.Join(a.Data, "buffer-fixture-"+string(rune('A'+i)))
		if e := os.WriteFile(path, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
		want := common.Hash([]byte(content))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				hash, _, e := a.snapshot(ctx, path, false)
				if e != nil || hash != want {
					t.Errorf("concurrent snapshot corrupted: %v", e)
					return
				}
			}
		}()
	}
	wg.Wait()
	common.M(common.M(a.C["monitor"])["reconciliation"])["max_read_mib_per_second"] = 1
	start := time.Now()
	for i := 0; i < 1024; i++ {
		if !a.limitRead(ctx, 1024) {
			t.Fatal("budget unexpectedly cancelled")
		}
	}
	if time.Since(start) < 850*time.Millisecond {
		t.Fatal("aggregate 1MiB/s budget was exceeded")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if a.limitRead(cancelled, 1024) {
		t.Fatal("cancelled budget continued")
	}
}

func TestPendingQueryUsesIndexAndRetainsHistory(t *testing.T) {
	a, _ := testAgent(t)
	tx, e := a.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2000; i++ {
		if _, e = tx.Exec("INSERT INTO events VALUES(?,?,?,NULL,?)", common.ID(), "{}", float64(i), 123); e != nil {
			tx.Rollback()
			t.Fatal(e)
		}
	}
	if _, e = tx.Exec("INSERT INTO events VALUES('pending-fixture','{}',3000,NULL,NULL)"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	query := "SELECT id,payload FROM events WHERE exported IS NULL AND accepted IS NULL ORDER BY created LIMIT 100"
	rows, e := a.DB.Query("EXPLAIN QUERY PLAN " + query)
	if e != nil {
		t.Fatal(e)
	}
	indexed := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if e = rows.Scan(&id, &parent, &unused, &detail); e != nil {
			t.Fatal(e)
		}
		indexed = indexed || strings.Contains(detail, "agent_events_un")
	}
	rows.Close()
	if !indexed {
		t.Fatal("pending poll scans history")
	}
	var id, payload string
	if e = a.DB.QueryRow(query).Scan(&id, &payload); e != nil || id != "pending-fixture" {
		t.Fatal("pending row lost")
	}
	var count int
	a.DB.QueryRow("SELECT count(*) FROM events").Scan(&count)
	if count != 2001 {
		t.Fatal("accepted history was altered")
	}
}
