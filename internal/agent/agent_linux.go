//go:build linux

package agent

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
	"webscan/internal/persist"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

const Schema = `
CREATE TABLE IF NOT EXISTS manifest(path TEXT PRIMARY KEY,hash TEXT,stat TEXT);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,payload TEXT,created REAL,exported TEXT,accepted REAL);
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY,path TEXT,old_path TEXT,operation TEXT);
CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,path TEXT,hash TEXT,lease REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS counters(key TEXT PRIMARY KEY,value REAL);
CREATE TABLE IF NOT EXISTS logfiles(path TEXT PRIMARY KEY,created REAL);`

const IndexSchema = `CREATE INDEX IF NOT EXISTS agent_events_unexported ON events(created) WHERE accepted IS NULL AND exported IS NULL;
CREATE INDEX IF NOT EXISTS agent_events_unaccepted ON events(created) WHERE accepted IS NULL;
CREATE INDEX IF NOT EXISTS agent_events_retention ON events(created) WHERE accepted IS NOT NULL;
CREATE INDEX IF NOT EXISTS agent_scans_lease ON scans(lease);`

type Rules struct {
	Policy  *common.Policy
	Yara    []byte
	Version string
}

var hashBuffers = sync.Pool{New: func() any { return make([]byte, 256*1024) }}

type manifestRow struct{ Hash, Stat string }
type move struct {
	Path      string
	At        time.Time
	Directory bool
}
type Agent struct {
	C                                       common.Map
	ConfigPath, Data, Logs, Probe, Instance string
	DB                                      *sql.DB
	HTTP                                    *http.Client
	rules                                   atomic.Pointer[Rules]
	writeMu, watchMu, inventoryMu           sync.Mutex
	readMu                                  sync.Mutex
	metricsMu                               sync.Mutex
	statusMu                                sync.Mutex
	readDue                                 time.Time
	fd                                      int
	watches                                 map[int]string
	byPath                                  map[string]int
	coverage                                atomic.Int32
	watchFailure                            atomic.Pointer[watchFailure]
	ready                                   atomic.Bool
	baseline                                atomic.Bool
	reconcileNeeded                         atomic.Bool
	fullNeeded                              atomic.Bool
	inventoryRunning                        atomic.Bool
	inventoryChecked                        atomic.Int64
	signature                               string
	worker                                  sync.WaitGroup
}

func New(c common.Map, path string) (*Agent, error) {
	policy, e := common.NewPolicy(common.M(c["monitor"]))
	if e != nil {
		return nil, e
	}
	data, logs := common.S(c["data_dir"]), common.S(c["log_dir"])
	for _, dir := range []string{data, logs, common.S(c["probe_directory"]), filepath.Dir(common.S(c["metrics_file"]))} {
		if e = os.MkdirAll(dir, 0700); e != nil {
			return nil, e
		}
	}
	yara, e := os.ReadFile(common.S(c["yara_rules"]))
	if e != nil {
		return nil, e
	}
	d, e := persist.OpenDB(filepath.Join(data, "agent.sqlite3"))
	if e != nil {
		return nil, e
	}
	if _, e = d.Exec(Schema); e != nil {
		d.Close()
		return nil, e
	}
	columns, e := d.Query("PRAGMA table_info(scans)")
	if e != nil {
		d.Close()
		return nil, e
	}
	hasLease := false
	for columns.Next() {
		var cid, notNull, primary int
		var name, typ string
		var value any
		if e = columns.Scan(&cid, &name, &typ, &notNull, &value, &primary); e != nil {
			columns.Close()
			d.Close()
			return nil, e
		}
		hasLease = hasLease || name == "lease"
	}
	e = columns.Err()
	columns.Close()
	if e != nil {
		d.Close()
		return nil, e
	}
	if !hasLease {
		if _, e = d.Exec("ALTER TABLE scans ADD COLUMN lease REAL DEFAULT 0"); e != nil {
			d.Close()
			return nil, e
		}
	}
	if _, e = d.Exec(IndexSchema); e != nil {
		d.Close()
		return nil, e
	}
	if _, e = d.Exec("UPDATE scans SET lease=0"); e != nil {
		d.Close()
		return nil, e
	}
	for _, key := range []string{"inotify_overflow_total", "dropped_events_total", "read_errors_total", "watch_errors_total", "transport_errors_total", "local_probe_seconds", "coverage_ok", "last_inotify_overflow_seconds", "last_drop_seconds"} {
		if _, e = d.Exec("INSERT OR IGNORE INTO counters VALUES(?,0)", key); e != nil {
			d.Close()
			return nil, e
		}
	}
	client, e := common.HTTPClient(common.S(c["central_ca_file"]), time.Duration(common.I(common.M(c["transport"])["request_timeout_seconds"]))*time.Second)
	if e != nil {
		d.Close()
		return nil, e
	}
	fd, e := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if e != nil {
		d.Close()
		return nil, e
	}
	a := &Agent{C: common.Clone(c), ConfigPath: path, Data: data, Logs: logs, Probe: common.S(c["probe_directory"]), Instance: common.ID(), DB: d, HTTP: client, fd: fd, watches: map[int]string{}, byPath: map[string]int{}}
	a.rules.Store(&Rules{policy, yara, policy.Version(yara)})
	if raw, e := os.ReadFile(path); e == nil {
		a.signature = common.Hash(append(raw, yara...))
	}
	return a, nil
}
func (a *Agent) Close() { unix.Close(a.fd); a.DB.Close() }
func (a *Agent) counter(key string, value float64, set bool) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	op := "value+excluded.value"
	if set {
		op = "excluded.value"
	}
	_, e := a.DB.Exec("INSERT INTO counters VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value="+op, key, value)
	return e
}
func (a *Agent) site(p string) string {
	for _, root := range a.rules.Load().Policy.Roots {
		if p != root && common.Inside(p, root) {
			return strings.Split(strings.TrimPrefix(p, strings.TrimRight(root, "/")+"/"), "/")[0]
		}
	}
	if common.Inside(p, a.Probe) {
		return "_monitor"
	}
	return "_critical"
}
func (a *Agent) event(tx *sql.Tx, operation, path, sha string, extra common.Map) error {
	r := a.rules.Load()
	event := common.Map{"rules_version": r.Version, "event_id": common.ID(), "node_id": a.C["node_id"], "site": a.site(path), "path": path, "operation": operation, "time": common.Stamp(), "sha256": nil, "risk": "unclassified", "scan": common.Map{"status": "pending"}, "detection": "inotify", "important_config": common.Contains(r.Policy.Important, filepath.Base(path)) || common.Contains(r.Policy.Critical, path)}
	if sha != "" {
		event["sha256"] = sha
	}
	for k, v := range extra {
		event[k] = v
	}
	if _, e := tx.Exec("INSERT INTO events(id,payload,created) VALUES(?,?,?)", event["event_id"], string(common.JSON(event)), common.Now()); e != nil {
		return e
	}
	if common.Contains([]string{"create", "modify", "move"}, operation) && sha != "" && !common.Inside(path, a.Probe) {
		_, e := tx.Exec("INSERT OR IGNORE INTO scans(id,path,hash) VALUES(?,?,?)", event["event_id"], path, sha)
		return e
	}
	return nil
}
func (a *Agent) health(reason string, extra common.Map) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	tx, e := a.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	extra = common.Clone(extra)
	extra["reason"], extra["risk"], extra["scan"] = reason, "warning", common.Map{"status": "not_applicable"}
	if e = a.event(tx, "health", "", "", extra); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *Agent) validPath(p string) bool {
	if utf8.ValidString(p) {
		return true
	}
	a.counter("read_errors_total", 1, false)
	a.health("unrepresentable_filename", common.Map{"file_path": strings.ToValidUTF8(p, "�")})
	return false
}
func metadata(st *unix.Stat_t) string {
	return fmt.Sprintf("[%d, %d, %d, %d]", st.Ino, st.Size, st.Mtim.Nano(), st.Ctim.Nano())
}

// Charge all reconciliation reads to one budget. Coalesce small waits so a
// timer is not created for every tiny file; at most 5ms of credit is carried.
func (a *Agent) limitRead(ctx context.Context, bytes int) bool {
	rate := max(common.F(common.M(common.M(a.C["monitor"])["reconciliation"])["max_read_mib_per_second"]), 1) * 1048576
	now := time.Now()
	a.readMu.Lock()
	if a.readDue.Before(now.Add(-5 * time.Millisecond)) {
		a.readDue = now.Add(-5 * time.Millisecond)
	}
	a.readDue = a.readDue.Add(time.Duration(float64(bytes) / rate * float64(time.Second)))
	delay := a.readDue.Sub(now)
	a.readMu.Unlock()
	if delay < 5*time.Millisecond {
		return ctx.Err() == nil
	}
	return common.Sleep(ctx, delay)
}
func (a *Agent) snapshot(ctx context.Context, path string, limited bool) (string, string, error) {
	real, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", "", e
	}
	if real != path {
		return "", "", errors.New("symlink_path_not_followed")
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", "", e
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after unix.Stat_t
	if e = unix.Fstat(fd, &before); e != nil {
		return "", "", e
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", "", errors.New("not_regular_file")
	}
	h := sha256.New()
	buffer := hashBuffers.Get().([]byte)
	defer hashBuffers.Put(buffer)
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			h.Write(buffer[:n])
			if limited && !a.limitRead(ctx, n) {
				return "", "", ctx.Err()
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", err
		}
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
	}
	if e = unix.Fstat(fd, &after); e != nil {
		return "", "", e
	}
	if metadata(&before) != metadata(&after) {
		return "", "", errors.New("content_changed_during_read")
	}
	return hex.EncodeToString(h.Sum(nil)), metadata(&after), nil
}
func (a *Agent) Process(ctx context.Context, path, operation, oldPath string, baseline, limited bool) error {
	if !a.validPath(path) || oldPath != "" && !a.validPath(oldPath) {
		return nil
	}
	r := a.rules.Load()
	if !r.Policy.Tracked(path, a.Probe) && !(oldPath != "" && r.Policy.Tracked(oldPath, a.Probe)) {
		return nil
	}
	if oldPath != "" && r.Policy.Tracked(oldPath, a.Probe) && !r.Policy.Tracked(path, a.Probe) {
		path, operation, oldPath = oldPath, "delete", ""
	}
	sha, stamp := "", ""
	if operation != "delete" {
		var e error
		sha, stamp, e = a.snapshot(ctx, path, limited)
		if e != nil {
			if !errors.Is(e, os.ErrNotExist) {
				a.writeMu.Lock()
				defer a.writeMu.Unlock()
				_, err := a.DB.Exec("INSERT INTO counters VALUES('read_errors_total',1) ON CONFLICT(key) DO UPDATE SET value=value+1")
				if err != nil {
					return err
				}
				tx, err := a.DB.Begin()
				if err != nil {
					return err
				}
				defer tx.Rollback()
				if err = a.event(tx, "health", "", "", common.Map{"scan": common.Map{"status": "not_applicable"}, "risk": "warning", "reason": "file_read_gap", "file_path": path, "error": common.SecretFree(e)}); err != nil {
					return err
				}
				return tx.Commit()
			}
		}
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	r = a.rules.Load()
	if !r.Policy.Tracked(path, a.Probe) && !(oldPath != "" && r.Policy.Tracked(oldPath, a.Probe)) {
		return nil
	}
	if sha != "" {
		var now unix.Stat_t
		if err := unix.Lstat(path, &now); err != nil || metadata(&now) != stamp {
			return errors.New("content_changed_before_commit")
		}
	}
	tx, e := a.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	lookup := path
	if oldPath != "" {
		lookup = oldPath
	}
	var oldHash, oldStat string
	e = tx.QueryRow("SELECT hash,stat FROM manifest WHERE path=?", lookup).Scan(&oldHash, &oldStat)
	found := e == nil
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if found && oldHash == sha && oldStat == stamp && oldPath == "" {
		return nil
	}
	if oldPath != "" && oldPath != path {
		if _, e = tx.Exec("DELETE FROM manifest WHERE path=?", oldPath); e != nil {
			return e
		}
	}
	if sha != "" {
		_, e = tx.Exec("INSERT INTO manifest VALUES(?,?,?) ON CONFLICT(path) DO UPDATE SET hash=excluded.hash,stat=excluded.stat", path, sha, stamp)
	} else {
		_, e = tx.Exec("DELETE FROM manifest WHERE path=?", path)
	}
	if e != nil {
		return e
	}
	if baseline || !found && sha == "" || found && oldHash == sha && oldPath == "" {
		return tx.Commit()
	}
	kind := "modify"
	if oldPath != "" {
		kind = "move"
		if sha == "" {
			kind = "delete"
		}
	} else if !found {
		kind = "create"
	} else if sha == "" {
		kind = "delete"
	}
	if common.Inside(path, a.Probe) {
		if sha != "" {
			if _, e = tx.Exec("INSERT INTO counters VALUES('local_probe_seconds',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", common.Now()); e != nil {
				return e
			}
			if e = a.event(tx, "probe", path, sha, common.Map{"scan": common.Map{"status": "not_applicable"}}); e != nil {
				return e
			}
		}
		return tx.Commit()
	}
	detection := "inotify"
	if limited {
		detection = "reconciliation"
	}
	scan := "pending"
	if sha == "" {
		scan = "not_applicable"
		sha = oldHash
	}
	extras := common.Map{"old_path": nil, "previous_hash": nil, "detection": detection, "scan": common.Map{"status": scan}}
	if oldPath != "" {
		extras["old_path"] = oldPath
	}
	if found {
		extras["previous_hash"] = oldHash
	}
	eventPath := path
	if kind == "delete" && oldPath != "" {
		eventPath = oldPath
	}
	if e = a.event(tx, kind, eventPath, sha, extras); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *Agent) roots(p *common.Policy) []string {
	roots := append([]string{}, p.Roots...)
	roots = append(roots, a.Probe)
	for _, path := range p.Critical {
		dir := filepath.Dir(path)
		if !common.Contains(roots, dir) {
			roots = append(roots, dir)
		}
	}
	return roots
}
func (a *Agent) addWatch(path string) error {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	if _, ok := a.byPath[path]; ok {
		return nil
	}
	wd, e := unix.InotifyAddWatch(a.fd, path, unix.IN_CLOSE_WRITE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_DELETE|unix.IN_CREATE|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_ONLYDIR|unix.IN_DONT_FOLLOW)
	if e != nil {
		return e
	}
	if prior, ok := a.watches[wd]; ok {
		delete(a.byPath, prior)
	}
	a.watches[wd] = path
	a.byPath[path] = wd
	return nil
}
func (a *Agent) addTree(ctx context.Context, root string, p *common.Policy) bool {
	ok := true
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if e == nil {
			e = errors.New("not_a_real_directory")
		}
		a.recordWatchFailure(root, e)
		return false
	}
	e = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && path != root {
				return nil
			}
			ok = false
			a.recordWatchFailure(path, err)
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if !p.Watches(path, a.Probe) {
			return filepath.SkipDir
		}
		if e := a.addWatch(path); e != nil {
			if errors.Is(e, os.ErrNotExist) && path != root {
				return nil
			}
			ok = false
			a.recordWatchFailure(path, e)
		}
		return nil
	})
	return ok && e == nil
}
func (a *Agent) forget(wd int, remove bool) {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	if path, ok := a.watches[wd]; ok {
		delete(a.byPath, path)
		delete(a.watches, wd)
		if remove {
			unix.InotifyRmWatch(a.fd, uint32(wd))
		}
	}
}
func (a *Agent) pruneWatches(p *common.Policy) {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	for wd, path := range a.watches {
		if !p.Watches(path, a.Probe) {
			unix.InotifyRmWatch(a.fd, uint32(wd))
			delete(a.watches, wd)
			delete(a.byPath, path)
		}
	}
}
func (a *Agent) Journal(path, operation, oldPath string) error {
	p := a.rules.Load().Policy
	if !p.Tracked(path, a.Probe) && !(oldPath != "" && p.Tracked(oldPath, a.Probe)) {
		return nil
	}
	if !a.validPath(path) || oldPath != "" && !a.validPath(oldPath) {
		return nil
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_, e := a.DB.Exec("INSERT INTO jobs(path,old_path,operation) VALUES(?,?,?)", path, oldPath, operation)
	return e
}
func (a *Agent) listen(ctx context.Context) {
	cookies := map[uint32]move{}
	buffer := make([]byte, 256*1024)
	for ctx.Err() == nil {
		n, e := unix.Read(a.fd, buffer)
		if e == unix.EAGAIN {
			for cookie, m := range cookies {
				if time.Since(m.At) > time.Second {
					if m.Directory {
						a.directoryMove(m.Path, "", a.rules.Load().Policy)
					} else if e = a.Journal(m.Path, "delete", ""); e != nil {
						a.health("journal_failed", common.Map{})
					}
					delete(cookies, cookie)
				}
			}
			common.Sleep(ctx, 50*time.Millisecond)
			continue
		}
		if e != nil {
			if ctx.Err() == nil {
				a.health("listener_failed", common.Map{})
				common.Sleep(ctx, time.Second)
			}
			continue
		}
		for offset := 0; offset+16 <= n; {
			wd := int(int32(binary.NativeEndian.Uint32(buffer[offset:])))
			mask := binary.NativeEndian.Uint32(buffer[offset+4:])
			cookie := binary.NativeEndian.Uint32(buffer[offset+8:])
			size := int(binary.NativeEndian.Uint32(buffer[offset+12:]))
			if offset+16+size > n {
				break
			}
			name := strings.TrimRight(string(buffer[offset+16:offset+16+size]), "\x00")
			offset += 16 + size
			if mask&unix.IN_Q_OVERFLOW != 0 {
				a.counter("inotify_overflow_total", 1, false)
				a.counter("last_inotify_overflow_seconds", common.Now(), true)
				a.health("inotify_overflow", common.Map{})
				a.reconcileNeeded.Store(true)
				a.fullNeeded.Store(true)
				continue
			}
			if mask&unix.IN_IGNORED != 0 {
				a.forget(wd, false)
				continue
			}
			a.watchMu.Lock()
			directory, ok := a.watches[wd]
			a.watchMu.Unlock()
			if !ok {
				continue
			}
			path := directory
			if name != "" {
				path = filepath.Join(directory, name)
			}
			isdir := mask&unix.IN_ISDIR != 0 || name == ""
			if isdir {
				if mask&unix.IN_MOVED_FROM != 0 && name != "" {
					cookies[cookie] = move{path, time.Now(), true}
				}
				if mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
					a.addTree(ctx, path, a.rules.Load().Policy)
				}
				if mask&unix.IN_MOVED_TO != 0 && name != "" {
					if previous, ok := cookies[cookie]; ok {
						a.directoryMove(previous.Path, path, a.rules.Load().Policy)
						delete(cookies, cookie)
					}
				}
				if mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
					a.watchMu.Lock()
					expired := []int{}
					for id, p := range a.watches {
						if common.Inside(p, path) {
							expired = append(expired, id)
						}
					}
					a.watchMu.Unlock()
					for _, id := range expired {
						a.forget(id, true)
					}
				}
				if mask&unix.IN_MOVE_SELF != 0 {
					a.addTree(ctx, path, a.rules.Load().Policy)
				}
				a.reconcileNeeded.Store(true)
				continue
			}
			var err error
			switch {
			case mask&unix.IN_MOVED_FROM != 0:
				cookies[cookie] = move{path, time.Now(), false}
			case mask&unix.IN_MOVED_TO != 0:
				old := ""
				if m, ok := cookies[cookie]; ok {
					old = m.Path
					delete(cookies, cookie)
				}
				if !a.rules.Load().Policy.Tracked(old, a.Probe) {
					old = ""
				}
				err = a.Journal(path, "move", old)
			case mask&unix.IN_DELETE != 0:
				err = a.Journal(path, "delete", "")
			case mask&unix.IN_CLOSE_WRITE != 0:
				err = a.Journal(path, "modify", "")
			}
			if err != nil {
				a.health("journal_failed", common.Map{})
			}
		}
	}
}
func (a *Agent) directoryMove(old, dest string, p *common.Policy) {
	rows, e := a.DB.Query("SELECT path FROM manifest WHERE path LIKE ? ESCAPE '\\'", strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(old)+"/%")
	if e != nil {
		return
	}
	paths := []string{}
	for rows.Next() {
		var path string
		rows.Scan(&path)
		paths = append(paths, path)
	}
	rows.Close()
	for _, path := range paths {
		if dest == "" {
			a.Journal(path, "delete", "")
		} else {
			a.Journal(dest+strings.TrimPrefix(path, old), "move", path)
		}
	}
}
func (a *Agent) loadManifest() (map[string]manifestRow, error) {
	rows, e := a.DB.Query("SELECT path,hash,stat FROM manifest")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]manifestRow{}
	for rows.Next() {
		var path, hash, stat string
		if e = rows.Scan(&path, &hash, &stat); e != nil {
			return nil, e
		}
		out[path] = manifestRow{hash, stat}
	}
	return out, rows.Err()
}

type baselineEntry struct{ Path, Hash, Stat string }

func (a *Agent) saveBaseline(ctx context.Context, entries []baselineEntry) error {
	if len(entries) == 0 {
		return nil
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO manifest VALUES(?,?,?) ON CONFLICT(path) DO UPDATE SET hash=excluded.hash,stat=excluded.stat")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, entry := range entries {
		if !a.rules.Load().Policy.Tracked(entry.Path, a.Probe) {
			continue
		}
		if _, err = stmt.ExecContext(ctx, entry.Path, entry.Hash, entry.Stat); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (a *Agent) Reconcile(ctx context.Context, baseline, full bool, previous *common.Policy) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // Intentionally not unlocked: exiting retires this thread.
		rec := common.M(common.M(a.C["monitor"])["reconciliation"])
		priorityErr := unix.Setpriority(unix.PRIO_PROCESS, unix.Gettid(), common.I(rec["nice"]))
		_, _, ioErr := unix.Syscall(unix.SYS_IOPRIO_SET, 1, uintptr(unix.Gettid()), uintptr(common.I(rec["ionice_class"])<<13))
		if priorityErr != nil || ioErr != 0 {
			fmt.Println("reconciliation_priority_not_applied")
		}
		result <- a.reconcile(ctx, baseline, full, previous)
	}()
	return <-result
}
func (a *Agent) reconcile(ctx context.Context, baseline, full bool, previous *common.Policy) error {
	a.inventoryMu.Lock()
	defer a.inventoryMu.Unlock()
	a.inventoryChecked.Store(0)
	a.inventoryRunning.Store(true)
	defer a.inventoryRunning.Store(false)
	if err := ctx.Err(); err != nil {
		return err
	}
	manifest, e := a.loadManifest()
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	enumeration := true
	current := a.rules.Load().Policy
	batch := make([]baselineEntry, 0, 256)
	flush := func() error { err := a.saveBaseline(ctx, batch); batch = batch[:0]; return err }
	paths := append(append([]string{}, current.Roots...), a.Probe)
	check := func(path string) error {
		p := a.rules.Load().Policy
		if !p.Tracked(path, a.Probe) {
			return nil
		}
		a.inventoryChecked.Add(1)
		seen[path] = true
		if !a.validPath(path) {
			return nil
		}
		prior, exists := manifest[path]
		var st unix.Stat_t
		if !full && exists && unix.Lstat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && prior.Stat == metadata(&st) {
			return nil
		}
		quiet := baseline || previous != nil && !previous.Tracked(path, a.Probe)
		if quiet && !common.Inside(path, a.Probe) {
			sha, stat, err := a.snapshot(ctx, path, true)
			if err == nil {
				batch = append(batch, baselineEntry{path, sha, stat})
				if len(batch) == cap(batch) {
					return flush()
				}
				return nil
			}
			// Preserve the existing read-gap handling for failed files.
		}
		return a.Process(ctx, path, "reconcile", "", quiet, true)
	}
	for _, root := range paths {
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			enumeration = false
			continue
		}
		err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					enumeration = false
				}
				return nil
			}
			p := a.rules.Load().Policy
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if d.IsDir() {
				if p.Excluded(path) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			return check(path)
		})
		if err != nil {
			return err
		}
	}
	for _, path := range current.Critical {
		if _, err := os.Lstat(path); err == nil {
			if e = check(path); e != nil {
				return e
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			enumeration = false
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if enumeration {
		for path := range manifest {
			if seen[path] {
				continue
			}
			if a.rules.Load().Policy.Tracked(path, a.Probe) {
				if e = a.Process(ctx, path, "delete", "", baseline, true); e != nil {
					return e
				}
			} else {
				a.writeMu.Lock()
				_, e = a.DB.Exec("DELETE FROM manifest WHERE path=?", path)
				a.writeMu.Unlock()
				if e != nil {
					return e
				}
			}
		}
	} else {
		a.health("coverage_inventory_incomplete", common.Map{})
	}
	coverage := enumeration
	for _, root := range a.roots(a.rules.Load().Policy) {
		coverage = a.addTree(ctx, root, a.rules.Load().Policy) && coverage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if coverage {
		a.coverage.Store(1)
	} else {
		a.coverage.Store(0)
	}
	if e = a.counter("coverage_ok", float64(a.coverage.Load()), true); e != nil {
		return e
	}
	return a.counter("reconciliation_seconds", common.Now(), true)
}
func (a *Agent) jobs(ctx context.Context) {
	for ctx.Err() == nil {
		if a.baseline.Load() {
			common.Sleep(ctx, 200*time.Millisecond)
			continue
		}
		var id int64
		var path, op string
		var old sql.NullString
		e := a.DB.QueryRow("SELECT id,path,old_path,operation FROM jobs ORDER BY id LIMIT 1").Scan(&id, &path, &old, &op)
		if e == sql.ErrNoRows {
			common.Sleep(ctx, 200*time.Millisecond)
			continue
		}
		if e != nil {
			common.Sleep(ctx, time.Second)
			continue
		}
		var pages, free, pageSize int
		a.DB.QueryRow("PRAGMA page_count").Scan(&pages)
		a.DB.QueryRow("PRAGMA freelist_count").Scan(&free)
		a.DB.QueryRow("PRAGMA page_size").Scan(&pageSize)
		if int64(pages-free)*int64(pageSize) > int64(common.I(common.M(a.C["transport"])["local_event_queue_max_mib"]))*1048576 {
			a.counter("dropped_events_total", 1, false)
			a.counter("last_drop_seconds", common.Now(), true)
		} else {
			e = a.Process(ctx, path, op, old.String, false, false)
		}
		if e != nil {
			fmt.Println("job_error=" + common.SecretFree(e))
			common.Sleep(ctx, time.Second)
			continue
		}
		a.writeMu.Lock()
		_, e = a.DB.Exec("DELETE FROM jobs WHERE id=?", id)
		a.writeMu.Unlock()
		if e != nil {
			fmt.Println("job_delete_error=" + common.SecretFree(e))
		}
	}
}
func (a *Agent) status(state string, err error) error {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	return a.writeStatus(state, err)
}
func (a *Agent) writeStatus(state string, err error) error {
	a.watchMu.Lock()
	watches := len(a.watches)
	a.watchMu.Unlock()
	return common.AtomicJSON(filepath.Join(a.Data, "rules-status.json"), common.Map{"capability": 1, "node_id": a.C["node_id"], "pid": os.Getpid(), "instance_id": a.Instance, "implementation": "goframe", "state": state, "version": a.rules.Load().Version, "time": common.Now(), "coverage_ok": a.coverage.Load(), "coverage_error": a.watchFailure.Load(), "collector_ready": a.ready.Load(), "watches": watches, "error": nullableError(err)})
}
func nullableError(e error) any {
	if e != nil {
		return common.SecretFree(e)
	}
	return nil
}
func (a *Agent) validateYara(ctx context.Context, rules []byte) error {
	f, e := os.CreateTemp(a.Data, "rules-check-*.yar")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(rules); e != nil {
		f.Close()
		return e
	}
	f.Close()
	check, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if e = exec.CommandContext(check, "yara", "-w", name, "/dev/null").Run(); e != nil {
		return errors.New("invalid_yara_rules")
	}
	return nil
}
func stripRules(m common.Map) common.Map {
	out := common.Clone(m)
	monitor := common.M(out["monitor"])
	for _, key := range common.RuleFields {
		delete(monitor, key)
	}
	return out
}
func (a *Agent) Reload(ctx context.Context) error {
	raw, e := os.ReadFile(a.ConfigPath)
	if e != nil {
		return e
	}
	yara, e := os.ReadFile(common.S(a.C["yara_rules"]))
	if e != nil {
		return e
	}
	sig := common.Hash(append(append([]byte{}, raw...), yara...))
	if sig == a.signature {
		return nil
	}
	a.signature = sig
	old := a.rules.Load()
	reject := func(e error) error {
		a.counter("rules_reload_failure_total", 1, false)
		a.status("rejected", e)
		fmt.Println("rules_reload_rejected=" + common.SecretFree(e))
		return e
	}
	if len(raw) > 4*1048576 || len(yara) > 1048576 {
		return reject(errors.New("rules_too_large"))
	}
	v, e := common.Decode(raw)
	if e != nil {
		return reject(e)
	}
	candidate := common.M(v)
	if string(common.JSON(stripRules(candidate))) != string(common.JSON(stripRules(a.C))) {
		return reject(errors.New("unsupported_runtime_change"))
	}
	policy, e := common.NewPolicy(common.M(candidate["monitor"]))
	if e != nil {
		return reject(e)
	}
	if e = a.validateYara(ctx, yara); e != nil {
		return reject(e)
	}
	version := policy.Version(yara)
	if version == old.Version {
		return a.status("applied", nil)
	}
	changed := string(common.JSON(policy.Monitor)) != string(common.JSON(old.Policy.Monitor))
	a.status("applying", nil)
	if changed {
		for _, root := range a.roots(policy) {
			if !a.addTree(ctx, root, policy) {
				a.pruneWatches(old.Policy)
				return reject(errors.New("new_watch_coverage_incomplete"))
			}
		}
	}
	a.writeMu.Lock()
	a.rules.Store(&Rules{policy, append([]byte{}, yara...), version})
	a.writeMu.Unlock()
	if changed {
		a.pruneWatches(policy)
		if e = a.purge(); e == nil {
			e = a.Reconcile(ctx, false, false, old.Policy)
		}
		if e != nil || a.coverage.Load() != 1 {
			a.rules.Store(old)
			a.pruneWatches(old.Policy)
			for _, root := range a.roots(old.Policy) {
				a.addTree(ctx, root, old.Policy)
			}
			a.reconcileNeeded.Store(true)
			if e == nil {
				e = errors.New("new_inventory_coverage_incomplete")
			}
			return reject(e)
		}
	}
	a.counter("rules_reload_success_total", 1, false)
	a.counter("rules_reload_applied_seconds", common.Now(), true)
	fmt.Println("rules_reload_applied=" + version)
	return a.status("applied", nil)
}
func (a *Agent) purge() error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	p := a.rules.Load().Policy
	for _, table := range []string{"manifest", "jobs", "scans"} {
		id := "id"
		if table == "manifest" {
			id = "path"
		}
		query := "SELECT " + id + ",path FROM " + table
		if table == "jobs" {
			query += " WHERE old_path IS NULL OR old_path=''"
		}
		rows, e := a.DB.Query(query)
		if e != nil {
			return e
		}
		ids := []any{}
		for rows.Next() {
			var key any
			var path string
			if e = rows.Scan(&key, &path); e != nil {
				rows.Close()
				return e
			}
			if !p.Tracked(path, a.Probe) {
				ids = append(ids, key)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for start := 0; start < len(ids); start += 1000 {
			tx, e := a.DB.Begin()
			if e != nil {
				return e
			}
			stmt, e := tx.Prepare("DELETE FROM " + table + " WHERE " + id + "=?")
			if e != nil {
				tx.Rollback()
				return e
			}
			for _, key := range ids[start:min(start+1000, len(ids))] {
				if _, e = stmt.Exec(key); e != nil {
					break
				}
			}
			stmt.Close()
			if e != nil {
				tx.Rollback()
				return e
			}
			if e = tx.Commit(); e != nil {
				return e
			}
		}
	}
	return nil
}
func (a *Agent) rulesLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if e := a.Reload(ctx); e != nil {
			fmt.Println("rules_poll_error=" + common.SecretFree(e))
		}
		if !common.Sleep(ctx, 5*time.Second) {
			return
		}
	}
}
func (a *Agent) initializeStartup() error {
	a.ready.Store(false)
	a.coverage.Store(0)
	a.inventoryChecked.Store(0)
	if err := a.counter("collector_ready", 0, true); err != nil {
		return err
	}
	if err := a.counter("coverage_ok", 0, true); err != nil {
		return err
	}
	if err := common.Atomic(common.S(a.C["metrics_file"]), []byte("webscan_collector_ready 0\n"), 0644); err != nil {
		return err
	}
	return a.status("initializing", nil)
}

func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer func() { cancel(); a.worker.Wait() }()
	if e := a.validateYara(ctx, a.rules.Load().Yara); e != nil {
		return e
	}
	var complete int
	a.DB.QueryRow("SELECT 1 FROM counters WHERE key='baseline_completed' AND value=1").Scan(&complete)
	a.baseline.Store(complete != 1)
	if e := a.initializeStartup(); e != nil {
		return e
	}
	for _, root := range a.roots(a.rules.Load().Policy) {
		a.addTree(ctx, root, a.rules.Load().Policy)
	}
	for _, fn := range []func(context.Context){a.listen, a.jobs, a.export, a.metricLoop, a.probeLoop} {
		a.worker.Add(1)
		go func(f func(context.Context)) { defer a.worker.Done(); f(ctx) }(fn)
	}
	for i := 0; i < max(common.I(common.M(common.M(a.C["scan"])["yara"])["workers"]), 1); i++ {
		a.worker.Add(1)
		go func() { defer a.worker.Done(); a.scans(ctx) }()
	}
	if e := a.Reconcile(ctx, a.baseline.Load(), false, nil); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	a.baseline.Store(false)
	a.ready.Store(true)
	a.counter("baseline_completed", 1, true)
	a.counter("collector_ready", 1, true)
	// Publish current readiness immediately rather than waiting for the next
	// periodic metrics tick after a lengthy startup inventory.
	if e := a.Metrics(ctx); e != nil {
		return e
	}
	a.status("applied", nil)
	a.worker.Add(1)
	go func() { defer a.worker.Done(); a.rulesLoop(ctx) }()
	interval := time.Duration(common.I(common.M(common.M(a.C["monitor"])["reconciliation"])["interval_hours"])) * time.Hour
	jitter := time.Duration(rand.Int64N(max(int64(common.I(common.M(common.M(a.C["monitor"])["reconciliation"])["start_jitter_minutes"]))*60, 1))) * time.Second
	next := time.Now().Add(interval + jitter)
	coverage := time.Now().Add(time.Minute)
	for ctx.Err() == nil {
		if time.Now().After(coverage) {
			if err := a.refreshCoverage(ctx); err != nil && ctx.Err() == nil {
				fmt.Println("coverage_refresh_failed=" + common.SecretFree(err))
			}
			coverage = time.Now().Add(time.Minute)
		}
		if time.Now().After(next) || a.reconcileNeeded.Swap(false) {
			full := time.Now().After(next) || a.fullNeeded.Swap(false)
			if e := a.Reconcile(ctx, false, full, nil); e != nil && ctx.Err() == nil {
				a.health("reconciliation_failed", common.Map{})
			}
			if full {
				next = time.Now().Add(interval)
			}
		}
		common.Sleep(ctx, time.Second)
	}
	a.worker.Wait()
	return nil
}
func Run(ctx context.Context, path string) error {
	c, e := common.ReadJSON(path)
	if e != nil {
		return e
	}
	a, e := New(c, path)
	if e != nil {
		return e
	}
	defer a.Close()
	return a.Run(ctx)
}
