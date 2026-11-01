package nodeops

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"webscan/internal/persist"
)

const schema = `CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),node TEXT NOT NULL,current_job TEXT NOT NULL);
CREATE TABLE jobs(id TEXT PRIMARY KEY,digest TEXT NOT NULL,spec_digest TEXT NOT NULL,epoch INTEGER NOT NULL,retired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE phases(job TEXT NOT NULL REFERENCES jobs(id),phase TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('running','complete','failed')),outcome TEXT NOT NULL DEFAULT '{}',error_code TEXT NOT NULL DEFAULT '',PRIMARY KEY(job,phase));
PRAGMA user_version=1;`

// The lock covers the complete handler operation, not just a SQLite transaction.
// A disconnected SSH client cannot obtain the lock to overlap another phase.
// If the process is killed, the committed running row forces reconciliation
// rather than assuming that releasing a kernel lock completed the operation.
type Journal struct {
	root    string
	handler Handler
}

func Open(root string, handler Handler) (*Journal, error) {
	if handler == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("invalid-journal")
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return nil, err
	}
	return &Journal{root, handler}, nil
}

func ensurePrivateDirectory(root string) error {
	// Validate every existing ancestor. Only the service account may write the
	// leaf; reject symlink parents rather than following an uploaded pathname.
	for p := root; p != "/"; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe-journal")
		}
		if err != nil && !os.IsNotExist(err) {
			return errors.New("unsafe-journal")
		}
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return errors.New("journal-unavailable")
	}
	st, err := os.Lstat(root)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("unsafe-journal")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe-journal")
	}
	return nil
}
func privateFile(path string, optional bool) error {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) && optional {
		return nil
	}
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return errors.New("unsafe-journal")
	}
	return nil
}
func (s *Journal) lock() (*os.File, error) {
	path := filepath.Join(s.root, "operation.lock")
	if err := privateFile(path, true); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("journal-busy")
	}
	if err = privateFile(path, false); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func (s *Journal) database() (*sql.DB, error) {
	for _, name := range []string{"journal.sqlite3", "journal.sqlite3-wal", "journal.sqlite3-shm"} {
		if err := privateFile(filepath.Join(s.root, name), true); err != nil {
			return nil, err
		}
	}
	// SQLite inherits WAL/SHM permissions from the main file. Create it as
	// 0600 before opening, rather than chmod after a permissive first open.
	fd, err := unix.Open(filepath.Join(s.root, "journal.sqlite3"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	unix.Close(fd)
	db, err := persist.OpenDB(filepath.Join(s.root, "journal.sqlite3"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var version, count int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version == 0 {
		if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&count); err == nil && count == 0 {
			tx, e := db.Begin()
			if e != nil {
				err = e
			} else {
				_, err = tx.Exec(schema)
				if err == nil {
					err = tx.Commit()
				}
				tx.Rollback()
			}
		} else if err == nil {
			err = errors.New("unknown-journal-schema")
		}
	} else if version != 1 {
		err = errors.New("unknown-journal-schema")
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
func (s *Journal) Handle(r Request) (res Result) {
	if r.Validate() != nil {
		return result(r, "unknown", "invalid-request", Outcome{})
	}
	if !s.handler.Supports(r.Phase) {
		return result(r, "unknown", "executor-unavailable", Outcome{})
	}
	lock, err := s.lock()
	if err != nil {
		code := "storage-failed"
		if err.Error() == "journal-busy" {
			code = "busy"
		}
		return result(r, "unknown", code, Outcome{})
	}
	defer lock.Close()
	// Run while the Journal operation lock still fences successors. A failed
	// evidence read cannot turn into a successful, unbound final receipt.
	defer func() {
		if res.Code == "ok" && res.State == "complete" && r.Uninstall != nil {
			provider, ok := s.handler.(uninstallEvidenceProvider)
			if !ok {
				res = result(r, "unknown", "verification-failed", Outcome{})
				return
			}
			if r.Phase == "finalize" {
				evidence, err := provider.removalEvidence(r)
				if err != nil || evidence == nil || !evidence.Valid() {
					res = result(r, "unknown", "verification-failed", Outcome{})
					return
				}
				res.Removal = evidence
			} else if r.Phase == "verify-rollback" {
				evidence, err := provider.restorationEvidence(r)
				if err != nil || evidence == nil || !evidence.Valid() {
					res = result(r, "unknown", "verification-failed", Outcome{})
					return
				}
				res.Restoration = evidence
			}
			return
		}
		if res.Code != "ok" || res.State != "complete" || r.Phase != "finalize" || r.Recovery != nil {
			return
		}
		if provider, ok := s.handler.(installationEvidenceProvider); ok {
			evidence, err := provider.installationEvidence(r)
			if err != nil || evidence == nil || !evidence.Valid() {
				res = result(r, "unknown", "verification-failed", Outcome{})
				return
			}
			res.Installation = evidence
		}
	}()
	db, err := s.database()
	if err != nil {
		return result(r, "unknown", "storage-failed", Outcome{})
	}
	defer db.Close()
	code, err := s.adopt(db, r)
	if err != nil {
		return result(r, "unknown", "storage-failed", Outcome{})
	}
	if code != "ok" {
		return result(r, "unknown", code, Outcome{})
	}
	// Adoption persists the new fence before reconciliation. An unresolved prior
	// action still prevents any new phase from executing under that fence.
	var pending string
	err = db.QueryRow("SELECT phase FROM phases WHERE job=? AND status='running'", r.Job).Scan(&pending)
	if err != nil && err != sql.ErrNoRows {
		return result(r, "unknown", "storage-failed", Outcome{})
	}
	if pending != "" {
		prior := r
		prior.Phase = pending
		state, out, e := s.handler.Reconcile(prior)
		if e != nil || state != "absent" && state != "complete" {
			return result(r, "unknown", "remote-state-unknown", Outcome{})
		}
		if !validOutcome(out) {
			return result(r, "unknown", "remote-state-unknown", Outcome{})
		}
		status := "failed"
		if state == "complete" {
			status = "complete"
		}
		if _, err = db.Exec("UPDATE phases SET status=?,outcome=?,error_code='' WHERE job=? AND phase=?", status, outcomeJSON(out), r.Job, pending); err != nil {
			return result(r, "unknown", "storage-failed", Outcome{})
		}
	}
	code, err = phaseOrder(db, r)
	if err != nil {
		return result(r, "unknown", "storage-failed", Outcome{})
	}
	if code != "ok" {
		return result(r, "unknown", code, Outcome{})
	}
	var status, raw string
	err = db.QueryRow("SELECT status,outcome FROM phases WHERE job=? AND phase=?", r.Job, r.Phase).Scan(&status, &raw)
	if err != nil && err != sql.ErrNoRows {
		return result(r, "unknown", "storage-failed", Outcome{})
	}
	if status == "complete" {
		var out Outcome
		if json.Unmarshal([]byte(raw), &out) != nil || !validOutcome(out) {
			return result(r, "unknown", "storage-failed", Outcome{})
		}
		if verifier, ok := s.handler.(CompletedVerifier); ok {
			if err := verifier.VerifyCompleted(r, out); err != nil {
				return result(r, "unknown", failureCode(err), Outcome{})
			}
		}
		return result(r, "complete", "ok", out)
	}
	if r.Operation == "inspect" {
		return result(r, "absent", "ok", Outcome{})
	}
	// Commit intent before performing any external effect. Handler errors after
	// mutation keep this intent unresolved, because a timeout is not proof of no-op.
	if _, err = db.Exec("INSERT INTO phases(job,phase,status,outcome,error_code) VALUES(?,?,'running','{}','') ON CONFLICT(job,phase) DO UPDATE SET status='running',outcome='{}',error_code=''", r.Job, r.Phase); err != nil {
		return result(r, "unknown", "storage-failed", Outcome{})
	}
	out, err := s.handler.Apply(r)
	if err != nil || !validOutcome(out) {
		code := "remote-state-unknown"
		if err != nil {
			code = failureCode(err)
		}
		if !validOutcome(out) {
			out = Outcome{}
		}
		if phaseIndex(r.Phase) < 2 {
			_, _ = db.Exec("UPDATE phases SET status='failed',outcome=?,error_code=? WHERE job=? AND phase=?", outcomeJSON(out), code, r.Job, r.Phase)
		}
		return result(r, "unknown", code, out)
	}
	if _, err = db.Exec("UPDATE phases SET status='complete',outcome=? WHERE job=? AND phase=?", outcomeJSON(out), r.Job, r.Phase); err != nil {
		return result(r, "unknown", "storage-failed", Outcome{})
	}
	return result(r, "complete", "ok", out)
}
func (s *Journal) adopt(db *sql.DB, r Request) (string, error) {
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var node, current string
	err = tx.QueryRow("SELECT node,current_job FROM meta WHERE id=1").Scan(&node, &current)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	if node != "" && node != r.Node {
		return "remote-conflict", nil
	}
	var digest, spec string
	var epoch int64
	var retired int
	err = tx.QueryRow("SELECT digest,spec_digest,epoch,retired FROM jobs WHERE id=?", r.Job).Scan(&digest, &spec, &epoch, &retired)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	if err == nil {
		if retired != 0 || current != r.Job || digest != r.PlanDigest || spec != r.identityDigest() {
			return "remote-conflict", nil
		}
		if r.Epoch < epoch {
			return "fenced", nil
		}
		if _, err = tx.Exec("UPDATE jobs SET epoch=? WHERE id=?", r.Epoch, r.Job); err != nil {
			return "", err
		}
		return "ok", tx.Commit()
	}
	if r.Recovery != nil {
		allowed, err := s.authorizeRecovery(tx, r, current)
		if err != nil {
			return "", err
		}
		if !allowed {
			return "remote-conflict", nil
		}
	}
	if current != "" {
		var pending, risky, finished int
		if err = tx.QueryRow("SELECT count(*) FROM phases WHERE job=? AND status='running'", current).Scan(&pending); err != nil {
			return "", err
		}
		if err = tx.QueryRow("SELECT count(*) FROM phases WHERE job=? AND phase IN ('backup','activate','verify','finalize','restore','verify-rollback')", current).Scan(&risky); err != nil {
			return "", err
		}
		if err = tx.QueryRow("SELECT count(*) FROM phases WHERE job=? AND status='complete' AND phase IN ('finalize','verify-rollback')", current).Scan(&finished); err != nil {
			return "", err
		}
		if risky > 0 && (pending > 0 || finished == 0) {
			return "remote-conflict", nil
		}
		if _, err = tx.Exec("UPDATE jobs SET retired=1 WHERE id=?", current); err != nil {
			return "", err
		}
	}
	if _, err = tx.Exec("INSERT INTO jobs(id,digest,spec_digest,epoch) VALUES(?,?,?,?)", r.Job, r.PlanDigest, r.identityDigest(), r.Epoch); err != nil {
		return "", err
	}
	if _, err = tx.Exec("INSERT INTO meta(id,node,current_job) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET current_job=excluded.current_job", r.Node, r.Job); err != nil {
		return "", err
	}
	return "ok", tx.Commit()
}
func phaseOrder(db *sql.DB, r Request) (string, error) {
	index := phaseIndex(r.Phase)
	var count int
	if index < len(forward) {
		if err := db.QueryRow("SELECT count(*) FROM phases WHERE job=? AND phase IN ('restore','verify-rollback')", r.Job).Scan(&count); err != nil {
			return "", err
		}
		if count > 0 {
			return "phase-order", nil
		}
		for _, prior := range forward[:index] {
			if err := db.QueryRow("SELECT count(*) FROM phases WHERE job=? AND phase=? AND status='complete'", r.Job, prior).Scan(&count); err != nil {
				return "", err
			}
			if count != 1 {
				return "phase-order", nil
			}
		}
	} else if r.Phase == "verify-rollback" {
		if err := db.QueryRow("SELECT count(*) FROM phases WHERE job=? AND phase='restore' AND status='complete'", r.Job).Scan(&count); err != nil {
			return "", err
		}
		if count != 1 {
			return "phase-order", nil
		}
	}
	return "ok", nil
}
func outcomeJSON(out Outcome) string { raw, _ := json.Marshal(out); return string(raw) }
func validOutcome(out Outcome) bool {
	if len(out.Checks) > 200 {
		return false
	}
	for _, c := range out.Checks {
		if !idPattern.MatchString(c.ID) || !idPattern.MatchString(c.Code) || c.Status != "passed" && c.Status != "failed" && c.Status != "unknown" && c.Status != "warning" {
			return false
		}
	}
	return true
}
