package nodeops

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type testHandler struct {
	calls            []string
	reconcile        string
	fail             string
	entered, release chan struct{}
	crash            bool
	marker           string
}

func (h *testHandler) Supports(string) bool { return true }
func (h *testHandler) Apply(r Request) (Outcome, error) {
	h.calls = append(h.calls, r.Phase)
	if h.entered != nil {
		close(h.entered)
		<-h.release
	}
	if h.crash {
		if err := os.WriteFile(h.marker, []byte("external-side-effect-complete"), 0600); err != nil {
			panic(err)
		}
		os.Exit(19)
	}
	if h.fail == r.Phase {
		return Outcome{}, errors.New("must-never-leak-password-or-private-key")
	}
	return Outcome{Checks: []Check{{ID: "fixture", Status: "passed", Code: "verified"}}}, nil
}
func (h *testHandler) Reconcile(r Request) (string, Outcome, error) {
	state := h.reconcile
	if state == "" {
		state = "unknown"
	}
	if h.marker != "" {
		if raw, err := os.ReadFile(h.marker); err == nil && string(raw) == "external-side-effect-complete" {
			state = "complete"
		}
	}
	return state, Outcome{}, nil
}
func testRoot(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	p, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func testRequest(root string) Request {
	return Request{Protocol: Protocol, Operation: "apply", Job: "job-one", Node: "node-one", PlanDigest: strings.Repeat("a", 64), Epoch: 1, Phase: "preflight", Spec: Spec{Mode: "native", MetricsPort: 19100, MonitorDirectories: []string{root}}}
}
func openTestJournal(t *testing.T, root string, h Handler) *Journal {
	t.Helper()
	j, err := Open(root, h)
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func requireResult(t *testing.T, r Result, state, code string) {
	t.Helper()
	if r.State != state || r.Code != code {
		t.Fatalf("state=%s code=%s, expected %s %s", r.State, r.Code, state, code)
	}
}
func finishThrough(t *testing.T, j *Journal, r Request, last string) {
	t.Helper()
	for _, phase := range forward {
		r.Phase = phase
		requireResult(t, j.Handle(r), "complete", "ok")
		if phase == last {
			return
		}
	}
}

func TestJournalPhaseOrderReplayAndFencing(t *testing.T) {
	root := testRoot(t)
	h := &testHandler{}
	j := openTestJournal(t, root, h)
	r := testRequest(root)
	r.Phase = "activate"
	requireResult(t, j.Handle(r), "unknown", "phase-order")
	r.Phase = "preflight"
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "absent", "ok")
	r.Operation = "apply"
	requireResult(t, j.Handle(r), "complete", "ok")
	requireResult(t, j.Handle(r), "complete", "ok")
	if len(h.calls) != 1 {
		t.Fatal("replayed a completed action", h.calls)
	}
	r.Epoch = 2
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Epoch = 1
	r.Operation = "apply"
	r.Phase = "stage"
	requireResult(t, j.Handle(r), "unknown", "fenced")
	r.Epoch = 2
	finishThrough(t, j, r, "finalize")
	r.Job = "job-two"
	r.PlanDigest = strings.Repeat("b", 64)
	r.Epoch = 1
	r.Phase = "preflight"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Job = "job-one"
	r.PlanDigest = strings.Repeat("a", 64)
	r.Epoch = 99
	requireResult(t, j.Handle(r), "unknown", "remote-conflict")
	if _, err := os.Stat(filepath.Join(root, "journal.sqlite3")); err != nil {
		t.Fatal(err)
	}
}
func TestJournalBindsNodePlanAndSpec(t *testing.T) {
	root := testRoot(t)
	h := &testHandler{}
	j := openTestJournal(t, root, h)
	r := testRequest(root)
	requireResult(t, j.Handle(r), "complete", "ok")
	for _, change := range []func(*Request){func(r *Request) { r.Node = "other-node" }, func(r *Request) { r.PlanDigest = strings.Repeat("b", 64) }, func(r *Request) { r.Spec.MetricsPort = 19200 }} {
		changed := r
		change(&changed)
		requireResult(t, j.Handle(changed), "unknown", "remote-conflict")
	}
	if len(h.calls) != 1 {
		t.Fatal("changed request executed")
	}
}

// Rolling back a successor restores the previous installation, not the old
// task's authority. A delayed request must never revive that retired job.
// Further rollback needs a separately bound recovery task, not a higher epoch
// supplied with the original task identity.
func TestJournalSuccessorRollbackDoesNotReviveRetiredTask(t *testing.T) {
	root := testRoot(t)
	h := &testHandler{}
	j := openTestJournal(t, root, h)
	original := testRequest(root)
	finishThrough(t, j, original, "finalize")
	next := original
	next.Job, next.PlanDigest = "job-successor", strings.Repeat("b", 64)
	finishThrough(t, j, next, "finalize")
	next.Epoch = 2
	for _, phase := range rollback {
		next.Phase = phase
		requireResult(t, j.Handle(next), "complete", "ok")
	}
	j = openTestJournal(t, root, h)
	before := len(h.calls)
	original.Epoch = 99
	for _, operation := range []string{"apply", "inspect"} {
		for _, phase := range []string{"restore", "verify-rollback", "preflight"} {
			original.Operation, original.Phase = operation, phase
			requireResult(t, j.Handle(original), "unknown", "remote-conflict")
		}
	}
	if len(h.calls) != before {
		t.Fatal("retired request executed an action")
	}
	db, err := j.database()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var retired int
	var current string
	if err := db.QueryRow("SELECT retired FROM jobs WHERE id=?", original.Job).Scan(&retired); err != nil || retired != 1 {
		t.Fatal("retirement lost", retired, err)
	}
	if err := db.QueryRow("SELECT current_job FROM meta WHERE id=1").Scan(&current); err != nil || current != next.Job {
		t.Fatal("current task changed", current, err)
	}
}
func TestJournalCrossConnectionLockCoversOperation(t *testing.T) {
	root := testRoot(t)
	h := &testHandler{entered: make(chan struct{}), release: make(chan struct{})}
	j := openTestJournal(t, root, h)
	r := testRequest(root)
	done := make(chan Result, 1)
	go func() { done <- j.Handle(r) }()
	<-h.entered
	other := openTestJournal(t, root, &testHandler{})
	next := r
	next.Epoch = 2
	requireResult(t, other.Handle(next), "unknown", "busy")
	close(h.release)
	requireResult(t, <-done, "complete", "ok")
	next.Operation = "inspect"
	requireResult(t, other.Handle(next), "complete", "ok")
	requireResult(t, j.Handle(r), "unknown", "fenced")
}
func TestJournalConcurrentInitialRequestsCannotOverlap(t *testing.T) {
	root := testRoot(t)
	r := testRequest(root)
	var wg sync.WaitGroup
	results := make(chan Result, 16)
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); j := openTestJournal(t, root, &testHandler{}); results <- j.Handle(r) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for res := range results {
		if res.Code == "ok" {
			success++
		} else if res.Code != "busy" {
			t.Fatal(res.Code)
		}
	}
	if success < 1 {
		t.Fatal("all requests failed")
	}
	j := openTestJournal(t, root, &testHandler{})
	db, err := j.database()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err = db.QueryRow("SELECT count(*) FROM phases WHERE status='complete'").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}
func TestJournalFailedReadOnlyProbeCanBeReplaced(t *testing.T) {
	root := testRoot(t)
	h := &testHandler{fail: "preflight"}
	j := openTestJournal(t, root, h)
	r := testRequest(root)
	res := j.Handle(r)
	requireResult(t, res, "unknown", "remote-unavailable")
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), "must-never") {
		t.Fatal("raw error leaked")
	}
	h.fail = ""
	r.Job = "job-two"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Job = "job-one"
	r.Epoch = 100
	requireResult(t, j.Handle(r), "unknown", "remote-conflict")
}
func TestJournalMutatingFailureRemainsUnknownAndBlocksReplacement(t *testing.T) {
	root := testRoot(t)
	h := &testHandler{fail: "backup"}
	j := openTestJournal(t, root, h)
	r := testRequest(root)
	finishThrough(t, j, r, "stage")
	r.Phase = "backup"
	requireResult(t, j.Handle(r), "unknown", "remote-unavailable")
	next := r
	next.Job = "job-two"
	next.Phase = "preflight"
	requireResult(t, j.Handle(next), "unknown", "remote-conflict")
	r.Epoch = 2
	r.Operation = "inspect"
	requireResult(t, j.Handle(r), "unknown", "remote-state-unknown")
	// Even an uncertain outcome fences the old owner before it may retry.
	old := r
	old.Epoch = 1
	requireResult(t, j.Handle(old), "unknown", "fenced")
	h.reconcile = "complete"
	requireResult(t, j.Handle(r), "complete", "ok")
	calls := len(h.calls)
	r.Operation = "apply"
	requireResult(t, j.Handle(r), "complete", "ok")
	if len(h.calls) != calls {
		t.Fatal("repeated action after reconcile")
	}
	r.Phase = "restore"
	requireResult(t, j.Handle(r), "complete", "ok")
	r.Phase = "activate"
	requireResult(t, j.Handle(r), "unknown", "phase-order")
	r.Phase = "verify-rollback"
	requireResult(t, j.Handle(r), "complete", "ok")
	next.Phase = "preflight"
	requireResult(t, j.Handle(next), "complete", "ok")
}
func TestJournalSymlinksAndPublicPermissionsRejected(t *testing.T) {
	root := testRoot(t)
	public := filepath.Join(root, "public")
	os.Mkdir(public, 0755)
	if _, err := Open(public, &testHandler{}); err == nil {
		t.Fatal("public directory accepted")
	}
	link := filepath.Join(root, "link")
	os.Symlink(root, link)
	if _, err := Open(filepath.Join(link, "nested"), &testHandler{}); err == nil {
		t.Fatal("parent symlink accepted")
	}
	for _, name := range []string{"journal.sqlite3", "journal.sqlite3-wal", "journal.sqlite3-shm", "operation.lock"} {
		t.Run(name, func(t *testing.T) {
			dir := testRoot(t)
			target := filepath.Join(testRoot(t), "unrelated")
			os.WriteFile(target, []byte("unchanged"), 0600)
			os.Symlink(target, filepath.Join(dir, name))
			j := openTestJournal(t, dir, &testHandler{})
			requireResult(t, j.Handle(testRequest(dir)), "unknown", "storage-failed")
			raw, _ := os.ReadFile(target)
			if string(raw) != "unchanged" {
				t.Fatal("symlink target changed")
			}
		})
	}
}
func TestJournalUnknownSchemaDoesNotAdopt(t *testing.T) {
	root := testRoot(t)
	j := openTestJournal(t, root, &testHandler{})
	r := testRequest(root)
	requireResult(t, j.Handle(r), "complete", "ok")
	db, err := j.database()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("PRAGMA user_version=999")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	requireResult(t, j.Handle(r), "unknown", "storage-failed")
}
func TestJournalCrashChild(t *testing.T) {
	root := os.Getenv("WEBSCAN_NODEOPS_CRASH_ROOT")
	if root == "" {
		return
	}
	var r Request
	if err := json.NewDecoder(os.Stdin).Decode(&r); err != nil {
		t.Fatal(err)
	}
	j := openTestJournal(t, root, &testHandler{crash: true, marker: filepath.Join(root, "side-effect")})
	j.Handle(r)
	t.Fatal("child did not terminate")
}
func TestJournalReconcilesAfterProcessDiesBeforeReceipt(t *testing.T) {
	root := testRoot(t)
	r := testRequest(root)
	// Reach the first mutating phase, then kill the helper after its simulated
	// effect but before SQLite records completion. This uses a real process exit.
	j := openTestJournal(t, root, &testHandler{})
	finishThrough(t, j, r, "stage")
	r.Phase = "backup"
	cmd := exec.Command(os.Args[0], "-test.run=^TestJournalCrashChild$")
	cmd.Env = append(os.Environ(), "WEBSCAN_NODEOPS_CRASH_ROOT="+root)
	raw, _ := json.Marshal(r)
	cmd.Stdin = strings.NewReader(string(raw))
	output, err := cmd.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 19 {
		t.Fatal("crash subprocess", err, string(output))
	}
	h := &testHandler{marker: filepath.Join(root, "side-effect")}
	restarted := openTestJournal(t, root, h)
	r.Epoch = 2
	r.Operation = "inspect"
	requireResult(t, restarted.Handle(r), "complete", "ok")
	r.Operation = "apply"
	requireResult(t, restarted.Handle(r), "complete", "ok")
	if len(h.calls) != 0 {
		t.Fatal("replayed the already completed remote phase")
	}
}
