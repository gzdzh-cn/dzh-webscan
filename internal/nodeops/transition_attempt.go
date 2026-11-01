package nodeops

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// The independent quiesce marker is durable before the first service mutation.
// It distinguishes a failed ownership/config capture from a lost capture after
// stopping a writer. Missing/corrupt recovery data must never become a no-op.
type backupAttempt struct {
	Format  int               `json:"format"`
	Binding transitionBinding `json:"binding"`
}
type quiesceIntent struct {
	Format        int               `json:"format"`
	Binding       transitionBinding `json:"binding"`
	CaptureSHA256 string            `json:"capture_sha256"`
}
type noEffectsRestore struct {
	Format        int               `json:"format"`
	Binding       transitionBinding `json:"binding"`
	AttemptSHA256 string            `json:"attempt_sha256"`
}

func (b *transitionBackup) rollbackStarted(r Request) bool {
	for _, name := range []string{"intent.json", "no-effects.json"} {
		if _, err := os.Lstat(filepath.Join(b.directory(r), "restoration", name)); !os.IsNotExist(err) {
			return true
		}
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "uninstall/restoration-intent.json")); !os.IsNotExist(err) {
		return true
	}
	return false
}

func (b *transitionBackup) beginAttempt(r Request) error {
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "backup" {
		return errors.New("invalid-backup-attempt")
	}
	if b.rollbackStarted(r) {
		return errors.New("rollback-already-started")
	}
	for _, dir := range []string{b.root, filepath.Join(b.root, "transitions"), b.directory(r)} {
		if err := ensurePrivateDirectory(dir); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(backupAttempt{1, binding(r)})
	if err != nil {
		return err
	}
	return replacePrivateFile(filepath.Join(b.directory(r), "backup-attempt.json"), raw, nil)
}

func (b *transitionBackup) beforeQuiesce(r Request) error {
	raw, err := readPrivate(filepath.Join(b.directory(r), "capture", "intent.json"), 4<<20)
	if err != nil {
		return err
	}
	want, err := json.Marshal(quiesceIntent{1, binding(r), sha(raw)})
	if err != nil {
		return err
	}
	return replacePrivateFile(filepath.Join(b.directory(r), "quiesce.json"), want, nil)
}

// No host command is needed: these invariants are established by the backup
// writer before it is allowed to stop any service. The operation lock must be
// held by the caller. A missing attempt cannot adopt an older unknown writer.
func (b *transitionBackup) uncaptured(r Request) (bool, []byte, error) {
	for _, dir := range []string{b.root, filepath.Join(b.root, "transitions"), b.directory(r)} {
		if err := privateDirectoryTree(dir); err != nil {
			return false, nil, err
		}
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "capture")); err == nil {
		return false, nil, nil
	} else if !os.IsNotExist(err) {
		return false, nil, err
	}
	var attempt backupAttempt
	raw, err := decodePrivateJSON(filepath.Join(b.directory(r), "backup-attempt.json"), &attempt, 4096)
	if err != nil || attempt.Format != 1 || attempt.Binding != binding(r) {
		return false, nil, errors.New("backup-attempt-not-proven")
	}
	for _, name := range []string{"quiesce.json", "snapshot", "activation", "finalized.json", "restoration/intent.json", "restoration/export.json", "uninstall/intent.json", "uninstall/tombstone.json"} {
		if _, err := os.Lstat(filepath.Join(b.directory(r), name)); !os.IsNotExist(err) {
			return false, nil, errors.New("service-effects-cannot-be-excluded")
		}
	}
	// A target pointer for this task is an unrecorded activation, not evidence
	// that no changes occurred. Unrelated/operator changes are left untouched.
	var active ActiveInstallation
	if _, err := os.Lstat(filepath.Join(b.root, "active.json")); err == nil {
		if _, err := decodePrivateJSON(filepath.Join(b.root, "active.json"), &active, MaxRequestBytes); err != nil || active.Job == r.Job {
			return false, nil, errors.New("unrecorded-activation-effects")
		}
	} else if !os.IsNotExist(err) {
		return false, nil, err
	}
	return true, raw, nil
}

func (b *transitionBackup) restoreUncaptured(r Request, write bool) (bool, error) {
	if r.Validate() != nil || r.Operation != "apply" || r.Phase != "restore" {
		return false, errors.New("invalid-recovery-request")
	}
	path := filepath.Join(b.directory(r), "restoration", "no-effects.json")
	_, markerErr := os.Lstat(path)
	if markerErr != nil && !os.IsNotExist(markerErr) {
		return false, markerErr
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "capture")); err == nil {
		if markerErr == nil {
			return false, errors.New("no-effects-receipt-conflict")
		}
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	eligible, attempt, err := b.uncaptured(r)
	if err != nil || !eligible {
		return false, err
	}
	want, err := json.Marshal(noEffectsRestore{1, binding(r), sha(attempt)})
	if err != nil {
		return false, err
	}
	if write {
		if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
			return false, err
		}
		if err := replacePrivateFile(path, want, nil); err != nil {
			return false, err
		}
	} else {
		var receipt noEffectsRestore
		if _, err := decodePrivateJSON(path, &receipt, 4096); err != nil || receipt.Format != 1 || receipt.Binding != binding(r) || receipt.AttemptSHA256 != sha(attempt) {
			return false, errors.New("no-effects-receipt-not-proven")
		}
	}
	return true, nil
}
