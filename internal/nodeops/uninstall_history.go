package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type uninstallIntent struct {
	Format            int                `json:"format"`
	Binding           transitionBinding  `json:"binding"`
	Spec              Spec               `json:"spec"`
	Reference         UninstallReference `json:"reference"`
	CaptureSHA256     string             `json:"capture_sha256"`
	SnapshotSHA256    string             `json:"snapshot_sha256"`
	PreservedSHA256   string             `json:"preserved_sha256"`
	PreviousTombstone json.RawMessage    `json:"previous_tombstone,omitempty"`
}
type removalTombstone struct {
	Format          int                `json:"format"`
	Binding         transitionBinding  `json:"binding"`
	Spec            Spec               `json:"spec"`
	Reference       UninstallReference `json:"reference"`
	CaptureSHA256   string             `json:"capture_sha256"`
	IntentSHA256    string             `json:"intent_sha256"`
	PreservedSHA256 string             `json:"preserved_sha256"`
}
type preservedFile struct {
	Area   string     `json:"area"`
	File   backupFile `json:"file"`
	Device uint64     `json:"device"`
	Inode  uint64     `json:"inode"`
}
type uninstallPreservation struct {
	Format  int               `json:"format"`
	Binding transitionBinding `json:"binding"`
	Files   []preservedFile   `json:"files"`
}

func (u *uninstallLifecycle) preservation(ctx context.Context, r Request) (uninstallPreservation, []byte, error) {
	var p uninstallPreservation
	raw, err := decodePrivateJSON(filepath.Join(u.directory(r), "preserved.json"), &p, 16<<20)
	if err != nil || p.Format != 1 || p.Binding != binding(r) || len(p.Files) > 110000 {
		return p, nil, errors.New("uninstall-preservation-not-proven")
	}
	canonical, _ := json.Marshal(p)
	if !bytes.Equal(canonical, raw) {
		return p, nil, errors.New("uninstall-preservation-not-canonical")
	}
	seen := map[string]bool{}
	for _, f := range p.Files {
		if !validBackupPath(f.File.Path) || !validDigest(f.File.SHA256) || f.Inode == 0 || f.Area != "data" && f.Area != "logs" || seen[f.Area+"/"+f.File.Path] {
			return p, nil, errors.New("uninstall-preservation-invalid")
		}
		seen[f.Area+"/"+f.File.Path] = true
	}
	return p, raw, nil
}
func (u *uninstallLifecycle) publishPreservation(ctx context.Context, r Request) (string, error) {
	path := filepath.Join(u.directory(r), "preserved.json")
	if _, err := os.Lstat(path); err == nil {
		_, raw, e := u.preservation(ctx, r)
		return sha(raw), e
	} else if !os.IsNotExist(err) {
		return "", err
	}
	p := uninstallPreservation{Format: 1, Binding: binding(r), Files: []preservedFile{}}
	for _, area := range []struct{ name, root string }{{"data", u.backup.data}, {"logs", u.backup.logs}} {
		if _, err := os.Lstat(area.root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return "", err
		}
		if err := privateDirectoryTree(area.root); err != nil {
			return "", err
		}
		err := filepath.WalkDir(area.root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			rel, e := filepath.Rel(area.root, path)
			if e != nil {
				return e
			}
			if rel == "." {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("uninstall-preservation-symlink")
			}
			if d.IsDir() {
				return privateDirectoryTree(path)
			}
			if !d.Type().IsRegular() {
				return errors.New("uninstall-preservation-special-file")
			}
			if area.name == "data" && !(rel == "agent.sqlite3" || rel == "agent.sqlite3-wal" || rel == "agent.sqlite3-shm" || strings.HasPrefix(rel, "pki-trust/") || strings.HasPrefix(rel, "pki-identity/")) {
				return nil
			}
			if area.name == "logs" && !strings.HasSuffix(rel, ".jsonl") {
				return nil
			}
			f, e := describePrivateFile(ctx, path, filepath.ToSlash(rel), 1<<63-1)
			if e != nil {
				return e
			}
			info, e := os.Lstat(path)
			if e != nil {
				return e
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.New("uninstall-file-identity-unavailable")
			}
			p.Files = append(p.Files, preservedFile{area.name, f, uint64(stat.Dev), uint64(stat.Ino)})
			if len(p.Files) > 110000 {
				return errors.New("uninstall-preservation-too-large")
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	sort.Slice(p.Files, func(i, j int) bool {
		return p.Files[i].Area+"/"+p.Files[i].File.Path < p.Files[j].Area+"/"+p.Files[j].File.Path
	})
	raw, _ := json.Marshal(p)
	if err := ensurePrivateDirectory(u.directory(r)); err != nil {
		return "", err
	}
	if err := replacePrivateFile(path, raw, nil); err != nil {
		return "", err
	}
	return sha(raw), nil
}
func (u *uninstallLifecycle) verifyPreservation(ctx context.Context, r Request, want string, mutable bool) error {
	p, raw, err := u.preservation(ctx, r)
	if err != nil || sha(raw) != want {
		return errors.New("uninstall-preserved-material-changed")
	}
	for _, f := range p.Files {
		root := u.backup.data
		if f.Area == "logs" {
			root = u.backup.logs
		}
		path := filepath.Join(root, filepath.FromSlash(f.File.Path))
		if err := privateDirectoryTree(filepath.Dir(path)); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		// SQLite may remove its transient WAL/SHM after a successful restart.
		transient := f.Area == "data" && (f.File.Path == "agent.sqlite3-wal" || f.File.Path == "agent.sqlite3-shm")
		if mutable && transient && os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("uninstall-preserved-file-missing")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("uninstall-file-identity-unavailable")
		}
		if !mutable || f.Area == "data" && f.File.Path == "agent.sqlite3" {
			if uint64(stat.Dev) != f.Device || uint64(stat.Ino) != f.Inode {
				return errors.New("uninstall-live-data-replaced")
			}
		}
		if !mutable {
			if err := verifyBackupFile(ctx, path, f.File); err != nil {
				return err
			}
		}
	}
	return nil
}
func (u *uninstallLifecycle) plan(ctx context.Context, r Request, publish bool) (uninstallIntent, []byte, error) {
	var i uninstallIntent
	path := filepath.Join(u.directory(r), "intent.json")
	if _, err := os.Lstat(path); err == nil {
		raw, e := decodePrivateJSON(path, &i, 4<<20)
		if e != nil || i.Format != 1 || i.Binding != binding(r) || i.Spec.digest() != r.Spec.digest() || !sameUninstall(i.Reference, *r.Uninstall) || !validDigest(i.CaptureSHA256) || !validDigest(i.SnapshotSHA256) || !validDigest(i.PreservedSHA256) {
			return i, nil, errors.New("uninstall-intent-not-proven")
		}
		capture, e := readPrivate(filepath.Join(u.backup.directory(r), "capture/intent.json"), 4<<20)
		if e != nil || sha(capture) != i.CaptureSHA256 {
			return i, nil, errors.New("uninstall-capture-changed")
		}
		snapshot, e := readPrivate(filepath.Join(u.backup.directory(r), "snapshot/receipt.json"), 16<<20)
		if e != nil || sha(snapshot) != i.SnapshotSHA256 {
			return i, nil, errors.New("uninstall-snapshot-changed")
		}
		if _, e = u.backup.verify(ctx, r); e != nil {
			return i, nil, e
		}
		return i, raw, nil
	} else if !os.IsNotExist(err) {
		return i, nil, err
	}
	if !publish {
		return i, nil, os.ErrNotExist
	}
	capture, err := readPrivate(filepath.Join(u.backup.directory(r), "capture/intent.json"), 4<<20)
	if err != nil {
		return i, nil, err
	}
	if _, err = u.backup.verify(ctx, r); err != nil {
		return i, nil, err
	}
	snapshot, err := readPrivate(filepath.Join(u.backup.directory(r), "snapshot/receipt.json"), 16<<20)
	if err != nil {
		return i, nil, err
	}
	if _, _, err = u.source(ctx, r); err != nil {
		return i, nil, err
	}
	if err = u.recoveryMaterials(ctx, r); err != nil {
		return i, nil, err
	}
	captured, err := u.removalInstallation(ctx, r)
	if err != nil || captured.DatabasePresent == nil {
		return i, nil, errors.New("uninstall-database-presence-unknown")
	}
	if *captured.DatabasePresent {
		if err := privateFile(filepath.Join(u.backup.data, "agent.sqlite3"), false); err != nil {
			return i, nil, err
		}
	}
	preserved, err := u.publishPreservation(ctx, r)
	if err != nil {
		return i, nil, err
	}
	previous, err := readPrivate(filepath.Join(u.runtime.root, "uninstalled.json"), 4<<20)
	if err != nil && !os.IsNotExist(err) {
		return i, nil, err
	}
	if len(previous) > 0 {
		if _, _, err = u.host.readRemovalTombstone(ctx, previous); err != nil {
			return i, nil, err
		}
	}
	i = uninstallIntent{1, binding(r), r.Spec, *r.Uninstall, sha(capture), sha(snapshot), preserved, previous}
	raw, _ := json.Marshal(i)
	if err = replacePrivateFile(path, raw, nil); err != nil {
		return i, nil, err
	}
	return i, raw, nil
}
func sameUninstall(a, b UninstallReference) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func (u *uninstallLifecycle) removalInstallation(ctx context.Context, r Request) (backupIntent, error) {
	i, err := u.backup.readIntent(ctx, r)
	if err != nil {
		return i, err
	}
	if i.Installed.Generation != "v3" || i.Installed.Mode != r.Spec.Mode || len(i.Installed.Services) != 1 || hasLegacyMembers(i.Installed) {
		return i, errors.New("uninstall-captured-installation-invalid")
	}
	return i, nil
}
func (u *uninstallLifecycle) remove(ctx context.Context, r Request) error {
	if u.backup.rollbackStarted(r) {
		return errors.New("rollback-already-started")
	}
	lock, err := u.backup.agentLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	i, _, err := u.plan(ctx, r, true)
	if err != nil {
		return err
	}
	if err = u.verifyPreservation(ctx, r, i.PreservedSHA256, false); err != nil {
		return err
	}
	captured, err := u.removalInstallation(ctx, r)
	if err != nil {
		return err
	}
	s := captured.Installed.Services[0]
	raw, err := readPrivate(filepath.Join(u.backup.directory(r), "capture/active.json"), MaxRequestBytes)
	if err != nil {
		return err
	}
	if _, err = originalOrAbsent(filepath.Join(u.runtime.root, "active.json"), raw); err != nil {
		return err
	}
	if s.Kind == "native" {
		unit, err := readPrivate(filepath.Join(u.backup.directory(r), "capture/native.service"), 64<<10)
		if err != nil {
			return err
		}
		if current, e := readPrivate(u.host.unitPath, 64<<10); e == nil {
			if !bytes.Equal(current, unit) {
				return errors.New("uninstall-unit-changed")
			}
			stopped, e := u.host.stopped(ctx, captured.Installed)
			if e != nil || !stopped {
				return errors.New("uninstall-writer-not-stopped")
			}
			if err = removeExpectedPrivate(u.host.unitPath, unit); err != nil {
				return err
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		if _, err = u.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
	} else {
		absent, err := u.host.containerAbsent(ctx, s.ID)
		if err != nil {
			return err
		}
		if !absent {
			stopped, e := u.host.stopped(ctx, captured.Installed)
			if e != nil || !stopped {
				return errors.New("uninstall-writer-not-stopped")
			}
			if _, err = u.host.docker(ctx, "rm", s.ID); err != nil {
				return err
			}
		}
	}
	if err = removeExpectedPrivate(filepath.Join(u.runtime.root, "active.json"), raw); err != nil {
		return err
	}
	complete, err := u.removalState(ctx, r)
	if err != nil {
		return err
	}
	if !complete {
		return errors.New("uninstall-object-still-present")
	}
	return nil
}
func (u *uninstallLifecycle) removalState(ctx context.Context, r Request) (bool, error) {
	i, _, err := u.plan(ctx, r, false)
	if err != nil {
		return false, err
	}
	if err = u.verifyPreservation(ctx, r, i.PreservedSHA256, false); err != nil {
		return false, err
	}
	captured, err := u.removalInstallation(ctx, r)
	if err != nil {
		return false, err
	}
	pointer, err := readPrivate(filepath.Join(u.backup.directory(r), "capture/active.json"), MaxRequestBytes)
	if err != nil {
		return false, err
	}
	old, err := originalOrAbsent(filepath.Join(u.runtime.root, "active.json"), pointer)
	if err != nil {
		return false, err
	}
	absent, err := u.host.removedObject(ctx, captured.Installed)
	if err != nil {
		return false, err
	}
	return absent && !old, nil
}
func (h installationHost) containerAbsent(ctx context.Context, id string) (bool, error) {
	if !validDigest(id) {
		return false, errors.New("invalid-container-id")
	}
	raw, err := h.docker(ctx, "ps", "-a", "--no-trunc", "--filter", "id="+id, "--format", "{{.ID}}")
	if err != nil {
		return false, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true, nil
	}
	if raw != id {
		return false, errors.New("container-lookup-not-unique")
	}
	return false, nil
}
func (h installationHost) removedObject(ctx context.Context, i Installation) (bool, error) {
	if !i.valid(i.Node) || i.Generation != "v3" || len(i.Services) != 1 || hasLegacyMembers(i) {
		return false, errors.New("uninstall-object-not-proven")
	}
	s := i.Services[0]
	if s.Kind == "docker" {
		absent, err := h.containerAbsent(ctx, s.ID)
		if err != nil {
			return false, err
		}
		if !absent {
			c, e := h.ownedContainer(ctx, s)
			if e != nil {
				return false, e
			}
			if c.Status == "running" || c.Restart != "no" {
				return false, errors.New("unexpected-uninstall-writer")
			}
			return false, nil
		}
		named, err := h.containerNamed(ctx, s.Name)
		if err != nil {
			return false, err
		}
		if named != nil {
			return false, errors.New("removed-container-name-reused")
		}
		if _, err = os.Lstat(h.unitPath); !os.IsNotExist(err) {
			return false, errors.New("unexpected-native-unit")
		}
		return true, nil
	}
	if raw, err := readPrivate(h.unitPath, 64<<10); err == nil {
		if sha(raw) != s.Proof {
			return false, errors.New("uninstall-unit-changed")
		}
		status, e := h.native(ctx, s)
		if e != nil {
			return false, e
		}
		if status.MainPID != 0 || status.UnitFileState != "disabled" {
			return false, errors.New("unexpected-uninstall-writer")
		}
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	raw, commandErr := h.command(ctx, "systemctl", "show", nativeServiceName, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
	status, err := decodeNativeStatus(raw, true, true)
	if err == nil && status.LoadState == "loaded" && status.MainPID == 0 && status.FragmentPath == h.unitPath && status.UnitFileState == "disabled" {
		return false, nil
	}
	if err != nil || commandErr != nil && status.LoadState != "not-found" || status.MainPID != 0 || status.LoadState != "not-found" {
		return false, errors.New("removed-native-service-state-unknown")
	}
	return true, nil
}
func (u *uninstallLifecycle) verifyRemoval(ctx context.Context, r Request, final bool) error {
	complete, err := u.removalState(ctx, r)
	if err != nil {
		return err
	}
	if !complete {
		return errors.New("uninstall-incomplete")
	}
	if final {
		_, err = u.readTombstone(ctx, r)
	}
	return err
}
func (u *uninstallLifecycle) finalizeRemoval(ctx context.Context, r Request) error {
	if err := u.verifyRemoval(ctx, r, false); err != nil {
		return err
	}
	i, intent, err := u.plan(ctx, r, false)
	if err != nil {
		return err
	}
	t := removalTombstone{1, binding(r), r.Spec, *r.Uninstall, i.CaptureSHA256, sha(intent), i.PreservedSHA256}
	raw, _ := json.Marshal(t)
	if err = replacePrivateFile(filepath.Join(u.directory(r), "tombstone.json"), raw, nil); err != nil {
		return err
	}
	return replacePrivateFile(filepath.Join(u.runtime.root, "uninstalled.json"), raw, i.PreviousTombstone)
}
func (u *uninstallLifecycle) readTombstone(ctx context.Context, r Request) ([]byte, error) {
	raw, err := readPrivate(filepath.Join(u.directory(r), "tombstone.json"), 4<<20)
	if err != nil {
		return nil, err
	}
	t, source, err := u.host.readRemovalTombstone(ctx, raw)
	if err != nil || source.identityDigest() != r.identityDigest() || t.Binding != binding(r) {
		return nil, errors.New("uninstall-tombstone-not-proven")
	}
	current, err := readPrivate(filepath.Join(u.runtime.root, "uninstalled.json"), 4<<20)
	if err != nil || !bytes.Equal(current, raw) {
		return nil, errors.New("uninstall-current-tombstone-changed")
	}
	return raw, nil
}

// A crash may publish the immutable receipt before its current-state pointer.
// Only the exact predecessor recorded before removal can be completed later.
func (u *uninstallLifecycle) tombstonePublished(ctx context.Context, r Request) (bool, error) {
	raw, err := readPrivate(filepath.Join(u.directory(r), "tombstone.json"), 4<<20)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	t, source, err := u.host.readRemovalTombstone(ctx, raw)
	if err != nil || source.identityDigest() != r.identityDigest() || t.Binding != binding(r) {
		return false, errors.New("uninstall-tombstone-not-proven")
	}
	i, _, err := u.plan(ctx, r, false)
	if err != nil {
		return false, err
	}
	current, err := readPrivate(filepath.Join(u.runtime.root, "uninstalled.json"), 4<<20)
	if os.IsNotExist(err) && len(i.PreviousTombstone) == 0 {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if bytes.Equal(current, raw) {
		return true, nil
	}
	if bytes.Equal(current, i.PreviousTombstone) {
		return false, nil
	}
	return false, errors.New("uninstall-current-tombstone-changed")
}
func (h installationHost) readRemovalTombstone(ctx context.Context, raw []byte) (removalTombstone, Request, error) {
	var t removalTombstone
	if len(raw) > 4<<20 || json.Unmarshal(raw, &t) != nil {
		return t, Request{}, errors.New("invalid-uninstall-tombstone")
	}
	r := Request{Protocol: Protocol, Operation: "apply", Job: t.Binding.Job, Node: t.Binding.Node, PlanDigest: t.Binding.Plan, Epoch: 1, Phase: "finalize", Spec: t.Spec, Uninstall: &t.Reference}
	canonical, _ := json.Marshal(t)
	if r.Validate() != nil || t.Format != 1 || t.Binding != binding(r) || !bytes.Equal(raw, canonical) || !validDigest(t.CaptureSHA256) || !validDigest(t.IntentSHA256) || !validDigest(t.PreservedSHA256) {
		return t, r, errors.New("invalid-uninstall-tombstone")
	}
	var intent uninstallIntent
	intentRaw, e := decodePrivateJSON(filepath.Join(h.root, "transitions", r.Job, "uninstall/intent.json"), &intent, 4<<20)
	if e != nil || sha(intentRaw) != t.IntentSHA256 || intent.Binding != binding(r) || intent.CaptureSHA256 != t.CaptureSHA256 || intent.PreservedSHA256 != t.PreservedSHA256 {
		return t, r, errors.New("uninstall-tombstone-intent-changed")
	}
	persisted, err := readPrivate(filepath.Join(h.root, "transitions", r.Job, "uninstall/tombstone.json"), 4<<20)
	if err != nil || !bytes.Equal(persisted, raw) {
		return t, r, errors.New("uninstall-tombstone-not-anchored")
	}
	return t, r, nil
}
func (h installationHost) uninstalledInventory(ctx context.Context, node string) (*Installation, error) {
	raw, err := readPrivate(filepath.Join(h.root, "uninstalled.json"), 4<<20)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t, r, err := h.readRemovalTombstone(ctx, raw)
	if err != nil || r.Node != node {
		return nil, errors.New("uninstalled-node-not-proven")
	}
	u := &uninstallLifecycle{runtime: &LocalRuntime{root: h.root}, backup: newTransitionBackup(h.root), host: h}
	u.backup.unit = h.unitPath
	u.backup.host = h
	if h.data != "" {
		u.backup.data = h.data
	}
	if h.logs != "" {
		u.backup.logs = h.logs
	}
	// Snapshot/capture validation is independent of current data bytes: a failed
	// reinstall may have appended events which must remain in the live queue.
	if _, _, err = u.plan(ctx, r, false); err != nil {
		return nil, err
	}
	if _, _, err = u.source(ctx, r); err != nil {
		return nil, err
	}
	captured, err := u.removalInstallation(ctx, r)
	if err != nil {
		return nil, err
	}
	absent, err := h.removedObject(ctx, captured.Installed)
	if err != nil || !absent {
		return nil, errors.New("uninstalled-service-not-absent")
	}
	if err = u.verifyPreservation(ctx, r, t.PreservedSHA256, true); err != nil {
		return nil, err
	}
	ref := &ReinstallReference{r.Job, r.PlanDigest, sha(raw)}
	return &Installation{Node: node, Generation: "absent", Services: []ServiceRecord{}, Removal: ref}, nil
}

func originalOrAbsent(path string, want []byte) (bool, error) {
	raw, err := readPrivate(path, 2<<20)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(raw, want) {
		return false, errors.New("effective-file-changed")
	}
	return true, nil
}
