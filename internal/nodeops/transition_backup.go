package nodeops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	"webscan/internal/nodepki"
	"webscan/internal/persist"
)

type installationQuiescer interface {
	inventory(context.Context, string, string) (Installation, error)
	stop(context.Context, Installation) error
	stopped(context.Context, Installation) (bool, error)
}

type transitionBackup struct {
	root, data, logs, unit string
	host                   installationQuiescer
}

func newTransitionBackup(root string) *transitionBackup {
	return &transitionBackup{root: root, data: agentDataDirectory, logs: agentLogDirectory, unit: nativeUnitPath, host: newInstallationHost(root)}
}

type transitionBinding struct{ Job, Node, Plan, Spec string }

func binding(r Request) transitionBinding {
	if r.Uninstall != nil || r.Reinstall != nil {
		return transitionBinding{r.Job, r.Node, r.PlanDigest, r.identityDigest()}
	}
	return transitionBinding{r.Job, r.Node, r.PlanDigest, r.Spec.digest()}
}

type backupFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}
type backupIntent struct {
	Format          int               `json:"format"`
	Binding         transitionBinding `json:"binding"`
	Installed       Installation      `json:"installed"`
	Files           []backupFile      `json:"files"`
	DatabasePresent *bool             `json:"database_present,omitempty"`
}
type backupSnapshot struct {
	Format        int               `json:"format"`
	Binding       transitionBinding `json:"binding"`
	IntentSHA256  string            `json:"intent_sha256"`
	Database      *backupFile       `json:"database,omitempty"`
	Logs          []backupFile      `json:"logs"`
	SecurityState []backupFile      `json:"security_state"`
	IdentityState []backupFile      `json:"identity_state,omitempty"`
}

func (b *transitionBackup) directory(r Request) string {
	return filepath.Join(b.root, "transitions", r.Job)
}

func (b *transitionBackup) prepareIntent(ctx context.Context, r Request) (backupIntent, error) {
	var empty backupIntent
	if r.Validate() != nil || !r.Spec.configurationValid() || b.host == nil {
		return empty, errors.New("invalid-backup-request")
	}
	if err := privateDirectoryTree(b.root); err != nil {
		return empty, err
	}
	parent := filepath.Join(b.root, "transitions")
	if err := ensurePrivateDirectory(parent); err != nil {
		return empty, err
	}
	job := b.directory(r)
	if err := ensurePrivateDirectory(job); err != nil {
		return empty, err
	}
	capture := filepath.Join(job, "capture")
	if _, err := os.Lstat(capture); !os.IsNotExist(err) {
		return b.readIntent(ctx, r)
	}
	installed, err := b.host.inventory(ctx, r.Node, r.Spec.Mode)
	if err != nil || !installed.valid(r.Node) {
		return empty, errors.New("installation-ownership-not-proven")
	}
	if !sameReinstall(installed.Removal, r.Reinstall) {
		return empty, errors.New("reinstall-source-not-proven")
	}
	stage, err := os.MkdirTemp(job, ".capture-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(stage)
	intent := backupIntent{Format: 1, Binding: binding(r), Installed: installed, Files: []backupFile{}}
	databasePresent := false
	databasePath := filepath.Join(b.data, "agent.sqlite3")
	if _, err := os.Lstat(databasePath); err == nil {
		if err := privateFile(databasePath, false); err != nil {
			return empty, err
		}
		databasePresent = true
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	intent.DatabasePresent = &databasePresent
	if installed.Runtime != "" {
		files, err := copyPrivateTree(ctx, filepath.Dir(installed.Runtime), filepath.Join(stage, "config"), "config", 16<<20, 2048, nil)
		if err != nil {
			return empty, err
		}
		intent.Files = append(intent.Files, files...)
	}
	for _, s := range installed.Services {
		if s.Kind == "native" {
			f, err := copyBackupFile(ctx, b.unit, filepath.Join(stage, "native.service"), "native.service", 64<<10)
			if err != nil || f.SHA256 != s.Proof {
				return empty, errors.New("native-snapshot-identity-mismatch")
			}
			intent.Files = append(intent.Files, f)
		}
	}
	active := filepath.Join(b.root, "active.json")
	if _, err := os.Lstat(active); err == nil {
		f, err := copyBackupFile(ctx, active, filepath.Join(stage, "active.json"), "active.json", MaxRequestBytes)
		if err != nil {
			return empty, err
		}
		intent.Files = append(intent.Files, f)
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	sort.Slice(intent.Files, func(i, j int) bool { return intent.Files[i].Path < intent.Files[j].Path })
	raw, _ := json.Marshal(intent)
	if err := writePrivate(filepath.Join(stage, "intent.json"), bytes.NewReader(raw), int64(len(raw)), 0600); err != nil {
		return empty, err
	}
	if err := syncTreeDirectories(stage); err != nil {
		return empty, err
	}
	if err := renameNoReplace(stage, capture); err != nil {
		return empty, err
	}
	if err := syncDirectory(job); err != nil {
		return empty, err
	}
	return b.readIntent(ctx, r)
}

func decodePrivateJSON(path string, dst any, limit int64) ([]byte, error) {
	raw, err := readPrivate(path, limit)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid-private-receipt")
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errors.New("invalid-private-receipt")
	}
	return raw, nil
}
func (b *transitionBackup) readIntent(ctx context.Context, r Request) (backupIntent, error) {
	var i backupIntent
	root := filepath.Join(b.directory(r), "capture")
	if err := privateDirectoryTree(root); err != nil {
		return i, err
	}
	_, err := decodePrivateJSON(filepath.Join(root, "intent.json"), &i, 4<<20)
	if err != nil || i.Format != 1 || i.Binding != binding(r) || !i.Installed.valid(r.Node) || len(i.Files) > 2050 {
		return i, errors.New("backup-intent-mismatch")
	}
	if !sameReinstall(i.Installed.Removal, r.Reinstall) {
		return i, errors.New("reinstall-capture-source-changed")
	}
	if err := b.verifyWrapperMembers(r, i.Installed); err != nil {
		return i, err
	}
	seen := map[string]bool{}
	for _, f := range i.Files {
		if !validBackupPath(f.Path) || seen[f.Path] || !(strings.HasPrefix(f.Path, "config/") || f.Path == "native.service" || f.Path == "active.json") {
			return i, errors.New("invalid-capture-file")
		}
		seen[f.Path] = true
		if err := verifyBackupFile(ctx, filepath.Join(root, f.Path), f); err != nil {
			return i, err
		}
	}
	if err := exactBackupTree(ctx, root, seen, "intent.json"); err != nil {
		return i, err
	}
	return i, nil
}
func validBackupPath(p string) bool {
	return p != "" && p != "." && !filepath.IsAbs(p) && filepath.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\x00\r\n\\")
}

// A manifest must describe the entire private artifact. Accepting unlisted
// files could silently carry an unverified key, unit or rollback log forward.
func exactBackupTree(ctx context.Context, root string, files map[string]bool, metadata string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return privateDirectoryTree(path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || !validBackupPath(relative) || !files[relative] && relative != metadata {
			return errors.New("unlisted-backup-file")
		}
		return privateFile(path, false)
	})
}

func (b *transitionBackup) unchanged(ctx context.Context, i backupIntent) error {
	config := map[string]bool{}
	for _, f := range i.Files {
		var source string
		switch {
		case strings.HasPrefix(f.Path, "config/"):
			relative := strings.TrimPrefix(f.Path, "config/")
			config[relative] = true
			source = filepath.Join(filepath.Dir(i.Installed.Runtime), relative)
		case f.Path == "native.service":
			source = b.unit
		case f.Path == "active.json":
			source = filepath.Join(b.root, "active.json")
		default:
			return errors.New("invalid-capture-file")
		}
		if err := verifyBackupFile(ctx, source, f); err != nil {
			return errors.New("installed-files-changed")
		}
	}
	if i.Installed.Runtime != "" {
		if err := exactBackupTree(ctx, filepath.Dir(i.Installed.Runtime), config, ""); err != nil {
			return errors.New("installed-files-changed")
		}
	}
	return nil
}

// run publishes intent/configs before stopping a writer. A retry reuses that
// original service state; it never mistakes an already-stopped service for the
// state that should be restored. A published snapshot is immutable.
func (b *transitionBackup) run(ctx context.Context, r Request) (backupSnapshot, error) {
	var empty backupSnapshot
	if r.Operation != "apply" || r.Phase != "backup" || r.Validate() != nil || ctx.Err() != nil {
		return empty, errors.New("invalid-backup-request")
	}
	ctx, release, err := acquireServiceOperation(ctx, b.root)
	if err != nil {
		return empty, err
	}
	defer release()
	if err := b.beginAttempt(r); err != nil {
		return empty, err
	}
	i, err := b.prepareIntent(ctx, r)
	if err != nil {
		return empty, err
	}
	if err := b.unchanged(ctx, i); err != nil {
		return empty, err
	}
	// Calculate space before changing service state, then check again with the
	// writers stopped. Unmanaged writers are not killed if their lock is busy.
	if err := b.checkSpace(ctx, r); err != nil {
		return empty, err
	}
	if err := b.beforeQuiesce(r); err != nil {
		return empty, err
	}
	if err := b.host.stop(ctx, i.Installed); err != nil {
		return empty, err
	}
	stopped, err := b.host.stopped(ctx, i.Installed)
	if err != nil || !stopped {
		return empty, errors.New("node-writers-not-stopped")
	}
	lock, err := b.agentLock()
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	if err := b.unchanged(ctx, i); err != nil {
		return empty, err
	}
	if _, err := os.Lstat(filepath.Join(b.directory(r), "snapshot")); !os.IsNotExist(err) {
		return b.verify(ctx, r)
	}
	if err := b.checkSpace(ctx, r); err != nil {
		return empty, err
	}
	stage, err := os.MkdirTemp(b.directory(r), ".snapshot-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(stage)
	intentRaw, err := readPrivate(filepath.Join(b.directory(r), "capture/intent.json"), 4<<20)
	if err != nil {
		return empty, err
	}
	s := backupSnapshot{Format: 1, Binding: binding(r), IntentSHA256: sha(intentRaw), Logs: []backupFile{}, SecurityState: []backupFile{}}
	dbfile := filepath.Join(b.data, "agent.sqlite3")
	if _, err := os.Lstat(dbfile); err == nil {
		for _, name := range []string{"agent.sqlite3", "agent.sqlite3-wal", "agent.sqlite3-shm"} {
			if err := privateFile(filepath.Join(b.data, name), name != "agent.sqlite3"); err != nil {
				return empty, err
			}
		}
		db, err := persist.OpenReadOnly(dbfile)
		if err != nil {
			return empty, err
		}
		err = persist.BackupDB(db, filepath.Join(stage, "agent.sqlite3"))
		closeErr := db.Close()
		if err != nil {
			return empty, err
		}
		if closeErr != nil {
			return empty, closeErr
		}
		f, err := describePrivateFile(ctx, filepath.Join(stage, "agent.sqlite3"), "agent.sqlite3", 1<<63-1)
		if err != nil {
			return empty, err
		}
		if err := checkSQLiteSnapshot(filepath.Join(stage, "agent.sqlite3")); err != nil {
			return empty, err
		}
		s.Database = &f
	} else if !os.IsNotExist(err) {
		return empty, err
	} else if i.DatabasePresent != nil && *i.DatabasePresent {
		return empty, errors.New("live-agent-database-missing")
	}
	if _, err := os.Lstat(b.logs); err == nil {
		s.Logs, err = copyPrivateTree(ctx, b.logs, filepath.Join(stage, "logs"), "logs", 1<<63-1, 100000, func(path string, d os.DirEntry) bool { return !d.IsDir() && strings.HasSuffix(path, ".jsonl") })
		if err != nil {
			return empty, err
		}
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	pki := filepath.Join(b.data, "pki-trust")
	if _, err := os.Lstat(pki); err == nil {
		s.SecurityState, err = copyPrivateTree(ctx, pki, filepath.Join(stage, "security"), "security", 8<<20, 16, nil)
		if err != nil {
			return empty, err
		}
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	// Node leaf state and its private history live outside replaceable runtime
	// configurations. Back them up before switching; never restore over live
	// state on ordinary rollback (the same rule as CRL floors and event queues).
	identity := filepath.Join(b.data, "pki-identity")
	if _, err := os.Lstat(identity); err == nil {
		err = nodepki.WithIdentitySnapshot(ctx, identity, func() error {
			var copyErr error
			s.IdentityState, copyErr = copyPrivateTree(ctx, identity, filepath.Join(stage, "identity"), "identity", 32<<20, 4096, nil)
			return copyErr
		})
		if err != nil {
			return empty, err
		}
	} else if !os.IsNotExist(err) {
		return empty, err
	}
	raw, _ := json.Marshal(s)
	if err := writePrivate(filepath.Join(stage, "receipt.json"), bytes.NewReader(raw), int64(len(raw)), 0600); err != nil {
		return empty, err
	}
	if err := syncTreeDirectories(stage); err != nil {
		return empty, err
	}
	if err := renameNoReplace(stage, filepath.Join(b.directory(r), "snapshot")); err != nil {
		return empty, err
	}
	if err := syncDirectory(b.directory(r)); err != nil {
		return empty, err
	}
	return b.verify(ctx, r)
}

func (b *transitionBackup) verify(ctx context.Context, r Request) (backupSnapshot, error) {
	var s backupSnapshot
	if r.Validate() != nil || !r.Spec.configurationValid() {
		return s, errors.New("invalid-backup-request")
	}
	captured, err := b.readIntent(ctx, r)
	if err != nil {
		return s, err
	}
	root := filepath.Join(b.directory(r), "snapshot")
	if err := privateDirectoryTree(root); err != nil {
		return s, err
	}
	_, err = decodePrivateJSON(filepath.Join(root, "receipt.json"), &s, 16<<20)
	intent, readErr := readPrivate(filepath.Join(b.directory(r), "capture/intent.json"), 4<<20)
	if err != nil || readErr != nil || s.Format != 1 || s.Binding != binding(r) || s.IntentSHA256 != sha(intent) || len(s.Logs) > 100000 || len(s.SecurityState) > 16 || len(s.IdentityState) > 4096 {
		return s, errors.New("backup-receipt-mismatch")
	}
	if captured.DatabasePresent != nil && *captured.DatabasePresent && s.Database == nil {
		return s, errors.New("backup-database-missing")
	}
	files := append(append(append([]backupFile{}, s.Logs...), s.SecurityState...), s.IdentityState...)
	if s.Database != nil {
		if s.Database.Path != "agent.sqlite3" {
			return s, errors.New("invalid-backup-database")
		}
		files = append(files, *s.Database)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if !validBackupPath(f.Path) || seen[f.Path] || !(f.Path == "agent.sqlite3" || strings.HasPrefix(f.Path, "logs/") && strings.HasSuffix(f.Path, ".jsonl") || strings.HasPrefix(f.Path, "security/") || strings.HasPrefix(f.Path, "identity/")) {
			return s, errors.New("invalid-backup-file")
		}
		seen[f.Path] = true
		if err := verifyBackupFile(ctx, filepath.Join(root, f.Path), f); err != nil {
			return s, err
		}
	}
	if err := exactBackupTree(ctx, root, seen, "receipt.json"); err != nil {
		return s, err
	}
	if s.Database != nil {
		if err := checkSQLiteSnapshot(filepath.Join(root, "agent.sqlite3")); err != nil {
			return s, err
		}
	}
	return s, nil
}

func checkSQLiteSnapshot(path string) error {
	db, err := persist.OpenReadOnly(path)
	if err != nil {
		return err
	}
	defer db.Close()
	var result string
	if err := db.QueryRow("PRAGMA quick_check(1)").Scan(&result); err != nil || result != "ok" {
		return errors.New("backup-database-check-failed")
	}
	return nil
}

func (b *transitionBackup) agentLock() (*os.File, error) {
	if err := ensurePrivateDirectory(b.data); err != nil {
		return nil, err
	}
	path := filepath.Join(b.data, "agent.lock")
	if err := privateFile(path, true); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("unmanaged-agent-writer-active")
	}
	if err := privateFile(path, false); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (b *transitionBackup) checkSpace(ctx context.Context, r Request) error {
	var needed uint64 = 64 << 20
	for _, root := range []string{b.data, b.logs} {
		if _, err := os.Lstat(root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := privateDirectoryTree(root); err != nil {
			return err
		}
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			security := root == b.data && (relative == "pki-identity" || strings.HasPrefix(relative, "pki-identity/") || relative == "pki-trust" || strings.HasPrefix(relative, "pki-trust/"))
			if d.IsDir() {
				if security {
					return privateDirectoryTree(path)
				}
				return nil
			}
			if security {
				if err := privateFile(path, false); err != nil {
					return err
				}
			}
			if root == b.logs && !strings.HasSuffix(path, ".jsonl") {
				return nil
			}
			if root == b.data && !security && filepath.Base(path) != "agent.sqlite3" && filepath.Base(path) != "agent.sqlite3-wal" {
				return nil
			}
			st, err := os.Lstat(path)
			if err != nil || !st.Mode().IsRegular() || st.Size() < 0 {
				return errors.New("unsafe-backup-source")
			}
			size := uint64(st.Size())
			if root == b.data {
				if size > (^uint64(0)-needed)/2 {
					return errors.New("backup-space-overflow")
				}
				size *= 2
			}
			if size > ^uint64(0)-needed {
				return errors.New("backup-space-overflow")
			}
			needed += size
			return nil
		})
		if err != nil {
			return err
		}
	}
	free, _, err := filesystemFree(b.directory(r))
	if err != nil || free < needed {
		return errors.New("insufficient-backup-space")
	}
	return nil
}

func describePrivateFile(ctx context.Context, path, name string, limit int64) (backupFile, error) {
	var out backupFile
	f, err := openPrivateFile(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 0 || st.Size() > limit {
		return out, errors.New("backup-file-size-invalid")
	}
	digest, err := fileDigest(ctx, f, limit)
	if err != nil {
		return out, err
	}
	return backupFile{Path: name, Bytes: st.Size(), SHA256: digest, Mode: uint32(st.Mode().Perm())}, nil
}
func verifyBackupFile(ctx context.Context, path string, want backupFile) error {
	if want.Bytes < 0 || !validDigest(want.SHA256) || want.Mode&0077 != 0 || want.Mode > 0700 {
		return errors.New("invalid-backup-file")
	}
	got, err := describePrivateFile(ctx, path, want.Path, want.Bytes)
	if err != nil || got != want {
		return errors.New("backup-file-changed")
	}
	return nil
}
func copyBackupFile(ctx context.Context, source, target, name string, limit int64) (backupFile, error) {
	var out backupFile
	f, err := openPrivateFile(source)
	if err != nil {
		return out, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 0 || st.Size() > limit {
		return out, errors.New("backup-file-size-invalid")
	}
	if err := ensurePrivateDirectory(filepath.Dir(target)); err != nil {
		return out, err
	}
	h := sha256.New()
	if err := writePrivate(target, io.TeeReader(&contextReader{ctx, f}, h), st.Size(), st.Mode().Perm()); err != nil {
		return out, err
	}
	return backupFile{Path: name, Bytes: st.Size(), SHA256: hex.EncodeToString(h.Sum(nil)), Mode: uint32(st.Mode().Perm())}, nil
}
func copyPrivateTree(ctx context.Context, source, target, prefix string, maxBytes int64, maxFiles int, accept func(string, os.DirEntry) bool) ([]backupFile, error) {
	files := []backupFile{}
	var total int64
	if err := privateDirectoryTree(source); err != nil {
		return nil, err
	}
	err := filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return privateDirectoryTree(path)
		}
		if accept != nil && !accept(path, d) {
			return nil
		}
		if len(files) >= maxFiles {
			return errors.New("too-many-backup-files")
		}
		rel, err := filepath.Rel(source, path)
		if err != nil || !validBackupPath(rel) {
			return errors.New("unsafe-backup-source")
		}
		file, err := copyBackupFile(ctx, path, filepath.Join(target, rel), filepath.Join(prefix, rel), maxBytes-total)
		if err != nil {
			return err
		}
		total += file.Bytes
		files = append(files, file)
		return nil
	})
	return files, err
}
