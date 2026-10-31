package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type metricsSnapshotStage struct {
	parent, directory  *os.File
	name, path, output string
	published          bool
}

func newMetricsSnapshotStage(output string) (*metricsSnapshotStage, error) {
	if !snapshotAbsolutePath(output) {
		return nil, errMetricsSnapshot
	}
	parent, err := trustDirectory(filepath.Dir(output), true)
	if err != nil {
		return nil, errMetricsSnapshot
	}
	s := &metricsSnapshotStage{parent: parent, output: output, name: ".metrics-backup-" + token()}
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), filepath.Base(output), &stat, unix.AT_SYMLINK_NOFOLLOW); err != unix.ENOENT {
		parent.Close()
		return nil, errMetricsSnapshot
	}
	if unix.Mkdirat(int(parent.Fd()), s.name, 0700) != nil {
		parent.Close()
		return nil, errMetricsSnapshot
	}
	s.path = filepath.Join(filepath.Dir(output), s.name)
	fd, err := unix.Openat(int(parent.Fd()), s.name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Unlinkat(int(parent.Fd()), s.name, unix.AT_REMOVEDIR)
		parent.Close()
		return nil, errMetricsSnapshot
	}
	s.directory = os.NewFile(uintptr(fd), s.path)
	return s, nil
}

func (s *metricsSnapshotStage) close() {
	if !s.published {
		// Remove only this operation's pinned, newly created tree. Never
		// traverse a replacement path while unwinding a failed copy.
		_ = removeSnapshotStage(s.directory)
		_ = unix.Unlinkat(int(s.parent.Fd()), s.name, unix.AT_REMOVEDIR)
	}
	s.directory.Close()
	s.parent.Close()
}

func removeSnapshotStage(dir *os.File) error {
	entries, err := snapshotEntries(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			child, err := openSnapshotDirectory(dir, entry.Name())
			if err != nil {
				return err
			}
			err = removeSnapshotStage(child)
			child.Close()
			if err != nil || unix.Unlinkat(int(dir.Fd()), entry.Name(), unix.AT_REMOVEDIR) != nil {
				return errMetricsSnapshot
			}
		} else if unix.Unlinkat(int(dir.Fd()), entry.Name(), 0) != nil {
			return errMetricsSnapshot
		}
	}
	return nil
}

func (s *metricsSnapshotStage) publish(ctx context.Context) error {
	if ctx.Err() != nil || s.directory.Sync() != nil || publishTrustDirectory(int(s.parent.Fd()), s.name, filepath.Base(s.output)) != nil {
		return errMetricsSnapshot
	}
	s.published = true
	if s.parent.Sync() != nil {
		return errMetricsSnapshot
	}
	return nil
}

func (s *metricsSnapshotStage) writeManifest(raw []byte) error {
	f, err := createSnapshotFile(s.directory, "snapshot.json")
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil || f.Sync() != nil {
		return errMetricsSnapshot
	}
	return nil
}

func openSnapshotDirectory(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errMetricsSnapshot
	}
	f := os.NewFile(uintptr(fd), name)
	st, err := f.Stat()
	if err != nil || !snapshotOwned(st) || st.Mode().Perm()&0022 != 0 {
		f.Close()
		return nil, errMetricsSnapshot
	}
	return f, nil
}

func snapshotOwned(st os.FileInfo) bool {
	if st == nil {
		return false
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && (owner.Uid == 0 || owner.Uid == uint32(os.Geteuid()))
}

func snapshotEntries(dir *os.File) ([]os.DirEntry, error) {
	// A separate descriptor keeps traversal repeatable without sharing offsets
	// with recursive readers or verification passes.
	f, err := openSnapshotDirectory(dir, ".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries := []os.DirEntry{}
	for {
		batch, err := f.ReadDir(1024)
		entries = append(entries, batch...)
		if len(entries) > metricsSnapshotMaxFiles {
			return nil, errMetricsSnapshot
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errMetricsSnapshot
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func createSnapshotFile(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errMetricsSnapshot
	}
	return os.NewFile(uintptr(fd), name), nil
}

func copySnapshotFile(ctx context.Context, source, destination *os.File, name string, private bool, budget int64) (metricsSnapshotFile, error) {
	fd, err := unix.Openat(int(source.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return metricsSnapshotFile{}, errMetricsSnapshot
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !snapshotOwned(before) || !before.Mode().IsRegular() || before.Size() > budget || before.Mode().Perm()&0022 != 0 {
		return metricsSnapshotFile{}, errMetricsSnapshot
	}
	// Source VM parts are intentionally hard-linked; a backup tree is not.
	if private {
		owner := before.Sys().(*syscall.Stat_t)
		if owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || before.Mode().Perm() != 0600 {
			return metricsSnapshotFile{}, errMetricsSnapshot
		}
	}
	var out *os.File
	if destination != nil {
		out, err = createSnapshotFile(destination, name)
		if err != nil {
			return metricsSnapshotFile{}, err
		}
		defer out.Close()
	}
	hash := sha256.New()
	writer := io.Writer(hash)
	if out != nil {
		writer = io.MultiWriter(out, hash)
	}
	// Checking cancellation between bounded reads prevents a large part from
	// holding a canceled backup/restore indefinitely.
	buffer := make([]byte, 256<<10)
	var copied int64
	for {
		if ctx.Err() != nil {
			return metricsSnapshotFile{}, ctx.Err()
		}
		n, readErr := f.Read(buffer)
		if copied+int64(n) > before.Size() {
			return metricsSnapshotFile{}, errMetricsSnapshot
		}
		if n > 0 {
			if _, err := writer.Write(buffer[:n]); err != nil {
				return metricsSnapshotFile{}, errMetricsSnapshot
			}
			copied += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return metricsSnapshotFile{}, errMetricsSnapshot
		}
	}
	after, err := f.Stat()
	if err != nil || copied != before.Size() || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || after.Size() != before.Size() || before.Mode() != after.Mode() {
		return metricsSnapshotFile{}, errMetricsSnapshot
	}
	if out != nil && out.Sync() != nil {
		return metricsSnapshotFile{}, errMetricsSnapshot
	}
	return metricsSnapshotFile{Path: name, Bytes: copied, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

// Copy a pinned tree without following deeper symlinks, device files or FIFO.
// The only allowed symlinks are resolved separately by captureMetricsSnapshot.
func walkMetricsSnapshot(ctx context.Context, source, target *os.File, prefix string, private bool, manifest *metricsSnapshotManifest, total *int64) error {
	if ctx.Err() != nil || len(manifest.Directories)+len(manifest.Files) >= metricsSnapshotMaxFiles {
		return errMetricsSnapshot
	}
	if private {
		st, err := source.Stat()
		if err != nil || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return errMetricsSnapshot
		}
	}
	encoded, _ := json.Marshal(prefix)
	manifest.encodedBytes += len(encoded) + 1
	if manifest.encodedBytes > (64<<20)-4096 {
		return errMetricsSnapshot
	}
	manifest.Directories = append(manifest.Directories, prefix)
	entries, err := snapshotEntries(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if len(manifest.Directories)+len(manifest.Files) >= metricsSnapshotMaxFiles || !validSnapshotRelative(path.Join(prefix, entry.Name())) {
			return errMetricsSnapshot
		}
		if entry.IsDir() {
			child, err := openSnapshotDirectory(source, entry.Name())
			if err != nil {
				return err
			}
			var destination *os.File
			if target != nil {
				if err := unix.Mkdirat(int(target.Fd()), entry.Name(), 0700); err != nil {
					child.Close()
					return errMetricsSnapshot
				}
				destination, err = openSnapshotDirectory(target, entry.Name())
				if err != nil {
					child.Close()
					return err
				}
			}
			err = walkMetricsSnapshot(ctx, child, destination, path.Join(prefix, entry.Name()), private, manifest, total)
			child.Close()
			if destination != nil {
				if destination.Sync() != nil {
					err = errMetricsSnapshot
				}
				destination.Close()
			}
			if err != nil {
				return err
			}
			continue
		}
		file, err := copySnapshotFile(ctx, source, target, entry.Name(), private, metricsSnapshotMaxBytes-*total)
		if err != nil || file.Bytes > metricsSnapshotMaxBytes-*total {
			return errMetricsSnapshot
		}
		*total += file.Bytes
		file.Path = path.Join(prefix, entry.Name())
		encoded, _ := json.Marshal(file)
		manifest.encodedBytes += len(encoded) + 1
		if manifest.encodedBytes > (64<<20)-4096 {
			return errMetricsSnapshot
		}
		manifest.Files = append(manifest.Files, file)
	}
	return nil
}

func captureMetricsSnapshot(ctx context.Context, storage, target *os.File, name string, manifest *metricsSnapshotManifest) error {
	snapshots, err := openSnapshotDirectory(storage, "snapshots")
	if err != nil {
		return err
	}
	defer snapshots.Close()
	snapshot, err := openSnapshotDirectory(snapshots, name)
	if err != nil {
		return err
	}
	defer snapshot.Close()
	entries, err := snapshotEntries(snapshot)
	if err != nil || len(entries) != 3 || entries[0].Name() != "data" || entries[1].Name() != "indexdb" || entries[2].Name() != "metadata" {
		return errMetricsSnapshot
	}
	data, err := openSnapshotDirectory(snapshot, "data")
	if err != nil {
		return err
	}
	defer data.Close()
	parts, err := snapshotEntries(data)
	if err != nil || len(parts) != 2 || parts[0].Name() != "big" || parts[1].Name() != "small" || unix.Mkdirat(int(target.Fd()), "data", 0700) != nil {
		return errMetricsSnapshot
	}
	destinationData, err := openSnapshotDirectory(target, "data")
	if err != nil {
		return err
	}
	defer destinationData.Close()
	manifest.Directories = append(manifest.Directories, "data")
	manifest.encodedBytes = len(`"data",`)
	var total int64
	for _, component := range []struct {
		parent, output  *os.File
		entry, resolved string
	}{
		{data, destinationData, "big", filepath.Join("data", "big", "snapshots", name)},
		{data, destinationData, "small", filepath.Join("data", "small", "snapshots", name)},
		{snapshot, target, "indexdb", filepath.Join("indexdb", "snapshots", name)},
		{snapshot, target, "metadata", ""},
	} {
		var from *os.File
		if component.resolved == "" {
			from, err = openSnapshotDirectory(component.parent, component.entry)
		} else {
			var link [4096]byte
			n, e := unix.Readlinkat(int(component.parent.Fd()), component.entry, link[:])
			base := filepath.Join("snapshots", name)
			if component.parent == data {
				base = filepath.Join(base, "data")
			}
			if e != nil || n == len(link) || filepath.IsAbs(string(link[:n])) || filepath.Clean(filepath.Join(base, string(link[:n]))) != component.resolved {
				return errMetricsSnapshot
			}
			// Open the expected path component-by-component from the pinned
			// storage descriptor; never follow the supplied symlink itself.
			from, err = openSnapshotComponents(storage, strings.Split(component.resolved, string(filepath.Separator)))
		}
		if err != nil {
			return err
		}
		if unix.Mkdirat(int(component.output.Fd()), component.entry, 0700) != nil {
			from.Close()
			return errMetricsSnapshot
		}
		to, err := openSnapshotDirectory(component.output, component.entry)
		if err != nil {
			from.Close()
			return err
		}
		prefix := component.entry
		if component.parent == data {
			prefix = path.Join("data", prefix)
		}
		err = walkMetricsSnapshot(ctx, from, to, prefix, false, manifest, &total)
		from.Close()
		if to.Sync() != nil {
			err = errMetricsSnapshot
		}
		to.Close()
		if err != nil {
			return err
		}
	}
	if destinationData.Sync() != nil {
		return errMetricsSnapshot
	}
	sort.Strings(manifest.Directories)
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	return nil
}

func openSnapshotComponents(root *os.File, parts []string) (*os.File, error) {
	dir, err := openSnapshotDirectory(root, ".")
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		next, e := openSnapshotDirectory(dir, part)
		dir.Close()
		if e != nil {
			return nil, e
		}
		dir = next
	}
	return dir, nil
}

func validSnapshotRelative(value string) bool {
	return value != "" && value != "." && path.Clean(value) == value && !strings.HasPrefix(value, "../") && !path.IsAbs(value) && !strings.ContainsAny(value, "\\\x00\r\n") && len(value) <= 4096
}

func readMetricsSnapshotManifest(directory, expected string) (metricsSnapshotManifest, error) {
	var manifest metricsSnapshotManifest
	raw, err := readTrustData(filepath.Join(directory, "snapshot.json"), true, 64<<20)
	if err != nil || !releaseDigest(expected) || digest(raw) != expected || singleDecode(raw, &manifest) != nil || manifest.Format != 1 || manifest.Engine != "victoriametrics-single" || !validMetricsSnapshotName(manifest.Snapshot) || manifest.Started.IsZero() || manifest.Completed.Before(manifest.Started) || len(manifest.Directories)+len(manifest.Files) > metricsSnapshotMaxFiles {
		return manifest, errMetricsSnapshot
	}
	return manifest, nil
}

// expected is supplied by the parent backup's verified manifest, never read
// from this tree itself. A self-checksum alone cannot authenticate an archive.
func verifyMetricsSnapshot(ctx context.Context, directory, expected string) (metricsSnapshotManifest, error) {
	manifest, err := readMetricsSnapshotManifest(directory, expected)
	if err != nil {
		return manifest, err
	}
	dir, err := trustDirectory(directory, true)
	if err != nil {
		return manifest, errMetricsSnapshot
	}
	defer dir.Close()
	actual := metricsSnapshotManifest{Files: []metricsSnapshotFile{}}
	var total int64
	entries, err := snapshotEntries(dir)
	if err != nil || len(entries) != 4 || entries[0].Name() != "data" || entries[1].Name() != "indexdb" || entries[2].Name() != "metadata" || entries[3].Name() != "snapshot.json" {
		return manifest, errMetricsSnapshot
	}
	for _, entry := range entries[:3] {
		from, err := openSnapshotDirectory(dir, entry.Name())
		if err != nil {
			return manifest, err
		}
		err = walkMetricsSnapshot(ctx, from, nil, entry.Name(), true, &actual, &total)
		from.Close()
		if err != nil {
			return manifest, err
		}
	}
	sort.Strings(actual.Directories)
	sort.Slice(actual.Files, func(i, j int) bool { return actual.Files[i].Path < actual.Files[j].Path })
	if !reflect.DeepEqual(manifest.Directories, actual.Directories) || !reflect.DeepEqual(manifest.Files, actual.Files) {
		return manifest, errMetricsSnapshot
	}
	return manifest, nil
}

// Stage a fresh data path for an OFFLINE isolated VictoriaMetrics instance.
// This never starts/stops a server or overwrites an existing storage directory.
func restoreMetricsSnapshot(ctx context.Context, directory, expected, output string) error {
	if !snapshotAbsolutePath(directory) || !snapshotAbsolutePath(output) || output == directory || strings.HasPrefix(output, directory+"/") || strings.HasPrefix(directory, output+"/") {
		return errMetricsSnapshot
	}
	manifest, err := verifyMetricsSnapshot(ctx, directory, expected)
	if err != nil {
		return err
	}
	stage, err := newMetricsSnapshotStage(output)
	if err != nil {
		return err
	}
	defer stage.close()
	source, err := trustDirectory(directory, true)
	if err != nil {
		return errMetricsSnapshot
	}
	defer source.Close()
	actual := metricsSnapshotManifest{Files: []metricsSnapshotFile{}}
	var total int64
	for _, name := range []string{"data", "indexdb", "metadata"} {
		from, err := openSnapshotDirectory(source, name)
		if err != nil {
			return err
		}
		if unix.Mkdirat(int(stage.directory.Fd()), name, 0700) != nil {
			from.Close()
			return errMetricsSnapshot
		}
		to, err := openSnapshotDirectory(stage.directory, name)
		if err != nil {
			from.Close()
			return err
		}
		err = walkMetricsSnapshot(ctx, from, to, name, true, &actual, &total)
		from.Close()
		if to.Sync() != nil {
			err = errMetricsSnapshot
		}
		to.Close()
		if err != nil {
			return err
		}
	}
	sort.Strings(actual.Directories)
	sort.Slice(actual.Files, func(i, j int) bool { return actual.Files[i].Path < actual.Files[j].Path })
	if !reflect.DeepEqual(manifest.Directories, actual.Directories) || !reflect.DeepEqual(manifest.Files, actual.Files) {
		return errMetricsSnapshot
	}
	return stage.publish(ctx)
}
