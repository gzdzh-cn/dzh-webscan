package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var errSingleBackup = errors.New("单中心备份未完成或恢复资料校验失败；请检查安装绑定、权限、空间和维护任务，原服务及密钥未替换")

type singleBackupSource struct {
	Path        string `json:"source"`
	Destination string `json:"destination"`
	Directory   bool   `json:"directory"`
}

// Private recovery metadata retains original executable modes. Every archived
// file is private 0600; staging never installs executable files into live paths.
type singleBackupMode struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}

func singleBackupContains(parent, child string) bool {
	return parent == child || strings.HasPrefix(child, parent+string(filepath.Separator))
}

// Roots come from the verified installation and host configuration, never a
// browser request. Database and VM live directories are expressly excluded;
// those engines have their own consistent export/snapshot components.
func normalizeSingleBackupSources(root string, files, directories []string, output string) ([]singleBackupSource, error) {
	if !snapshotAbsolutePath(root) || !snapshotAbsolutePath(output) || singleBackupContains(root, output) || singleBackupContains(output, root) {
		return nil, errSingleBackup
	}
	dirs := []string{root}
	dirs = append(dirs, directories...)
	sort.Strings(dirs)
	kept := []string{}
	for _, directory := range dirs {
		if !snapshotAbsolutePath(directory) || singleBackupContains(directory, output) || singleBackupContains(output, directory) {
			return nil, errSingleBackup
		}
		// Never silently absorb a runtime dependency placed in either live
		// engine directory. The logical archive cannot replace that material.
		for _, engine := range []string{"postgres-data", "metrics-data"} {
			if singleBackupContains(filepath.Join(root, engine), directory) {
				return nil, errSingleBackup
			}
		}
		covered := false
		for _, existing := range kept {
			covered = covered || singleBackupContains(existing, directory)
		}
		if !covered {
			// External roots may not cover the installation's parent or any
			// other broad filesystem tree. Each is an explicit private subtree.
			if directory != root && singleBackupContains(directory, root) {
				return nil, errSingleBackup
			}
			kept = append(kept, directory)
		}
	}
	out := []singleBackupSource{}
	for _, directory := range kept {
		out = append(out, singleBackupSource{Path: directory, Destination: "host/tree-" + strconv.Itoa(len(out)), Directory: true})
	}
	sort.Strings(files)
	previous := ""
	for _, file := range files {
		if !snapshotAbsolutePath(file) || singleBackupContains(output, file) || singleBackupContains(file, output) {
			return nil, errSingleBackup
		}
		for _, engine := range []string{"postgres-data", "metrics-data"} {
			if singleBackupContains(filepath.Join(root, engine), file) {
				return nil, errSingleBackup
			}
		}
		covered := file == previous
		previous = file
		for _, directory := range kept {
			covered = covered || singleBackupContains(directory, file)
		}
		if !covered {
			out = append(out, singleBackupSource{Path: file, Destination: "host/file-" + strconv.Itoa(len(out))})
		}
	}
	return out, nil
}

func singleBackupSkip(relative, name string) bool {
	if name == ".lock" || name == ".pki-maintenance.lock" {
		return true // Locks are recreated and are not recovery state.
	}
	return relative == "" && (name == "postgres-data" || name == "metrics-data")
}

func captureSingleBackupTree(ctx context.Context, source, target *os.File, prefix, relative string, installation bool, manifest *metricsSnapshotManifest, modes *[]singleBackupMode, total *int64) error {
	if ctx.Err() != nil || len(manifest.Files)+len(manifest.Directories) >= metricsSnapshotMaxFiles {
		return errSingleBackup
	}
	manifest.Directories = append(manifest.Directories, prefix)
	entries, err := snapshotEntries(source)
	if err != nil {
		return errSingleBackup
	}
	for _, entry := range entries {
		if (installation && singleBackupSkip(relative, entry.Name())) || (!installation && entry.Name() == ".lock") {
			// Validate excluded lock names too: a link/device pretending to be
			// a lock or engine path must not hide a required recovery file.
			st, err := singleBackupInfo(source, entry.Name())
			engine := relative == "" && installation && (entry.Name() == "postgres-data" || entry.Name() == "metrics-data")
			if err != nil || st.Mode()&os.ModeSymlink != 0 || engine && !st.IsDir() || !engine && (!singleBackupHostFile(st) || st.Size() != 0) {
				return fmt.Errorf("excluded entry %s/%s: %w", prefix, entry.Name(), errSingleBackup)
			}
			continue
		}
		item := path.Join(prefix, entry.Name())
		if !validSnapshotRelative(item) || len(manifest.Files)+len(manifest.Directories) >= metricsSnapshotMaxFiles {
			return errSingleBackup
		}
		if entry.IsDir() {
			from, err := openSnapshotDirectory(source, entry.Name())
			if err != nil {
				return errSingleBackup
			}
			var to *os.File
			if target != nil {
				if err := unix.Mkdirat(int(target.Fd()), entry.Name(), 0700); err != nil {
					from.Close()
					return errSingleBackup
				}
				to, err = openSnapshotDirectory(target, entry.Name())
				if err != nil {
					from.Close()
					return errSingleBackup
				}
			}
			err = captureSingleBackupTree(ctx, from, to, item, path.Join(relative, entry.Name()), installation, manifest, modes, total)
			from.Close()
			if to != nil {
				if to.Sync() != nil {
					err = errSingleBackup
				}
				to.Close()
			}
			if err != nil {
				return err
			}
			continue
		}
		st, err := singleBackupInfo(source, entry.Name())
		if err != nil || !singleBackupHostFile(st) {
			return fmt.Errorf("host entry %s: %w", item, errSingleBackup)
		}
		file, err := copySnapshotFile(ctx, source, target, entry.Name(), false, metricsSnapshotMaxBytes-*total)
		if err != nil {
			return fmt.Errorf("host copy %s: %w", item, errSingleBackup)
		}
		file.Path = item
		manifest.Files = append(manifest.Files, file)
		*modes = append(*modes, singleBackupMode{Path: item, Mode: uint32(st.Mode().Perm())})
		*total += file.Bytes
	}
	return nil
}

// Compare a second descriptor-based capture after all components are written.
// The shared PKI/database locks prevent supported writers; this detects an
// out-of-band administrator change and refuses to publish a mixed archive.
func captureSingleBackupHost(ctx context.Context, root string, sources []singleBackupSource, target *os.File) (metricsSnapshotManifest, []singleBackupMode, error) {
	manifest := metricsSnapshotManifest{Files: []metricsSnapshotFile{}, Directories: []string{}}
	modes := []singleBackupMode{}
	var total int64
	for _, source := range sources {
		name := path.Base(source.Destination)
		if source.Directory {
			from, err := trustDirectory(source.Path, true)
			if err != nil {
				return manifest, nil, errSingleBackup
			}
			var to *os.File
			if target != nil {
				if unix.Mkdirat(int(target.Fd()), name, 0700) != nil {
					from.Close()
					return manifest, nil, errSingleBackup
				}
				to, err = openSnapshotDirectory(target, name)
				if err != nil {
					from.Close()
					return manifest, nil, errSingleBackup
				}
			}
			err = captureSingleBackupTree(ctx, from, to, source.Destination, "", source.Path == root, &manifest, &modes, &total)
			from.Close()
			if to != nil {
				if to.Sync() != nil {
					err = errSingleBackup
				}
				to.Close()
			}
			if err != nil {
				return manifest, nil, fmt.Errorf("host tree %s: %w", source.Destination, err)
			}
		} else {
			from, err := trustDirectory(filepath.Dir(source.Path), false)
			if err != nil {
				return manifest, nil, fmt.Errorf("host parent %s: %w", source.Destination, errSingleBackup)
			}
			// The flat destination has a generated name; copy through a pinned
			// private intermediate directory without buffering a large artifact.
			st, err := singleBackupInfo(from, filepath.Base(source.Path))
			if err != nil || !singleBackupHostFile(st) {
				from.Close()
				return manifest, nil, fmt.Errorf("host file %s: %w", source.Destination, errSingleBackup)
			}
			file, err := copySnapshotFile(ctx, from, nil, filepath.Base(source.Path), false, metricsSnapshotMaxBytes-total)
			if err == nil && target != nil {
				err = copySingleBackupNamedFile(ctx, from, filepath.Base(source.Path), target, name, file)
			}
			from.Close()
			if err != nil {
				return manifest, nil, fmt.Errorf("host flat copy %s: %w", source.Destination, errSingleBackup)
			}
			file.Path = source.Destination
			manifest.Files = append(manifest.Files, file)
			modes = append(modes, singleBackupMode{Path: file.Path, Mode: uint32(st.Mode().Perm())})
			total += file.Bytes
		}
	}
	sort.Strings(manifest.Directories)
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	sort.Slice(modes, func(i, j int) bool { return modes[i].Path < modes[j].Path })
	return manifest, modes, nil
}

func sameSingleBackupHost(a, b metricsSnapshotManifest, am, bm []singleBackupMode) bool {
	return reflect.DeepEqual(a.Directories, b.Directories) && reflect.DeepEqual(a.Files, b.Files) && reflect.DeepEqual(am, bm)
}

// Use the same bounded copier for generated names: a temporary pinned
// directory keeps copySnapshotFile's no-follow and cancellation guarantees.
func copySingleBackupNamedFile(ctx context.Context, from *os.File, name string, to *os.File, output string, expected metricsSnapshotFile) error {
	temp := ".copy-" + token()
	if unix.Mkdirat(int(to.Fd()), temp, 0700) != nil {
		return errSingleBackup
	}
	dir, err := openSnapshotDirectory(to, temp)
	if err != nil {
		return errSingleBackup
	}
	defer func() {
		_ = removeSnapshotStage(dir)
		dir.Close()
		_ = unix.Unlinkat(int(to.Fd()), temp, unix.AT_REMOVEDIR)
	}()
	actual, err := copySnapshotFile(ctx, from, dir, name, false, expected.Bytes)
	if err != nil || actual.Bytes != expected.Bytes || actual.SHA256 != expected.SHA256 {
		return errSingleBackup
	}
	if unix.Linkat(int(dir.Fd()), name, int(to.Fd()), output, 0) != nil || unix.Unlinkat(int(dir.Fd()), name, 0) != nil || to.Sync() != nil {
		return errSingleBackup
	}
	return nil
}

func singleBackupHostFile(st os.FileInfo) bool {
	if st == nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Mode().Perm()&0400 == 0 {
		return false
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && owner.Nlink == 1 && owner.Uid == uint32(os.Geteuid())
}

// DirEntry.Info would resolve against os.File.Name, which is deliberately only
// a diagnostic label on descriptor-relative directory handles. Inspect through
// that descriptor instead, without following links or blocking on a FIFO.
func singleBackupInfo(directory *os.File, name string) (os.FileInfo, error) {
	var initial unix.Stat_t
	if unix.Fstatat(int(directory.Fd()), name, &initial, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return nil, errSingleBackup
	}
	kind := uint32(initial.Mode) & unix.S_IFMT
	if kind != unix.S_IFREG && kind != unix.S_IFDIR {
		return nil, errSingleBackup
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errSingleBackup
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return f.Stat()
}

func writeSingleBackupJSON(directory *os.File, name string, value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 64<<20 {
		return nil, errSingleBackup
	}
	f, err := createSnapshotFile(directory, name)
	if err != nil {
		return nil, errSingleBackup
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil || f.Sync() != nil {
		return nil, errSingleBackup
	}
	return raw, nil
}
