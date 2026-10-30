package nodeops

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxExpandedBundle = 1 << 30
const maxBundleFile = 256 << 20
const maxBundleFiles = 4096

// LocalRuntime prepares private, immutable release directories only. Installing
// services and restoring effective config remain unsupported until their own
// crash-reconciliation and data-preservation implementations are available.
type LocalRuntime struct {
	root       string
	probe      func(context.Context, string, Spec) error
	rulesProbe func(context.Context, string, string) error
	// Empty selects the fixed production Agent state directory. Kept separate
	// from immutable deployment files and never accepted in a remote request.
	identityData string
}

func NewLocalRuntime() *LocalRuntime {
	return &LocalRuntime{root: DeploymentRoot, probe: probeBundle}
}

func (*LocalRuntime) Supports(phase string) bool { return phase == "preflight" || phase == "stage" }

func (w *LocalRuntime) Apply(r Request) (Outcome, error) {
	if r.Phase == "preflight" {
		return (LocalPreflight{}).Apply(r)
	}
	if r.Phase != "stage" {
		return Outcome{}, Failure{"executor-unavailable"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := w.prepare(ctx, r.Spec); err != nil {
		return Outcome{}, Failure{"artifact-invalid"}
	}
	if r.Spec.Mode == "docker" {
		if err := prepareDockerImage(ctx, w.root, r.Spec); err != nil {
			return Outcome{Checks: []Check{{ID: "agent-image", Status: "failed", Code: "image-identity-not-verified"}}}, Failure{"artifact-invalid"}
		}
	}
	if r.Spec.configurationValid() {
		if err := w.prepareConfiguration(ctx, r); err != nil {
			return Outcome{Checks: []Check{{ID: "node-configuration", Status: "failed", Code: "configuration-not-verified"}}}, Failure{"artifact-invalid"}
		}
	}
	return stageOutcome(r.Spec), nil
}

func (w *LocalRuntime) Reconcile(r Request) (string, Outcome, error) {
	if r.Phase == "preflight" {
		return "absent", Outcome{}, nil
	}
	if r.Phase != "stage" || !r.Spec.bundleValid() {
		return "unknown", Outcome{}, Failure{"executor-unavailable"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dir := w.releaseDir(r.Spec)
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		// Only private staging files may have been created. No process or
		// effective configuration was changed by this phase.
		return "absent", Outcome{}, nil
	}
	if err := w.verifyPrepared(ctx, r.Spec); err != nil {
		return "unknown", Outcome{}, Failure{"artifact-invalid"}
	}
	if r.Spec.configurationValid() {
		if _, err := os.Lstat(w.configurationDir(r.Spec)); os.IsNotExist(err) {
			return "absent", Outcome{}, nil
		}
		if err := w.verifyConfiguration(ctx, r); err != nil {
			return "unknown", Outcome{}, Failure{"artifact-invalid"}
		}
	}
	if r.Spec.Mode == "docker" {
		if err := inspectDockerImage(ctx, w.root, r.Spec); err != nil {
			// A download may be incomplete or still running in the daemon.
			// Repeating an immutable image pull changes no live container.
			return "absent", Outcome{}, nil
		}
	}
	return "complete", stageOutcome(r.Spec), nil
}

func (w *LocalRuntime) VerifyCompleted(r Request, _ Outcome) error {
	if r.Phase != "stage" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := w.verifyPrepared(ctx, r.Spec); err != nil {
		return Failure{"artifact-invalid"}
	}
	if r.Spec.configurationValid() {
		if err := w.verifyConfiguration(ctx, r); err != nil {
			return Failure{"artifact-invalid"}
		}
	}
	if r.Spec.Mode == "docker" {
		if err := inspectDockerImage(ctx, w.root, r.Spec); err != nil {
			return Failure{"artifact-invalid"}
		}
	}
	return nil
}

func preparedOutcome() Outcome {
	return Outcome{Checks: []Check{{ID: "release-bundle", Status: "passed", Code: "bundle-verified"}, {ID: "scan-tools", Status: "passed", Code: "scan-tools-verified"}}}
}

func stageOutcome(s Spec) Outcome {
	out := preparedOutcome()
	if s.configurationValid() {
		out.Checks = append(out.Checks, Check{ID: "node-configuration", Status: "passed", Code: "configuration-verified"})
	}
	if s.Mode == "docker" {
		out.Checks = append(out.Checks, Check{ID: "agent-image", Status: "passed", Code: "image-digest-verified"})
	}
	return out
}

func (w *LocalRuntime) releaseDir(s Spec) string {
	return filepath.Join(w.root, "releases", s.BundleSHA256)
}

type preparedReceipt struct {
	Format          int    `json:"format"`
	Release         string `json:"release"`
	SHA256          string `json:"sha256"`
	ChecksumsSHA256 string `json:"checksums_sha256"`
}

func (w *LocalRuntime) prepare(ctx context.Context, s Spec) error {
	if !s.bundleValid() || !filepath.IsAbs(w.root) || filepath.Clean(w.root) != w.root || w.probe == nil {
		return errors.New("invalid-bundle")
	}
	for _, dir := range []string{w.root, filepath.Join(w.root, "packages"), filepath.Join(w.root, "releases")} {
		if err := ensurePrivateDirectory(dir); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(w.releaseDir(s)); !os.IsNotExist(err) {
		return w.verifyPrepared(ctx, s)
	}
	archive := filepath.Join(w.root, "packages", s.BundleSHA256, "agent-native.tar.gz")
	if err := privateDirectoryTree(filepath.Dir(archive)); err != nil {
		return err
	}
	f, err := openPrivateFile(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 1 || uint64(st.Size()) != s.ArtifactBytes {
		return errors.New("bundle-size-mismatch")
	}
	got, err := fileDigest(ctx, f, int64(s.ArtifactBytes))
	if err != nil || got != s.BundleSHA256 {
		return errors.New("bundle-digest-mismatch")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Join(w.root, "releases"), ".stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := extractBundle(ctx, f, stage); err != nil {
		return err
	}
	if err := verifyBundle(ctx, stage, s); err != nil {
		return err
	}
	if err := w.probe(ctx, stage, s); err != nil {
		return err
	}
	// A signed executable may have run read-only probes, but neither a wrapper
	// nor a probe may change the files subsequently used for service activation.
	if err := verifyBundle(ctx, stage, s); err != nil {
		return err
	}
	checksums, err := readPrivate(filepath.Join(stage, "SHA256SUMS"), 1<<20)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(preparedReceipt{1, s.Release, s.BundleSHA256, sha(checksums)})
	if err := writePrivate(filepath.Join(stage, ".prepared.json"), bytes.NewReader(raw), int64(len(raw)), 0600); err != nil {
		return err
	}
	if err := syncTreeDirectories(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, w.releaseDir(s)); err != nil {
		return err
	}
	return syncDirectory(filepath.Join(w.root, "releases"))
}

func (w *LocalRuntime) verifyPrepared(ctx context.Context, s Spec) error {
	if !s.bundleValid() || w.probe == nil {
		return errors.New("invalid-bundle")
	}
	dir := w.releaseDir(s)
	for _, d := range []string{w.root, filepath.Join(w.root, "releases"), dir} {
		if err := privateDirectoryTree(d); err != nil {
			return err
		}
	}
	raw, err := readPrivate(filepath.Join(dir, ".prepared.json"), 1024)
	if err != nil {
		return err
	}
	var receipt preparedReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Format != 1 || receipt.Release != s.Release || receipt.SHA256 != s.BundleSHA256 || !validDigest(receipt.ChecksumsSHA256) {
		return errors.New("prepared-receipt-mismatch")
	}
	expected, _ := json.Marshal(receipt)
	checksums, err := readPrivate(filepath.Join(dir, "SHA256SUMS"), 1<<20)
	if err != nil || !bytes.Equal(raw, expected) || sha(checksums) != receipt.ChecksumsSHA256 {
		return errors.New("prepared-receipt-mismatch")
	}
	if err := verifyBundle(ctx, dir, s); err != nil {
		return err
	}
	if err := w.probe(ctx, dir, s); err != nil {
		return err
	}
	return verifyBundle(ctx, dir, s)
}

var bundleName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,254}$`)

func bundlePath(name string) (string, bool) {
	if name == "." || name == "./" {
		return ".", true
	}
	if strings.HasPrefix(name, "/") {
		return "", false
	}
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimSuffix(name, "/")
	if name == "" || path.Clean(name) != name || strings.Contains(name, "\\") {
		return "", false
	}
	for _, p := range strings.Split(name, "/") {
		if !bundleName.MatchString(p) {
			return "", false
		}
	}
	switch name {
	case "webscan", "VERSION", "SHA256SUMS", "tools", "tools/bin", "tools/lib", "licenses":
		return name, true
	case "tools/bin/yara", "tools/bin/clamdscan":
		return name, true
	}
	parts := strings.Split(name, "/")
	return name, len(parts) == 3 && parts[0] == "tools" && parts[1] == "lib" || len(parts) == 2 && parts[0] == "licenses"
}

func bundleDirectory(name string) bool {
	return name == "." || name == "tools" || name == "tools/bin" || name == "tools/lib" || name == "licenses"
}

func extractBundle(ctx context.Context, file io.Reader, directory string) error {
	br := bufio.NewReader(file)
	gz, err := gzip.NewReader(br)
	if err != nil {
		return err
	}
	defer gz.Close()
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	var expanded int64
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || entries >= maxBundleFiles {
			return errors.New("invalid-bundle-archive")
		}
		name, valid := bundlePath(h.Name)
		if !valid || seen[name] || h.Linkname != "" || h.Size < 0 || h.Size > maxBundleFile || expanded+h.Size > maxExpandedBundle {
			return errors.New("unsafe-bundle-entry")
		}
		for k := range h.PAXRecords {
			if strings.HasPrefix(k, "GNU.sparse") || strings.HasPrefix(k, "SCHILY.") {
				return errors.New("unsafe-bundle-entry")
			}
		}
		seen[name] = true
		expanded += h.Size
		if h.Typeflag == tar.TypeDir {
			if !bundleDirectory(name) || h.Size != 0 {
				return errors.New("unsafe-bundle-directory")
			}
			if err := os.MkdirAll(filepath.Join(directory, name), 0700); err != nil {
				return err
			}
			continue
		}
		if h.Typeflag != tar.TypeReg || name == "." || name == "tools" || name == "licenses" || name == "tools/bin" || name == "tools/lib" {
			return errors.New("unsafe-bundle-entry")
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(directory, name)), 0700); err != nil {
			return err
		}
		if err := writePrivate(filepath.Join(directory, name), &contextReader{ctx, tr}, h.Size, bundleMode(name)); err != nil {
			return err
		}
	}
	// Read through gzip EOF to validate its CRC, rejecting concatenated streams
	// and hidden trailing payload. GNU tar's zero record padding is permitted.
	padding, err := io.ReadAll(io.LimitReader(&contextReader{ctx, gz}, 1<<20+1))
	if err != nil || len(padding) > 1<<20 || bytes.Count(padding, []byte{0}) != len(padding) {
		return errors.New("invalid-bundle-trailer")
	}
	if _, err := br.ReadByte(); err != io.EOF {
		return errors.New("invalid-bundle-trailer")
	}
	return nil
}

func bundleMode(name string) os.FileMode {
	if name == "webscan" || strings.HasPrefix(name, "tools/") {
		return 0700
	}
	return 0600
}

func verifyBundle(ctx context.Context, directory string, s Spec) error {
	manifest, err := readPrivate(filepath.Join(directory, "SHA256SUMS"), 1<<20)
	if err != nil {
		return err
	}
	expected := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		if len(line) < 67 || line[64:66] != "  " || !validDigest(line[:64]) {
			return errors.New("invalid-bundle-checksums")
		}
		name, valid := bundlePath(line[66:])
		if !valid || name == "." || name == "SHA256SUMS" || expected[name] != "" {
			return errors.New("invalid-bundle-checksums")
		}
		expected[name] = line[:64]
	}
	var total int64
	count := 0
	err = filepath.WalkDir(directory, func(file string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := filepath.Rel(directory, file)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if !bundleDirectory(name) {
				return errors.New("unexpected-prepared-directory")
			}
			return privateDirectoryTree(file)
		}
		if name == ".prepared.json" {
			return nil // compared independently to the exact receipt
		}
		if _, valid := bundlePath(name); !valid || count >= maxBundleFiles {
			return errors.New("unsafe-prepared-file")
		}
		f, err := openPrivateFile(file)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.Mode().Perm() != bundleMode(name) || st.Size() > maxBundleFile || total+st.Size() > maxExpandedBundle {
			return errors.New("unsafe-prepared-file")
		}
		total += st.Size()
		count++
		if name == "SHA256SUMS" {
			return nil
		}
		got, err := fileDigest(ctx, f, maxBundleFile)
		if err != nil || expected[name] == "" || got != expected[name] {
			return errors.New("prepared-file-digest-mismatch")
		}
		delete(expected, name)
		return nil
	})
	if err != nil || len(expected) != 0 {
		return errors.New("incomplete-or-corrupt-bundle")
	}
	for _, name := range []string{"webscan", "VERSION", "tools/bin/yara", "tools/lib/yara", "tools/lib/ld-linux-x86-64.so.2"} {
		if err := privateFile(filepath.Join(directory, name), false); err != nil {
			return err
		}
	}
	if s.ClamAV {
		for _, name := range []string{"tools/bin/clamdscan", "tools/lib/clamdscan"} {
			if err := privateFile(filepath.Join(directory, name), false); err != nil {
				return err
			}
		}
	}
	version, err := readPrivate(filepath.Join(directory, "VERSION"), 128)
	if err != nil || strings.TrimSpace(string(version)) != s.Release {
		return errors.New("bundle-version-mismatch")
	}
	f, err := elf.Open(filepath.Join(directory, "webscan"))
	if err != nil {
		return errors.New("bundle-program-not-elf")
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 || f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return errors.New("bundle-program-platform-mismatch")
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}

func fileDigest(ctx context.Context, f io.Reader, limit int64) (string, error) {
	if limit < 0 {
		return "", errors.New("file-size-or-read-failure")
	}
	h := sha256.New()
	reader := &contextReader{ctx, f}
	_, err := io.Copy(h, io.LimitReader(reader, limit))
	if err != nil {
		return "", errors.New("file-size-or-read-failure")
	}
	var extra [1]byte
	if n, err := reader.Read(extra[:]); n != 0 || err != io.EOF {
		return "", errors.New("file-size-or-read-failure")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func openPrivateFile(file string) (*os.File, error) {
	if err := directoryAncestors(filepath.Dir(file)); err != nil {
		return nil, err
	}
	if err := privateFile(file, false); err != nil {
		return nil, err
	}
	fd, err := unix.Open(file, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), file)
	st, err := f.Stat()
	var opened unix.Stat_t
	var named unix.Stat_t
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || unix.Fstat(fd, &opened) != nil || unix.Lstat(file, &named) != nil || opened.Uid != uint32(os.Geteuid()) || opened.Nlink != 1 || opened.Dev != named.Dev || opened.Ino != named.Ino {
		f.Close()
		return nil, errors.New("unsafe-private-file")
	}
	return f, nil
}

func readPrivate(file string, max int64) ([]byte, error) {
	f, err := openPrivateFile(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, errors.New("private-file-read-failed")
	}
	return raw, nil
}

func writePrivate(file string, source io.Reader, size int64, mode os.FileMode) error {
	fd, err := unix.Open(file, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), file)
	defer f.Close()
	if _, err := io.CopyN(f, source, size); err != nil {
		return err
	}
	return f.Sync()
}

func privateDirectoryTree(dir string) error {
	if err := directoryAncestors(dir); err != nil {
		return err
	}
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0700 {
		return errors.New("unsafe-private-directory")
	}
	var stat unix.Stat_t
	if err := unix.Stat(dir, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe-private-directory")
	}
	return nil
}

func directoryAncestors(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("unsafe-private-directory")
	}
	for p := dir; p != "/"; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe-private-directory")
		}
	}
	return nil
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncTreeDirectories(root string) error {
	var dirs []string
	if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	}); err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := syncDirectory(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}
