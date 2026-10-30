package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"webscan/internal/nodeconfig"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// ProvisionHelper only stages the signature-pinned deployment executable. It
// does not stop/install an Agent, alter its config, register a node, or advance
// a deployment checkpoint. The executor is intentionally not publicly enabled.
// The caller supplies a private local release file, never a client-uploaded path.
func (w *SSHNodeRuntime) ProvisionHelper(ctx context.Context, j DeploymentJob, localFile string) error {
	return w.provisionArtifact(ctx, j, localFile, "helper")
}

// ProvisionBundle transports an immutable archive only. Extraction and scanner
// validation are performed by the locked node-v3 stage handler afterwards.
func (w *SSHNodeRuntime) ProvisionBundle(ctx context.Context, j DeploymentJob, localFile string) error {
	return w.provisionArtifact(ctx, j, localFile, "native")
}

func (w *SSHNodeRuntime) ProvisionImageArchive(ctx context.Context, j DeploymentJob, localFile string) error {
	return w.provisionArtifact(ctx, j, localFile, "image")
}

func (w *SSHNodeRuntime) ProvisionConfiguration(ctx context.Context, j DeploymentJob, localFile string) error {
	return w.provisionArtifact(ctx, j, localFile, "configuration")
}

func (w *SSHNodeRuntime) provisionArtifact(ctx context.Context, j DeploymentJob, localFile, kind string) error {
	if (j.Kind == "recover" || j.Plan.Recovery != nil) && kind != "helper" {
		return DeploymentFailure{"artifact-invalid"}
	}
	if _, err := w.request(ctx, j, "inspect"); err != nil {
		return err
	}
	artifact, limit, timeout := w.Release.manifest.Helper, uint64(256<<20), 3*time.Minute
	message := "helper-ready"
	if kind == "native" {
		artifact, limit, timeout = w.Release.manifest.Native, 4<<30, 10*time.Minute
		message = "bundle-ready"
	} else if kind == "image" && j.Plan.Node.Mode == "docker" && w.Release.manifest.ImageArchive != nil {
		artifact, limit, timeout = *w.Release.manifest.ImageArchive, 4<<30, 10*time.Minute
		message = "image-ready"
	} else if kind == "configuration" && j.Plan.Request.RuntimeArtifact != nil {
		artifact, limit, timeout = *j.Plan.Request.RuntimeArtifact, nodeconfig.MaxBytes, time.Minute
		message = "configuration-ready"
	} else if kind != "helper" {
		return DeploymentFailure{"artifact-invalid"}
	}
	f, err := verifiedReleaseFile(ctx, localFile, artifact, limit)
	if err != nil {
		return DeploymentFailure{"artifact-invalid"}
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	remote, err := w.Store.ConnectDeploymentSSH(ctx, w.Vault, j)
	if err != nil {
		return err
	}
	defer remote.Close()
	// A retry may already have the exact signed artifact. Recheck ownership,
	// links, size and every byte before reusing it; a name alone is no proof.
	probe, probeErr := runNodeCommand(ctx, remote.Client, artifactReuseCommand(artifact, kind), nil)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if probeErr != nil {
		var exit *ssh.ExitError
		if !errors.As(probeErr, &exit) {
			return DeploymentFailure{"remote-unavailable"}
		}
		return DeploymentFailure{"artifact-invalid"}
	}
	if probe.overflow {
		return DeploymentFailure{"artifact-invalid"}
	}
	switch strings.TrimSpace(string(probe.raw)) {
	case "artifact-verified":
		return nil
	case "artifact-missing":
	default:
		return DeploymentFailure{"artifact-invalid"}
	}
	capture, err := runNodeCommand(ctx, remote.Client, artifactInstallCommand(artifact, kind), io.LimitReader(f, int64(artifact.Bytes)+1))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		var exit *ssh.ExitError
		if !errors.As(err, &exit) {
			return DeploymentFailure{"remote-unavailable"}
		}
		return DeploymentFailure{"artifact-invalid"}
	}
	if capture.overflow || strings.TrimSpace(string(capture.raw)) != message {
		return DeploymentFailure{"artifact-invalid"}
	}
	return nil
}

func verifiedHelper(ctx context.Context, path string, artifact ReleaseArtifact) (*os.File, error) {
	return verifiedReleaseFile(ctx, path, artifact, 256<<20)
}

func verifiedReleaseFile(ctx context.Context, path string, artifact ReleaseArtifact, limit uint64) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	valid := false
	defer func() {
		if !valid {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || st.Size() < 1 || uint64(st.Size()) != artifact.Bytes || !releaseDigest(artifact.SHA256) || artifact.Bytes > limit {
		return nil, DeploymentFailure{"artifact-invalid"}
	}
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var total uint64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := f.Read(buffer)
		total += uint64(n)
		if total > artifact.Bytes {
			return nil, DeploymentFailure{"artifact-invalid"}
		}
		h.Write(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if total != artifact.Bytes || hex.EncodeToString(h.Sum(nil)) != artifact.SHA256 {
		return nil, DeploymentFailure{"artifact-invalid"}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	valid = true
	return f, nil
}

// artifactReuseCommand never trusts a previous receipt without rehashing the
// current root-private artifact. Missing files may be uploaded; unsafe or
// different existing files stop the task instead of being overwritten.
func artifactReuseCommand(a ReleaseArtifact, kind string) string {
	folder, file, mode, limit := "tools", "webscan", "700", uint64(256<<20)
	switch kind {
	case "helper":
	case "native":
		folder, file, mode, limit = "packages", "agent-native.tar.gz", "600", 4<<30
	case "image":
		folder, file, mode, limit = "images", "docker-image.tar", "600", 4<<30
	case "configuration":
		folder, file, mode, limit = "configs", "node.json", "600", nodeconfig.MaxBytes
	default:
		return "exit 1"
	}
	if !releaseDigest(a.SHA256) || a.Bytes < 1 || a.Bytes > limit {
		return "exit 1"
	}
	return artifactDirectoryCommand(true, folder) + `target=/var/lib/webscan-deploy/v3/` + folder + `/` + a.SHA256 + `
 test ! -L "$target"
 if test ! -e "$target"; then printf 'artifact-missing\n'; exit 0; fi
 test -d "$target"
 test "$(stat -c '%u:%a' "$target")" = 0:700
 file="$target/` + file + `"
 test ! -L "$file"
 if test ! -e "$file"; then printf 'artifact-missing\n'; exit 0; fi
 test -f "$file"
 test "$(stat -c '%u:%a:%h:%s' "$file")" = '0:` + mode + `:1:` + strconv.FormatUint(a.Bytes, 10) + `'
 printf '%s  %s\n' '` + a.SHA256 + `' "$file" | sha256sum --check --status
 printf 'artifact-verified\n'
`
}

func helperInstallCommand(a ReleaseArtifact) string {
	return artifactInstallCommand(a, "helper")
}

func artifactInstallCommand(a ReleaseArtifact, kind string) string {
	folder, file, mode, message, limit := "tools", "webscan", "700", "helper-ready", uint64(256<<20)
	if kind == "native" {
		folder, file, mode, message, limit = "packages", "agent-native.tar.gz", "600", "bundle-ready", 4<<30
	} else if kind == "image" {
		folder, file, mode, message, limit = "images", "docker-image.tar", "600", "image-ready", 4<<30
	} else if kind == "configuration" {
		folder, file, mode, message, limit = "configs", "node.json", "600", "configuration-ready", nodeconfig.MaxBytes
	} else if kind != "helper" {
		return "exit 1"
	}
	if !releaseDigest(a.SHA256) || a.Bytes < 1 || a.Bytes > limit {
		return "exit 1"
	}
	// Only a validated hexadecimal digest and decimal byte count are inserted.
	// Check each ancestor before descending; do not follow an existing symlink,
	// repair insecure permissions, or overwrite a different program. The private
	// temporary directory is on the same filesystem as the final immutable file.
	return artifactDirectoryCommand(true, folder) + `stage=$(mktemp -d /var/lib/webscan-deploy/v3/` + folder + `/.stage-XXXXXXXX)
file=` + file + `
trap 'rm -f -- "$stage/$file"; rmdir -- "$stage"' EXIT
trap 'exit 1' HUP INT TERM
cat > "$stage/$file"
test "$(stat -c '%s' "$stage/$file")" = ` + strconv.FormatUint(a.Bytes, 10) + `
printf '%s  %s\n' '` + a.SHA256 + `' "$stage/$file" | sha256sum --check --status
chmod ` + mode + ` "$stage/$file"
target=/var/lib/webscan-deploy/v3/` + folder + `/` + a.SHA256 + `
test ! -L "$target"
if test ! -e "$target"; then mkdir -m 700 "$target" || test -d "$target"; fi
test -d "$target"
test "$(stat -c '%u:%a' "$target")" = 0:700
test ! -L "$target/$file"
if test -e "$target/$file"; then
  test -f "$target/$file"
  test "$(stat -c '%u:%a:%h:%s' "$target/$file")" = '0:` + mode + `:1:` + strconv.FormatUint(a.Bytes, 10) + `'
  printf '%s  %s\n' '` + a.SHA256 + `' "$target/$file" | sha256sum --check --status
else
  mv -f -- "$stage/$file" "$target/$file"
fi
sync "$target/$file"
sync "$target"
sync /var/lib/webscan-deploy/v3/` + folder + `
sync /var/lib/webscan-deploy/v3
printf '` + message + `\n'
`
}

func helperDirectoryCommand(create bool) string {
	return artifactDirectoryCommand(create, "tools")
}

func artifactDirectoryCommand(create bool, folder string) string {
	if folder != "tools" && folder != "packages" && folder != "images" && folder != "configs" {
		return "exit 1\n"
	}
	creation := ""
	if create {
		creation = `if test ! -e "$d"; then mkdir -m 700 "$d" || test -d "$d"; fi`
	}
	return `set -eu
umask 077
for d in /var /var/lib /var/lib/webscan-deploy /var/lib/webscan-deploy/v3 /var/lib/webscan-deploy/v3/` + folder + `; do
  test ! -L "$d"
  ` + creation + `
  test -d "$d"
  test "$(stat -c '%u' "$d")" = 0
  mode=$(stat -c '%a' "$d")
  test "$((0$mode & 022))" = 0
done
test "$(stat -c '%a' /var/lib/webscan-deploy/v3)" = 700
test "$(stat -c '%a' /var/lib/webscan-deploy/v3/` + folder + `)" = 700
`
}

func helperRunCommand(a ReleaseArtifact) string {
	if !releaseDigest(a.SHA256) || a.Bytes < 1 || a.Bytes > 256<<20 {
		return "exit 1"
	}
	return helperDirectoryCommand(false) + `target=/var/lib/webscan-deploy/v3/tools/` + a.SHA256 + `
test ! -L "$target"
test -d "$target"
test "$(stat -c '%u:%a' "$target")" = 0:700
test ! -L "$target/webscan"
test -f "$target/webscan"
test "$(stat -c '%u:%a:%h:%s' "$target/webscan")" = '0:700:1:` + strconv.FormatUint(a.Bytes, 10) + `'
printf '%s  %s\n' '` + a.SHA256 + `' "$target/webscan" | sha256sum --check --status
exec "$target/webscan" node-v3
`
}

func runNodeCommand(ctx context.Context, client *ssh.Client, command string, input io.Reader) (*nodeResponseCapture, error) {
	capture := &nodeResponseCapture{}
	session, err := client.NewSession()
	if err != nil {
		return capture, err
	}
	defer session.Close()
	session.Stdin, session.Stdout, session.Stderr = input, capture, io.Discard
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case <-ctx.Done():
		// Session.Close terminates the SSH transport before reading capture;
		// only return an empty buffer while its writer might still be active.
		return &nodeResponseCapture{}, ctx.Err()
	case err := <-done:
		return capture, err
	}
}
