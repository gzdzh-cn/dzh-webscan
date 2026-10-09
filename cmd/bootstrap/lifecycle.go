package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
	"webscan/internal/deploy"
	"webscan/internal/progress"
)

type dockerCommand func(context.Context, io.Reader, ...string) ([]byte, error)

func lockBootstrap() (func(), error) {
	dir := "/var/lib/webscan-deploy"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "bootstrap.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("bootstrap_already_running")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}

func cleanStaleBootstrap(ctx context.Context, docker dockerCommand) error {
	b, err := docker(ctx, nil, "ps", "-aq", "--filter", "label=io.webscan.bootstrap=true", "--filter", "status=created")
	if err != nil {
		return err
	}
	for _, id := range strings.Fields(string(b)) {
		progress.Info(ctx, "清理上次中断留下的未运行引导容器："+id)
		if _, err = docker(ctx, nil, "rm", id); err != nil {
			return errors.New("bootstrap_stale_cleanup_failed")
		}
	}
	return nil
}

func extractTool(ctx context.Context, docker dockerCommand, tmp, ref string) (binary string, err error) {
	id := "webscan-bootstrap-" + common.ID()
	binary = filepath.Join(tmp, "webscan")
	cleanup := func() error {
		// A cancelled download/copy must not cancel container cleanup too.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, e := docker(cleanupCtx, nil, "rm", "-f", id)
		return e
	}
	created := false
	defer func() {
		if created {
			if e := cleanup(); e != nil {
				err = errors.New("bootstrap_container_cleanup_failed")
			}
		}
	}()
	err = progress.Stage(ctx, "主服务器", "提取 Go 部署程序（完成后立即删除临时容器）", func(ctx context.Context) error {
		// Register cleanup before create: cancellation can hide a successful create.
		created = true
		if _, e := docker(ctx, nil, "create", "--pull", "never", "--label", "io.webscan.bootstrap=true", "--name", id, ref, "version"); e != nil {
			return e
		}
		if _, e := docker(ctx, nil, "cp", id+":/usr/local/bin/webscan", binary); e != nil {
			return e
		}
		return os.Chmod(binary, 0700)
	})
	return binary, err
}

func validateToolVersion(ctx context.Context, binary string) error {
	b, err := command(ctx, nil, binary, "version")
	if err != nil || strings.TrimSpace(string(b)) != Release {
		return errors.New("bootstrap_tool_release_mismatch")
	}
	return nil
}

func validateToolVersionForImage(ctx context.Context, binary, image string) error {
	if !strings.HasSuffix(image, ":latest") {
		return validateToolVersion(ctx, binary)
	}
	b, err := command(ctx, nil, binary, "version")
	version := strings.TrimSpace(string(b))
	if err != nil || !regexp.MustCompile(`^v2\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9_.-]+)?$`).MatchString(version) {
		return errors.New("bootstrap_tool_release_mismatch")
	}
	progress.Info(ctx, "latest 镜像中部署工具的实际版本："+version)
	return nil
}

func bootstrapImageForOperation(image string, args []string) string {
	if !strings.HasSuffix(image, ":latest") {
		return image
	}
	for _, arg := range args {
		flag := strings.Split(arg, "=")[0]
		if flag != "--resume" && flag != "--rollback" && flag != "--install" {
			continue
		}
		state, err := common.ReadJSON(filepath.Join(deploy.StateRoot, "state.json"))
		if err == nil {
			// Menu 1 automatically continues an interrupted installation. Use
			// its recorded tool too, even after a newer script was distributed.
			if flag == "--install" && (!pendingDeployment(state) || retryConfirmedRollout(state, args)) {
				continue
			}
			if locked := common.S(state["target_tool_image"]); regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$`).MatchString(locked) {
				return locked
			}
			version := common.S(state["target_release"])
			if regexp.MustCompile(`^v2\.[0-9]+\.[0-9]+(?:[-.][A-Za-z0-9_.-]+)?$`).MatchString(version) {
				return strings.TrimSuffix(image, ":latest") + ":" + version
			}
		}
	}
	return image
}

func matchingToolDigest(ref string, digests []string) string {
	repository := func(image string) string {
		image = strings.Split(image, "@")[0]
		if colon := strings.LastIndex(image, ":"); colon > strings.LastIndex(image, "/") {
			image = image[:colon]
		}
		return strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(image, "docker.io/"), "index.docker.io/"), "registry-1.docker.io/")
	}
	for _, digest := range digests {
		if repository(digest) == repository(ref) && regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}$`).MatchString(digest) {
			return digest
		}
	}
	return ""
}

func runDeploymentTool(ctx context.Context, binary string, args []string) error {
	cmd := exec.Command(binary, append([]string{"deploy"}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return errors.New("deployment_tool_failed")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return errors.New("deployment_tool_failed")
		}
		return nil
	case <-ctx.Done():
		// Don't kill the child while its own signal handler restores old services.
		_ = cmd.Process.Signal(syscall.SIGTERM)
		<-done
		return ctx.Err()
	}
}

// A new bootstrap may introduce configuration fields unavailable in a stale
// mirrored latest. Allow newer releases, but never silently select an older one.
func toolOlderThanBootstrap(ctx context.Context, binary string) bool {
	b, e := command(ctx, nil, binary, "version")
	if e != nil {
		return true
	}
	parse := func(value string) []int {
		parts := regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-.][A-Za-z0-9_.-]+)?$`).FindStringSubmatch(strings.TrimSpace(value))
		if len(parts) != 4 {
			return nil
		}
		out := []int{}
		for _, p := range parts[1:] {
			n, _ := strconv.Atoi(p)
			out = append(out, n)
		}
		return out
	}
	actual, minimum := parse(string(b)), parse(Release)
	if len(minimum) == 0 {
		return false
	}
	if len(actual) == 0 {
		return true
	}
	for i := range minimum {
		if actual[i] != minimum[i] {
			return actual[i] < minimum[i]
		}
	}
	return false
}
