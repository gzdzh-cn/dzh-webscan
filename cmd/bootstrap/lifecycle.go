package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
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
