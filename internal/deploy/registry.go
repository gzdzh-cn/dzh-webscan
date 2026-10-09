package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/progress"
)

type Docker struct {
	Dir, Host string
	Config    *Config
}

func RunCommand(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = input
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if label := progress.CommandLabel(args); label != "" && progress.Enabled(ctx) {
		stdout := progress.Stream(ctx, label)
		stderr := progress.Stream(ctx, label+"诊断")
		defer stdout.Close()
		defer stderr.Close()
		cmd.Stdout = io.MultiWriter(progress.Limit(&out, 65536), stdout)
		cmd.Stderr = stderr
	}
	if e := cmd.Run(); e != nil {
		return nil, fmt.Errorf("command_failed_%s", filepath.Base(args[0]))
	}
	return out.Bytes(), nil
}
func NewDocker(ctx context.Context, c *Config, publishing bool) (*Docker, error) {
	dir, e := os.MkdirTemp("", "webscan-docker-auth-")
	if e != nil {
		return nil, e
	}
	os.Chmod(dir, 0700)
	d := &Docker{Dir: dir, Config: c}
	// Preserve CLI plugin discovery while starting with no registry credentials.
	if home, err := os.UserHomeDir(); err == nil {
		pluginDir := filepath.Join(home, ".docker", "cli-plugins")
		if stat, err := os.Stat(pluginDir); err == nil && stat.IsDir() {
			if err = common.AtomicJSON(filepath.Join(dir, "config.json"), common.Map{"cliPluginsExtraDirs": []string{pluginDir}}); err != nil {
				d.Close()
				return nil, err
			}
		}
	}

	b, e := RunCommand(ctx, nil, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	if e != nil {
		os.RemoveAll(dir)
		return nil, e
	}
	d.Host = strings.TrimSpace(string(b))
	if d.Host == "" {
		os.RemoveAll(dir)
		return nil, errors.New("docker_endpoint_missing")
	}
	r := common.M(c.Raw["registry"])
	if common.B(r["auth_required"]) || publishing {
		if common.S(r["username"]) == "" || common.S(r["password"]) == "" {
			d.Close()
			return nil, errors.New("registry_publishing_credentials_required")
		}
		host := strings.Split(common.S(r["prefix"]), "/")[0]
		if _, e = d.Exec(ctx, strings.NewReader(common.S(r["password"])+"\n"), "login", host, "--username", common.S(r["username"]), "--password-stdin"); e != nil {
			d.Close()
			return nil, errors.New("registry_authentication_failed")
		}
	}
	return d, nil
}
func (d *Docker) Close() { os.RemoveAll(d.Dir) }
func (d *Docker) Exec(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	base := []string{"docker", "--host", d.Host, "--config", d.Dir}
	return RunCommand(ctx, input, append(base, args...)...)
}
func (d *Docker) Pull(ctx context.Context, image string) (string, error) {
	for _, candidate := range pullCandidates(d.Config, image) {
		progress.Info(ctx, "镜像下载来源："+candidate)
		request, cancel := context.WithTimeout(ctx, 5*time.Minute)
		_, err := d.Exec(request, nil, "pull", "--platform", "linux/amd64", candidate)
		cancel()
		if err == nil {
			progress.Info(ctx, "正在校验镜像摘要")
			return d.Resolve(ctx, candidate)
		}
		progress.Warn(ctx, "当前来源下载失败，尝试下一个可用来源")
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	return "", errors.New("all_image_pull_sources_failed")
}
func (d *Docker) Resolve(ctx context.Context, image string) (string, error) {
	b, e := d.Exec(ctx, nil, "image", "inspect", image)
	if e != nil {
		return "", e
	}
	v, e := common.Decode(b)
	if e != nil {
		return "", e
	}
	items := common.A(v)
	if len(items) != 1 {
		return "", errors.New("image_inspection_failed")
	}
	info := common.M(items[0])
	repo := imageRepository(image)
	for _, digest := range common.SS(info["RepoDigests"]) {
		if repositoryKey(imageRepository(digest)) == repositoryKey(repo) {
			return digest, nil
		}
	}
	id := common.S(info["Id"])
	if !strings.HasPrefix(id, "sha256:") {
		return "", errors.New("image_digest_missing")
	}
	return id, nil
}
func RemotePull(ctx context.Context, r *Remote, c *Config, image string) (string, error) {
	for _, candidate := range pullCandidates(c, image) {
		progress.Info(ctx, "子服务器镜像下载来源："+candidate)
		if err := remotePullOne(ctx, r, c, candidate); err == nil {
			return candidate, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		progress.Warn(ctx, "节点当前来源下载失败，尝试其他来源")
	}
	return "", errors.New("all_remote_image_pull_sources_failed")
}
func remotePullOne(ctx context.Context, r *Remote, c *Config, image string) error {
	command, input := remotePullCommand(c, image)
	request, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_, err := r.ExecVisible(request, command, input, "下载进度")
	return err
}
func remotePullCommand(c *Config, image string) (string, io.Reader) {
	reg := common.M(c.Raw["registry"])
	host := strings.Split(common.S(reg["prefix"]), "/")[0]
	command := "set -eu; umask 077; task_auth_dir=$(mktemp -d /tmp/webscan-docker-auth.XXXXXXXX); trap 'rm -rf -- \"$task_auth_dir\"' EXIT; "
	var input io.Reader
	if common.B(reg["auth_required"]) && strings.HasPrefix(image, host+"/") {
		command += "docker --config \"$task_auth_dir\" login " + Q(host) + " --username " + Q(common.S(reg["username"])) + " --password-stdin >/dev/null 2>&1; "
		input = strings.NewReader(common.S(reg["password"]) + "\n")
	}
	command += "docker --config \"$task_auth_dir\" pull --platform linux/amd64 " + Q(image)
	return command, input
}

func imageRepository(image string) string {
	repo := strings.Split(image, "@")[0]
	if colon := strings.LastIndex(repo, ":"); colon > strings.LastIndex(repo, "/") {
		repo = repo[:colon]
	}
	return repo
}

func repositoryKey(repo string) string {
	repo = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(repo, "docker.io/"), "index.docker.io/"), "registry-1.docker.io/")
	if !strings.Contains(repo, "/") {
		return "library/" + repo
	}
	return repo
}
