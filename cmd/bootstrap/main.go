// Lightweight, offline-validating YAML bootstrap embedded in the Bash package.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/deploy"
	"webscan/internal/progress"
)

var Release = "development"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "引导失败:", progress.Explain(err))
		os.Exit(1)
	}
}
func command(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
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
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, progress.CommandError("bootstrap_command_failed", err)
	}
	return out.Bytes(), nil
}
func run() error {
	args, err := selectAction(os.Args[1:], os.Stdin, os.Stdout)
	if errors.Is(err, errMenuExit) {
		return nil
	}
	if err != nil {
		return err
	}
	parsed, err := parseBootstrapArgs(args)
	if err != nil {
		return err
	}
	if parsed["--config-help"] == "true" {
		fmt.Print(configuration.Help())
		return nil
	}
	path := parsed["--config"]
	if path == "" {
		path = "webscan.yaml"
	}
	dry, node := parsed["--dry-run"] == "true", parsed["--node"]
	uninstall, centralOnly := parsed["--uninstall"] == "true", parsed["--central-only"] == "true"
	if parsed["--help"] == "true" || parsed["-h"] == "true" {
		fmt.Println("bash deploy-webscan.sh：显示 1 安装、2 重装、3 卸载、4 增加子服务器菜单\nbash deploy-webscan.sh [--install|--reinstall|--uninstall|--check|--upgrade|--add-node|--resume|--rollback|--reload-rules] [--dry-run] [--config-help] [--config YAML] [--node ID] [--central-only|--grafana-only|--sync-grafana-credentials] [--non-interactive]\n菜单 4 等同于 --add-node --node 节点ID，沿用主服务器当前版本和配置；恢复追加 --resume，回退追加 --rollback。\n重装与卸载保留监控数据、凭据、备份及三文件部署包。")
		return nil
	}

	if err := validateActions(args); err != nil {
		return err
	}
	c, err := configuration.Load(path)
	if err != nil {
		return err
	}
	selected := c.Selected(node)
	if uninstall {
		selected = c.UninstallNodes(node)
	}
	if node != "" && len(selected) == 0 {
		if uninstall {
			return errors.New("selected_node_not_configured")
		}
		return errors.New("selected_node_not_enabled")
	}
	if dry {
		if parsed["--add-node"] == "true" {
			return deploy.Run(context.Background(), deploy.Options{Config: path, Node: node, AddNode: true, DryRun: true})
		}
		mode := "install"
		if uninstall {
			mode = "uninstall"
		}
		if parsed["--reinstall"] == "true" {
			mode = "reinstall"
		}

		order := []string{}
		if node == "" {
			order = append(order, "central")
		}
		if !centralOnly {
			for _, n := range selected {
				order = append(order, common.S(n["id"]))
			}
		}
		fmt.Println(string(common.JSON(common.Map{"configuration": configuration.Redact(c.Raw), "release": Release, "server_order": order, "images": c.Raw["images"], "offline": true, "action": mode, "preserve_data": true})))
		return nil
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("run_on_linux_amd64_main_server_as_root")
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return errors.New("actual_yaml_requires_0600_permissions")
	}
	if owner, ok := st.Sys().(*syscall.Stat_t); !ok || owner.Uid != 0 {
		return errors.New("actual_yaml_requires_root_ownership")
	}
	baseCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	unlock, err := lockBootstrap()
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(baseCtx, 15*time.Minute)
	defer cancel()
	reporter, err := progress.Open(c.Raw, "引导", "/var/lib/webscan-deploy/logs")
	if err != nil {
		return err
	}
	defer reporter.Close()
	ctx = progress.With(ctx, reporter)
	host := progress.Host(c.Raw)
	progress.Info(ctx, "版本："+Release+"；正在执行主服务器引导")
	if uninstall {
		progress.Info(ctx, "卸载使用脚本内置 Go 维护程序；无需镜像仓库，也不创建引导容器")
		return deploy.Run(baseCtx, deploy.Options{Config: path, Node: node, Uninstall: true, CentralOnly: centralOnly})
	}
	if err = progress.Stage(ctx, host, "检查 Docker 和 Compose", func(ctx context.Context) error {
		_, dockerErr := command(ctx, nil, "docker", "info")
		_, composeErr := command(ctx, nil, "docker", "compose", "version")
		if dockerErr != nil || composeErr != nil {
			progress.Info(ctx, "缺少 Docker 或 Compose，开始安装固定版本")
			script, _ := assets.Files.ReadFile("install-docker.sh")
			if _, installErr := command(ctx, bytes.NewReader(script), "bash"); installErr != nil {
				return errors.New("fresh_docker_installation_failed")
			}
		}
		return nil
	}); err != nil {
		return err
	}
	endpoint, err := command(ctx, nil, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "webscan-bootstrap-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	authDir := filepath.Join(tmp, "auth")
	if err = os.Mkdir(authDir, 0700); err != nil {
		return err
	}
	docker := func(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
		base := []string{"docker", "--host", strings.TrimSpace(string(endpoint)), "--config", authDir}
		return command(ctx, input, append(base, args...)...)
	}
	if err = cleanStaleBootstrap(ctx, docker); err != nil {
		return err
	}
	reg := common.M(c.Raw["registry"])
	if common.B(reg["auth_required"]) {
		if err = progress.Stage(ctx, host, "认证私有镜像仓库（凭据已隐藏）", func(ctx context.Context) error {
			registryHost := strings.Split(common.S(reg["prefix"]), "/")[0]
			if _, loginErr := docker(ctx, strings.NewReader(common.S(reg["password"])+"\n"), "login", registryHost, "--username", common.S(reg["username"]), "--password-stdin"); loginErr != nil {
				return errors.New("registry_authentication_failed")
			}
			return nil
		}); err != nil {
			return err
		}
	} else {
		progress.Info(ctx, "公用镜像仓库：匿名下载，不使用已有登录状态")
	}
	ref := c.Image("central")
	if err = progress.Stage(ctx, host, "下载主服务器镜像（包含 Go 部署工具）", func(ctx context.Context) error {
		progress.Info(ctx, "镜像："+ref)
		if _, pullErr := docker(ctx, nil, "pull", "--platform", "linux/amd64", ref); pullErr != nil {
			return errors.New("bootstrap_central_image_pull_failed")
		}
		return nil
	}); err != nil {
		return err
	}
	binary, err := extractTool(ctx, docker, tmp, ref)
	if err != nil {
		return err
	}
	if err = validateToolVersion(ctx, binary); err != nil {
		return err
	}

	if err = os.RemoveAll(authDir); err != nil {
		return err
	}
	progress.Info(ctx, "引导完成，临时容器已删除；开始执行部署工具，后续进度继续写入同一日志")
	return runDeploymentTool(baseCtx, binary, args)
}
