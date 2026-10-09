// Lightweight, offline-validating YAML bootstrap embedded in the Bash package.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
func run() (runErr error) {
	initial, err := parseBootstrapArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if stage := initial["--prepare-package"]; stage != "" {
		if len(os.Args) != 3 || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
			return errors.New("包准备操作仅允许 root 在 Linux amd64 主服务器执行，不能混用其他参数")
		}
		if e := preparePackage(stage, systemPackagePaths(), os.Stdout); e != nil {
			return &progress.Failure{Code: "package_prepare_failed", Message: e.Error()}
		}
		return nil
	}
	readOnly := initial["--dry-run"] == "true" || initial["--check"] == "true" || initial["--help"] == "true" || initial["-h"] == "true" || initial["--config-help"] == "true"
	interactive := !readOnly && initial["--non-interactive"] != "true"
	var unlock func()
	if !readOnly {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
			return errors.New("run_on_linux_amd64_main_server_as_root")
		}
		unlock, err = lockBootstrap()
		if err != nil {
			return err
		}
		defer unlock()
	}
	scanner := bufio.NewScanner(terminalLineReader{os.Stdin})
	initialized := false
	pathBefore := configPath(os.Args[1:])
	if interactive {
		// Do not initialize during recovery/uninstall or maintenance operations.
		setupAllowed := len(os.Args) == 1 || initial["--install"] == "true" || initial["--upgrade"] == "true" || initial["--reinstall"] == "true"
		if setupAllowed && initial["--resume"] != "true" && initial["--rollback"] != "true" {
			initialized, err = initializeConfig(pathBefore, deploy.StateRoot, liveInput(scanner, os.Stdout))
			if err != nil {
				if errors.Is(err, errSetupCancel) {
					fmt.Fprintln(os.Stdout, "配置已取消，未启动安装；原文件保留。")
					return nil
				}
				return setupError(err)
			}
		}
	}
	if !readOnly {
		state, e := deploymentState()
		if e != nil {
			return e
		}
		if isInstalled(state) {
			if e = safeRegular(pathBefore); os.IsNotExist(e) {
				return &progress.Failure{Code: "installed_config_missing", Message: "系统已安装但 webscan.yaml 丢失，请恢复原配置；不能重新初始化"}
			}
		}
		absolute, _ := filepath.Abs(pathBefore)
		if absolute == "/root/webscan-deploy/webscan.yaml" {
			if !registerLocalShortcut(systemPackagePaths(), os.Stdout) {
				defer fmt.Fprintln(os.Stdout, "本次未注册全局命令；请继续使用 bash /root/webscan-deploy/deploy-webscan.sh 管理，不要使用其他软件的 webscan。")
			}
		}
	}
	loadNodes := func() ([]common.Map, error) {
		c, e := configuration.Load(pathBefore)
		if e != nil {
			return nil, e
		}
		return c.Nodes, nil
	}
	setup := func(a []string, s *bufio.Scanner, out io.Writer) ([]string, error) {
		if initialized {
			return a, nil
		}
		return installationSSL(a, s, out)
	}
	var add func(*bufio.Scanner, io.Writer) ([]string, error)
	if interactive {
		add = func(s *bufio.Scanner, out io.Writer) ([]string, error) {
			return addConfiguredNode(pathBefore, deploy.StateRoot, liveInput(s, out))
		}
	}
	args, err := selectActionWithScanner(os.Args[1:], scanner, os.Stdout, loadNodes, setup, add)
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
		fmt.Println("bash deploy-webscan.sh：显示 1 安装、2 重装、3 卸载、4 增加子服务器、5 SSL 设置并自动部署菜单\nbash deploy-webscan.sh [--set-ssl on|off] [--install|--reinstall|--uninstall|--check|--upgrade|--add-node|--resume|--rollback|--reload-rules] [--dry-run] [--config-help] [--config YAML] [--node ID] [--central-only|--grafana-only|--sync-grafana-credentials] [--non-interactive]\n菜单 4 等同于 --add-node --node 节点ID，沿用主服务器当前版本和配置；恢复追加 --resume，回退追加 --rollback。\n--set-ssl on/off 保存协议后自动完整部署；交互安装和重装会引导选择 SSL，--non-interactive 沿用 YAML。\n重装与卸载保留监控数据、凭据、备份及三文件部署包。")
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
	if unlock == nil {
		unlock, err = lockBootstrap()
		if err != nil {
			return err
		}
		defer unlock()
	}
	if mode := parsed["--set-ssl"]; mode != "" {
		// Release only the deployment lock before starting the child. The
		// bootstrap lock remains held until the whole installation finishes.
		args, err = prepareSSLDeployment(path, mode, args, os.Stdout)
		if err != nil {
			return err
		}
		defer func() {
			if runErr == nil {
				return
			}
			state, readErr := deploymentState()
			if readErr == nil && pendingDeployment(state) {
				fmt.Fprintln(os.Stderr, "SSL 部署尚未完成，所选 YAML 和部署记录已保留。请保持本次配置，执行 bash deploy-webscan.sh --resume 继续，或 --rollback 回退。")
			} else {
				retryAction := ""
				if parsed["--reinstall"] == "true" {
					retryAction = "--reinstall "
				}
				fmt.Fprintf(os.Stderr, "SSL 部署未完成，所选 YAML 已保留；请查看失败阶段及日志，排除原因后重新执行 bash deploy-webscan.sh %s--set-ssl %s。\n", retryAction, mode)
			}
		}()
		parsed, err = parseBootstrapArgs(args)
		if err != nil {
			return err
		}
		c, err = configuration.Load(path)
		if err != nil {
			return err
		}
	}
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
	ref := bootstrapImageForOperation(c.Image("central"), args)
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
	if strings.HasSuffix(ref, ":latest") && toolOlderThanBootstrap(ctx, binary) {
		if common.B(reg["auth_required"]) || !strings.HasPrefix(ref, "docker.io/") {
			return errors.New("bootstrap_tool_release_mismatch")
		}
		progress.Warn(ctx, "加速源返回的 latest 程序版本过旧，改从 Docker Hub 官方入口获取")
		ref = strings.Replace(ref, "docker.io/", "registry-1.docker.io/", 1)
		if err = progress.Stage(ctx, host, "从官方入口重新下载主服务器镜像", func(ctx context.Context) error {
			_, e := docker(ctx, nil, "pull", "--platform", "linux/amd64", ref)
			return e
		}); err != nil {
			return err
		}
		binary, err = extractTool(ctx, docker, tmp, ref)
		if err != nil {
			return err
		}
		if toolOlderThanBootstrap(ctx, binary) {
			return errors.New("bootstrap_tool_release_mismatch")
		}
	}
	if err = validateToolVersionForImage(ctx, binary, c.Image("central")); err != nil {
		return err
	}
	if strings.HasSuffix(c.Image("central"), ":latest") {
		b, inspectErr := docker(ctx, nil, "image", "inspect", "--format", "{{json .RepoDigests}}", ref)
		if inspectErr != nil {
			return errors.New("bootstrap_tool_image_lock_failed")
		}
		var digests []string
		if json.Unmarshal(b, &digests) != nil || len(digests) == 0 {
			return errors.New("bootstrap_tool_image_lock_failed")
		}
		locked := matchingToolDigest(ref, digests)
		if locked == "" {
			return errors.New("bootstrap_tool_image_lock_failed")
		}
		if err = os.Setenv("WEBSCAN_TOOL_IMAGE_LOCK", locked); err != nil {
			return err
		}
		defer os.Unsetenv("WEBSCAN_TOOL_IMAGE_LOCK")
	}

	if err = os.RemoveAll(authDir); err != nil {
		return err
	}
	progress.Info(ctx, "引导完成，临时容器已删除；开始执行部署工具，后续进度继续写入同一日志")
	return runDeploymentTool(baseCtx, binary, args)
}
