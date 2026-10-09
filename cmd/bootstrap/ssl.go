package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/deploy"
	"webscan/internal/progress"
)

func configPath(args []string) string {
	parsed, _ := parseBootstrapArgs(args)
	if path := parsed["--config"]; path != "" {
		return path
	}
	return "webscan.yaml"
}

func deploymentState() (common.Map, error) {
	state, err := common.ReadJSON(filepath.Join(deploy.StateRoot, "state.json"))
	if os.IsNotExist(err) {
		return common.Map{}, nil
	}
	return state, err
}

func pendingDeployment(state common.Map) bool {
	return strings.HasPrefix(common.S(state["run_id"]), "go-") && common.S(state["step"]) != "complete" && common.S(state["step"]) != "rolled-back"
}

func checkSSLState(state common.Map) error {
	if pendingDeployment(state) {
		return &progress.Failure{Code: "ssl_settings_pending_deployment", Message: "存在未完成部署，SSL 设置未修改；请使用原配置和原操作范围 --resume 或 --rollback，再修改 SSL 设置"}
	}
	if pending := common.M(state["single_uninstall"]); common.B(state["central_uninstall_pending"]) || len(pending) > 0 && !common.B(pending["complete"]) {
		return &progress.Failure{Code: "ssl_settings_pending_uninstall", Message: "存在未完成卸载，SSL 设置未修改；请先使用原卸载范围继续卸载，再设置 SSL"}
	}
	return nil
}

// The menu and setup share one scanner, so pasted selections aren't lost to
// buffered reads. Merely choosing a protocol never modifies files here.
func installationSSL(args []string, scanner *bufio.Scanner, out io.Writer) ([]string, error) {
	parsed, err := parseBootstrapArgs(args)
	if err != nil {
		return nil, err
	}
	if parsed["--set-ssl"] != "" {
		return args, nil
	}
	for _, flag := range []string{"--non-interactive", "--dry-run", "--check", "--resume", "--rollback", "--help", "-h", "--config-help", "--central-only", "--grafana-only"} {
		if parsed[flag] == "true" {
			return args, nil
		}
	}
	if parsed["--node"] != "" {
		return args, nil
	}
	state, err := deploymentState()
	if err != nil {
		return nil, err
	}
	if pendingDeployment(state) && parsed["--install"] == "true" {
		if retryConfirmedRollout(state, args) {
			fmt.Fprintln(out, "上次全部节点已确认回退，没有已验收节点；沿用本次 YAML 和 SSL 设置，使用配置指定的目标镜像重新部署，保留原备份和数据。")
			return args, nil
		}
		fmt.Fprintln(out, "正在继续上次未完成部署，沿用原任务的 SSL 协议，不重新询问。需修改协议时，请先完成原任务或回退。")
		return args, nil
	}
	if parsed["--upgrade"] == "true" && (common.B(state["central_installed"]) || common.S(state["go_release"]) != "") {
		return args, nil
	}
	if err = checkSSLState(state); err != nil {
		return nil, err
	}
	c, err := configuration.Load(configPath(args))
	if err != nil {
		return nil, err
	}
	current, mode := "HTTPS", "on"
	if !c.SSLEnabled() {
		current, mode = "HTTP", "off"
	}
	operation := "安装"
	if parsed["--reinstall"] == "true" {
		operation = "重装"
	} else if !common.B(state["central_installed"]) && common.S(state["go_release"]) == "" {
		operation = "首次安装"
	}
	for {
		fmt.Fprintf(out, "\n%s：请选择 SSL 模式（通信、指标采集和系统面板统一切换）\n当前 YAML 设置：%s；回车沿用。选择后自动完成主服务器和全部启用子服务器的%s。\n1、使用 SSL（HTTPS）\n2、不使用 SSL（HTTP；通信明文，面板可交给宝塔 HTTPS 反代）\n0、返回（直接命令则退出）\n请选择 [1/2/0，回车沿用 %s]：", operation, current, operation, current)
		if !scanner.Scan() {
			return nil, &progress.Failure{Code: "ssl_setup_requires_selection", Message: "未收到 SSL 选择，未修改配置或启动安装。请重新执行脚本选择协议；无人值守请使用 --non-interactive 沿用 YAML"}
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "0":
			return nil, nil
		case "1":
			mode = "on"
		case "2":
			mode = "off"
		case "":
		default:
			fmt.Fprintln(out, "请输入 0、1、2，或回车沿用当前设置。")
			continue
		}
		clean := []string{}
		for _, arg := range args {
			key := strings.SplitN(arg, "=", 2)[0]
			if key != "--install" && key != "--upgrade" {
				clean = append(clean, arg)
			}
		}
		return append(clean, "--set-ssl", mode), nil
	}
}

func retryConfirmedRollout(state common.Map, args []string) bool {
	c, err := deploy.Load(configPath(args))
	return err == nil && deploy.CanRetryRolledBackRollout(c, state)
}

func sslDeploymentArgs(args []string, state common.Map) []string {
	clean := []string{}
	for i := 0; i < len(args); i++ {
		key, _, equals := strings.Cut(args[i], "=")
		if key == "--set-ssl" {
			if !equals {
				i++
			}
			continue
		}
		clean = append(clean, args[i])
	}
	parsed, _ := parseBootstrapArgs(clean)
	if parsed["--reinstall"] == "true" {
		return clean
	}
	if common.B(state["central_installed"]) || common.S(state["go_release"]) != "" {
		return append(clean, "--upgrade")
	}
	return append(clean, "--install")
}

func prepareSSLDeployment(path, mode string, args []string, out io.Writer) ([]string, error) {
	unlock, err := lockSSLSettings()
	if err != nil {
		return nil, err
	}
	defer unlock()
	state, err := deploymentState()
	if err != nil {
		return nil, err
	}
	if err = checkSSLState(state); err != nil {
		return nil, err
	}
	if err = saveSSLChoice(path, mode == "on", out); err != nil {
		return nil, err
	}
	return sslDeploymentArgs(args, state), nil
}

func lockSSLSettings() (func(), error) {
	f, err := os.OpenFile(filepath.Join(deploy.StateRoot, "deploy.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, &progress.Failure{Code: "ssl_settings_deployment_running", Message: "正在执行部署，SSL 设置未修改。请等待本次部署结束后再选择 SSL 设置"}
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}

func yamlField(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// Update YAML nodes instead of replacing the configuration with an effective
// snapshot: node overrides, comments and original credential values survive.
func saveSSLChoice(path string, enabled bool, out io.Writer) error {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return errors.New("cannot_read_yaml")
	}
	if _, err = configuration.Load(path); err != nil {
		return err
	}
	state, err := deploymentState()
	if err != nil {
		return err
	}
	if err = checkSSLState(state); err != nil {
		return err
	}
	before, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(before, &doc); err != nil {
		return errors.New("invalid_yaml")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("expected_yaml_mapping")
	}
	root := doc.Content[0]
	ssl := yamlField(root, "ssl")
	if ssl == nil {
		ssl = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ssl"}, ssl)
	}
	if ssl.Kind != yaml.MappingNode {
		return errors.New("expected_mapping_ssl")
	}
	value := yamlField(ssl, "enabled")
	if value == nil {
		value = &yaml.Node{}
		ssl.Content = append(ssl.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "enabled"}, value)
	}
	value.Kind, value.Tag, value.Value = yaml.ScalarNode, "!!bool", fmt.Sprint(enabled)
	if central := yamlField(root, "central"); central != nil {
		if public := yamlField(central, "public_url"); public != nil {
			if u, e := url.Parse(public.Value); e == nil {
				u.Scheme = "http"
				if enabled {
					u.Scheme = "https"
				}
				public.Value = u.String()
			}
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err = enc.Encode(&doc); err != nil {
		return err
	}
	if err = enc.Close(); err != nil {
		return err
	}
	// Validate the candidate before replacing the actual YAML; failed validation
	// leaves the existing file byte for byte unchanged.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".webscan-ssl-*.yaml")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if _, err = configuration.Load(name); err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, before) {
		return errors.New("ssl_configuration_changed_retry")
	}
	backupDir := filepath.Join(deploy.StateRoot, "config-backups")
	if err = os.MkdirAll(backupDir, 0700); err != nil {
		return err
	}
	if err = os.Chmod(backupDir, 0700); err != nil {
		return err
	}
	backup := filepath.Join(backupDir, "ssl-before-"+common.ID()+".yaml")
	if err = common.Atomic(backup, before, 0600); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	protocol := "HTTP"
	if enabled {
		protocol = "HTTPS"
	}
	fmt.Fprintf(out, "SSL 设置已保存：%s；YAML 权限 0600。端口、账号和数据保持不变。\n", protocol)
	fmt.Fprintf(out, "修改前的 YAML 已备份：%s（仅 root 可读）。接下来按本次所选操作自动部署主服务器和全部启用节点，并应用 YAML 中其他修改及目标镜像版本。\n", backup)
	return nil
}
