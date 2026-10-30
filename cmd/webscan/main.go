package main

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/os/gcmd"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"webscan/internal/agent"
	"webscan/internal/central"
	"webscan/internal/config"
	"webscan/internal/controlplane"
	"webscan/internal/deploy"
	"webscan/internal/management"
	"webscan/internal/nodeops"
	"webscan/internal/nodepki"
	"webscan/internal/progress"
	"webscan/internal/tool"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	root := &gcmd.Command{Name: "webscan", Brief: "GoFrame durable website monitoring", Strict: true}
	cfg := []gcmd.Argument{{Name: "config", Default: "webscan.yaml", Brief: "Configuration file"}}
	agentCmd := &gcmd.Command{Name: "agent", Arguments: cfg, Strict: true, Func: func(ctx context.Context, p *gcmd.Parser) error { return agent.Run(ctx, p.GetOpt("config").String()) }}
	centralCmd := &gcmd.Command{Name: "central", Arguments: cfg, Strict: true, Func: func(ctx context.Context, p *gcmd.Parser) error { return central.Run(ctx, p.GetOpt("config").String()) }}
	args := append([]gcmd.Argument{}, cfg...)
	for _, name := range []string{"dry-run", "check", "install", "reinstall", "upgrade", "add-node", "resume", "rollback", "uninstall", "central-only", "grafana-only", "sync-grafana-credentials", "reload-rules", "non-interactive", "config-help", "keep-images", "acknowledge-preflight-warnings"} {
		args = append(args, gcmd.Argument{Name: name, Orphan: true})
	}
	args = append(args, gcmd.Argument{Name: "node"}, gcmd.Argument{Name: "yara-rules"}, gcmd.Argument{Name: "expected-revision"})
	deployCmd := &gcmd.Command{Name: "deploy", Arguments: args, Strict: true, Func: func(ctx context.Context, p *gcmd.Parser) error {
		if present(p, "config-help") {
			fmt.Print(config.Help())
			return nil
		}
		return deploy.Run(ctx, deploy.Options{Config: p.GetOpt("config").String(), Node: p.GetOpt("node").String(), YaraRules: p.GetOpt("yara-rules").String(), DryRun: present(p, "dry-run"), Check: present(p, "check"), Install: present(p, "install"), Reinstall: present(p, "reinstall"), Upgrade: present(p, "upgrade"), AddNode: present(p, "add-node"), Resume: present(p, "resume"), Rollback: present(p, "rollback"), Uninstall: present(p, "uninstall"), CentralOnly: present(p, "central-only"), GrafanaOnly: present(p, "grafana-only"), SyncGrafana: present(p, "sync-grafana-credentials"), ReloadRules: present(p, "reload-rules"), NonInteractive: present(p, "non-interactive"), KeepImages: present(p, "keep-images"), AcknowledgeWarnings: present(p, "acknowledge-preflight-warnings"), ExpectedRevision: p.GetOpt("expected-revision").String()})
	}}
	toolCmd := &gcmd.Command{Name: "tool", Strict: true, Arguments: []gcmd.Argument{{Name: "action"}, {Name: "input"}, {Name: "output"}, {Name: "uninstall", Orphan: true}}, Func: func(ctx context.Context, p *gcmd.Parser) error {
		return tool.Run(ctx, p.GetOpt("action").String(), p.GetOpt("input").String(), p.GetOpt("output").String(), present(p, "uninstall"))
	}}
	passwordCmd := &gcmd.Command{Name: "website-password", Brief: "管理员交互式重置后台密码（不回显）", Arguments: cfg, Strict: true, Func: func(ctx context.Context, p *gcmd.Parser) error {
		return resetWebsitePassword(p.GetOpt("config").String())
	}}
	manager := &gcmd.Command{Name: "manager", Brief: "宿主机可视化管理服务", Strict: true, Arguments: append(cfg, gcmd.Argument{Name: "state", Default: "/var/lib/webscan-deploy"}, gcmd.Argument{Name: "socket", Default: "/run/webscan-management/control.sock"}), Func: func(ctx context.Context, p *gcmd.Parser) error {
		return management.Run(ctx, p.GetOpt("config").String(), p.GetOpt("state").String(), p.GetOpt("socket").String())
	}}
	adopt := &gcmd.Command{Name: "adopt-compose", Brief: "在主服务器接管 Go Compose 包并启用可视化部署", Arguments: cfg, Strict: true, Func: func(ctx context.Context, p *gcmd.Parser) error {
		return deploy.AdoptCompose(ctx, p.GetOpt("config").String())
	}}
	version := &gcmd.Command{Name: "version", Func: func(context.Context, *gcmd.Parser) error { fmt.Println(deploy.Release); return nil }}
	v3Args := []gcmd.Argument{{Name: "config", Default: "webscan-v3.yaml"}, {Name: "action", Default: "check"}, {Name: "role", Default: "all"}, {Name: "topology"}, {Name: "username"}, {Name: "password-file"}, {Name: "source"}, {Name: "notifications-source"}, {Name: "backup-directory"}, {Name: "request-key"}, {Name: "snapshot"}, {Name: "output"}, {Name: "public-url"}, {Name: "non-interactive", Orphan: true}}
	v3 := &gcmd.Command{Name: "control-v3", Brief: "v3 独立重构验证入口；不替换现有主控", Strict: true, Arguments: v3Args, Func: func(ctx context.Context, p *gcmd.Parser) error {
		return controlplane.Command(ctx, controlplane.Options{Config: p.GetOpt("config").String(), Action: p.GetOpt("action").String(), Role: p.GetOpt("role").String(), Topology: p.GetOpt("topology").String(), Username: p.GetOpt("username").String(), PasswordFile: p.GetOpt("password-file").String(), Source: p.GetOpt("source").String(), NotificationsSource: p.GetOpt("notifications-source").String(), BackupDirectory: p.GetOpt("backup-directory").String(), RequestKey: p.GetOpt("request-key").String(), Snapshot: p.GetOpt("snapshot").String(), Output: p.GetOpt("output").String(), PublicURL: p.GetOpt("public-url").String(), NonInteractive: present(p, "non-interactive")}, os.Stdin, os.Stdout)
	}}
	nodeV3 := &gcmd.Command{Name: "node-v3", Brief: "v3 节点阶段工具（默认仅检查与准备）", Strict: true, Arguments: []gcmd.Argument{{Name: "lifecycle", Orphan: true}, {Name: "identity-recovery", Orphan: true}, {Name: "identity-name-change", Orphan: true}}, Func: func(ctx context.Context, p *gcmd.Parser) error {
		if present(p, "identity-name-change") {
			if present(p, "lifecycle") || present(p, "identity-recovery") {
				return &progress.Failure{Code: "node_v3_conflicting_modes", Message: "身份名称变更不能与部署阶段或身份恢复同时执行"}
			}
			return nodeops.CommandNameChange(ctx, os.Stdin, os.Stdout)
		}
		if present(p, "identity-recovery") {
			if present(p, "lifecycle") {
				return &progress.Failure{Code: "node_v3_conflicting_modes", Message: "身份恢复不能与部署阶段同时执行"}
			}
			return nodeops.CommandIdentityRecovery(ctx, os.Stdin, os.Stdout)
		}
		if present(p, "lifecycle") {
			return nodeops.CommandLifecycle(ctx, os.Stdin, os.Stdout)
		}
		return nodeops.Command(ctx, os.Stdin, os.Stdout)
	}}
	pkiV3 := &gcmd.Command{Name: "pki-v3", Brief: "v3 离线证书管理工具（不安装、不下发）", Strict: true, Arguments: []gcmd.Argument{{Name: "action"}, {Name: "authority"}, {Name: "output"}, {Name: "role"}, {Name: "id"}, {Name: "names"}, {Name: "certificate"}, {Name: "lifetime-hours"}, {Name: "ca-file"}, {Name: "identity-file"}, {Name: "source"}, {Name: "expected-certificate-sha256"}}, Func: func(ctx context.Context, p *gcmd.Parser) error {
		hours := 0
		if value := p.GetOpt("lifetime-hours").String(); value != "" {
			var err error
			hours, err = strconv.Atoi(value)
			if err != nil || hours < 1 || hours > 2160 {
				return fmt.Errorf("证书有效小时数必须为 1～2160 的整数")
			}
		}
		return nodepki.Command(ctx, nodepki.Options{Action: p.GetOpt("action").String(), Authority: p.GetOpt("authority").String(), Output: p.GetOpt("output").String(), Role: p.GetOpt("role").String(), ID: p.GetOpt("id").String(), Names: p.GetOpt("names").String(), Certificate: p.GetOpt("certificate").String(), LifetimeHours: hours, CAFile: p.GetOpt("ca-file").String(), IdentityFile: p.GetOpt("identity-file").String(), Source: p.GetOpt("source").String(), ExpectedSHA256: p.GetOpt("expected-certificate-sha256").String()}, os.Stdout)
	}}
	releaseV3 := &gcmd.Command{Name: "release-v3", Brief: "v3 离线发布签名与校验（不上传、不安装）", Strict: true, Arguments: []gcmd.Argument{{Name: "action"}, {Name: "output"}, {Name: "key-file"}, {Name: "public-key-file"}, {Name: "manifest"}, {Name: "signature"}, {Name: "release"}, {Name: "helper"}, {Name: "native-bundle"}, {Name: "agent-image"}, {Name: "image-archive"}, {Name: "image-config-sha256"}}, Func: func(ctx context.Context, p *gcmd.Parser) error {
		return controlplane.ReleaseCommand(ctx, controlplane.ReleaseOptions{Action: p.GetOpt("action").String(), Output: p.GetOpt("output").String(), KeyFile: p.GetOpt("key-file").String(), PublicKeyFile: p.GetOpt("public-key-file").String(), Manifest: p.GetOpt("manifest").String(), Signature: p.GetOpt("signature").String(), Release: p.GetOpt("release").String(), Helper: p.GetOpt("helper").String(), NativeBundle: p.GetOpt("native-bundle").String(), AgentImage: p.GetOpt("agent-image").String(), ImageArchive: p.GetOpt("image-archive").String(), ImageConfigSHA256: p.GetOpt("image-config-sha256").String()}, os.Stdout)
	}}
	vaultV3 := &gcmd.Command{Name: "vault-v3", Brief: "v3 独立凭据密钥初始化与检查（不修改数据库）", Strict: true, Arguments: []gcmd.Argument{{Name: "action"}, {Name: "output"}, {Name: "key-file"}}, Func: func(ctx context.Context, p *gcmd.Parser) error {
		return controlplane.VaultCommand(ctx, controlplane.VaultOptions{Action: p.GetOpt("action").String(), Output: p.GetOpt("output").String(), KeyFile: p.GetOpt("key-file").String()}, os.Stdout)
	}}
	if e := root.AddCommand(agentCmd, centralCmd, deployCmd, toolCmd, version, passwordCmd, manager, adopt, v3, nodeV3, pkiV3, releaseV3, vaultV3); e != nil {
		fmt.Fprintln(os.Stderr, "command_registration_failed")
		os.Exit(1)
	}
	if e := root.RunWithError(ctx); e != nil {
		fmt.Fprintln(os.Stderr, "错误:", progress.Explain(e))
		os.Exit(1)
	}
}

// GoFrame orphan options have an empty string value when present.
func present(p *gcmd.Parser, name string) bool {
	value := p.GetOpt(name)
	return value != nil && (value.String() == "" || value.Bool())
}
