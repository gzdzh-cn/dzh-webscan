package main

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/os/gcmd"
	"os"
	"os/signal"
	"syscall"
	"webscan/internal/agent"
	"webscan/internal/central"
	"webscan/internal/config"
	"webscan/internal/deploy"
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
	for _, name := range []string{"dry-run", "check", "install", "reinstall", "upgrade", "add-node", "resume", "rollback", "uninstall", "central-only", "grafana-only", "sync-grafana-credentials", "reload-rules", "non-interactive", "config-help"} {
		args = append(args, gcmd.Argument{Name: name, Orphan: true})
	}
	args = append(args, gcmd.Argument{Name: "node"}, gcmd.Argument{Name: "yara-rules"})
	deployCmd := &gcmd.Command{Name: "deploy", Arguments: args, Strict: true, Func: func(ctx context.Context, p *gcmd.Parser) error {
		if present(p, "config-help") {
			fmt.Print(config.Help())
			return nil
		}
		return deploy.Run(ctx, deploy.Options{Config: p.GetOpt("config").String(), Node: p.GetOpt("node").String(), YaraRules: p.GetOpt("yara-rules").String(), DryRun: present(p, "dry-run"), Check: present(p, "check"), Install: present(p, "install"), Reinstall: present(p, "reinstall"), Upgrade: present(p, "upgrade"), AddNode: present(p, "add-node"), Resume: present(p, "resume"), Rollback: present(p, "rollback"), Uninstall: present(p, "uninstall"), CentralOnly: present(p, "central-only"), GrafanaOnly: present(p, "grafana-only"), SyncGrafana: present(p, "sync-grafana-credentials"), ReloadRules: present(p, "reload-rules"), NonInteractive: present(p, "non-interactive")})
	}}
	toolCmd := &gcmd.Command{Name: "tool", Strict: true, Arguments: []gcmd.Argument{{Name: "action"}, {Name: "input"}, {Name: "output"}, {Name: "uninstall", Orphan: true}}, Func: func(ctx context.Context, p *gcmd.Parser) error {
		return tool.Run(ctx, p.GetOpt("action").String(), p.GetOpt("input").String(), p.GetOpt("output").String(), present(p, "uninstall"))
	}}
	passwordCmd := &gcmd.Command{Name: "website-password", Brief: "管理员交互式重置后台密码（不回显）", Arguments: cfg, Strict: true, Func: func(ctx context.Context, p *gcmd.Parser) error {
		return resetWebsitePassword(p.GetOpt("config").String())
	}}
	version := &gcmd.Command{Name: "version", Func: func(context.Context, *gcmd.Parser) error { fmt.Println(deploy.Release); return nil }}
	if e := root.AddCommand(agentCmd, centralCmd, deployCmd, toolCmd, version, passwordCmd); e != nil {
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
