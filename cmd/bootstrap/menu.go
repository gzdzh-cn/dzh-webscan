package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/progress"
)

var errMenuExit = errors.New("menu_exit")

// The offline uninstall path calls Go directly, so it must enforce the same
// strict options as the container-extracted GoFrame CLI before removing anything.
func parseBootstrapArgs(args []string) (map[string]string, error) {
	parsed := map[string]string{}
	boolean := []string{"--install", "--reinstall", "--uninstall", "--upgrade", "--add-node", "--resume", "--rollback", "--check", "--grafana-only", "--sync-grafana-credentials", "--reload-rules", "--central-only", "--non-interactive", "--dry-run", "--config-help", "--help", "-h"}
	for i := 0; i < len(args); i++ {
		key, value, equals := strings.Cut(args[i], "=")
		switch key {
		case "--config", "--node", "--yara-rules", "--set-ssl", "--prepare-package":
			if !equals {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
					return nil, &progress.Failure{Code: "cli_option_requires_value", Message: "此参数必须填写值；指定子服务器请使用 --node 节点ID，已停止操作"}
				}
				i++
				value = args[i]
			}
			if value == "" {
				return nil, &progress.Failure{Code: "cli_option_requires_value", Message: "此参数必须填写值；指定子服务器请使用 --node 节点ID，已停止操作"}
			}
		default:
			if !common.Contains(boolean, key) {
				return nil, &progress.Failure{Code: "unknown_cli_option", Message: "包含无法识别的命令参数，请核对 --node、--central-only 等参数拼写，已停止操作"}
			}
			if !equals {
				value = "true"
			} else {
				b, err := strconv.ParseBool(value)
				if err != nil {
					return nil, &progress.Failure{Code: "cli_boolean_option_invalid", Message: "开关参数只能使用 true 或 false，已停止操作"}
				}
				value = strconv.FormatBool(b)
			}
		}
		parsed[key] = value
	}
	return parsed, nil
}

func validateActions(args []string) error {
	parsed, err := parseBootstrapArgs(args)
	if err != nil {
		return err
	}
	flags := map[string]bool{}
	for key, value := range parsed {
		flags[key] = value == "true"
		if key == "--node" || key == "--config" || key == "--yara-rules" || key == "--set-ssl" {
			flags[key] = true
		}
	}
	if flags["--set-ssl"] {
		if parsed["--set-ssl"] != "on" && parsed["--set-ssl"] != "off" {
			return &progress.Failure{Code: "invalid_ssl_selection", Message: "SSL 设置只能使用 --set-ssl on 或 --set-ssl off"}
		}
		if flags["--node"] || flags["--central-only"] || flags["--dry-run"] {
			return errors.New("incompatible_cli_options")
		}
	}
	if flags["--yara-rules"] && !flags["--reload-rules"] {
		return errors.New("incompatible_cli_options")
	}

	count := 0
	for _, flag := range []string{"--install", "--reinstall", "--uninstall", "--upgrade", "--add-node", "--resume", "--rollback", "--check", "--grafana-only", "--sync-grafana-credentials", "--reload-rules", "--set-ssl"} {
		if flag == "--add-node" && (flags["--resume"] || flags["--rollback"]) {
			continue
		}
		if flag == "--set-ssl" && flags["--reinstall"] {
			continue
		}
		if flag == "--upgrade" && (flags["--resume"] || flags["--grafana-only"]) {
			continue
		}
		if flags[flag] {
			count++
		}
	}
	if count > 1 || flags["--reinstall"] && (flags["--node"] || flags["--central-only"]) || flags["--node"] && flags["--central-only"] {
		return errors.New("incompatible_cli_options")
	}
	if flags["--add-node"] && (!flags["--node"] || flags["--upgrade"] || flags["--central-only"]) {
		return errors.New("incompatible_cli_options")
	}
	if flags["--dry-run"] {
		for _, flag := range []string{"--check", "--rollback", "--grafana-only", "--sync-grafana-credentials", "--reload-rules"} {
			if flags[flag] {
				return errors.New("incompatible_cli_options")
			}
		}
	}
	return nil
}

func selectAction(args []string, in io.Reader, out io.Writer) ([]string, error) {
	return selectActionWithSetup(args, in, out, func() ([]common.Map, error) {
		c, err := configuration.Load(configPath(args))
		if err != nil {
			return nil, err
		}
		return c.Nodes, nil
	}, installationSSL)
}

func selectActionWithNodes(args []string, in io.Reader, out io.Writer, loadNodes func() ([]common.Map, error)) ([]string, error) {
	return selectActionWithSetup(args, in, out, loadNodes, nil)
}

type installSetup func([]string, *bufio.Scanner, io.Writer) ([]string, error)

func selectActionWithSetup(args []string, in io.Reader, out io.Writer, loadNodes func() ([]common.Map, error), setup installSetup) ([]string, error) {
	return selectActionWithScanner(args, bufio.NewScanner(in), out, loadNodes, setup, nil)
}

func selectActionWithScanner(args []string, scanner *bufio.Scanner, out io.Writer, loadNodes func() ([]common.Map, error), setup installSetup, add func(*bufio.Scanner, io.Writer) ([]string, error)) ([]string, error) {
	parsed, err := parseBootstrapArgs(args)
	if err != nil {
		return nil, err
	}
	if err = validateActions(args); err != nil {
		return nil, err
	}
	prepare := func(selected []string) ([]string, error) {
		if setup == nil {
			return selected, nil
		}
		return setup(selected, scanner, out)
	}
	for _, arg := range args {
		key := strings.SplitN(arg, "=", 2)[0]
		switch key {
		case "--set-ssl", "--install", "--reinstall", "--uninstall", "--upgrade", "--add-node", "--resume", "--rollback", "--check", "--dry-run", "--reload-rules", "--grafana-only", "--sync-grafana-credentials", "--config-help", "--help", "-h":
			if (key == "--install" || key == "--upgrade" || key == "--reinstall") && parsed[key] == "true" {
				selected, err := prepare(args)
				if selected == nil && err == nil {
					return nil, errMenuExit
				}
				return selected, err
			}
			return args, nil
		}
	}
	if parsed["--non-interactive"] == "true" {
		return append(args, "--install"), nil
	}
	for {
		fmt.Fprintln(out, "\n网站监控部署管理\n1、安装（首次安装；已安装时升级或继续）\n2、重装（重建监控容器和配置，保留数据及账号）\n3、卸载（选择卸载范围，保留数据与部署包）\n4、增加子服务器（选择已有节点或交互录入新节点）\n5、SSL 设置并自动部署（统一控制主子通信、采集和面板）\n0、退出")
		fmt.Fprint(out, "请选择 [1/2/3/4/5/0]：")
		if !scanner.Scan() {
			return nil, errors.New("menu_requires_selection_or_non_interactive")
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "1":
			selected, err := prepare(append(args, "--install"))
			if err != nil {
				return nil, err
			}
			if selected == nil {
				continue
			}
			return selected, nil
		case "2":
			selected, err := prepare(append(args, "--reinstall"))
			if err != nil {
				return nil, err
			}
			if selected == nil {
				continue
			}
			return selected, nil
		case "3":
			selection, err := selectUninstall(scanner, out, loadNodes)
			if err != nil {
				return nil, err
			}
			if selection == nil {
				continue
			}
			return append(withoutScope(args), selection...), nil
		case "4":
			selection, err := selectAdditionWithNew(scanner, out, loadNodes, add)
			if err != nil {
				return nil, err
			}
			if selection == nil {
				continue
			}
			return append(withoutScope(args), selection...), nil
		case "5":
			for {
				fmt.Fprintln(out, "\nSSL 设置并自动部署（统一控制节点事件、监控指标和系统面板）\n选择后自动安装或完整升级主服务器和全部启用节点，同时应用 YAML 中其他修改及配置指定的镜像版本。\n0、返回上一级\n1、使用 SSL（HTTPS）\n2、不使用 SSL（HTTP；通信明文，面板可交给宝塔 HTTPS 反代）")
				fmt.Fprint(out, "请选择 [0/1/2]：")
				if !scanner.Scan() {
					return nil, errors.New("menu_requires_selection_or_non_interactive")
				}
				choice := strings.TrimSpace(scanner.Text())
				if choice == "0" {
					break
				}
				if choice == "1" {
					return append(withoutScope(args), "--set-ssl", "on"), nil
				}
				if choice == "2" {
					return append(withoutScope(args), "--set-ssl", "off"), nil
				}
				fmt.Fprintln(out, "请输入 0、1 或 2。")
			}
		case "0":
			return nil, errMenuExit
		default:
			fmt.Fprintln(out, "请输入 1、2、3、4、5 或 0。")
		}
	}
}

func withoutScope(args []string) []string {
	clean := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--node" {
			i++
			continue
		}
		if args[i] == "--central-only" || strings.HasPrefix(args[i], "--central-only=") || strings.HasPrefix(args[i], "--node=") {
			continue
		}
		clean = append(clean, args[i])
	}
	return clean
}

func selectAddition(scanner *bufio.Scanner, out io.Writer, loadNodes func() ([]common.Map, error)) ([]string, error) {
	return selectAdditionWithNew(scanner, out, loadNodes, nil)
}
func selectAdditionWithNew(scanner *bufio.Scanner, out io.Writer, loadNodes func() ([]common.Map, error), add func(*bufio.Scanner, io.Writer) ([]string, error)) ([]string, error) {
	nodes, err := loadNodes()
	if err != nil {
		return nil, err
	}
	enabled := []common.Map{}
	for _, n := range nodes {
		if common.B(n["enabled"]) {
			enabled = append(enabled, n)
		}
	}
	if len(enabled) == 0 && add == nil {
		fmt.Fprintln(out, "YAML 中没有启用的子服务器。请先配置 nodes、enabled: true 和 deployment.node_order，然后重新执行脚本。")
		return nil, nil
	}
	for {
		fmt.Fprintln(out, "\n请选择需要增加的子服务器\n已安装节点会执行单节点更新；可选择 N 交互新增节点。\n0、返回上一级")
		for i, n := range enabled {
			fmt.Fprintf(out, "%d、%s [%s] %s\n", i+1, common.S(n["name"]), common.S(n["id"]), common.S(n["host"]))
		}
		if add != nil {
			fmt.Fprintln(out, "N、录入新子服务器并立即安装")
		}
		fmt.Fprint(out, "请输入序号：")
		if !scanner.Scan() {
			return nil, errors.New("menu_requires_selection_or_non_interactive")
		}
		if strings.EqualFold(strings.TrimSpace(scanner.Text()), "N") && add != nil {
			selection, e := add(scanner, out)
			if errors.Is(e, errSetupCancel) {
				continue
			}
			return selection, e
		}
		choice, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
		if err == nil && choice == 0 {
			return nil, nil
		}
		if err != nil || choice < 1 || choice > len(enabled) {
			fmt.Fprintln(out, "序号无效，请重新选择。")
			continue
		}
		return []string{"--add-node", "--node", common.S(enabled[choice-1]["id"])}, nil
	}
}

func selectUninstall(scanner *bufio.Scanner, out io.Writer, loadNodes func() ([]common.Map, error)) ([]string, error) {
	for {
		fmt.Fprintln(out, "\n请选择卸载范围\n0、返回上一级\n1、主服务器 + 全部子服务器\n2、主服务器\n3、单个子服务器")
		fmt.Fprint(out, "请选择 [0/1/2/3]：")
		if !scanner.Scan() {
			return nil, errors.New("menu_requires_selection_or_non_interactive")
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "0":
			return nil, nil
		case "1":
			return []string{"--uninstall"}, nil
		case "2":
			return []string{"--uninstall", "--central-only"}, nil
		case "3":
			nodes, err := loadNodes()
			if err != nil {
				return nil, err
			}
			if len(nodes) == 0 {
				fmt.Fprintln(out, "YAML 未配置子服务器。")
				continue
			}
			for {
				fmt.Fprintln(out, "\n请选择需要卸载的子服务器\n0、返回上一级")
				for i, n := range nodes {
					status := ""
					if !common.B(n["enabled"]) {
						status = "（已停用）"
					}
					fmt.Fprintf(out, "%d、%s [%s] %s%s\n", i+1, common.S(n["name"]), common.S(n["id"]), common.S(n["host"]), status)
				}
				fmt.Fprint(out, "请输入序号：")
				if !scanner.Scan() {
					return nil, errors.New("menu_requires_selection_or_non_interactive")
				}
				choice, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
				if err == nil && choice == 0 {
					break
				}
				if err != nil || choice < 1 || choice > len(nodes) {
					fmt.Fprintln(out, "序号无效，请重新选择。")
					continue
				}
				return []string{"--uninstall", "--node", common.S(nodes[choice-1]["id"])}, nil
			}
		default:
			fmt.Fprintln(out, "请输入 0、1、2 或 3。")
		}
	}
}
