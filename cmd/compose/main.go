// Prepare independent, per-host Compose packages locally; never connect to servers.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"webscan/internal/config"
	"webscan/internal/deploy"
	"webscan/internal/progress"
)

func main() {
	if err := execute(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "生成／检查失败：", explainComposeError(err))
		fmt.Fprintln(os.Stderr, "填写全部参数：go run ./cmd/compose --config-help\n修正后仅检查：go run ./cmd/compose --config 你的配置.yaml --check")
		os.Exit(1)
	}
}

func execute(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("compose", flag.ContinueOnError)
	// The flag parser can echo supplied values; replace its output with safe guidance.
	flags.SetOutput(io.Discard)
	path := flags.String("config", "webscan.yaml", "本地 YAML 配置")
	output := flags.String("output", "compose-deploy", "新部署包目录，不能已存在")
	launcher := flags.String("launcher", "compose.yaml", "根目录 Compose 入口文件")
	check := flags.Bool("check", false, "仅校验，不生成部署包")
	help := flags.Bool("config-help", false, "全部 YAML 参数与填写示例")
	usage := "用法：go run ./cmd/compose [--config YAML] [--output 新目录] [--launcher compose.yaml] [--check] [--config-help]\n--check 只检查配置；--config-help 显示全部参数；--help 显示命令用法。\n"
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(out, usage)
			return nil
		}
		return &progress.Failure{Code: "invalid_compose_cli_options", Message: "命令参数无法解析。路径参数 --config、--output、--launcher 必须填写值；开关可使用 --check 或 --check=true，不能填写其他值。\n" + usage}
	}
	if flags.NArg() > 0 {
		return &progress.Failure{Code: "unexpected_compose_cli_arguments", Message: "存在多余参数；路径必须写在 --config、--output 或 --launcher 后面，布尔开关使用 --check 或 --check=true。\n" + usage}
	}
	for _, option := range []struct{ Name, Value string }{{"config", *path}, {"output", *output}, {"launcher", *launcher}} {
		if option.Value == "" || option.Value[0] == '-' {
			return &progress.Failure{Code: "compose_option_requires_path", Message: "--" + option.Name + " 必须填写有效路径，不能留空或用另一个开关代替路径。\n" + usage}
		}
	}
	if *help {
		fmt.Fprint(out, config.Help())
		return nil
	}
	if *check {
		c, err := deploy.Load(*path)
		if err != nil {
			return err
		}
		if err = deploy.ValidateComposeConfiguration(c); err != nil {
			return err
		}
		fmt.Fprintln(out, "配置格式与 Compose 生成要求检查通过；未创建部署包、未连接服务器、未检查实际网络或飞书送达。")
		return nil
	}
	if err := run(*path, *output, *launcher); err != nil {
		return err
	}
	fmt.Fprintln(out, "Compose 部署包已生成。主服务器使用 central，子服务器使用各自节点目录。")
	fmt.Fprintln(out, "包内包含运行凭据，请通过 SSH 上传；账号密码见 central/grafana-credentials.json。")
	return nil
}

func explainComposeError(err error) string { return progress.Explain(err) }

func run(path, output, launcher string) error {
	c, err := deploy.Load(path)
	if err != nil {
		return err
	}
	entry, err := os.ReadFile(launcher)
	if err != nil {
		return fmt.Errorf("compose_launcher_unreadable")
	}
	return deploy.PrepareCompose(c, output, entry)
}
