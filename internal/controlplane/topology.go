package controlplane

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SelectTopology only prompts for a fresh interactive installation. Existing
// deployments cannot change topology through an ordinary upgrade.
func SelectTopology(saved, requested string, fresh, nonInteractive bool, in io.Reader, out io.Writer) (string, error) {
	return selectTopology(saved, requested, fresh, nonInteractive, bufio.NewScanner(in), out)
}
func selectTopology(saved, requested string, fresh, nonInteractive bool, scanner *bufio.Scanner, out io.Writer) (string, error) {
	valid := func(v string) bool { return v == "single" || v == "ha" }
	if saved != "" && !valid(saved) || requested != "" && !valid(requested) {
		return "", errors.New("--topology 只允许 single 或 ha")
	}
	if !fresh {
		if saved == "" {
			saved = "single"
		}
		if requested != "" && requested != saved {
			return "", errors.New("普通升级不能切换部署方式，请先执行拓扑迁移预览")
		}
		return saved, nil
	}
	if requested != "" {
		return requested, nil
	}
	if nonInteractive {
		return "single", nil
	}
	for {
		fmt.Fprint(out, "请选择主控部署方式：\n\n1. 单中心部署（默认）\n2. 高可用部署\n\n请选择 [1]: ")
		if !scanner.Scan() {
			if scanner.Err() != nil {
				return "", scanner.Err()
			}
			return "", errors.New("未收到部署方式选择，未保存配置")
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "", "1":
			return "single", nil
		case "2":
			return "ha", nil
		default:
			fmt.Fprintln(out, "请选择 1 或 2。")
		}
	}
}

func Initialize(o Options, in io.Reader, out io.Writer) error {
	if _, e := os.Lstat(o.Config); e == nil {
		c, e := LoadConfig(o.Config)
		if e != nil {
			return e
		}
		_, e = SelectTopology(c.Central.Topology, o.Topology, false, o.NonInteractive, in, out)
		return e
	} else if !os.IsNotExist(e) {
		return e
	}
	scanner := bufio.NewScanner(in)
	topology, e := selectTopology("", o.Topology, true, o.NonInteractive, scanner, out)
	if e != nil {
		return e
	}
	line := func(label, def string) (string, error) {
		if o.NonInteractive {
			return def, nil
		}
		fmt.Fprintf(out, "%s [%s]: ", label, def)
		if !scanner.Scan() {
			return "", errors.New("输入已结束，配置未保存")
		}
		v := strings.TrimSpace(scanner.Text())
		if v == "" {
			v = def
		}
		return v, nil
	}
	var c Config
	c.Version = 3
	c.Central.Topology = topology
	c.Central.Instance, _ = os.Hostname()
	c.Central.Listen = "127.0.0.1:19444"
	c.Central.PublicURL, e = line("主控 HTTPS 访问地址", o.PublicURL)
	if e != nil {
		return e
	}
	c.Database.DSNFile = "/etc/webscan-v3/postgres.dsn"
	c.Metrics.WriteURL = "http://127.0.0.1:8428"
	c.Metrics.QueryURL = c.Metrics.WriteURL
	c.Collector.CAFile = "/etc/webscan-v3/pki/ca.crt"
	c.Collector.CertFile = "/etc/webscan-v3/pki/collector.crt"
	c.Collector.KeyFile = "/etc/webscan-v3/pki/collector.key"
	if topology == "ha" {
		if o.NonInteractive {
			return errors.New("高可用非交互初始化请提供完整 v3 YAML，缺少机器和入口时不会生成配置")
		}
		c.HA.Entrypoint, e = line("已配置的高可用 HTTPS 入口", c.Central.PublicURL)
		if e != nil {
			return e
		}
		fmt.Fprintln(out, "高可用至少需要三台独立机器；本步骤只保存配置，网络与故障接管仍需实际验收。")
		for i := 0; i < 3; i++ {
			m := HAMember{ID: fmt.Sprintf("central-%d", i+1), SSHPort: 22}
			m.Host, e = line(fmt.Sprintf("中心 %d SSH 主机", i+1), "")
			if e != nil {
				return e
			}
			m.PrivateAddress, e = line("内部通信 IP", "")
			if e != nil {
				return e
			}
			port, err := line("SSH 端口", "22")
			if err != nil {
				return err
			}
			m.SSHPort, err = strconv.Atoi(port)
			if err != nil {
				return errors.New("SSH 端口必须为整数")
			}
			m.SSHKeyFile, e = line("主控上的 SSH 私钥绝对路径", "")
			if e != nil {
				return e
			}
			c.HA.Members = append(c.HA.Members, m)
		}
		c.Metrics.WriteURL, e = line("vminsert 写入基础地址（含 /insert/0/prometheus）", "")
		if e != nil {
			return e
		}
		c.Metrics.QueryURL, e = line("vmselect 查询基础地址（含 /select/0/prometheus）", "")
		if e != nil {
			return e
		}
	}
	if e = SaveConfig(o.Config, c); e != nil {
		return e
	}
	fmt.Fprintln(out, "v3 配置已保存，尚未安装或切换任何服务。")
	return nil
}

func SaveConfig(path string, c Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() {
			return errors.New("配置路径不能为符号链接或特殊文件")
		}
		return errors.New("配置已存在，初始化不会覆盖原文件")
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	raw, e := yaml.Marshal(c)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".v3-config-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Link(f.Name(), path)
}

type LayoutMember struct {
	ID    string   `json:"id"`
	Host  string   `json:"host"`
	Roles []string `json:"roles"`
}
type Layout struct {
	Topology        string         `json:"topology"`
	Members         []LayoutMember `json:"members"`
	Entrypoint      string         `json:"entrypoint"`
	NetworkVerified bool           `json:"network_verified"`
}

func PlanLayout(c Config) (Layout, error) {
	if e := c.Validate(); e != nil {
		return Layout{}, e
	}
	p := Layout{Topology: c.Central.Topology, Entrypoint: c.Central.PublicURL}
	if c.Central.Topology == "single" {
		p.Members = []LayoutMember{{ID: c.Central.Instance, Host: "local", Roles: []string{"api", "collector", "notifier", "executor", "postgres", "victoriametrics"}}}
		return p, nil
	}
	p.Entrypoint = c.HA.Entrypoint
	for i, m := range c.HA.Members {
		roles := []string{"collector", "postgres", "etcd", "vmstorage"}
		if i < 2 {
			roles = append(roles, "api", "notifier", "executor", "vminsert", "vmselect")
		}
		p.Members = append(p.Members, LayoutMember{ID: m.ID, Host: m.Host, Roles: roles})
	}
	return p, nil
}
