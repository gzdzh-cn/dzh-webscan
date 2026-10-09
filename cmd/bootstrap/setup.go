package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/progress"
)

var errSetupCancel = errors.New("configuration_setup_cancelled")

// A one-byte reader avoids buffering a pasted secret before ReadPassword.
type terminalLineReader struct{ io.Reader }

func (r terminalLineReader) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}

type setupInput struct {
	scanner *bufio.Scanner
	out     io.Writer
	secret  func() (string, error)
}

func (i setupInput) line(label, def string, validate func(string) error) (string, error) {
	for {
		fmt.Fprintf(i.out, "%s", label)
		if def != "" {
			fmt.Fprintf(i.out, " [回车沿用 %s]", def)
		}
		fmt.Fprint(i.out, "：")
		if !i.scanner.Scan() {
			return "", errors.New("未收到完整输入，配置未保存；请重新执行 webscan")
		}
		v := strings.TrimSpace(i.scanner.Text())
		if v == "0" {
			return "", errSetupCancel
		}
		if v == "" {
			v = def
		}
		if validate != nil {
			if e := validate(v); e != nil {
				fmt.Fprintln(i.out, "填写错误："+e.Error())
				continue
			}
		}
		return v, nil
	}
}
func required(v string) error {
	if v == "" {
		return errors.New("此项不能为空")
	}
	if strings.ContainsAny(v, "\x00\r\n") {
		return errors.New("不能包含控制字符")
	}
	return nil
}
func validIP(v string) error {
	if net.ParseIP(v) == nil || net.ParseIP(v).To4() == nil {
		return errors.New("请填写真实 IPv4 地址，不填写域名、协议或端口")
	}
	ip := net.ParseIP(v)
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
		return errors.New("不能填写回环、空地址或组播地址")
	}
	return nil
}
func validName(v string) error {
	if e := required(v); e != nil {
		return e
	}
	if len([]rune(v)) > 100 {
		return errors.New("名称最多 100 个字")
	}
	return nil
}
func validAccount(v string) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9_.@-]+$`).MatchString(v) {
		return errors.New("账号只能包含字母、数字及 _.@-")
	}
	return nil
}
func portValue(v string) error {
	n, e := strconv.Atoi(v)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("端口必须为 1～65535 的整数")
	}
	return nil
}
func managementPort(v string) error {
	if e := portValue(v); e != nil {
		return e
	}
	n, _ := strconv.Atoi(v)
	for _, reserved := range []int{18081, 19443, 19190, 19193, 19110, 3100} {
		if n == reserved {
			return errors.New("该端口被监控内部组件占用，请更换")
		}
	}
	return nil
}
func (i setupInput) yes(label string, def bool) (bool, error) {
	d := "2"
	if def {
		d = "1"
	}
	v, e := i.line(label+"（1 是／开启，2 否／关闭）", d, func(v string) error {
		if v != "1" && v != "2" {
			return errors.New("请选择 1 或 2；0 取消")
		}
		return nil
	})
	return v == "1", e
}
func (i setupInput) password(label string) (string, error) {
	for {
		fmt.Fprint(i.out, label+"（输入不回显）：")
		var v string
		var e error
		if i.secret != nil {
			v, e = i.secret()
			fmt.Fprintln(i.out)
		} else {
			if !i.scanner.Scan() {
				e = io.EOF
			} else {
				v = i.scanner.Text()
			}
		}
		if e != nil {
			return "", errors.New("秘密输入结束，未保存配置")
		}
		if e = required(v); e != nil {
			fmt.Fprintln(i.out, e.Error())
			continue
		}
		return v, nil
	}
}
func liveInput(scanner *bufio.Scanner, out io.Writer) setupInput {
	i := setupInput{scanner: scanner, out: out}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		i.secret = func() (string, error) { b, e := term.ReadPassword(int(os.Stdin.Fd())); return string(b), e }
	}
	return i
}
func (i setupInput) roots() ([]string, error) {
	roots := []string{}
	for {
		def := ""
		if len(roots) == 0 {
			def = "/www/wwwroot"
		}
		v, e := i.line("监控目录（子服务器上的绝对路径）", def, configuration.ValidPath)
		if e != nil {
			return nil, e
		}
		if common.Contains(roots, v) {
			fmt.Fprintln(i.out, "该目录已填写，请填写其他目录。 ")
			continue
		}
		roots = append(roots, v)
		more, e := i.yes("继续添加监控目录", false)
		if e != nil {
			return nil, e
		}
		if !more {
			return roots, nil
		}
	}
}
func (i setupInput) node(existing []common.Map) (common.Map, error) {
	seen := map[string]bool{}
	for _, n := range existing {
		seen[common.S(n["id"])] = true
	}
	next := 1
	for seen[fmt.Sprintf("node-%d", next)] {
		next++
	}
	id, e := i.line("节点 ID", fmt.Sprintf("node-%d", next), func(v string) error {
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(v) {
			return errors.New("ID 仅允许字母、数字、下划线和连字符，最多 64 位")
		}
		if seen[v] {
			return errors.New("该节点 ID 已存在")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	name, e := i.line("子服务器名称", fmt.Sprintf("子服务器%d", next), validName)
	if e != nil {
		return nil, e
	}
	host, e := i.line("子服务器 IP", "", func(v string) error {
		if e := validIP(v); e != nil {
			return e
		}
		for _, n := range existing {
			if common.S(n["host"]) == v {
				return errors.New("该 IP 已配置，请选择已有节点更新")
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	port, e := i.line("SSH 端口", "22", portValue)
	if e != nil {
		return nil, e
	}
	pn, _ := strconv.Atoi(port)
	mode, e := i.line("SSH 认证（1 私钥，2 密码；用户固定 root）", "1", func(v string) error {
		if v != "1" && v != "2" {
			return errors.New("请选择 1 或 2")
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	ssh := common.Map{"username": "root", "port": pn, "host_key_sha256": ""}
	if mode == "1" {
		key, e := i.line("主服务器上的私钥绝对路径", "", func(v string) error {
			if !filepath.IsAbs(v) {
				return errors.New("请填写主服务器上的绝对路径，不能使用 ~ 或 Mac 路径")
			}
			if e := ownedRegular(v); e != nil {
				return errors.New("私钥不存在、非普通文件或所有者不正确")
			}
			st, e := os.Stat(v)
			if e != nil {
				return e
			}
			if st.Mode().Perm() != 0400 && st.Mode().Perm() != 0600 {
				return errors.New("私钥权限须为 0400 或 0600")
			}
			return nil
		})
		if e != nil {
			return nil, e
		}
		ssh["auth_method"], ssh["private_key_path"], ssh["password"] = "key", key, ""
	} else {
		pass, e := i.password("SSH 密码")
		if e != nil {
			return nil, e
		}
		ssh["auth_method"], ssh["password"], ssh["private_key_path"] = "password", pass, ""
	}
	node := common.Map{"id": id, "name": name, "host": host, "enabled": true, "ssh": ssh}
	override, e := i.yes("为此节点设置独立监控目录（否则继承公共目录）", false)
	if e != nil {
		return nil, e
	}
	if override {
		roots, e := i.roots()
		if e != nil {
			return nil, e
		}
		node["monitor"] = common.Map{"roots": roots}
	}
	return node, nil
}
func loadYAMLDocument(path string) (*yaml.Node, []byte, error) {
	if e := ownedRegular(path); e != nil {
		return nil, nil, e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, nil, e
	}
	var doc yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(b))
	if e = d.Decode(&doc); e != nil {
		return nil, nil, e
	}
	var extra yaml.Node
	if e = d.Decode(&extra); e != io.EOF {
		return nil, nil, errors.New("只允许一份 YAML 文档")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("配置必须为 YAML 映射")
	}
	return &doc, b, nil
}
func setYAML(root *yaml.Node, value any, keys ...string) error {
	n := root
	for _, k := range keys[:len(keys)-1] {
		if n.Kind != yaml.MappingNode {
			return errors.New("配置层级必须为映射")
		}
		child := yamlField(n, k)
		if child == nil {
			child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, child)
		}
		n = child
	}
	k := keys[len(keys)-1]
	v := &yaml.Node{}
	if e := v.Encode(value); e != nil {
		return e
	}
	if old := yamlField(n, k); old != nil {
		v.HeadComment, v.LineComment, v.FootComment = old.HeadComment, old.LineComment, old.FootComment
		*old = *v
	} else {
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, v)
	}
	return nil
}
func saveSetup(path string, doc *yaml.Node, before []byte, stateDir string) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if e := enc.Encode(doc); e != nil {
		return e
	}
	if e := enc.Close(); e != nil {
		return e
	}
	tmp, e := os.CreateTemp(filepath.Dir(path), ".webscan-setup-*.yaml")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(buf.Bytes()); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Sync(); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	if _, e = configuration.Load(name); e != nil {
		return e
	}
	unlock, e := packageLock(stateDir, "deploy.lock")
	if e != nil {
		return e
	}
	defer unlock()
	state, e := readPackageState(stateDir)
	if e != nil {
		return e
	}
	if hasPendingTask(state) {
		return errors.New("存在未完成部署或卸载，配置未修改；请恢复原任务")
	}
	if e = ownedRegular(path); e != nil {
		return e
	}
	current, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if !bytes.Equal(current, before) {
		return errors.New("配置已被其他操作修改，请重新填写")
	}
	if e = backupPackage(packagePaths{state: stateDir}, "webscan.yaml", before); e != nil {
		return e
	}
	return os.Rename(name, path)
}
func initializeConfig(path, stateDir string, i setupInput) (bool, error) {
	markerPath := filepath.Join(filepath.Dir(path), ".setup-pending.json")
	if e := ownedRegular(markerPath); os.IsNotExist(e) {
		return false, nil
	} else if e != nil {
		return false, e
	}
	marker, e := common.ReadJSON(markerPath)
	if e != nil {
		return false, e
	}
	state, e := readPackageState(stateDir)
	if e != nil {
		return false, e
	}
	if isInstalled(state) || hasPendingTask(state) {
		return false, errors.New("已有安装或未完成任务，不能初始化示例配置；请恢复原 YAML")
	}
	doc, before, e := loadYAMLDocument(path)
	if e != nil {
		return false, e
	}
	if common.Hash(before) != common.S(marker["template_sha256"]) {
		if _, e = configuration.Load(path); e != nil {
			return false, errors.New("模板已手动修改但配置不完整，请先按字段提示完善 YAML；未覆盖已有内容")
		}
		return false, os.Remove(markerPath)
	}
	fmt.Fprintln(i.out, "\n首次配置向导：填写必要数据，0 取消；秘密输入不回显。保存后进入部署菜单，不会立即安装。")
	root := doc.Content[0]
	name, e := i.line("主服务器名称", "网站监控中心", validName)
	if e != nil {
		return false, e
	}
	ip, e := i.line("主服务器真实 IP", "", validIP)
	if e != nil {
		return false, e
	}
	source, e := i.line("指标采集来源 IP", ip, validIP)
	if e != nil {
		return false, e
	}
	sslChoice, e := i.line("SSL 模式（1 HTTPS，2 HTTP）", "1", func(v string) error {
		if v != "1" && v != "2" {
			return errors.New("请选择 1 或 2")
		}
		return nil
	})
	if e != nil {
		return false, e
	}
	ssl := sslChoice == "1"
	scheme := "http"
	if ssl {
		scheme = "https"
	}
	website, e := i.yes("开启网站监控后台", true)
	if e != nil {
		return false, e
	}
	websitePort := "19444"
	if website {
		websitePort, e = i.line("网站后台端口", "19444", managementPort)
		if e != nil {
			return false, e
		}
	}
	grafanaPort, e := i.line("Grafana 端口", "3000", func(v string) error {
		if e := managementPort(v); e != nil {
			return e
		}
		if website && v == websitePort {
			return errors.New("不能与网站后台端口相同")
		}
		return nil
	})
	if e != nil {
		return false, e
	}
	account, e := i.line("网站后台管理员（密码留空自动生成）", "admin", validAccount)
	if e != nil {
		return false, e
	}
	gaccount, e := i.line("Grafana 管理员（密码留空自动生成）", "admin", validAccount)
	if e != nil {
		return false, e
	}
	feishu, e := i.yes("开启飞书通知", true)
	if e != nil {
		return false, e
	}
	webhook, secret := "", ""
	sign := false
	if feishu {
		webhook, e = i.password("飞书机器人完整 HTTPS Webhook")
		if e != nil {
			return false, e
		}
		for {
			u, err := url.Parse(webhook)
			if err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil {
				break
			}
			fmt.Fprintln(i.out, "Webhook 必须为完整 HTTPS 地址，请重新填写。")
			webhook, e = i.password("飞书 Webhook")
			if e != nil {
				return false, e
			}
		}
		sign, e = i.yes("飞书机器人已开启加签", true)
		if e != nil {
			return false, e
		}
		if sign {
			secret, e = i.password("飞书加签密钥")
			if e != nil {
				return false, e
			}
		}
	}
	roots, e := i.roots()
	if e != nil {
		return false, e
	}
	nodes := []common.Map{}
	for {
		add, e := i.yes("添加一台子服务器（可稍后通过菜单 4 添加）", false)
		if e != nil {
			return false, e
		}
		if !add {
			break
		}
		n, e := i.node(nodes)
		if e != nil {
			return false, e
		}
		nodes = append(nodes, n)
	}
	order := []string{}
	for _, n := range nodes {
		order = append(order, common.S(n["id"]))
	}
	wp, _ := strconv.Atoi(websitePort)
	gp, _ := strconv.Atoi(grafanaPort)
	values := []struct {
		keys  []string
		value any
	}{
		{[]string{"central", "name"}, name}, {[]string{"central", "public_url"}, scheme + "://" + net.JoinHostPort(ip, "19443")},
		{[]string{"ssl", "enabled"}, ssl}, {[]string{"central", "website_monitor", "enabled"}, website}, {[]string{"central", "website_monitor", "host_port"}, wp},
		{[]string{"central", "website_monitor", "admin_username"}, account}, {[]string{"central", "website_monitor", "admin_password"}, ""},
		{[]string{"central", "grafana", "host_port"}, gp}, {[]string{"central", "grafana", "admin_username"}, gaccount}, {[]string{"central", "grafana", "admin_password"}, ""},
		{[]string{"feishu", "enabled"}, feishu}, {[]string{"feishu", "mode"}, "inline"}, {[]string{"feishu", "webhook_url"}, webhook}, {[]string{"feishu", "signing_enabled"}, sign}, {[]string{"feishu", "signing_secret"}, secret},
		{[]string{"node_defaults", "metrics", "allowed_source_ip"}, source}, {[]string{"node_defaults", "monitor", "roots"}, roots}, {[]string{"nodes"}, nodes}, {[]string{"deployment", "node_order"}, order},
	}
	for _, v := range values {
		if e = setYAML(root, v.value, v.keys...); e != nil {
			return false, e
		}
	}
	fmt.Fprintf(i.out, "\n配置摘要：主服务器 %s（%s），协议 %s，后台 %t / %d，Grafana %d；飞书 %t（凭据隐藏），子服务器 %d 台，监控目录 %s。\n", name, ip, strings.ToUpper(scheme), website, wp, gp, feishu, len(nodes), strings.Join(roots, ", "))
	save, e := i.yes("保存配置并进入部署菜单", true)
	if e != nil {
		return false, e
	}
	if !save {
		return false, errSetupCancel
	}
	if e = saveSetup(path, doc, before, stateDir); e != nil {
		return false, e
	}
	if e = os.Remove(markerPath); e != nil {
		return false, e
	}
	fmt.Fprintln(i.out, "配置已保存为 webscan.yaml（0600），原模板已备份。请放行事件 19443、后台端口及 Grafana 端口；节点需允许主服务器访问 SSH 和 19100。云安全组需自行设置。")
	return true, nil
}
func addConfiguredNode(path, stateDir string, i setupInput) ([]string, error) {
	state, e := readPackageState(stateDir)
	if e != nil {
		return nil, e
	}
	if !isInstalled(state) {
		return nil, errors.New("请先通过菜单 1 安装主服务器，再增加子服务器")
	}
	if hasPendingTask(state) {
		return nil, errors.New("存在未完成任务，请按原范围恢复，未追加节点")
	}
	c, e := configuration.Load(path)
	if e != nil {
		return nil, e
	}
	doc, before, e := loadYAMLDocument(path)
	if e != nil {
		return nil, e
	}
	n, e := i.node(c.Nodes)
	if e != nil {
		return nil, e
	}
	nodes := yamlField(doc.Content[0], "nodes")
	v := &yaml.Node{}
	if e = v.Encode(n); e != nil {
		return nil, e
	}
	nodes.Content = append(nodes.Content, v)
	order := append(common.SS(common.M(c.Raw["deployment"])["node_order"]), common.S(n["id"]))
	if e = setYAML(doc.Content[0], order, "deployment", "node_order"); e != nil {
		return nil, e
	}
	fmt.Fprintf(i.out, "将增加 %s [%s] %s；SSH 与监控凭据隐藏。\n", common.S(n["name"]), common.S(n["id"]), common.S(n["host"]))
	save, e := i.yes("保存节点并立即安装验收", true)
	if e != nil {
		return nil, e
	}
	if !save {
		return nil, errSetupCancel
	}
	if e = saveSetup(path, doc, before, stateDir); e != nil {
		return nil, e
	}
	return []string{"--add-node", "--node", common.S(n["id"])}, nil
}
func setupError(err error) error {
	if errors.Is(err, errSetupCancel) {
		return errMenuExit
	}
	if err != nil {
		return &progress.Failure{Code: "configuration_setup_failed", Message: err.Error()}
	}
	return nil
}
