package deploy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/diagnostic"
	"webscan/internal/progress"
)

// CheckNodeNetwork transfers the current static Go executable into a private
// temporary directory. No installed binary, YAML or running service is changed.
func CheckNodeNetwork(ctx context.Context, c *Config, n common.Map, r *Remote, emit func(CheckItem)) []CheckItem {
	items := []CheckItem{}
	started := time.Now()
	if emit != nil {
		emit(CheckItem{Name: "双向网络检测", Status: "running", Message: "正在校验中心能力、传输临时程序并验证双向连接"})
	}
	add := func(name, status, message, advice string) {
		v := CheckItem{Name: name, Status: status, Message: message, Suggestion: advice, DurationMS: time.Since(started).Milliseconds()}
		started = time.Now()
		items = append(items, v)
		if emit != nil {
			emit(v)
		}
	}
	runtime, e := common.ReadJSON(filepath.Join(c.CentralRoot(), "runtime.json"))
	if e != nil {
		add("中心网络检测能力", "failed", "无法读取当前运行配置", "请先完成中心安装或恢复运行配置")
		return items
	}
	port := common.I(runtime["port"])
	token := common.S(runtime["alert_token"])
	client, _ := common.HTTPClient("", 12*time.Second)
	request := func(body common.Map) (common.Map, error) {
		status, v, e := common.Request(ctx, client, "POST", fmt.Sprintf("http://127.0.0.1:%d/node-preflight", port), body, map[string]string{"Authorization": "Bearer " + token})
		if e != nil || status != 200 {
			return nil, fmt.Errorf("中心未提供网络检测能力（HTTP %d），请先更新中心；不会重建中心", status)
		}
		return common.M(v), nil
	}
	// Capabilities are checked before transferring or starting anything remotely.
	status, capability, e := common.Request(ctx, client, "POST", fmt.Sprintf("http://127.0.0.1:%d/node-capabilities", port), common.Map{}, map[string]string{"Authorization": "Bearer " + token})
	if e != nil || status != 200 || !common.B(common.M(capability)["node_preflight"]) {
		add("中心网络检测能力", "failed", "当前中心不支持部署前网络检测", "请先更新中心，本次未修改服务")
		return items
	}
	p := diagnostic.Probe{Host: common.S(n["host"])}
	if c.SSLEnabled() {
		p, e = diagnostic.NewTLS(p.Host)
		if e != nil {
			add("检测证书", "failed", "临时证书生成失败", "重新检查")
			return items
		}
	}
	p.Port = common.I(common.M(n["metrics"])["port"])
	p.Token = common.ID() + common.ID()
	p.Listen = true
	p.AllowedSource = common.S(common.M(n["metrics"])["allowed_source_ip"])
	p.EventURL = common.S(common.M(c.Raw["central"])["public_url"])
	registered := common.M(common.M(runtime["nodes"])[common.S(n["id"])])
	p.EventToken = common.S(registered["token"])
	if c.SSLEnabled() {
		b, e := os.ReadFile(filepath.Join(c.CentralRoot(), "pki", "ca.crt"))
		if e != nil {
			add("事件接口证书", "failed", "当前通信 CA 不可读", "请恢复中心证书后重试")
			return items
		}
		p.EventCA = string(b)
	}
	executable, e := os.Executable()
	if e != nil {
		add("检测程序", "failed", "无法定位当前程序", "检查主服务器管理程序")
		return items
	}
	binary, e := os.ReadFile(executable)
	if e != nil {
		add("检测程序", "failed", "当前程序不可读", "检查主服务器管理程序权限")
		return items
	}
	dir, e := r.Run(ctx, "umask 077; mktemp -d /var/tmp/webscan-preflight-XXXXXXXX")
	target := strings.TrimSpace(string(dir))
	if e != nil || !strings.HasPrefix(target, "/var/tmp/webscan-preflight-") || strings.ContainsAny(target, "\r\n \t") {
		add("检测程序", "failed", "无法创建临时检测目录", "检查 /var/tmp 权限与磁盘空间")
		return items
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		r.Run(cleanup, "rm -rf -- "+Q(target))
	}()
	if e = r.Write(ctx, target+"/webscan", binary, 0700); e == nil {
		_, e = r.Run(ctx, "test \"$(sha256sum "+Q(target+"/webscan")+" | cut -d ' ' -f1)\" = "+Q(common.Hash(binary))+" && test \"$("+Q(target+"/webscan")+" version)\" = "+Q(Release))
	}
	if e != nil {
		add("检测程序校验", "failed", "传输、SHA256 或版本校验失败", "确认磁盘空间及目标平台，重新检查")
		return items
	}
	session, e := r.Client.NewSession()
	if e != nil {
		add("检测程序", "failed", "无法创建 SSH 检测会话", "重新检查 SSH 连接")
		return items
	}
	defer session.Close()
	input, e := session.StdinPipe()
	if e != nil {
		add("检测程序", "failed", "无法创建 SSH 输入管道", "重新检查 SSH 连接")
		return items
	}
	defer input.Close()
	out, e := session.StdoutPipe()
	if e != nil {
		add("检测程序", "failed", "无法创建 SSH 输出管道", "重新检查 SSH 连接")
		return items
	}
	session.Stderr = io.Discard
	command := "trap " + Q("rm -rf -- "+Q(target)) + " EXIT; " + Q(target+"/webscan") + " tool --action deployment-probe --input=-"
	if e = session.Start(command); e != nil {
		add("检测程序", "failed", "检测程序启动失败", "检查目标平台及临时目录执行权限")
		return items
	}
	stop := context.AfterFunc(ctx, func() { input.Close(); session.Close() })
	defer stop()
	if _, e = input.Write(append(common.JSON(p), '\n')); e != nil {
		add("检测程序", "failed", "检测参数传输失败", "重新检查 SSH 连接")
		return items
	}
	var result diagnostic.Result
	if e = json.NewDecoder(bufio.NewReader(io.LimitReader(out, 8192))).Decode(&result); e != nil {
		add("检测程序", "failed", "检测程序未就绪或已超时", "检查目标平台及临时目录执行权限")
		return items
	}
	eventStatus := "passed"
	message := "子服务器到事件接口连接与授权通过"
	advice := ""
	switch {
	case result.EventError != "":
		eventStatus = "failed"
		message = result.EventError
	case result.EventStatus == 200:
	case p.EventToken == "" && (result.EventStatus == 401 || (result.EventStatus == 403 && common.B(common.M(runtime["https"])["sources_auto"]))):
		eventStatus = "pending"
		message = "事件接口可达；新节点来源及令牌授权将在登记后验证"
	default:
		eventStatus = "failed"
		message = fmt.Sprintf("事件接口返回 HTTP %d", result.EventStatus)
	}
	if eventStatus == "failed" {
		advice = "检查子服务器出站、主服务器入站、安全组、事件地址及来源限制"
	}
	add("子服务器 → 事件接口", eventStatus, message, advice)
	probe := diagnostic.Probe{Host: p.Host, Port: p.Port}
	if result.Ready {
		probe.Token = p.Token
		probe.CA = p.CA
		probe.ClientCert = p.ClientCert
		probe.ClientKey = p.ClientKey
	} else if !result.Occupied {
		add("指标端口", "failed", "检测监听未启动", "检查端口与目录权限")
		return items
	}
	v, e := request(common.Map{"node": n["id"], "probe": probe})
	if e != nil {
		add("中心 → 指标接口", "failed", e.Error(), "更新中心或检查管理接口")
	} else if !common.B(v["ok"]) {
		add("中心 → 指标接口", "failed", common.S(v["message"])+sourceNote(v), "检查指标端口占用、实际采集来源、安全组及防火墙")
	} else {
		add("中心 → 指标接口", "passed", common.S(v["message"])+sourceNote(v), "")
	}
	// Closing stdin stops the helper immediately, before the deployment claims the port.
	input.Close()
	session.Wait()
	return items
}
func sourceNote(v common.Map) string {
	if source := common.S(v["source"]); source != "" {
		return "；实际来源 " + source
	}
	return ""
}

func (d *Deploy) checkNodeNetwork(ctx context.Context, n common.Map, r *Remote) error {
	items := CheckNodeNetwork(ctx, d.C, n, r, func(v CheckItem) { progress.Info(ctx, v.Name+"："+v.Message+"；"+v.Suggestion) })
	for _, v := range items {
		if v.Status == "failed" {
			return fmt.Errorf("%s：%s；%s", v.Name, v.Message, v.Suggestion)
		}
	}
	return nil
}
