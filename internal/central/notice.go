package central

import (
	"fmt"
	"strings"
	"time"
	"webscan/internal/common"
)

var beijing = func() *time.Location {
	zone, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return time.FixedZone("北京时间", 8*60*60)
	}
	return zone
}()

// Notification formatting never changes canonical event timestamps or digests.
func noticeTime(stamp string) string {
	t, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || t.Year() < 1900 {
		return "时间未记录"
	}
	return t.In(beijing).Format("2006-01-02 15:04:05") + "（北京时间）"
}

func serverLine(name, ip string) string {
	if name == "" {
		name = "监控服务器"
	}
	if ip != "" {
		name += "（" + ip + "）"
	}
	return "服务器：" + name
}

func scanNotice(event common.Map) string {
	scan := common.M(event["scan"])
	switch common.S(scan["status"]) {
	case "pending":
		return "等待扫描，发现可疑内容会另行通知"
	case "matched":
		return "发现可疑代码，请尽快核查是否为正常业务代码"
	case "no_match":
		return "本次检查未发现可疑特征"
	case "error":
		reason := common.S(scan["reason"])
		for _, engine := range []string{"yara", "clamav"} {
			detail := common.M(common.M(scan["engines"])[engine])
			if common.S(detail["status"]) == "error" {
				reason = common.S(detail["reason"])
				break
			}
		}
		description := map[string]string{"scanner_exit": "扫描超时或执行失败", "scanner_failed": "扫描程序无法启动", "content_changed_before_scan": "扫描前文件再次变化", "scan_size_changed": "扫描期间文件大小发生变化", "scan_symlink_path": "文件路径为符号链接"}[reason]
		if description == "" {
			description = "扫描未能完成"
		}
		return description + "，本次未完成安全检查，请人工核查"
	case "skipped":
		return "本次未扫描，可能是文件类型或大小超出限制，请按需核查"
	case "not_applicable":
		if common.S(event["operation"]) == "delete" {
			return "文件已删除，无需扫描"
		}
		return "此类记录无需文件扫描"
	default:
		return "检查结果暂未提供，请按需核查"
	}
}

func healthReason(reason string) string {
	description := map[string]string{"unrepresentable_filename": "部分文件名无法识别", "file_read_gap": "部分文件无法读取，监控可能存在遗漏", "journal_failed": "文件变化记录保存失败", "listener_failed": "文件监听发生异常", "inotify_overflow": "文件变化过于密集，监听队列已满，正在补查", "coverage_inventory_incomplete": "部分目录或文件未能完成清单核对", "reconciliation_failed": "定期文件核对未能完成"}[reason]
	if description == "" {
		return "监控运行异常，请检查监控服务"
	}
	return description
}

func eventNotice(event common.Map) string {
	op := common.S(event["operation"])
	if op == "modify" && common.DeploymentPHPTest(common.S(event["path"])) {
		return strings.Join([]string{"部署后的 PHP 修改测试成功", serverLine(common.S(event["server_name"]), common.S(event["server_ip"])), "测试动作：修改独立测试目录中的 PHP 文件", "检测结果：该服务器的监控程序已发现真实文件修改，监控消息已送达飞书", "文件：" + common.S(event["path"]), "发生时间：" + noticeTime(common.S(event["time"])), "安全检查：" + scanNotice(event), "说明：这是部署后的自动测试，不是业务网站异常；测试文件会自动清理"}, "\n")
	}
	title := map[string]string{"create": "发现新增文件", "modify": "发现文件被修改", "delete": "发现文件被删除", "move": "发现文件被移动或改名", "scan": "文件安全检查结果", "health": "监控运行异常", "test": "监控通知测试", "probe": "监控链路检查"}[op]
	if title == "" {
		title = "发现文件变化"
	}
	if common.B(event["important_config"]) && op != "scan" && op != "health" {
		title = "重要配置提醒：" + title
	}
	if op == "scan" {
		switch common.S(common.M(event["scan"])["status"]) {
		case "matched":
			title = "文件中发现可疑代码"
		case "error":
			title = "文件安全检查未能完成"
		}
	}
	lines := []string{title, serverLine(common.S(event["server_name"]), common.S(event["server_ip"]))}
	if site := common.S(event["site"]); site != "" && site != "_monitor" && site != "_critical" {
		lines = append(lines, "网站："+site)
	}
	if old := common.S(event["old_path"]); op == "move" && old != "" {
		lines = append(lines, "原位置："+old)
	}
	if path := common.S(event["path"]); path != "" {
		lines = append(lines, "文件："+path)
	}
	lines = append(lines, "发生时间："+noticeTime(common.S(event["time"])))
	if op == "health" {
		lines = append(lines, "问题："+healthReason(common.S(event["reason"])))
		if path := common.S(event["file_path"]); path != "" {
			lines = append(lines, "关联文件："+path)
		}
	} else {
		lines = append(lines, "安全检查："+scanNotice(event))
		if common.S(event["risk"]) == "high" && common.S(common.M(event["scan"])["status"]) != "matched" {
			lines = append(lines, "风险提示：需要重点核查")
		}
		if common.Contains([]string{"create", "modify", "move", "delete"}, op) {
			lines = append(lines, "处理建议：如果不是您或网站程序的正常更新，请检查该文件")
		}
	}
	if strings.HasPrefix(common.S(event["site"]), ".webscan-") {
		lines = append([]string{"监控测试文件，请勿当作业务文件异常"}, lines...)
	}
	return strings.Join(lines, "\n")
}

func alertDescription(name string) string {
	description := map[string]string{"WebscanNodeUnreachable": "无法连接该服务器的监控采集服务", "WebscanAgentStopped": "文件监控程序长时间没有更新心跳", "WebscanLocalProbeStale": "服务器本地监控测试长时间未完成", "WebscanCoverageGap": "部分网站目录未被完整监控", "WebscanCentralProbeStale": "监控中心长时间没有收到该服务器的测试数据", "WebscanLokiProbeStale": "监控日志长时间未能确认入库", "WebscanInotifyOverflow": "文件监听队列已满，可能存在监控遗漏", "WebscanDroppedEvents": "监控链路出现数据丢弃，请检查队列和存储空间", "WebscanVectorStopped": "监控数据传输服务无法访问", "WebscanScannerStalled": "文件安全检查程序长时间没有更新心跳", "WebscanClockUnsynchronized": "服务器时间未同步或偏差过大", "WebscanCentralReceiverDown": "监控中心接收服务无法访问", "WebscanCentralHostMetricsDown": "主服务器指标采集服务无法访问", "WebscanExporterMissingAgentMetric": "采集服务缺少文件监控程序的心跳指标"}[name]
	if description != "" {
		return description
	}
	for _, pair := range [][2]string{{"Backlog", "监控数据积压，投递时间过长"}, {"CPU", "服务器处理器使用率过高"}, {"Memory", "服务器内存使用率过高"}, {"Disk", "服务器磁盘使用率过高"}, {"Inode", "服务器可用文件数量不足"}} {
		if strings.Contains(name, pair[0]) {
			return pair[1]
		}
	}
	return "监控指标异常，请检查服务器与监控服务"
}

func (s *Store) alertNotice(alert common.Map) string {
	labels := common.M(alert["labels"])
	info := common.M(common.M(s.Config["nodes"])[common.S(labels["node_id"])])
	name := common.S(info["name"])
	if name == "" {
		name = "监控中心"
	}
	title, stamp, label := "监控异常提醒", common.S(alert["startsAt"]), "问题"
	if common.S(alert["status"]) == "resolved" {
		title, stamp, label = "监控已恢复", common.S(alert["endsAt"]), "已恢复项目"
	}
	if stamp == "" {
		stamp = common.Stamp()
	}
	return fmt.Sprintf("%s\n%s\n%s：%s\n发生时间：%s", title, serverLine(name, common.S(info["host"])), label, alertDescription(common.S(labels["alertname"])), noticeTime(stamp))
}
