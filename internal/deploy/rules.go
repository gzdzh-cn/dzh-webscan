package deploy

import (
	"fmt"
	"webscan/internal/common"
)

func AlertRules(c *Config) common.Map {
	health := common.M(c.Raw["health"])
	a := common.M(health["alerts"])
	rules := []any{}
	add := func(name, expr string, duration int, severity string) {
		r := common.Map{"alert": name, "expr": expr, "labels": common.Map{"severity": severity}, "annotations": common.Map{"summary": name + " {{ $labels.node_id }} {{ $labels.instance }}", "description": "value={{ $value }}"}}
		if duration > 0 {
			r["for"] = fmt.Sprint(duration) + "s"
		}
		rules = append(rules, r)
	}
	value := func(key string) string { return fmt.Sprint(common.I(a[key])) }
	add("WebscanNodeUnreachable", `up{job=~"webscan-node-.*"} == 0`, common.I(a["node_unreachable_seconds"]), "critical")
	add("WebscanAgentStopped", "time() - webscan_agent_heartbeat_seconds > "+fmt.Sprint(max(60, 2*common.I(health["metrics_scrape_seconds"]))), common.I(a["agent_stopped_seconds"]), "warning")
	add("WebscanLocalProbeStale", "time() - webscan_local_probe_seconds > "+value("local_probe_stale_seconds"), 0, "warning")
	add("WebscanCoverageGap", "webscan_coverage_ok == 0", 60, "warning")
	add("WebscanCentralProbeStale", `(time() - webscan_probe_received_seconds > `+value("central_probe_stale_seconds")+`) and on(node_id) (up{job=~"webscan-node-.*"} == 1)`, 0, "warning")
	add("WebscanLokiProbeStale", `(time() - webscan_probe_loki_seconds > `+value("loki_probe_stale_seconds")+`) and on(node_id) (up{job=~"webscan-node-.*"} == 1)`, 0, "warning")
	for suffix, expr := range map[string]string{"Local": "webscan_local_oldest_pending_seconds", "Central": "webscan_oldest_pending_seconds"} {
		add("WebscanBacklog"+suffix, expr+" > "+value("oldest_pending_task_seconds"), 0, "warning")
	}
	if common.B(health["alert_on_inotify_overflow"]) {
		add("WebscanInotifyOverflow", "time()-webscan_last_inotify_overflow_seconds < 300", 0, "critical")
	}
	if common.B(health["alert_on_dropped_events"]) {
		add("WebscanDroppedEvents", "time()-webscan_last_drop_seconds < 300 or vector_component_discarded_events_total > 0", 0, "critical")
	}
	add("WebscanVectorStopped", "webscan_vector_metrics_up == 0", 60, "warning")
	add("WebscanScannerStalled", "time()-webscan_scan_heartbeat_seconds > 180", 60, "warning")
	for name, expr := range map[string]string{"Disk": `(1-node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"}/node_filesystem_size_bytes)*100`, "Inode": `(1-node_filesystem_files_free{fstype!~"tmpfs|overlay|squashfs"}/node_filesystem_files)*100`} {
		for _, level := range []string{"warning", "critical"} {
			key := "disk"
			if name == "Inode" {
				key = "inode"
			}
			title := "Warning"
			if level == "critical" {
				title = "Critical"
			}
			add("Webscan"+name+title, expr+" > "+value(key+"_"+level+"_percent"), 60, level)
		}
	}
	add("WebscanClockUnsynchronized", "node_timex_sync_status == 0 or abs(node_timex_offset_seconds) > "+value("clock_offset_warning_seconds"), common.I(a["clock_failure_duration_seconds"]), "warning")
	add("WebscanCentralReceiverDown", `up{job="webscan-central"} == 0`, 60, "critical")
	add("WebscanCentralHostMetricsDown", `up{job="webscan-central-host"} == 0`, 60, "warning")
	add("WebscanExporterMissingAgentMetric", `(up{job=~"webscan-node-.*"} == 1) unless on(node_id) webscan_agent_heartbeat_seconds`, 60, "warning")
	return common.Map{"groups": []any{common.Map{"name": "webscan", "rules": rules}}}
}
