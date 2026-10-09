package deploy

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"webscan/internal/common"
)

var VendorImages = map[string]string{"prometheus": "prom/prometheus:v3.5.0", "alertmanager": "prom/alertmanager:v0.28.1", "vector": "timberio/vector:0.45.0-alpine", "exporter": "prom/node-exporter:v1.9.1", "loki": "grafana/loki:3.5.0", "grafana": "grafana/grafana:12.0.0"}

func YAML(v any) []byte {
	b, e := yaml.Marshal(yamlNumbers(v))
	if e != nil {
		panic(e)
	}
	return b
}

// Config merges and saved state use json.Number to preserve exact JSON digits.
// yaml.v3 otherwise treats that string-backed type as a quoted YAML string.
func yamlNumbers(v any) any {
	switch x := v.(type) {
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		n, err := x.Float64()
		if err != nil {
			panic("invalid numeric configuration")
		}
		return n
	case common.Map:
		out := common.Map{}
		for key, value := range x {
			out[key] = yamlNumbers(value)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = yamlNumbers(value)
		}
		return out
	default:
		return v
	}
}
func CentralRuntime(c *Config, secrets common.Map, active []string) common.Map {
	center := common.M(c.Raw["central"])
	event := common.M(center["event_service"])
	u, _ := url.Parse(common.S(center["public_url"]))
	nodes := common.Map{}
	sources := common.SS(event["allowed_source_cidrs"])
	for _, n := range c.Nodes {
		if !common.B(n["enabled"]) {
			continue
		}
		id := common.S(n["id"])
		nodes[id] = common.Map{"host": n["host"], "name": n["name"], "token": common.M(common.M(secrets["nodes"])[id])["token"]}
		if len(common.SS(event["allowed_source_cidrs"])) == 0 {
			sources = append(sources, common.S(n["host"])+"/32")
		}
	}
	sources = append(sources, "127.0.0.1/32", u.Hostname()+"/32")
	f := common.Clone(common.M(c.Raw["feishu"]))
	runtime := common.Map{"runtime_dir": "/backup-config", "bind": "0.0.0.0", "port": event["port"], "https": common.Map{"bind": "0.0.0.0", "port": event["https_port"], "cert_file": "/backup-config/pki/central-" + strings.ReplaceAll(u.Hostname(), ".", "-") + ".crt", "key_file": "/backup-config/pki/central-" + strings.ReplaceAll(u.Hostname(), ".", "-") + ".key", "allowed_sources": sources}, "max_request_mib": event["max_request_mib"], "max_batch_events": event["max_batch_events"], "data_dir": center["data_dir"], "backup_dir": center["backup_dir"], "backup": c.Raw["backup"], "retention": c.Raw["retention"], "website_monitor": websiteRuntime(c, secrets), "feishu": f, "loki_url": "http://loki:3100", "alert_token": secrets["alert_token"], "nodes": nodes, "active_nodes": active}
	if !c.SSLEnabled() {
		common.M(runtime["https"])["port"] = 0
		common.M(runtime["https"])["cert_file"], common.M(runtime["https"])["key_file"] = "", ""
		runtime["public_http"] = common.Map{"bind": "0.0.0.0", "port": event["https_port"]}
	}
	return runtime
}
func NodeRuntime(c *Config, n, secrets common.Map) common.Map {
	health := common.M(c.Raw["health"])
	runtime := common.Map{"node_id": n["id"], "monitor": n["monitor"], "scan": n["scan"], "transport": n["transport"], "data_dir": "/var/lib/webscan-v1", "log_dir": "/var/log/webscan-v1", "probe_directory": health["probe_directory"], "probe_seconds": health["filesystem_probe_seconds"], "metrics_file": "/var/lib/webscan-v1/textfile/agent.prom", "yara_rules": "/etc/webscan-v1/php-webshell.yar", "retention_days": common.M(c.Raw["retention"])["local_logs_days"], "token": common.M(common.M(secrets["nodes"])[common.S(n["id"])])["token"], "public_url": strings.TrimRight(common.S(common.M(c.Raw["central"])["public_url"]), "/"), "central_ca_file": "/etc/webscan-v1/pki/ca.crt"}
	if !c.SSLEnabled() {
		runtime["central_ca_file"] = ""
	}
	return runtime
}
func VectorConfig(c *Config, n, secrets common.Map) common.Map {
	token := common.M(common.M(secrets["nodes"])[common.S(n["id"])])["token"]
	transport := common.M(n["transport"])
	vector := common.Map{"data_dir": "/var/lib/vector", "sources": common.Map{"events": common.Map{"type": "file", "include": []string{"/var/log/webscan-v1/events-*.jsonl"}, "read_from": "beginning", "max_line_bytes": 2097152}, "internal": common.Map{"type": "internal_metrics"}}, "transforms": common.Map{"decode": common.Map{"type": "remap", "inputs": []string{"events"}, "source": ". = parse_json!(string!(.message))"}}, "sinks": common.Map{"central": common.Map{"type": "http", "inputs": []string{"decode"}, "uri": strings.TrimRight(common.S(common.M(c.Raw["central"])["public_url"]), "/") + "/webscan/v1/events", "method": "post", "encoding": common.Map{"codec": "json"}, "framing": common.Map{"method": "newline_delimited"}, "auth": common.Map{"strategy": "bearer", "token": token}, "batch": common.Map{"max_events": 1}, "buffer": common.Map{"type": "disk", "max_size": common.I(transport["vector_buffer_mib"]) * 1048576, "when_full": "block"}, "acknowledgements": common.Map{"enabled": true}, "request": common.Map{"timeout_secs": transport["request_timeout_seconds"]}, "healthcheck": common.Map{"enabled": false}, "tls": common.Map{"ca_file": "/etc/webscan-v1/pki/ca.crt", "verify_certificate": true, "verify_hostname": true}}, "metrics": common.Map{"type": "prometheus_exporter", "inputs": []string{"internal"}, "address": "127.0.0.1:19101"}}}
	if !c.SSLEnabled() {
		delete(common.M(common.M(vector["sinks"])["central"]), "tls")
	}
	return vector
}
func service(image string) common.Map {
	return common.Map{"image": image, "restart": "unless-stopped", "read_only": true, "cap_drop": []string{"ALL"}, "security_opt": []string{"no-new-privileges:true"}, "logging": common.Map{"driver": "json-file", "options": common.Map{"max-size": "10m", "max-file": "3"}}}
}
func ReceiverService(c *Config, image string) common.Map {
	root := c.CentralRoot()
	center := common.M(c.Raw["central"])
	event := common.M(center["event_service"])
	data, backup := common.S(center["data_dir"]), common.S(center["backup_dir"])
	s := imageService(c, "central", image)
	s["command"] = []string{"central", "--config", root + "/runtime.json"}
	s["volumes"] = []string{root + ":" + root + ":ro", root + ":/backup-config:ro", data + ":" + data, backup + ":" + backup}
	s["ports"] = []string{"127.0.0.1:" + strconv.Itoa(common.I(event["port"])) + ":" + strconv.Itoa(common.I(event["port"])), common.S(event["https_bind_address"]) + ":" + strconv.Itoa(common.I(event["https_port"])) + ":" + strconv.Itoa(common.I(event["https_port"]))}
	s["mem_limit"] = strconv.Itoa(common.I(center["new_components_memory_budget_mib"])-common.I(center["new_components_memory_budget_mib"])*5/12-96) + "m"
	s["environment"] = common.Map{"GOMEMLIMIT": "96MiB", "GOMAXPROCS": "2"}
	if extra := websiteMemory(c); extra > 0 {
		wm := common.M(center["website_monitor"])
		s["ports"] = append(common.SS(s["ports"]), common.S(wm["bind_address"])+":"+strconv.Itoa(common.I(wm["host_port"]))+":"+strconv.Itoa(common.I(wm["host_port"])))
		s["mem_limit"] = strconv.Itoa(common.I(center["new_components_memory_budget_mib"])-common.I(center["new_components_memory_budget_mib"])*5/12-96+extra) + "m"
		common.M(s["environment"])["GOMEMLIMIT"] = strconv.Itoa(96+extra*3/4) + "MiB"
	}
	s["tmpfs"] = []string{"/tmp:size=16m"}
	s["networks"] = common.Map{"monitor": common.Map{"aliases": []string{"webscan-v1-receiver"}}}
	return s
}
func ComposeCentral(c *Config, images common.Map) common.Map {
	root := c.CentralRoot()
	center := common.M(c.Raw["central"])
	data := common.S(center["data_dir"])
	services := common.Map{"receiver": ReceiverService(c, common.S(images["central"]))}
	definitions := map[string]common.Map{
		"prometheus":    {"command": []string{"--config.file=/etc/prometheus/prometheus.yml", "--storage.tsdb.path=/prometheus", "--storage.tsdb.retention.time=" + strconv.Itoa(common.I(common.M(c.Raw["retention"])["prometheus_days"])) + "d", "--web.listen-address=0.0.0.0:19190"}, "volumes": []string{root + "/prometheus.yml:/etc/prometheus/prometheus.yml:ro", root + "/rules.yml:/etc/prometheus/rules.yml:ro", root + "/pki/prometheus:/etc/prometheus/pki:ro", data + "/prometheus:/prometheus"}, "ports": []string{"127.0.0.1:19190:19190"}, "user": "0:0", "mem_limit": strconv.Itoa(common.I(center["new_components_memory_budget_mib"])*5/12) + "m"},
		"alertmanager":  {"command": []string{"--config.file=/etc/alertmanager/alertmanager.yml", "--storage.path=/alertmanager", "--web.listen-address=0.0.0.0:19193", "--cluster.listen-address="}, "volumes": []string{root + "/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro", root + "/alert-token:/etc/alertmanager/token:ro", data + "/alertmanager:/alertmanager"}, "ports": []string{"127.0.0.1:19193:19193"}, "user": "0:0", "mem_limit": "64m"},
		"host-exporter": {"command": []string{"--web.listen-address=:19110", "--path.procfs=/host/proc", "--path.sysfs=/host/sys", "--path.rootfs=/rootfs"}, "volumes": []string{"/proc:/host/proc:ro", "/sys:/host/sys:ro", "/:/rootfs:ro,rslave"}, "ports": []string{"127.0.0.1:19110:19110"}, "user": "65534:65534", "pid": "host", "mem_limit": "32m"},
		"loki":          {"command": []string{"-config.file=/etc/loki/config.yml"}, "volumes": []string{root + "/loki.yml:/etc/loki/config.yml:ro", data + "/loki:/loki"}, "ports": []string{"127.0.0.1:3100:3100"}, "user": "0:0", "mem_limit": "256m"},
		"grafana":       {"volumes": []string{data + "/grafana:/var/lib/grafana", root + "/grafana.ini:/etc/grafana/grafana.ini:ro", root + "/provisioning:/etc/grafana/provisioning:ro", root + "/grafana-admin-password:/etc/grafana/admin-password:ro"}, "env_file": []string{root + "/grafana.env"}, "ports": []string{common.S(common.M(center["grafana"])["bind_address"]) + ":" + strconv.Itoa(common.I(common.M(center["grafana"])["host_port"])) + ":3000"}, "user": "0:0", "mem_limit": "192m"}}
	for name, values := range definitions {
		key := name
		if name == "host-exporter" {
			key = "exporter"
		}
		if (name == "grafana" || name == "loki") && common.B(common.M(center["reuse_existing"])[name]) {
			continue
		}
		s := imageService(c, key, common.S(images[key]))
		s["networks"] = common.Map{"monitor": common.Map{"aliases": []string{"webscan-v1-" + name}}}
		for k, v := range values {
			s[k] = v
		}
		services[name] = s
	}
	return common.Map{"name": "webscan-v1", "services": services, "networks": common.Map{"monitor": common.Map{"name": "webscan-v1-monitor"}}}
}
func ComposeAgent(c *Config, n common.Map, image string) common.Map {
	s := imageService(c, "agent", image)
	s["container_name"] = "webscan-agent-go"
	// Website files can be owned by www with mode 0600. Read-only bind mounts
	// protect websites while permitting the collector to read all monitored files.
	s["cap_add"] = []string{"DAC_READ_SEARCH"}
	s["network_mode"] = "host"
	s["command"] = []string{"agent", "--config", "/etc/webscan-v1/runtime.json"}
	resources := common.M(n["resources"])
	s["mem_limit"] = strconv.Itoa(common.I(resources["agent_memory_mib"])) + "m"
	s["cpus"] = common.F(resources["cpus"])
	s["environment"] = common.Map{"GOMEMLIMIT": strconv.Itoa(common.I(resources["go_memory_mib"])) + "MiB", "GOMAXPROCS": strconv.Itoa(common.I(resources["gomaxprocs"]))}
	s["tmpfs"] = []string{"/tmp:size=16m"}
	volumes := []string{"/etc/webscan-v1:/etc/webscan-v1:ro", "/var/lib/webscan-v1:/var/lib/webscan-v1", "/var/log/webscan-v1:/var/log/webscan-v1"}
	probe := common.S(common.M(c.Raw["health"])["probe_directory"])
	volumes = append(volumes, probe+":"+probe)
	p, _ := common.NewPolicy(common.M(n["monitor"]))
	mounts := append([]string{}, p.Roots...)
	for _, path := range p.Critical {
		dir := filepath.Dir(path)
		covered := false
		for _, root := range mounts {
			covered = covered || common.Inside(dir, root)
		}
		if !covered {
			mounts = append(mounts, dir)
		}
	}
	for _, root := range mounts {
		volumes = append(volumes, root+":"+root+":ro,rslave")
	}
	if common.B(common.M(common.M(n["scan"])["clamav"])["enabled"]) {
		volumes = append(volumes, "/run/clamav:/run/clamav")
	}
	s["volumes"] = volumes
	return common.Map{"name": "webscan-agent", "services": common.Map{"agent": s}}
}
func Prometheus(c *Config, active []string) common.Map {
	port := strconv.Itoa(common.I(common.M(common.M(c.Raw["central"])["event_service"])["port"]))
	jobs := []any{common.Map{"job_name": "webscan-central", "static_configs": []any{common.Map{"targets": []string{"webscan-v1-receiver:" + port}}}}, common.Map{"job_name": "webscan-central-host", "static_configs": []any{common.Map{"targets": []string{"webscan-v1-host-exporter:19110"}, "labels": common.Map{"node_id": "central", "server_name": common.M(c.Raw["central"])["name"]}}}}, common.Map{"job_name": "prometheus", "static_configs": []any{common.Map{"targets": []string{"webscan-v1-prometheus:19190"}}}}, common.Map{"job_name": "alertmanager", "static_configs": []any{common.Map{"targets": []string{"webscan-v1-alertmanager:19193"}}}}}
	for _, n := range c.Nodes {
		if !common.Contains(active, common.S(n["id"])) {
			continue
		}
		jobs = append(jobs, common.Map{"job_name": "webscan-node-" + common.S(n["id"]), "scheme": "https", "tls_config": common.Map{"ca_file": "/etc/prometheus/pki/ca.crt", "cert_file": "/etc/prometheus/pki/client.crt", "key_file": "/etc/prometheus/pki/client.key"}, "static_configs": []any{common.Map{"targets": []string{common.S(n["host"]) + ":" + strconv.Itoa(common.I(common.M(n["metrics"])["port"]))}, "labels": common.Map{"node_id": n["id"], "server_name": n["name"]}}}})
	}
	if !c.SSLEnabled() {
		for _, value := range jobs {
			job := common.M(value)
			if strings.HasPrefix(common.S(job["job_name"]), "webscan-node-") {
				job["scheme"] = "http"
				delete(job, "tls_config")
			}
		}
	}
	interval := strconv.Itoa(common.I(common.M(c.Raw["health"])["metrics_scrape_seconds"])) + "s"
	return common.Map{"global": common.Map{"scrape_interval": interval, "evaluation_interval": interval}, "rule_files": []string{"/etc/prometheus/rules.yml"}, "alerting": common.Map{"alertmanagers": []any{common.Map{"static_configs": []any{common.Map{"targets": []string{"webscan-v1-alertmanager:19193"}}}}}}, "scrape_configs": jobs}
}
func Alertmanager(c *Config) common.Map {
	a := common.M(common.M(c.Raw["health"])["alertmanager"])
	port := strconv.Itoa(common.I(common.M(common.M(c.Raw["central"])["event_service"])["port"]))
	return common.Map{"route": common.Map{"receiver": "central", "group_by": []string{"alertname", "node_id"}, "group_wait": fmt.Sprint(common.I(a["group_wait_seconds"])) + "s", "group_interval": fmt.Sprint(common.I(a["group_interval_seconds"])) + "s", "repeat_interval": fmt.Sprint(common.I(a["repeat_interval_hours"])) + "h"}, "receivers": []any{common.Map{"name": "central", "webhook_configs": []any{common.Map{"url": "http://webscan-v1-receiver:" + port + "/alerts", "send_resolved": true, "http_config": common.Map{"authorization": common.Map{"type": "Bearer", "credentials_file": "/etc/alertmanager/token"}}}}}}, "inhibit_rules": []any{common.Map{"source_matchers": []string{"alertname=\"WebscanNodeUnreachable\""}, "target_matchers": []string{"alertname=~\"WebscanAgentStopped|WebscanLocalProbeStale|WebscanCoverageGap|WebscanVectorStopped\""}, "equal": []string{"node_id"}}}}
}
func GrafanaURL(c *Config) string {
	u, _ := url.Parse(common.S(common.M(c.Raw["central"])["public_url"]))
	return "http://" + u.Hostname() + ":" + strconv.Itoa(common.I(common.M(common.M(c.Raw["central"])["grafana"])["host_port"]))
}
func GrafanaINI(c *Config) []byte {
	return []byte("[server]\nhttp_addr = 0.0.0.0\nhttp_port = 3000\nroot_url = " + GrafanaURL(c) + "/\n[auth.anonymous]\nenabled = false\n[users]\nallow_sign_up = false\n")
}

func ExporterWebConfig(c *Config) common.Map {
	if !c.SSLEnabled() {
		return common.Map{}
	}
	return common.Map{"tls_server_config": common.Map{"cert_file": "/etc/webscan-v1/pki/server.crt", "key_file": "/etc/webscan-v1/pki/server.key", "client_auth_type": "RequireAndVerifyClientCert", "client_ca_file": "/etc/webscan-v1/pki/ca.crt"}}
}
