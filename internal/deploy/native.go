package deploy

import (
	"context"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/progress"
	"webscan/internal/telemetry"
)

func Native(c *Config) bool {
	return common.S(common.M(common.M(c.Raw["central"])["monitoring"])["mode"]) == "native"
}
func monitoringRuntime(c *Config, active []string) common.Map {
	center := common.M(c.Raw["central"])
	health := common.M(c.Raw["health"])
	m := common.Clone(common.M(center["monitoring"]))
	m["interval_seconds"] = health["metrics_scrape_seconds"]
	m["alerts"] = health["alerts"]
	m["repeat_hours"] = common.M(health["alertmanager"])["repeat_interval_hours"]
	m["group_wait_seconds"] = common.M(health["alertmanager"])["group_wait_seconds"]
	m["group_interval_seconds"] = common.M(health["alertmanager"])["group_interval_seconds"]
	m["alert_on_inotify_overflow"] = health["alert_on_inotify_overflow"]
	m["alert_on_dropped_events"] = health["alert_on_dropped_events"]
	u, _ := url.Parse(common.S(center["public_url"]))
	nodes := []any{common.Map{"id": "central", "name": center["name"], "host": u.Hostname(), "url": "local://host", "central": true, "active": true}}
	for _, n := range c.Nodes {
		scheme := "http"
		if c.SSLEnabled() {
			scheme = "https"
		}
		nodes = append(nodes, common.Map{"id": n["id"], "name": n["name"], "host": n["host"], "url": scheme + "://" + common.S(n["host"]) + ":" + strconv.Itoa(common.I(common.M(n["metrics"])["port"])) + "/metrics", "active": common.B(n["enabled"]) && common.Contains(active, common.S(n["id"]))})
	}
	m["nodes"] = nodes
	m["host_metrics"] = common.Map{"proc": "/host/proc", "sys": "/host/sys", "root": "/rootfs"}
	if c.SSLEnabled() {
		m["ca_file"] = "/backup-config/pki/ca.crt"
		m["client_cert"] = "/backup-config/pki/client.crt"
		m["client_key"] = "/backup-config/pki/client.key"
	}
	return m
}

func requireManagementHost() error {
	info, e := os.Stat("/run/systemd/system")
	if e != nil || !info.IsDir() {
		return &progress.Failure{Code: "management_requires_systemd", Message: "可视化管理需要运行 systemd 的 Linux 主服务器；当前未发现 systemd，尚未切换监控容器。普通 Compose 可直接运行查看功能，接管管理需在 systemd 宿主机执行"}
	}
	if _, e = exec.LookPath("systemctl"); e != nil {
		return &progress.Failure{Code: "management_systemctl_missing", Message: "宿主机缺少 systemctl，无法安装 webscan-management；请先安装 systemd 管理工具"}
	}
	return nil
}

// InstallManagement installs a separately supervised host process; it never starts a deploy itself.
func (d *Deploy) InstallManagement(ctx context.Context) error {
	if e := requireManagementHost(); e != nil {
		if Native(d.C) {
			return e
		}
		return nil
	}
	dir := "/usr/local/lib/webscan"
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	binary, e := os.Executable()
	if e != nil {
		return e
	}
	b, e := os.ReadFile(binary)
	if e != nil {
		return e
	}
	target := filepath.Join(dir, "webscan-"+strings.ReplaceAll(Release, "/", "-"))
	if e = common.Atomic(target, b, 0700); e != nil {
		return e
	}
	config, e := filepath.Abs(d.O.Config)
	if e != nil {
		return e
	}
	if strings.ContainsAny(config, "\n\r\"%") {
		return fmt.Errorf("配置路径不支持控制字符、引号或百分号")
	}
	unit := fmt.Sprintf("[Unit]\nDescription=Webscan host management\nAfter=docker.service network-online.target\n[Service]\nType=simple\nExecStart=%s manager --config \"%s\" --state %s --socket /run/webscan-management/control.sock\nRestart=on-failure\nRestartSec=5\nUMask=0077\nMemoryMax=128M\nEnvironment=GOMEMLIMIT=96MiB\n[Install]\nWantedBy=multi-user.target\n", target, config, StateRoot)
	if e = os.MkdirAll("/run/webscan-management", 0700); e != nil {
		return e
	}
	oldUnit, _ := os.ReadFile("/etc/systemd/system/webscan-management.service")
	if e = common.Atomic("/etc/systemd/system/webscan-management.service", []byte(unit), 0600); e != nil {
		return e
	}
	if _, e = RunCommand(ctx, nil, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	_, e = RunCommand(ctx, nil, "systemctl", "enable", "--now", "webscan-management")
	if e == nil && len(oldUnit) > 0 && string(oldUnit) != unit && os.Getenv("WEBSCAN_MANAGEMENT_JOB") == "" {
		_, e = RunCommand(ctx, nil, "systemctl", "restart", "webscan-management")
	}
	return e
}

func (d *Deploy) registrationServices() []string {
	if Native(d.C) {
		return []string{"receiver"}
	}
	return []string{"receiver", "prometheus"}
}

// Native deployments retain the old data and journal. An existing legacy stack
// cannot be switched by editing YAML alone: the migration job must finish first.
func (d *Deploy) nativeCentral(ctx context.Context) error {
	root := d.C.CentralRoot()
	previous, err := common.ReadJSON(filepath.Join(root, "runtime.json"))
	fresh := os.IsNotExist(err)
	if err != nil && !fresh {
		return err
	}
	legacy := !fresh && common.S(common.M(previous["monitoring"])["mode"]) != "native"
	if legacy {
		ready, e := common.ReadJSON(filepath.Join(StateRoot, "native-migration-ready.json"))
		raw, _ := os.ReadFile(d.O.Config)
		if e != nil || !common.B(ready["metrics"]) || !common.B(ready["logs"]) || common.S(ready["target_config_revision"]) != common.Hash(raw) {
			return fmt.Errorf("旧组件历史尚未迁移，请在后台系统设置中执行迁移，不能直接切换 mode")
		}
	}
	if e := d.InstallManagement(ctx); e != nil {
		return e
	}
	center := common.M(d.C.Raw["central"])
	for _, key := range []string{"install_dir", "data_dir", "log_dir", "backup_dir"} {
		if e := os.MkdirAll(common.S(center[key]), 0700); e != nil {
			return e
		}
	}
	if !fresh {
		db, e := persist.OpenDB(filepath.Join(common.S(center["data_dir"]), "events-v1.sqlite3"))
		if e != nil {
			return e
		}
		backup := filepath.Join(d.Journal.Dir, "events-before-switch.sqlite3")
		if _, e = os.Stat(backup); os.IsNotExist(e) {
			e = persist.BackupDB(db, backup)
		}
		db.Close()
		if e != nil {
			return e
		}
	}
	active := d.plannedActive()
	if fresh && len(common.M(d.State["rollout"])) == 0 {
		active = []string{}
	}
	runtime := d.centralRuntime(active)
	common.M(runtime["monitoring"])["verify_after"] = time.Now().Unix()
	if legacy {
		common.M(runtime["monitoring"])["notifications_paused"] = true
	}
	compose := ComposeCentral(d.C, d.Images)
	if n := common.S(center["managed_compose_name"]); n != "" {
		compose["name"] = n
	}
	if networks := common.M(d.State["managed_networks"]); len(networks) > 0 {
		compose["networks"] = networks
	}
	files := map[string][]byte{"runtime.json": common.JSON(runtime), "compose.yml": YAML(compose), "alert-token": []byte(common.S(d.Secrets["alert_token"]))}
	if common.S(center["managed_runtime_dir"]) != "" {
		files["../services.yaml"] = YAML(compose)
	}
	for name := range files {
		if e := d.Journal.Remember(filepath.Join(root, name)); e != nil {
			return e
		}
	}
	if !fresh {
		if _, e := d.compose(ctx, "stop", "receiver"); e != nil {
			return e
		}
	}
	for name, b := range files {
		if e := d.Journal.Write(filepath.Join(root, name), b, 0600); e != nil {
			return e
		}
	}
	if rollout := common.M(d.State["rollout"]); len(rollout) > 0 {
		hashes := common.Map{}
		for name, b := range files {
			hashes[name] = common.Hash(b)
		}
		rollout["main_config_hashes"] = hashes
		if e := d.save(); e != nil {
			return e
		}
	}
	if _, e := d.compose(ctx, "up", "-d", "receiver"); e != nil {
		return e
	}
	if e := d.waitReady(ctx); e != nil {
		return e
	}
	if e := d.verifyWebsite(ctx); e != nil {
		return e
	}
	if e := d.waitNativeMetrics(ctx); e != nil {
		return e
	}
	// Stop only the exporter owned by the previously saved Compose project.
	if entry := common.M(d.Journal.Index[filepath.Join(root, "compose.yml")]); entry["backup"] != nil {
		oldBytes, e := os.ReadFile(filepath.Join(d.Journal.Dir, common.S(entry["backup"])))
		if e != nil {
			return e
		}
		var old common.Map
		if e = yaml.Unmarshal(oldBytes, &old); e != nil {
			return e
		}
		query, e := legacyOwnedContainerQuery(old, "host-exporter")
		if e != nil {
			return e
		}
		if query != nil {
			ids, e := RunCommand(ctx, nil, query...)
			if e != nil {
				return e
			}
			if fields := strings.Fields(string(ids)); len(fields) > 0 {
				if _, e = RunCommand(ctx, nil, append([]string{"docker", "update", "--restart=no"}, fields...)...); e != nil {
					return e
				}
				if _, e = RunCommand(ctx, nil, append([]string{"docker", "stop"}, fields...)...); e != nil {
					return e
				}
			}
		}
	}

	if legacy {
		// Capture the legacy tail while both collectors are alive. Native rows
		// win on overlap; the importer cannot overwrite a new live sample.
		ready, e := common.ReadJSON(filepath.Join(StateRoot, "native-migration-ready.json"))
		if e != nil {
			return e
		}
		settings := common.M(runtime["monitoring"])
		nodes := []telemetry.Node{}
		for _, v := range common.A(settings["nodes"]) {
			n := common.M(v)
			nodes = append(nodes, telemetry.Node{ID: common.S(n["id"]), Active: common.B(n["active"])})
		}
		store, e := telemetry.Open(common.S(center["data_dir"]), nodes, settings)
		if e != nil {
			return e
		}
		e = store.ImportPrometheus(ctx, &http.Client{Timeout: 30 * time.Second}, "http://127.0.0.1:19190", int64(common.F(ready["cutoff"])), time.Now().Unix(), nil)
		store.DB.Close()
		if e != nil {
			return fmt.Errorf("交接前指标增量迁移失败，旧服务保留：%w", e)
		}
		// Stop only services owned by the saved project Compose, never reused external containers.
		oldBytes, e := os.ReadFile(filepath.Join(d.Journal.Dir, common.S(common.M(d.Journal.Index[filepath.Join(root, "compose.yml")])["backup"])))
		if e != nil {
			return e
		}
		var oldCompose common.Map
		if e = yaml.Unmarshal(oldBytes, &oldCompose); e != nil {
			return e
		}
		for _, name := range []string{"alertmanager", "prometheus", "grafana", "loki"} {
			query, err := legacyOwnedContainerQuery(oldCompose, name)
			if err != nil {
				return err
			}
			if query == nil {
				continue
			}
			ids, err := RunCommand(ctx, nil, query...)
			if err != nil {
				return err
			}
			containers := strings.Fields(string(ids))
			if len(containers) == 0 {
				continue
			}
			if _, e = RunCommand(ctx, nil, append([]string{"docker", "stop"}, containers...)...); e != nil {
				return e
			}
		}
		delete(common.M(runtime["monitoring"]), "notifications_paused")
		if e = d.Journal.Write(filepath.Join(root, "runtime.json"), common.JSON(runtime), 0600); e != nil {
			return e
		}
		if _, e = d.compose(ctx, "up", "-d", "--no-deps", "--force-recreate", "receiver"); e != nil {
			return e
		}
		if e = d.waitReady(ctx); e != nil {
			return e
		}
	}
	d.State["active"], d.State["central_installed"], d.State["central_runtime_release"], d.State["step"] = active, true, Release, "central-go-ready"
	if r := common.M(d.State["rollout"]); len(r) > 0 {
		r["main_ready"] = true
	}
	delete(d.State, "central_uninstalled")
	delete(d.State, "central_uninstall_pending")
	return d.save()
}

// Compose usually generates container names. Ownership labels also exclude
// reused services belonging to another project, regardless of their names.
func legacyOwnedContainerQuery(old common.Map, service string) ([]string, error) {
	if len(common.M(common.M(old["services"])[service])) == 0 {
		return nil, nil
	}
	project := common.S(old["name"])
	if project == "" {
		return nil, fmt.Errorf("旧 Compose 缺少项目名称，无法安全停用旧组件；旧容器和数据已保留")
	}
	return []string{"docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project, "--filter", "label=com.docker.compose.service=" + service}, nil
}

func (d *Deploy) waitNativeMetrics(ctx context.Context) error {
	port := common.I(common.M(common.M(d.C.Raw["central"])["event_service"])["port"])
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		status, v, e := common.Request(ctx, d.HTTP, "POST", fmt.Sprintf("http://127.0.0.1:%d/native-verify", port), common.Map{}, map[string]string{"Authorization": "Bearer " + common.S(d.Secrets["alert_token"])})
		if e == nil && status == 200 && common.B(common.M(v)["ready"]) {
			return nil
		}
		if !common.Sleep(ctx, 3*time.Second) {
			return ctx.Err()
		}
	}
	return fmt.Errorf("Go 指标采集与数据库查询验收未通过；请检查 Go 主机采集、采集证书和主服务器日志，旧组件数据已保留")
}
