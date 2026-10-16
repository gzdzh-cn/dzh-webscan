package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
	"webscan/internal/progress"
)

func ResolveNodeMode(n, state common.Map) string {
	if common.B(n["_deployment_explicit"]) {
		return common.S(common.M(n["deployment"])["mode"])
	}
	old := common.M(common.M(state["nodes"])[common.S(n["id"])])
	if m := common.S(old["deployment_mode"]); m == "native" || m == "docker" {
		return m
	}
	if len(old) > 0 && common.S(old["phase"]) != "uninstalled" {
		return "docker"
	}
	if common.Contains(common.SS(state["active"]), common.S(n["id"])) {
		return "docker"
	}
	return "native"
}
func nodeMode(n common.Map) string {
	m := common.S(common.M(n["deployment"])["mode"])
	if m == "" {
		return "native"
	}
	return m
}
func (d *Deploy) checkNodeEnvironment(ctx context.Context, r *Remote, n common.Map) error {
	base := "set -eu; test $(id -u) = 0; test $(uname -m) = x86_64; test -d /run/systemd/system; command -v systemctl >/dev/null; test -x /bin/bash; command -v sync >/dev/null; command -v sha256sum >/dev/null; command -v tar >/dev/null"
	if _, e := r.Run(ctx, base); e != nil {
		return errors.New("native_requires_root_linux_amd64_systemd_and_tools")
	}
	// Reserve enough space for two consistent database snapshots and the
	// isolated scanner bundle before any running service is touched.
	if _, e := r.Run(ctx, "set -eu; free=$(df -Pk /var/lib | awk 'NR==2 {print $4}'); size=0; if [ -f /var/lib/webscan-v1/agent.sqlite3 ]; then size=$(du -k /var/lib/webscan-v1/agent.sqlite3 | cut -f1); fi; test \"$free\" -ge $((size * 2 + 262144))"); e != nil {
		return errors.New("node_disk_insufficient_for_bundle_and_database_backups")
	}
	if nodeMode(n) == "native" {
		b, e := r.Run(ctx, "systemctl --version; test -f /sys/fs/cgroup/cgroup.controllers && cat /sys/fs/cgroup/cgroup.controllers || { test -d /sys/fs/cgroup/memory && test -d /sys/fs/cgroup/cpu; echo 'memory cpu'; }")
		fields := strings.Fields(string(b))
		if len(fields) < 2 {
			return errors.New("native_systemd_version_unavailable")
		}
		version, err := strconv.Atoi(fields[1])
		if err != nil || version < 231 {
			return errors.New("native_requires_systemd_231")
		}
		if e != nil || !strings.Contains(string(b), "memory") || !strings.Contains(string(b), "cpu") {
			return errors.New("native_cpu_memory_cgroup_limits_unavailable")
		}
		return nil
	}
	if _, e := r.Run(ctx, "command -v docker >/dev/null"); e == nil {
		if _, e = r.Run(ctx, "docker info >/dev/null"); e != nil {
			return errors.New("docker_installed_but_daemon_unavailable_not_reinstalled")
		}
		if b, e := r.Run(ctx, "docker info --format '{{json .}}'"); e != nil {
			return e
		} else {
			ok, e := dockerCPUQuotaSupported(b)
			if e != nil || !ok {
				return errors.New("docker_cpu_limits_unavailable")
			}
		}
		if _, e = r.Run(ctx, "docker compose version >/dev/null"); e == nil {
			return nil
		}
		if d.O.Check {
			return errors.New("node_compose_missing")
		}
		return d.installComposeFallback(ctx, r)
	}
	if d.O.Check {
		return errors.New("node_docker_missing_choose_native_or_install")
	}
	script, _ := assets.Files.ReadFile("install-docker.sh")
	if _, e := r.Exec(ctx, "bash", strings.NewReader(string(script))); e != nil {
		return errors.New("node_docker_bootstrap_failed_choose_native_or_install_manually")
	}
	return nil
}
func (d *Deploy) prepareUnifiedNode(ctx context.Context, n common.Map) error {
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	id := common.S(n["id"])
	state := common.M(common.M(d.State["nodes"])[id])
	state["target_deployment_mode"] = nodeMode(n)
	if common.S(state["prepare_run_id"]) != d.RunID {
		state["prepare_run_id"] = d.RunID
		state["previous_agent_image"] = state["agent_image"]
		state["previous_go_image"] = state["go_image"]
		state["previous_go_release"] = state["go_release"]
		state["previous_deployment_mode"] = common.S(state["deployment_mode"])
		if common.S(state["previous_deployment_mode"]) == "" && common.S(state["phase"]) != "" {
			state["previous_deployment_mode"] = "docker"
		}
	}
	// The native package is supplied by a verified local agent image. The remote
	// machine needs only SSH, never a registry connection or Docker in native mode.
	dir, e := os.MkdirTemp("", "webscan-native-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	image := common.S(d.Images["agent"])
	state["agent_image"] = image
	container := "webscan-native-" + common.ID()
	if _, e = d.Docker.Exec(ctx, nil, "create", "--name", container, image, "version"); e != nil {
		return e
	}
	defer d.Docker.Exec(context.WithoutCancel(ctx), nil, "rm", "-f", container)
	archive := filepath.Join(dir, "agent-native.tar.gz")
	if _, e = d.Docker.Exec(ctx, nil, "cp", container+":/usr/local/lib/webscan/agent-native.tar.gz", archive); e != nil {
		return errors.New("agent_native_package_missing_upgrade_image")
	}
	raw, e := os.ReadFile(archive)
	if e != nil {
		return e
	}
	target := "/opt/webscan-go/releases/" + Release
	command := "set -eu; umask 077; mkdir -p /opt/webscan-go/releases /opt/webscan-go/bin; stage=$(mktemp -d /opt/webscan-go/releases/.stage-XXXXXX); trap 'rm -rf -- \"$stage\"' EXIT; cat > \"$stage/package.tar.gz\"; test \"$(sha256sum \"$stage/package.tar.gz\" | cut -d ' ' -f1)\" = " + Q(common.Hash(raw)) + "; tar -xzf \"$stage/package.tar.gz\" -C \"$stage\"; rm \"$stage/package.tar.gz\"; cd \"$stage\"; sha256sum -c SHA256SUMS >/dev/null; test \"$(./webscan version)\" = " + Q(Release) + "; ./tools/bin/yara --version >/dev/null; if [ -d " + Q(target) + " ]; then cmp SHA256SUMS " + Q(target+"/SHA256SUMS") + "; else mv \"$stage\" " + Q(target) + "; fi; cp " + Q(target+"/webscan") + " /opt/webscan-go/bin/webscan.new; chmod 700 /opt/webscan-go/bin/webscan.new; mv /opt/webscan-go/bin/webscan.new /opt/webscan-go/bin/webscan"
	if _, e = r.Exec(ctx, command, strings.NewReader(string(raw))); e != nil {
		return errors.New("native_bundle_transfer_or_verification_failed")
	}
	state["native_dir"], state["native_sha256"] = target, common.Hash(raw)
	if nodeMode(n) == "docker" {
		if pulled, err := RemotePull(ctx, r, d.C, image); err == nil {
			state["go_image"] = pulled
		} else {
			ref, err := d.TransferImage(ctx, r, image)
			if err != nil {
				return err
			}
			state["go_image"] = ref
		}
	}
	common.M(d.State["nodes"])[id] = state
	return d.save()
}

const stopNodeWriters = "set -eu; for name in webscan-agent-native webscan-agent-v1 webscan-vector-v1 webscan-exporter-v1 webscan-firewall-v1; do if systemctl cat \"$name.service\" >/dev/null 2>&1; then systemctl disable --now \"$name.service\"; fi; done; if [ -f /etc/webscan-v1/compose.yml ] && command -v docker >/dev/null 2>&1; then docker info >/dev/null; for name in webscan-agent-go webscan-vector-v1 webscan-exporter-v1; do if docker inspect \"$name\" >/dev/null 2>&1; then docker update --restart=no \"$name\" >/dev/null; docker stop -t 30 \"$name\" >/dev/null; fi; done; fi"

func (d *Deploy) installUnifiedNode(ctx context.Context, n common.Map) error {
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	id := common.S(n["id"])
	state := common.M(common.M(d.State["nodes"])[id])
	target := common.S(state["native_dir"])
	if target == "" {
		return errors.New("native_bundle_not_prepared")
	}
	rules, err := r.Read(ctx, "/etc/webscan-v1/php-webshell.yar")
	if err != nil {
		rules, _ = assets.Files.ReadFile("php-webshell.yar")
	}
	checkPath := "/var/lib/webscan-deploy/yara-check-" + common.ID() + ".yar"
	if e = r.Write(ctx, checkPath, rules, 0600); e != nil {
		return e
	}
	_, checkErr := r.Run(ctx, Q(target+"/tools/bin/yara")+" -w "+Q(checkPath)+" /dev/null")
	r.Run(context.WithoutCancel(ctx), "rm -f "+Q(checkPath))
	if checkErr != nil {
		return errors.New("node_yara_validation_failed")
	}
	if common.B(common.M(common.M(n["scan"])["clamav"])["enabled"]) {
		conf := "/var/lib/webscan-deploy/clamd-check-" + common.ID() + ".conf"
		if e = r.Write(ctx, conf, []byte("LocalSocket /run/clamav/clamd.ctl\n"), 0600); e != nil {
			return e
		}
		_, checkErr = r.Run(ctx, "set -eu; : > "+Q(conf+".probe")+"; test -S /run/clamav/clamd.ctl && "+Q(target+"/tools/bin/clamdscan")+" --fdpass --config-file="+Q(conf)+" --no-summary "+Q(conf+".probe"))
		r.Run(context.WithoutCancel(ctx), "rm -f "+Q(conf)+" "+Q(conf+".probe"))
		if checkErr != nil {
			return errors.New("node_clamav_service_unavailable")
		}
	}
	if e = d.setNodeMaintenance(ctx, n, true); e != nil {
		return e
	}
	state["backup_pending"] = d.RunID
	if e = d.save(); e != nil {
		return e
	}
	if e = d.nodeBackup(ctx, n); e != nil {
		return e
	}
	state["go_run_id"], state["phase"] = d.RunID, "go-prepared"
	delete(state, "backup_pending")
	if e = d.save(); e != nil {
		return e
	}
	if _, e = r.Run(ctx, stopNodeWriters); e != nil {
		return e
	}
	// Snapshot after writers stop. The initial backup captures service identities.
	backup := "/var/lib/webscan-deploy/runs/" + d.RunID
	if _, e = r.Run(ctx, "set -eu; if [ -f /var/lib/webscan-v1/agent.sqlite3 ]; then if [ ! -f "+Q(backup+"/agent-stopped.sqlite3")+" ]; then /opt/webscan-go/bin/webscan tool --action snapshot-db --input /var/lib/webscan-v1/agent.sqlite3 --output "+Q(backup+"/agent-stopped.sqlite3")+"; fi; /opt/webscan-go/bin/webscan tool --action import-agent-logs; fi"); e != nil {
		return e
	}
	if e = d.prepareInotify(ctx, n); e != nil {
		return e
	}
	runtime := NodeRuntime(d.C, n, d.Secrets)
	runtime["deployment_mode"] = nodeMode(n)
	runtime["clamav_config"] = "/etc/webscan-v1/clamd.conf"
	if nodeMode(n) == "native" {
		runtime["host_metrics"] = common.Map{"proc": "/proc", "sys": "/sys", "root": "/"}
		runtime["scanner_tools"] = common.Map{"yara": target + "/tools/bin/yara", "clamav": target + "/tools/bin/clamdscan"}
	}
	var yara []byte
	if b, err := r.Read(ctx, "/etc/webscan-v1/php-webshell.yar"); err == nil {
		yara = b
	} else {
		yara, _ = assets.Files.ReadFile("php-webshell.yar")
	}
	files := map[string][]byte{"/etc/webscan-v1/runtime.json": common.JSON(runtime), "/etc/webscan-v1/php-webshell.yar": yara, "/etc/webscan-v1/clamd.conf": []byte("LocalSocket /run/clamav/clamd.ctl\n")}
	if d.C.SSLEnabled() {
		for source, dest := range map[string]string{"ca.crt": "ca.crt", id + ".crt": "server.crt", id + ".key": "server.key"} {
			b, e := os.ReadFile(filepath.Join(d.C.CentralRoot(), "pki", source))
			if e != nil {
				return e
			}
			files["/etc/webscan-v1/pki/"+dest] = b
		}
	}
	if _, e = r.Run(ctx, "set -eu; umask 077; mkdir -p /etc/webscan-v1 /var/lib/webscan-v1/textfile /var/log/webscan-v1 "+Q(common.S(runtime["probe_directory"]))+"; chmod 700 /etc/webscan-v1 /var/lib/webscan-v1 /var/log/webscan-v1"); e != nil {
		return e
	}
	for path, b := range files {
		if e = r.Write(ctx, path, b, 0600); e != nil {
			return e
		}
	}
	if _, e = r.Run(ctx, Q(target+"/tools/bin/yara")+" -w /etc/webscan-v1/php-webshell.yar /dev/null"); e != nil {
		return errors.New("node_yara_validation_failed")
	}
	pause := "/var/lib/webscan-v1/transport-paused"
	if d.stagingNodes() {
		if e = r.Write(ctx, pause, []byte(d.RunID), 0600); e != nil {
			return e
		}
	} else {
		if _, e = r.Run(ctx, "rm -f "+Q(pause)); e != nil {
			return e
		}
	}
	if nodeMode(n) == "native" {
		// Keep the previous compose in the rollback journal, not as an active
		// native runtime marker that would require an unrelated Docker daemon.
		if _, e = r.Run(ctx, "rm -f /etc/webscan-v1/compose.yml"); e != nil {
			return e
		}
		unitNode := common.Clone(n)
		unitNode["probe_directory"] = runtime["probe_directory"]
		unit := NativeNodeUnit(unitNode, target)
		if e = r.Write(ctx, "/etc/systemd/system/webscan-agent-native.service", []byte(unit), 0600); e != nil {
			return e
		}
		if _, e = r.Run(ctx, "systemctl daemon-reload && systemctl enable --now webscan-agent-native"); e != nil {
			return e
		}
		limits, err := r.Run(ctx, "systemctl show webscan-agent-native -p MemoryMax -p CPUQuotaPerSecUSec -p LimitNOFILE")
		if err != nil || VerifyNativeLimits(string(limits), common.M(n["resources"])) != nil {
			return errors.New("native_resource_limits_not_effective")
		}
	} else {
		b, e := r.Run(ctx, "docker info --format '{{json .}}'")
		if e != nil {
			return e
		}
		supported, e := dockerCPUQuotaSupported(b)
		if e != nil {
			return e
		}
		if !supported {
			return errors.New("docker_cpu_limits_unavailable")
		}
		compose := compatibleAgentCompose(d.C, n, common.S(state["go_image"]), supported)
		if e = r.Write(ctx, "/etc/webscan-v1/compose.yml", YAML(compose), 0600); e != nil {
			return e
		}
		if _, e = r.Run(ctx, "/opt/webscan-go/bin/webscan tool --action pin-compose-images --output /etc/webscan-v1/compose.yml && docker compose -f /etc/webscan-v1/compose.yml up -d --pull never --no-deps agent"); e != nil {
			return e
		}
	}
	state["deployment_mode"], state["go_release"], state["phase"] = nodeMode(n), Release, "go-switched"
	if e = d.save(); e != nil {
		return e
	}
	if e = d.WaitNodeReady(ctx, n); e != nil {
		return e
	}
	if !d.stagingNodes() {
		if e = d.enableNodeTransport(ctx, n); e != nil {
			return e
		}
	}
	return nil
}
func NativeNodeUnit(n common.Map, target string) string {
	r := common.M(n["resources"])
	return fmt.Sprintf("[Unit]\nDescription=Webscan unified agent\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=simple\nUser=root\nUMask=0077\nExecStart=%s/webscan agent --config /etc/webscan-v1/runtime.json\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=60\nMemoryMax=%dM\nCPUQuota=%g%%\nEnvironment=GOMEMLIMIT=%dMiB\nEnvironment=GOMAXPROCS=%d\nLimitNOFILE=65536\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=/var/lib/webscan-v1 /var/log/webscan-v1 %s -/run/clamav\n[Install]\nWantedBy=multi-user.target\n", target, common.I(r["agent_memory_mib"]), common.F(r["cpus"])*100, common.I(r["go_memory_mib"]), common.I(r["gomaxprocs"]), systemdPath(common.S(n["probe_directory"])))
}
func (d *Deploy) enableNodeTransport(ctx context.Context, n common.Map) error {
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	_, e = r.Run(ctx, "rm -f /var/lib/webscan-v1/transport-paused")
	return e
}
func (d *Deploy) waitUnifiedTransport(ctx context.Context, n common.Map) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		m, e := d.metrics(ctx, n)
		if e == nil && m["webscan_transport_up"] == 1 {
			return nil
		}
		if !common.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("node_go_transport_not_ready")
}

func (d *Deploy) clearNodeMaintenance(ctx context.Context, n common.Map) error {
	return d.setNodeMaintenance(ctx, n, false)
}

// Reloads are idempotent. A busy or restarting center must not turn an accepted
// node into a failed installation after just one management request.
func (d *Deploy) reloadNodeMaintenance(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	port := common.I(common.M(common.M(d.C.Raw["central"])["event_service"])["port"])
	for attempt := 0; ; attempt++ {
		status, _, e := common.Request(ctx, d.HTTP, "POST", fmt.Sprintf("http://127.0.0.1:%d/reload-settings", port), common.Map{}, map[string]string{"Authorization": "Bearer " + common.S(d.Secrets["alert_token"])})
		if e == nil && status == 200 {
			return nil
		}
		reason := "请求失败或响应未确认"
		if status != 0 {
			reason = fmt.Sprintf("HTTP %d", status)
		}
		transient := status == 0 || status == 200 || status == 429 || status >= 500
		if !transient || attempt >= 4 || ctx.Err() != nil {
			return &progress.Failure{Code: "node_maintenance_release_failed", Message: "中心维护状态同步未完成（" + reason + "）。已保留部署现场，请按原范围继续任务；认证或配置校验失败不会自动重试。"}
		}
		progress.Info(ctx, fmt.Sprintf("中心维护状态同步暂未确认（%s），%d 秒后重试", reason, 1<<attempt))
		if !common.Sleep(ctx, time.Duration(1<<attempt)*time.Second) {
			return ctx.Err()
		}
	}
}

func (d *Deploy) setNodeMaintenance(ctx context.Context, n common.Map, enabled bool) error {
	path := filepath.Join(d.C.CentralRoot(), "runtime.json")
	runtime, e := common.ReadJSON(path)
	if e != nil {
		if !enabled && os.IsNotExist(e) {
			return nil
		}
		return e
	}
	m := common.M(runtime["monitoring"])
	previous := common.SS(m["maintenance_nodes"])
	list := []string{}
	for _, id := range previous {
		if id != common.S(n["id"]) {
			list = append(list, id)
		}
	}
	if enabled {
		list = append(list, common.S(n["id"]))
	}
	m["maintenance_nodes"] = list
	if string(common.JSON(previous)) != string(common.JSON(list)) {
		if d.Journal == nil {
			run := common.S(d.State["run_id"])
			if !strings.HasPrefix(run, "go-") {
				return errors.New("node_maintenance_requires_deployment_journal")
			}
			d.Journal, e = NewJournal(filepath.Join(StateRoot, "runs", run, "central"))
			if e != nil {
				return e
			}
		}
		if e = d.Journal.Write(path, common.JSON(runtime), 0600); e != nil {
			return e
		}
	}
	// Always confirm the running state, even when a previous attempt already
	// wrote the desired file but lost the reload response.
	return d.reloadNodeMaintenance(ctx)
}

func systemdPath(p string) string {
	if p == "" {
		p = "/var/lib/webscan-probe-v1"
	}
	return strconv.Quote(strings.ReplaceAll(p, "%", "%%"))
}

func VerifyNativeLimits(output string, resources common.Map) error {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, val, ok := strings.Cut(line, "="); ok {
			values[key] = strings.TrimSpace(val)
		}
	}
	memory, err := strconv.ParseInt(values["MemoryMax"], 10, 64)
	quota, qerr := time.ParseDuration(strings.ReplaceAll(values["CPUQuotaPerSecUSec"], " ", ""))
	if err != nil || qerr != nil || memory != int64(common.I(resources["agent_memory_mib"]))<<20 || quota != time.Duration(common.F(resources["cpus"])*float64(time.Second)) || values["LimitNOFILE"] != "65536" {
		return errors.New("native_resource_limits_not_effective")
	}
	return nil
}
