package deploy

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
	"webscan/internal/progress"
)

func (d *Deploy) remote(ctx context.Context, n common.Map) (*Remote, error) {
	id := common.S(n["id"])
	if r := d.Remotes[id]; r != nil {
		return r, nil
	}
	r, e := Connect(ctx, n)
	if e != nil {
		return nil, e
	}
	d.Remotes[id] = r
	return r, nil
}
func archiveConfig(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	tr := tar.NewReader(f)
	var manifest []struct{ Config string }
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			f.Close()
			return "", e
		}
		if h.Name == "manifest.json" {
			if e = json.NewDecoder(io.LimitReader(tr, 1048576)).Decode(&manifest); e != nil {
				f.Close()
				return "", e
			}
			break
		}
	}
	f.Close()
	if len(manifest) != 1 {
		return "", errors.New("image_archive_requires_one_platform_config")
	}
	f, e = os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	tr = tar.NewReader(f)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
		if h.Name == manifest[0].Config {
			if h.Size > 4*1048576 {
				return "", errors.New("image_config_too_large")
			}
			b, e := io.ReadAll(tr)
			if e != nil {
				return "", e
			}
			return "sha256:" + common.Hash(b), nil
		}
	}
	return "", errors.New("image_archive_config_missing")
}
func (d *Deploy) TransferImage(ctx context.Context, r *Remote, image string) (string, error) {
	dir, e := os.MkdirTemp("", "webscan-image-transfer-")
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "image.tar")
	progress.Info(ctx, "正在生成并校验 SSH 镜像归档")
	if _, e = d.Docker.Exec(ctx, nil, "image", "save", "--output", path, image); e != nil {
		return "", e
	}
	config, e := archiveConfig(path)
	if e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	hash := newSHAReader(f)
	if _, e = io.Copy(io.Discard, hash); e != nil {
		return "", e
	}
	checksum := hash.Sum()
	f.Seek(0, 0)
	target := "/tmp/webscan-image-" + common.ID() + ".tar"
	command := "set -eu; umask 077; trap " + Q("rm -f -- "+Q(target)) + " EXIT; cat > " + Q(target) + "; test \"$(sha256sum " + Q(target) + " | cut -d ' ' -f1)\" = " + Q(checksum) + "; docker load --input " + Q(target) + " >/dev/null; docker image inspect " + Q(image)
	info, _ := f.Stat()
	reader := io.Reader(f)
	if info != nil {
		reader = progress.Reader(ctx, f, info.Size(), "SSH 镜像传输")
	}
	b, e := r.Exec(ctx, command, reader)
	if e == nil {
		v, err := common.Decode(b)
		if err == nil {
			for _, item := range common.A(v) {
				info := common.M(item)
				if common.Contains(common.SS(info["RepoDigests"]), image) {
					return image, nil
				}
			}
		}
	}
	b, e = r.Run(ctx, "docker image inspect "+Q(config))
	if e != nil {
		return "", errors.New("loaded_image_identity_not_verified")
	}
	v, e := common.Decode(b)
	if e != nil {
		return "", e
	}
	items := common.A(v)
	if len(items) != 1 || common.S(common.M(items[0])["Id"]) != config {
		return "", errors.New("loaded_image_config_digest_mismatch")
	}
	return config, nil
}
func (d *Deploy) PrepareNode(ctx context.Context, n common.Map) error {
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	image := common.S(d.Images["agent"])
	if pulled, err := RemotePull(ctx, r, d.C, image); err == nil {
		image = pulled
	} else {
		fmt.Println(common.S(n["id"]) + " 直拉失败，使用已校验 SSH 传输镜像归档。")
		image, e = d.TransferImage(ctx, r, image)
		if e != nil {
			return e
		}
	}
	id := common.S(n["id"])
	nodes := common.M(d.State["nodes"])
	state := common.M(nodes[id])
	state["go_image"] = image
	nodes[id] = state
	d.State["nodes"] = nodes
	extract := "webscan-extract-" + common.ID()
	command := "set -eu; umask 077; mkdir -p /opt/webscan-go/bin; trap " + Q("docker rm -f "+Q(extract)+" >/dev/null 2>&1 || true") + " EXIT; docker create --name " + Q(extract) + " " + Q(image) + " version >/dev/null; docker cp " + Q(extract+":/usr/local/bin/webscan") + " /opt/webscan-go/bin/webscan.new; chmod 700 /opt/webscan-go/bin/webscan.new; mv /opt/webscan-go/bin/webscan.new /opt/webscan-go/bin/webscan; /opt/webscan-go/bin/webscan version"
	b, e := r.Run(ctx, command)
	if e != nil {
		return e
	}
	if !strings.Contains(string(b), Release) {
		return errors.New("node_binary_release_mismatch")
	}
	return d.save()
}
func (d *Deploy) nodeBackup(ctx context.Context, n common.Map) error {
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	backup := "/var/lib/webscan-deploy/runs/" + d.RunID
	_, e = r.Run(ctx, "set -eu; umask 077; mkdir -p "+Q(backup)+"; if [ ! -f "+Q(backup+"/node-state.json")+" ]; then /opt/webscan-go/bin/webscan tool --action backup-node --output "+Q(backup)+"; fi")
	return e
}
func (d *Deploy) InstallNode(ctx context.Context, n common.Map) error {
	id := common.S(n["id"])
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	if e = progress.Stage(ctx, progress.Node(n), "保存节点配置、数据库和服务状态", func(ctx context.Context) error { return d.nodeBackup(ctx, n) }); e != nil {
		return e
	}
	var compose common.Map
	if e = progress.Stage(ctx, progress.Node(n), "检查 Docker CPU 配额能力并适配容器配置", func(ctx context.Context) error {
		b, err := r.Run(ctx, "docker info --format '{{json .}}'")
		if err != nil {
			return errors.New("node_docker_cpu_capability_check_failed")
		}
		supported, err := dockerCPUQuotaSupported(b)
		if err != nil {
			return err
		}
		compose = compatibleAgentCompose(d.C, n, common.S(common.M(common.M(d.State["nodes"])[id])["go_image"]), supported)
		if !supported && common.F(common.M(n["resources"])["cpus"]) > 0 {
			progress.Warn(ctx, "Docker 不支持 CPU 配额，已跳过 cpus 硬限制；保留容器内存限制、GOMEMLIMIT 和 GOMAXPROCS。Go 并发限制不等同于 CPU 配额")
		} else {
			progress.Info(ctx, "CPU 配额能力检查完成，按节点资源配置生成容器")
		}
		return nil
	}); e != nil {
		return e
	}
	if e = d.prepareInotify(ctx, n); e != nil {
		return e
	}
	nodeState := common.M(common.M(d.State["nodes"])[id])
	nodeState["go_run_id"], nodeState["phase"] = d.RunID, "go-prepared"
	if e = d.save(); e != nil {
		return e
	}
	if d.stagingNodes() {
		// Disable boot and Docker dependencies too; events remain on local disk.
		if _, e = r.Run(ctx, holdVectorCommand); e != nil {
			return e
		}
	}
	runtime := NodeRuntime(d.C, n, d.Secrets)
	var yara []byte
	if b, err := r.Read(ctx, "/etc/webscan-v1/php-webshell.yar"); err == nil {
		yara = b
	} else {
		yara, _ = assets.Files.ReadFile("php-webshell.yar")
	}
	files := map[string][]byte{"/etc/webscan-v1/runtime.json": common.JSON(runtime), "/etc/webscan-v1/php-webshell.yar": yara, "/etc/webscan-v1/compose.yml": YAML(compose)}
	if d.C.SSLEnabled() {
		for source, dest := range map[string]string{"ca.crt": "ca.crt", id + ".crt": "server.crt", id + ".key": "server.key"} {
			b, e := os.ReadFile(filepath.Join(d.C.CentralRoot(), "pki", source))
			if e != nil {
				return e
			}
			files["/etc/webscan-v1/pki/"+dest] = b
		}
	}
	_, e = r.Run(ctx, "set -eu; mkdir -p /var/lib/webscan-v1/textfile /var/log/webscan-v1 "+Q(common.S(runtime["probe_directory"]))+"; if systemctl cat webscan-agent-v1.service >/dev/null 2>&1; then systemctl disable --now webscan-agent-v1; fi")
	if e != nil {
		return e
	}
	progress.Info(ctx, "正在写入节点配置、YARA 规则和通信配置")
	for path, b := range files {
		if e = r.Write(ctx, path, b, 0600); e != nil {
			return e
		}
	}
	image := common.S(nodeState["go_image"])
	if _, e = r.Run(ctx, "docker run --rm --network none --read-only -v /etc/webscan-v1:/etc/webscan-v1:ro --entrypoint yara "+Q(image)+" -w /etc/webscan-v1/php-webshell.yar /dev/null"); e != nil {
		return errors.New("node_yara_validation_failed")
	}
	if _, e = r.Run(ctx, "docker compose -f /etc/webscan-v1/compose.yml config --quiet"); e != nil {
		return e
	}
	if e = progress.Stage(ctx, progress.Node(n), "启动 Go 文件监控容器", func(ctx context.Context) error {
		if _, err := r.Run(ctx, "/opt/webscan-go/bin/webscan tool --action pin-compose-images --output /etc/webscan-v1/compose.yml"); err != nil {
			return err
		}
		_, err := r.ExecVisible(ctx, "docker compose -f /etc/webscan-v1/compose.yml up -d --pull never --no-deps agent", nil, "容器状态")
		return err
	}); e != nil {
		return e
	}
	vectorConfig, vectorErr := r.Read(ctx, "/etc/webscan-v1/vector.yml")
	if _, e = r.Run(ctx, "systemctl is-active --quiet webscan-vector-v1 && systemctl is-active --quiet webscan-exporter-v1"); d.stagingNodes() || e != nil || vectorErr != nil || !bytes.Equal(vectorConfig, YAML(VectorConfig(d.C, n, d.Secrets))) {
		if e = progress.Stage(ctx, progress.Node(n), "安装 Vector 日志传输和指标采集器", func(ctx context.Context) error { return d.InstallNodeSidecars(ctx, n) }); e != nil {
			return e
		}
	}
	if !d.stagingNodes() {
		if e = progress.Stage(ctx, progress.Node(n), "确认 Vector 和指标采集器正常运行", func(ctx context.Context) error { return d.WaitNodeSidecars(ctx, n) }); e != nil {
			return e
		}
	}
	if e = progress.Stage(ctx, progress.Node(n), "建立文件清单并核对目录监听覆盖", func(ctx context.Context) error { return d.WaitNodeReady(ctx, n) }); e != nil {
		return e
	}
	nodeState["phase"] = "go-switched"
	if e = d.save(); e != nil {
		return e
	}
	if d.stagingNodes() {
		return nil
	}
	active := common.SS(d.State["active"])
	if !common.Contains(active, id) {
		active = append(active, id)
		d.State["active"] = active
		if e = d.Journal.Write(filepath.Join(d.C.CentralRoot(), "runtime.json"), common.JSON(d.centralRuntime(active)), 0600); e != nil {
			return e
		}
		if e = d.Journal.Write(filepath.Join(d.C.CentralRoot(), "prometheus.yml"), YAML(Prometheus(d.C, active)), 0600); e != nil {
			return e
		}
		if e = progress.Stage(ctx, progress.Host(d.C.Raw), "登记节点并更新主服务器接收服务和 Prometheus", func(ctx context.Context) error {
			_, err := d.compose(ctx, "up", "-d", "--no-deps", "--pull", "never", "--force-recreate", "receiver", "prometheus")
			return err
		}); e != nil {
			return e
		}
		if e = d.waitReady(ctx); e != nil {
			return e
		}
	}
	return d.save()
}
func (d *Deploy) WaitNodeReady(ctx context.Context, n common.Map) error {
	return d.waitNodeReady(ctx, n, 30*time.Minute, 2*time.Second)
}

// Readiness belongs to the currently running container, not an applied rules
// file or completed baseline left in the retained data directory by an old run.
func currentNodeReady(status common.Map, metrics map[string]float64, started time.Time) bool {
	// The status confirms this process completed startup and applied its rules.
	// Live coverage comes from current metrics: older agents may retain the
	// initial coverage result in status after recovering their directory watches.
	if common.S(status["implementation"]) != "goframe" || common.S(status["state"]) != "applied" || common.S(status["instance_id"]) == "" || common.F(status["time"]) < float64(started.UnixNano())/1e9 {
		return false
	}
	if ready, exists := status["collector_ready"]; exists && !common.B(ready) {
		return false
	}
	return stagedNodeHealthy(metrics) && metrics["webscan_agent_heartbeat_seconds"] >= float64(started.UnixNano())/1e9
}

func (d *Deploy) waitNodeReady(ctx context.Context, n common.Map, timeout, poll time.Duration) error {
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	deadline := time.Now().Add(timeout)
	notice := time.Now().Add(-10 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		b, e := r.Run(ctx, "docker inspect --format '{{.State.Running}} {{.State.Restarting}} {{.State.StartedAt}}' webscan-agent-go")
		if e != nil || !strings.HasPrefix(strings.TrimSpace(string(b)), "true false") {
			return errors.New("node_agent_container_not_running")
		}
		fields := strings.Fields(string(b))
		if len(fields) != 3 {
			return errors.New("node_agent_start_time_unavailable")
		}
		started, e := time.Parse(time.RFC3339Nano, fields[2])
		if e != nil {
			return errors.New("node_agent_start_time_unavailable")
		}
		status := common.Map{}
		if b, e := r.Read(ctx, "/var/lib/webscan-v1/rules-status.json"); e == nil {
			if v, err := common.Decode(b); err == nil {
				status = common.M(v)
			}
		}
		metrics := map[string]float64{}
		if b, e := r.Read(ctx, "/var/lib/webscan-v1/textfile/agent.prom"); e == nil {
			metrics = parseMetrics(b)
		}
		if currentNodeReady(status, metrics, started) {
			progress.Info(ctx, "本次启动文件清单已完成，监控程序和目录监听覆盖正常")
			return nil
		}
		if time.Since(notice) >= 10*time.Second {
			progress.Info(ctx, "正在核对本次启动的网站文件清单；最长等待 30 分钟，不启动节点传输")
			flag := func(value float64) string {
				if value == 1 {
					return "正常"
				}
				return "等待"
			}
			progress.Info(ctx, fmt.Sprintf("清单进度：已核对 %.0f 个文件；当前监听目录 %.0f 个；待扫描 %.0f 条；待投递 %.0f 条；启动就绪 %s；目录覆盖 %s", metrics["webscan_inventory_files_checked"], metrics["webscan_watches"], metrics["webscan_pending_scans"], metrics["webscan_local_pending_events"], flag(metrics["webscan_collector_ready"]), flag(metrics["webscan_coverage_ok"])))
			if metrics["webscan_coverage_ok"] != 1 {
				progress.Info(ctx, fmt.Sprintf("目录监听累计失败 %.0f 次；失败数持续增加时需检查共享监听额度、目录权限和挂载", metrics["webscan_watch_errors_total"]))
				issue := common.M(status["coverage_error"])
				if common.S(issue["message"]) != "" {
					progress.Info(ctx, "最近一次目录监听失败："+common.S(issue["message"])+"；目录："+common.S(issue["path"]))
				}
			}
			notice = time.Now()
		}
		if !common.Sleep(ctx, poll) {
			return ctx.Err()
		}
	}
	return errors.New("node_agent_ready_timeout")
}
func (d *Deploy) InstallNodeSidecars(ctx context.Context, n common.Map) error {
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	refs := map[string]string{}
	for _, role := range []string{"vector", "exporter"} {
		image := common.S(d.Images[role])
		progress.Info(ctx, "准备节点组件："+progress.Role(role))
		if pulled, err := RemotePull(ctx, r, d.C, image); err == nil {
			image = pulled
		} else {
			image, e = d.TransferImage(ctx, r, image)
			if e != nil {
				return e
			}
		}
		refs[role] = image
	}
	if e = r.Write(ctx, "/etc/webscan-v1/vector.yml", YAML(VectorConfig(d.C, n, d.Secrets)), 0600); e != nil {
		return e
	}
	if _, e = r.Run(ctx, "docker run --rm --network none --read-only -v /etc/webscan-v1/vector.yml:/etc/vector/vector.yaml:ro "+Q(refs["vector"])+" validate --no-environment /etc/vector/vector.yaml"); e != nil {
		return errors.New("node_vector_config_invalid")
	}
	exporter := ExporterWebConfig(d.C)
	if e = r.Write(ctx, "/etc/webscan-v1/exporter.yml", YAML(exporter), 0600); e != nil {
		return e
	}
	base := "--network host --read-only --cap-drop ALL --security-opt no-new-privileges --log-opt max-size=10m --log-opt max-file=3"
	aliases := map[string]string{"vector": "docker.io/" + VendorImages["vector"], "exporter": "docker.io/" + VendorImages["exporter"]}
	commands := map[string]string{"vector": "/usr/bin/docker run --pull never --name webscan-vector-v1 " + base + " -v /etc/webscan-v1/vector.yml:/etc/vector/vector.yaml:ro -v /etc/webscan-v1/pki/ca.crt:/etc/webscan-v1/pki/ca.crt:ro -v /var/log/webscan-v1:/var/log/webscan-v1:ro -v /var/lib/webscan-vector-v1:/var/lib/vector " + aliases["vector"], "exporter": "/usr/bin/docker run --pull never --name webscan-exporter-v1 " + base + " --user 0:0 --pid host -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /:/rootfs:ro,rslave -v /var/lib/webscan-v1/textfile:/textfile:ro -v /etc/webscan-v1/exporter.yml:/etc/webscan-v1/exporter.yml:ro -v /etc/webscan-v1/pki:/etc/webscan-v1/pki:ro " + aliases["exporter"] + " --web.listen-address=:" + strconv.Itoa(common.I(common.M(n["metrics"])["port"])) + " --web.config.file=/etc/webscan-v1/exporter.yml --path.procfs=/host/proc --path.sysfs=/host/sys --path.rootfs=/rootfs --collector.textfile.directory=/textfile"}
	if !d.C.SSLEnabled() {
		commands["vector"] = strings.ReplaceAll(commands["vector"], " -v /etc/webscan-v1/pki/ca.crt:/etc/webscan-v1/pki/ca.crt:ro", "")
		commands["exporter"] = strings.ReplaceAll(commands["exporter"], " -v /etc/webscan-v1/pki:/etc/webscan-v1/pki:ro", "")
	}
	for name, command := range commands {
		// Restart=always does not recover a unit stopped through Requires=docker.
		// PartOf propagates Docker restarts; WantedBy also covers stop/start.
		unit := "[Unit]\nDescription=Webscan " + name + "\nRequires=docker.service\nPartOf=docker.service\nAfter=docker.service network-online.target\n[Service]\nExecStartPre=/usr/bin/docker image tag " + refs[name] + " " + aliases[name] + "\nExecStartPre=-/usr/bin/docker rm -f webscan-" + name + "-v1\nExecStart=" + command + "\nExecStop=/usr/bin/docker stop -t 20 webscan-" + name + "-v1\nRestart=always\nRestartSec=5\nTimeoutStopSec=35\n[Install]\nWantedBy=multi-user.target docker.service\n"
		if e = r.Write(ctx, "/etc/systemd/system/webscan-"+name+"-v1.service", []byte(unit), 0644); e != nil {
			return e
		}
	}
	port := strconv.Itoa(common.I(common.M(n["metrics"])["port"]))
	source := common.S(common.M(n["metrics"])["allowed_source_ip"])
	firewall := "#!/bin/sh\nset -eu\niptables -N WEBSCAN_V1 2>/dev/null || true\niptables -F WEBSCAN_V1\niptables -A WEBSCAN_V1 -s " + source + " -j ACCEPT\niptables -A WEBSCAN_V1 -s 127.0.0.1 -j ACCEPT\niptables -A WEBSCAN_V1 -j DROP\niptables -C INPUT -p tcp --dport " + port + " -j WEBSCAN_V1 2>/dev/null || iptables -I INPUT 1 -p tcp --dport " + port + " -j WEBSCAN_V1\nip6tables -N WEBSCAN_V1 2>/dev/null || true\nip6tables -F WEBSCAN_V1\nip6tables -A WEBSCAN_V1 -s ::1 -j ACCEPT\nip6tables -A WEBSCAN_V1 -j DROP\nip6tables -C INPUT -p tcp --dport " + port + " -j WEBSCAN_V1 2>/dev/null || ip6tables -I INPUT 1 -p tcp --dport " + port + " -j WEBSCAN_V1\n"
	if e = r.Write(ctx, "/opt/webscan-go/firewall.sh", []byte(firewall), 0700); e != nil {
		return e
	}
	unit := []byte("[Unit]\nDescription=Restrict Webscan TLS metrics\nBefore=webscan-exporter-v1.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/opt/webscan-go/firewall.sh\n[Install]\nWantedBy=multi-user.target\n")
	if e = r.Write(ctx, "/etc/systemd/system/webscan-firewall-v1.service", unit, 0644); e != nil {
		return e
	}
	command := "set -eu; mkdir -p /var/lib/webscan-vector-v1; systemctl daemon-reload; systemctl enable --now webscan-firewall-v1; systemctl enable webscan-exporter-v1; systemctl restart webscan-exporter-v1"
	if !d.stagingNodes() {
		command += "; systemctl enable webscan-vector-v1; systemctl restart webscan-vector-v1"
	}
	_, e = r.ExecVisible(ctx, command, nil, "服务状态")
	return e
}

func (d *Deploy) WaitNodeSidecars(ctx context.Context, n common.Map) error {
	r, err := d.remote(ctx, n)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		state, err := r.Run(ctx, "docker inspect --format '{{.State.Running}} {{.State.ExitCode}}' webscan-vector-v1 webscan-exporter-v1")
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(state)), "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) == "false 78" {
					return errors.New("node_vector_config_invalid")
				}
			}
			if len(lines) == 2 && strings.TrimSpace(lines[0]) == "true 0" && strings.TrimSpace(lines[1]) == "true 0" {
				if m, err := d.metrics(ctx, n); err == nil && m["webscan_vector_metrics_up"] == 1 {
					return nil
				}
			}
		}
		if !common.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("node_sidecars_not_ready")
}
func (d *Deploy) RollbackNode(ctx context.Context, n common.Map, uninstall bool) error {
	r, e := d.remote(ctx, n)
	if e != nil {
		return e
	}
	state := common.M(common.M(d.State["nodes"])[common.S(n["id"])])
	run := common.S(state["go_run_id"])
	if run == "" {
		return nil
	}
	command := "set -eu; docker stop -t 30 webscan-agent-go >/dev/null 2>&1 || true; /opt/webscan-go/bin/webscan tool --action restore-node --output " + Q("/var/lib/webscan-deploy/runs/"+run)
	if uninstall {
		command += " --uninstall"
	}
	_, e = r.Run(ctx, command)
	if e == nil {
		state["phase"] = "go-rolled-back"
	}
	return e
}
func (d *Deploy) Rollback(ctx context.Context, uninstall bool) error {
	if rollout := common.M(d.State["rollout"]); len(rollout) > 0 {
		if common.S(d.State["target_node"]) != d.O.Node || common.B(d.State["target_central_only"]) != d.O.CentralOnly {
			return errors.New("rollback_scope_must_match_original_run")
		}
		d.RunID = common.S(d.State["run_id"])
		j, err := NewJournal(filepath.Join(StateRoot, "runs", d.RunID, "central"))
		if err != nil {
			return err
		}
		d.Journal = j
		rollout["accepted"], rollout["main_ready"] = common.Map{}, false
		if err = d.rollbackRollout(ctx); err != nil {
			return err
		}
		d.State["go_release"], d.State["image_lock"] = d.State["previous_go_release"], d.State["previous_image_lock"]
		d.State["central_runtime_release"] = d.State["previous_central_runtime_release"]
		d.State["configuration"], d.State["config_hash"] = d.State["previous_configuration"], d.State["previous_config_hash"]
		d.State["step"] = "rolled-back"
		return d.save()
	}
	if d.addingNode() {
		if common.S(d.State["target_node"]) != d.O.Node || d.O.CentralOnly {
			return errors.New("rollback_scope_must_match_original_run")
		}
		d.RunID = common.S(d.State["run_id"])
		j, err := NewJournal(filepath.Join(StateRoot, "runs", d.RunID, "central"))
		if err != nil {
			return err
		}
		d.Journal = j
		return d.rollbackAddition(ctx)
	}
	nodes := d.rollbackNodes()
	for i := len(nodes) - 1; i >= 0; i-- {
		if e := d.RollbackNode(ctx, nodes[i], uninstall); e != nil {
			return e
		}
	}
	if d.O.Node != "" {
		return d.save()
	}
	run := common.S(d.State["run_id"])
	if !strings.HasPrefix(run, "go-") {
		return errors.New("no_goframe_deployment_to_rollback")
	}
	j, e := NewJournal(filepath.Join(StateRoot, "runs", run, "central"))
	if e != nil {
		return e
	}
	if e = d.restoreCentral(ctx, j, uninstall); e != nil {
		return e
	}

	d.State["go_release"] = d.State["previous_go_release"]
	d.State["image_lock"] = d.State["previous_image_lock"]
	d.State["rolled_back"] = true
	d.State["step"] = "rolled-back"
	return d.save()
}

var _ = bytes.NewReader

// A failed central-only stage must not roll back untouched nodes to an older run.
func (d *Deploy) rollbackNodes() []common.Map {
	if d.O.CentralOnly {
		return nil
	}
	out := []common.Map{}
	for _, n := range d.C.Selected(d.O.Node) {
		state := common.M(common.M(d.State["nodes"])[common.S(n["id"])])
		if d.O.Node != "" || common.S(state["go_run_id"]) == common.S(d.State["run_id"]) {
			out = append(out, n)
		}
	}
	return out
}
