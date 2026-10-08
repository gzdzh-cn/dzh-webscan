package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/progress"
)

var Release = "development"

var StateRoot = "/var/lib/webscan-deploy"

type Options struct {
	Config, Node, YaraRules                                                                                                                     string
	DryRun, Check, Install, Reinstall, Upgrade, Resume, Rollback, Uninstall, CentralOnly, GrafanaOnly, SyncGrafana, ReloadRules, NonInteractive bool
	AddNode                                                                                                                                     bool
}
type Deploy struct {
	C                      *Config
	O                      Options
	State, Secrets, Images common.Map
	Docker                 *Docker
	Remotes                map[string]*Remote
	Journal                *Journal
	HTTP                   *http.Client
	RunID                  string
}

func stateFile() string { return filepath.Join(StateRoot, "state.json") }
func New(c *Config, o Options) (*Deploy, error) {
	state, e := common.ReadJSON(stateFile())
	if os.IsNotExist(e) {
		state = common.Map{"nodes": common.Map{}, "active": []string{}}
	} else if e != nil {
		return nil, e
	}
	secrets, e := common.ReadJSON(filepath.Join(StateRoot, "credentials.json"))
	if os.IsNotExist(e) {
		secrets = common.Map{"nodes": common.Map{}}
	} else if e != nil {
		return nil, e
	}
	h, e := common.HTTPClient("", 15*time.Second)
	if e != nil {
		return nil, e
	}
	images := common.Clone(common.M(state["image_lock"]))
	delete(images, "deployer")
	return &Deploy{C: c, O: o, State: state, Secrets: secrets, Images: images, Remotes: map[string]*Remote{}, HTTP: h}, nil
}
func (d *Deploy) save() error { return common.AtomicJSON(stateFile(), d.State) }
func (d *Deploy) Close() {
	for _, r := range d.Remotes {
		r.Close()
	}
	if d.Docker != nil {
		d.Docker.Close()
	}
}
func Run(ctx context.Context, o Options) error {
	if o.Config == "" {
		o.Config = "webscan.yaml"
	}
	c, e := Load(o.Config)
	if e != nil {
		return e
	}
	d, e := New(c, o)
	if e != nil {
		return e
	}
	defer d.Close()
	if pending := common.M(d.State["single_uninstall"]); len(pending) > 0 && !common.B(pending["complete"]) && !o.Uninstall && !o.DryRun && !o.Check {
		return errors.New("single_uninstall_pending_use_original_node")
	}
	actions := 0
	for _, b := range []bool{o.Check, o.Install, o.Reinstall, o.Upgrade && !o.Resume && !o.GrafanaOnly, o.AddNode && !o.Resume && !o.Rollback, o.Resume, o.Rollback, o.Uninstall, o.GrafanaOnly, o.SyncGrafana, o.ReloadRules} {
		if b {
			actions++
		}
	}
	if actions > 1 || o.Node != "" && o.CentralOnly || o.DryRun && (o.Check || o.Rollback || o.GrafanaOnly || o.SyncGrafana || o.ReloadRules) || o.YaraRules != "" && !o.ReloadRules || o.ReloadRules && o.CentralOnly || o.GrafanaOnly && (o.Node != "" || o.CentralOnly) || o.SyncGrafana && (o.Node != "" || o.CentralOnly) || o.Reinstall && (o.Node != "" || o.CentralOnly) {
		return errors.New("incompatible_cli_options")
	}
	if o.AddNode {
		if o.Node == "" || o.CentralOnly || o.Install || o.Upgrade || o.Uninstall || o.Reinstall || o.Check || o.ReloadRules || o.GrafanaOnly || o.SyncGrafana {
			return errors.New("incompatible_cli_options")
		}
		if e = d.useInstalledMain(); e != nil {
			return e
		}
		c = d.C
	}
	selectedNodes := c.Selected(o.Node)
	if o.Uninstall {
		selectedNodes = c.UninstallNodes(o.Node)
	}
	if o.Node != "" && len(selectedNodes) == 0 {
		if o.Uninstall {
			return errors.New("selected_node_not_configured")
		}
		return errors.New("selected_node_not_enabled")
	}
	if o.DryRun {
		images := common.Map{"central": c.Image("central"), "agent": c.Image("agent")}
		if o.AddNode {
			images["central"] = common.M(d.State["image_lock"])["central"]
		}
		order := []string{"central"}
		if o.Node != "" {
			order = nil
		}
		if !o.CentralOnly {
			for _, n := range selectedNodes {
				order = append(order, common.S(n["id"]))
			}
		}
		fmt.Println(string(common.JSON(common.Map{"configuration": Redact(c.Raw), "release": Release, "server_order": order, "action": actionName(o), "preserve_data": true, "images": images, "main_image_unchanged": o.AddNode, "changes": common.Hash(common.JSON(Redact(c.Raw))) != common.S(d.State["config_hash"])})))
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("execute_on_main_server_as_root")
	}
	info, e := os.Lstat(o.Config)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("actual_yaml_requires_0600_permissions")
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != 0 {
		return errors.New("actual_yaml_requires_root_ownership")
	}
	if e = os.MkdirAll(StateRoot, 0700); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(StateRoot, "deploy.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("deployment_already_running")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	reporter, e := progress.Open(c.Raw, "部署", filepath.Join(StateRoot, "logs"))
	if e != nil {
		return e
	}
	defer reporter.Close()
	ctx = progress.With(ctx, reporter)
	progress.Protect(ctx, d.Secrets)
	progress.Info(ctx, "版本："+Release+"；主服务器："+progress.Host(c.Raw))
	var selected []string
	for _, n := range selectedNodes {
		selected = append(selected, progress.Node(n))
	}
	if o.CentralOnly {
		progress.Info(ctx, "本次仅处理主服务器")
	} else {
		progress.Info(ctx, "启用的子服务器："+strings.Join(selected, "、"))
	}
	if o.ReloadRules {
		return d.ReloadRules(ctx)
	}
	if o.SyncGrafana {
		return d.SyncGrafana(ctx)
	}
	if o.GrafanaOnly {
		return d.UpdateGrafana(ctx)
	}
	if o.Uninstall {
		return d.Uninstall(ctx)
	}
	if o.Rollback {
		return d.Rollback(ctx, false)
	}
	d.showScope(ctx)
	if o.Reinstall {
		if e = progress.Stage(ctx, progress.Host(c.Raw), "重装前检查环境和节点连接", d.Preflight); e != nil {
			return e
		}
		if e = progress.Stage(ctx, progress.Host(c.Raw), "重装前准备镜像，避免卸载后无法下载", d.LockImages); e != nil {
			return e
		}
		if e = d.Uninstall(ctx); e != nil {
			return e
		}
		fresh, err := New(c, Options{Config: o.Config, NonInteractive: o.NonInteractive})
		if err != nil {
			return err
		}
		defer fresh.Close()
		d = fresh
		progress.Protect(ctx, d.Secrets)
		progress.Info(ctx, "卸载阶段完成，开始重新部署；数据库、队列和 Grafana 账号继续使用")
	}
	if o.Install {
		d.selectInstallMode()
	}
	if e = progress.Stage(ctx, progress.Host(c.Raw), "部署环境检查", d.Preflight); e != nil {
		return e
	}
	if o.Check {
		fmt.Println("环境检查通过；未修改运行配置。")
		return nil
	}
	return d.Deploy(ctx)
}
func (d *Deploy) Preflight(ctx context.Context) error {
	if _, e := RunCommand(ctx, nil, "docker", "info", "--format", "{{.Architecture}}"); e != nil {
		return e
	}
	if _, e := RunCommand(ctx, nil, "docker", "compose", "version"); e != nil {
		return errors.New("docker_compose_plugin_required")
	}
	if e := d.detectReuse(ctx); e != nil {
		return e
	}
	if !d.O.CentralOnly {
		for _, n := range d.C.Selected(d.O.Node) {
			if err := progress.Stage(ctx, progress.Node(n), "自动记录或校验 SSH 主机指纹，检查 Docker、Compose 和磁盘", func(ctx context.Context) error {
				r, e := Connect(ctx, n)
				if e != nil {
					return fmt.Errorf("node_%s_%w", common.S(n["id"]), e)
				}
				d.Remotes[common.S(n["id"])] = r
				if _, checkErr := r.Run(ctx, "docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1"); checkErr != nil {
					if d.O.Check {
						return errors.New("node_docker_or_compose_missing")
					}
					script, _ := assets.Files.ReadFile("install-docker.sh")
					if _, checkErr = r.Exec(ctx, "bash", strings.NewReader(string(script))); checkErr != nil {
						if _, dockerErr := r.Run(ctx, "docker info >/dev/null 2>&1"); dockerErr != nil {
							return errors.New("node_fresh_docker_installation_failed")
						}
						if checkErr = d.installComposeFallback(ctx, r); checkErr != nil {
							return checkErr
						}
					}
				}
				b, e := r.Run(ctx, "uname -m; docker info --format '{{.Architecture}}'; docker compose version --short; df -Pk /var/lib; test -x /bin/bash; command -v sync >/dev/null; command -v sha256sum >/dev/null")
				if e != nil {
					return fmt.Errorf("node_%s_environment_check_failed", common.S(n["id"]))
				}
				if !strings.Contains(string(b), "x86_64") {
					return errors.New("linux_amd64_nodes_required")
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	if !common.B(d.State["central_installed"]) {
		b, e := os.ReadFile("/proc/meminfo")
		if e != nil {
			return e
		}
		available := 0
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 1 && fields[0] == "MemAvailable:" {
				available, _ = strconv.Atoi(fields[1])
			}
		}
		center := common.M(d.C.Raw["central"])
		needed := common.I(center["new_components_memory_budget_mib"]) + 128
		if !common.B(common.M(center["reuse_existing"])["grafana"]) {
			needed += 192
		}
		if !common.B(common.M(center["reuse_existing"])["loki"]) {
			needed += 256
		}
		progress.Info(ctx, fmt.Sprintf("首次安装内存检查：当前可用 %d MiB，要求至少 %d MiB；新组件预算 %d MiB", available/1024, needed, common.I(center["new_components_memory_budget_mib"])))
		if available < needed*1024 {
			return &progress.Failure{Code: "insufficient_available_memory_for_fresh_install", Message: fmt.Sprintf("首次安装内存不足：当前可用 %d MiB，要求至少 %d MiB；请调整 central.new_components_memory_budget_mib 或释放内存", available/1024, needed)}
		}
	}
	return nil
}
func (d *Deploy) initialize() error {
	if d.canRetryAddition() {
		d.State["step"] = "rolled-back"
	}
	if common.S(d.State["go_release"]) == "" && common.B(d.State["central_installed"]) && !d.O.Upgrade && !d.O.Resume {
		return errors.New("first_goframe_migration_requires_upgrade")
	}
	hash := common.Hash(common.JSON(Redact(d.C.Raw)))
	run := common.S(d.State["run_id"])
	unfinished := strings.HasPrefix(run, "go-") && common.S(d.State["step"]) != "complete" && common.S(d.State["step"]) != "rolled-back"
	if unfinished {
		if !d.O.Resume {
			return errors.New("unfinished_deployment_requires_resume_or_rollback")
		}
		if common.S(d.State["target_release"]) != Release || common.S(d.State["target_config_hash"]) != hash {
			return errors.New("resume_target_must_match_original_run")
		}
		if _, ok := d.State["target_node"]; ok && (common.S(d.State["target_node"]) != d.O.Node || common.B(d.State["target_central_only"]) != d.O.CentralOnly || common.B(d.State["target_add_node"]) != d.O.AddNode) {
			return errors.New("resume_scope_must_match_original_run")
		}
		d.RunID = run
	} else {
		if d.O.Resume {
			return errors.New("no_unfinished_deployment_to_resume")
		}
		if common.S(d.State["go_release"]) != "" && (common.S(d.State["go_release"]) != Release || common.S(d.State["config_hash"]) != hash) && !d.O.Upgrade && !d.O.AddNode {
			return errors.New("changed_release_or_configuration_requires_upgrade")
		}
		d.RunID = "go-" + time.Now().UTC().Format("20060102T150405Z") + "-" + common.ID()[:8]
		if locked := os.Getenv("WEBSCAN_TOOL_IMAGE_LOCK"); locked != "" {
			d.State["target_tool_image"] = locked
		} else {
			delete(d.State, "target_tool_image")
		}
		delete(d.State, "node_addition")
		delete(d.State, "rollout")
		delete(d.State, "central_image_services")
		if d.canAddNode() {
			d.State["node_addition"] = common.Map{"previous_active": common.SS(d.State["active"]), "previous_configuration": common.Clone(common.M(d.State["configuration"])), "previous_config_hash": d.State["config_hash"]}
		}
		if d.O.AddNode && !d.addingNode() {
			return errors.New("add_node_requires_installed_compatible_main")
		}
		d.State["previous_image_lock"] = common.Clone(common.M(d.State["image_lock"]))
		d.State["previous_configuration"] = common.Clone(common.M(d.State["configuration"]))
		d.State["previous_config_hash"] = d.State["config_hash"]
		d.State["previous_central_runtime_release"] = d.State["central_runtime_release"]
		d.State["previous_go_release"], d.State["run_id"] = d.State["go_release"], d.RunID
		delete(d.State, "target_images")
		d.State["target_release"], d.State["target_config_hash"], d.State["step"] = Release, hash, "preparing"
		d.State["target_node"], d.State["target_central_only"] = d.O.Node, d.O.CentralOnly
		d.State["target_add_node"] = d.O.AddNode
	}

	j, e := NewJournal(filepath.Join(StateRoot, "runs", d.RunID, "central"))
	if e != nil {
		return e
	}
	d.Journal = j
	g := common.M(common.M(d.C.Raw["central"])["grafana"])
	for _, key := range []string{"admin_password", "viewer_password"} {
		if common.S(d.Secrets[key]) == "" {
			v := common.S(g[key])
			if v == "" {
				v = common.ID() + common.ID()[:8]
			}
			d.Secrets[key] = v
		}
	}
	if common.S(d.Secrets["admin_username"]) == "" {
		d.Secrets["admin_username"] = g["admin_username"]
	}
	if common.S(d.Secrets["alert_token"]) == "" {
		d.Secrets["alert_token"] = common.ID() + common.ID()
	}
	nodes := common.M(d.Secrets["nodes"])
	for _, n := range d.C.Nodes {
		id := common.S(n["id"])
		if common.S(common.M(nodes[id])["token"]) == "" {
			nodes[id] = common.Map{"token": common.ID() + common.ID()}
		}
	}
	d.Secrets["nodes"] = nodes
	if e = common.AtomicJSON(filepath.Join(StateRoot, "credentials.json"), d.Secrets); e != nil {
		return e
	}
	return d.save()
}
func (d *Deploy) LockImages(ctx context.Context) error {
	docker, e := NewDocker(ctx, d.C, false)
	if e != nil {
		return e
	}
	d.Docker = docker
	if d.O.Resume && len(common.M(d.State["target_images"])) > 0 {
		d.Images = common.Clone(common.M(d.State["target_images"]))
		delete(d.Images, "deployer")
		for role, value := range d.Images {
			if d.addingNode() && !common.Contains([]string{"agent", "vector", "exporter"}, role) {
				continue
			}
			ref := common.S(value)
			if _, err := docker.Exec(ctx, nil, "image", "inspect", ref); err != nil {
				if _, err = docker.Pull(ctx, ref); err != nil {
					return errors.New("resume_locked_image_unavailable")
				}
			}
		}
		d.State["image_lock"] = common.Clone(d.Images)
		return d.save()
	}
	delete(d.Images, "deployer")
	roles := []string{"central", "agent"}
	if d.addingNode() {
		roles = []string{"agent"}
		progress.Info(ctx, "新增节点：沿用主服务器已锁定镜像，仅准备节点镜像；部署工具已从主服务器镜像提取")
	}
	for _, role := range roles {
		progress.Info(ctx, "拉取并锁定自研镜像："+progress.Role(role))
		var ref string
		e := progress.Stage(ctx, progress.Host(d.C.Raw), "下载并校验 "+progress.Role(role), func(ctx context.Context) error {
			var err error
			ref, err = docker.Pull(ctx, d.C.Image(role))
			return err
		})
		if e != nil {
			return fmt.Errorf("image_pull_failed_%s", role)
		}
		d.Images[role] = ref
	}
	for _, role := range []string{"prometheus", "alertmanager", "exporter", "loki", "grafana", "vector"} {
		if d.addingNode() && role != "vector" && role != "exporter" {
			continue
		}
		tag := VendorImages[role]
		if role == "grafana" || role == "loki" {
			if common.B(common.M(common.M(d.C.Raw["central"])["reuse_existing"])[role]) {
				continue
			}
		}
		locked := common.S(d.Images[role])
		refresh := common.B(common.M(d.C.Raw["deployment"])["upgrade_existing_components"])
		if locked != "" && !refresh {
			if _, e = docker.Exec(ctx, nil, "image", "inspect", locked); e == nil {
				continue
			}
			tag = locked
		}
		var ref string
		e := progress.Stage(ctx, progress.Host(d.C.Raw), "下载并校验 "+progress.Role(role), func(ctx context.Context) error { var err error; ref, err = docker.Pull(ctx, tag); return err })
		if e != nil {
			return fmt.Errorf("vendor_image_pull_failed_%s", role)
		}
		d.Images[role] = ref
	}
	d.State["image_lock"], d.State["target_images"] = d.Images, common.Clone(d.Images)
	return d.save()
}
func (d *Deploy) Deploy(ctx context.Context) (err error) {
	if d.O.Resume && common.S(d.State["step"]) == "notifying" {
		if err = d.initialize(); err != nil {
			return err
		}
		progress.Protect(ctx, d.Secrets)
		progress.Info(ctx, "继续部署通知阶段：核对现有服务，复用已保存的飞书队列和 PHP 测试记录")
		if err = d.waitReady(ctx); err != nil {
			return err
		}
		if !d.O.CentralOnly {
			for _, n := range d.C.Selected(d.O.Node) {
				if err = d.WaitHealth(ctx, n); err != nil {
					return err
				}
			}
		}
		return d.finishDeployment(ctx)
	}
	if !d.O.AddNode && !d.O.Upgrade && !d.O.Resume && common.S(d.State["go_release"]) == Release && common.S(d.State["step"]) == "complete" && common.S(d.State["config_hash"]) == common.Hash(common.JSON(Redact(d.C.Raw))) {
		if err = d.waitReady(ctx); err != nil {
			return err
		}
		for _, n := range d.C.Selected(d.O.Node) {
			if err = d.WaitHealth(ctx, n); err != nil {
				return err
			}
		}
		progress.Info(ctx, "目标版本已经部署，健康检查通过；容器保持运行。")
		return nil
	}
	if d.canRetryAddition() {
		progress.Info(ctx, "上次新增节点已确认回退；本次创建新的部署记录，保留原备份、数据库和队列")
	}
	if err = progress.Stage(ctx, progress.Host(d.C.Raw), "准备部署状态、凭据和回退记录", func(context.Context) error { return d.initialize() }); err != nil {
		return err
	}
	progress.Protect(ctx, d.Secrets)
	imageStage := "准备全部组件镜像"
	if d.addingNode() {
		imageStage = "准备新增节点所需镜像（沿用主服务器组件）"
	}
	if err = progress.Stage(ctx, progress.Host(d.C.Raw), imageStage, d.LockImages); err != nil {
		return err
	}
	if err = progress.Stage(ctx, progress.Host(d.C.Raw), "准备主服务器和节点 HTTPS 证书", func(context.Context) error {
		if err := d.restoreRetainedPKI(); err != nil {
			return err
		}
		return certificates(d.C)
	}); err != nil {
		return err
	}
	if !d.O.CentralOnly {
		for _, n := range d.C.Selected(d.O.Node) {
			id := common.S(n["id"])
			if err = progress.Stage(ctx, progress.Node(n), "下载节点镜像并准备部署工具", func(ctx context.Context) error { return d.PrepareNode(ctx, n) }); err != nil {
				return err
			}
			progress.Info(ctx, id+" 镜像和部署工具已准备")
		}
	}
	if d.addingNode() {
		if err = d.deployAddition(ctx); err != nil {
			return err
		}
		return d.finishDeployment(ctx)
	}
	// Every switching flow needs an initialized journal, locked images, valid
	// certificates and the extracted node tool. Additions take precedence over
	// the combined rollout so they retain the running main server version.
	if d.canStageRollout() {
		if err = d.deployRollout(ctx); err != nil {
			return err
		}
		return d.finishDeployment(ctx)
	}
	if err = progress.Stage(ctx, progress.Host(d.C.Raw), "安装主服务器组件并验收", d.Central); err != nil {
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 180*time.Second)
		defer cancel()
		if rollbackErr := progress.Stage(recovery, progress.Host(d.C.Raw), "恢复主服务器旧版本", func(ctx context.Context) error { return d.restoreCentral(ctx, d.Journal, false) }); rollbackErr != nil {
			return errors.New("central_failure_rollback_not_confirmed")
		}

		d.State["last_failure"] = common.Map{"stage": "central", "time": common.Now()}
		d.save()
		return err
	}
	if !d.O.CentralOnly {
		for _, n := range d.C.Selected(d.O.Node) {
			id := common.S(n["id"])
			nodeState := common.M(common.M(d.State["nodes"])[id])
			if common.S(nodeState["go_release"]) == Release && common.S(nodeState["phase"]) == "complete" && !d.O.Upgrade {
				progress.Info(ctx, id+" 已是目标 Go 版本，核对健康状态")
				if err = d.WaitHealth(ctx, n); err != nil {
					return err
				}
				continue
			}
			err = progress.Stage(ctx, progress.Node(n), "安装节点监控及采集组件", func(ctx context.Context) error { return d.InstallNode(ctx, n) })
			if err == nil {
				err = progress.Stage(ctx, progress.Node(n), "测试文件检测、扫描和飞书/Loki 投递", func(ctx context.Context) error { return d.AcceptNode(ctx, n) })
			}
			if err == nil {
				err = progress.Stage(ctx, progress.Node(n), "核对全部健康指标与待投递队列", func(ctx context.Context) error { return d.WaitHealth(ctx, n) })
			}
			if err != nil {
				progress.Warn(ctx, id+" 验收失败，恢复此节点旧服务并停止后续节点")
				rollback := progress.Stage(ctx, progress.Node(n), "恢复此节点旧服务", func(ctx context.Context) error { return d.RollbackNode(ctx, n, false) })
				d.State["last_failure"] = common.Map{"stage": id, "time": common.Now(), "rollback_confirmed": rollback == nil}
				d.save()
				return err
			}
			nodeState = common.M(common.M(d.State["nodes"])[id])
			nodeState["phase"], nodeState["go_release"] = "complete", Release
			common.M(d.State["nodes"])[id] = nodeState
			if err = d.save(); err != nil {
				return err
			}
			progress.Info(ctx, id+" Go 容器部署、检测、投递和健康验收通过")
		}
	}
	d.State["step"] = "notifying"
	if err = d.save(); err != nil {
		return err
	}
	return d.finishDeployment(ctx)
}

func (d *Deploy) finishDeployment(ctx context.Context) (err error) {
	if err = d.DeploymentNotifications(ctx); err != nil {
		progress.Warn(ctx, "部署通知或 PHP 测试尚未确认成功；监控容器保持运行，使用原参数加 --resume 继续")
		return err
	}
	if !d.addingNode() {
		if err = d.retirePython(ctx); err != nil {
			return err
		}
	}
	if err = progress.Stage(ctx, progress.Host(d.C.Raw), "验证并显示 Grafana 登录信息", d.ShowGrafana); err != nil {
		return err
	}
	d.State["step"], d.State["go_release"], d.State["configuration"], d.State["config_hash"] = "complete", Release, Redact(d.C.Raw), common.Hash(common.JSON(Redact(d.C.Raw)))
	d.State["completed_at"] = common.Now()
	delete(d.State, "last_failure")
	if err = d.save(); err != nil {
		return err
	}
	progress.Info(ctx, "GoFrame 部署完成；启用节点已通过文件检测、投递和健康验收")
	return nil
}
func (d *Deploy) compose(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "up" {
		if err := EnsureComposeImages(ctx, filepath.Join(d.C.CentralRoot(), "compose.yml")); err != nil {
			return nil, err
		}
		args = append([]string{"up", "--pull", "never"}, args[1:]...)
	}
	return RunCommand(ctx, nil, append([]string{"docker", "compose", "-f", filepath.Join(d.C.CentralRoot(), "compose.yml")}, args...)...)
}
func (d *Deploy) Central(ctx context.Context) error {
	root := d.C.CentralRoot()
	center := common.M(d.C.Raw["central"])
	if d.rolloutMainApplied(ctx) {
		progress.Info(ctx, "主服务器配置和容器已在上次中断前更新；继续就绪检查，不重复重建")
		if e := d.waitReady(ctx); e != nil {
			return e
		}
		if e := d.ConfigureGrafana(ctx); e != nil {
			return e
		}
		d.State["active"], d.State["central_installed"], d.State["central_runtime_release"], d.State["step"] = d.plannedActive(), true, Release, "central-go-ready"
		common.M(d.State["rollout"])["main_ready"] = true
		return d.save()
	}
	existing, e := os.ReadFile(filepath.Join(root, "compose.yml"))
	fresh := os.IsNotExist(e)
	if e != nil && !fresh {
		return e
	}
	active := d.plannedActive()
	if fresh && len(common.M(d.State["rollout"])) == 0 && !common.B(d.State["central_uninstalled"]) && !common.B(d.State["central_uninstall_pending"]) {
		active = []string{}
	}
	runtime := d.centralRuntime(active)
	if url := common.S(d.State["external_loki_url"]); url != "" {
		runtime["loki_url"] = url
	}
	if common.S(common.M(d.C.Raw["feishu"])["mode"]) == "existing_env" || common.S(common.M(d.C.Raw["feishu"])["mode"]) == "existing" {
		f, err := resolvedFeishu(common.M(d.C.Raw["feishu"]))
		if err != nil {
			return err
		}
		runtime["feishu"] = f
	}
	files := map[string][]byte{"runtime.json": common.JSON(runtime), "alert-token": []byte(common.S(d.Secrets["alert_token"]))}
	var compose common.Map
	promChanged := false
	if fresh {
		compose = ComposeCentral(d.C, d.Images)
		if network := common.S(d.State["external_network"]); network != "" {
			compose["networks"] = common.Map{"monitor": common.Map{"name": network, "external": true}}
		}
		files["prometheus.yml"] = YAML(Prometheus(d.C, active))
		files["rules.yml"] = YAML(AlertRules(d.C))
		files["alertmanager.yml"] = YAML(Alertmanager(d.C))
		files["grafana.ini"] = GrafanaINI(d.C)
		files["grafana.env"] = []byte("GF_SECURITY_ADMIN_USER=" + common.S(d.Secrets["admin_username"]) + "\nGF_SECURITY_ADMIN_PASSWORD__FILE=/etc/grafana/admin-password\n")
		files["grafana-admin-password"] = []byte(common.S(d.Secrets["admin_password"]))
		files["loki.yml"] = YAML(LokiConfig(d.C))
		for _, key := range []string{"install_dir", "data_dir", "log_dir", "backup_dir"} {
			if e = os.MkdirAll(common.S(center[key]), 0700); e != nil {
				return e
			}
		}
	} else {
		if e = yaml.Unmarshal(existing, &compose); e != nil {
			return e
		}
		services := common.M(compose["services"])
		old := common.M(services["receiver"])
		newService := ReceiverService(d.C, common.S(d.Images["central"]))
		if v, ok := old["networks"]; ok {
			newService["networks"] = v
		}
		services["receiver"] = newService
		compose["services"] = services
		if len(common.M(d.State["rollout"])) > 0 {
			b, err := os.ReadFile(filepath.Join(root, "prometheus.yml"))
			if err != nil {
				return err
			}
			var prom common.Map
			if err = yaml.Unmarshal(b, &prom); err != nil {
				return err
			}
			ids := []string{}
			for _, n := range d.C.Selected(d.O.Node) {
				ids = append(ids, common.S(n["id"]))
			}
			before := common.JSON(prom)
			mergeScrapeNodes(prom, Prometheus(d.C, active), ids)
			promChanged = !bytes.Equal(before, common.JSON(prom))
			if promChanged {
				files["prometheus.yml"] = YAML(prom)
			}
		}
		if (d.O.Upgrade || d.O.Resume) && !d.addingNode() {
			changed := common.SS(d.State["central_image_services"])
			for _, name := range updateVendorImageAliases(d.C, services, d.Images, common.B(common.M(d.C.Raw["deployment"])["upgrade_existing_components"])) {
				if !common.Contains(changed, name) {
					changed = append(changed, name)
				}
			}
			d.State["central_image_services"] = changed
			if rollout := common.M(d.State["rollout"]); len(rollout) > 0 {
				for _, name := range changed {
					if _, exists := rollout[name+"_before"]; !exists {
						identity, _ := d.serviceIdentity(ctx, name)
						rollout[name+"_before"] = identity
					}
				}
			}
			if e = d.save(); e != nil {
				return e
			}
		}
	}
	for _, name := range []string{"central.py", "common.py"} {
		if e = d.Journal.Remember(filepath.Join(root, "src", name)); e != nil {
			return e
		}
	}
	if e = d.Journal.Remember(filepath.Join(root, "compose.yml")); e != nil {
		return e
	}
	if !fresh {
		dbPath := filepath.Join(common.S(center["data_dir"]), "events-v1.sqlite3")
		db, e := persist.OpenDB(dbPath)
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
	files["compose.yml"] = YAML(compose)
	if rollout := common.M(d.State["rollout"]); len(rollout) > 0 {
		hashes := common.Map{}
		for name, b := range files {
			hashes[name] = common.Hash(b)
		}
		rollout["main_config_hashes"], rollout["prom_changed"] = hashes, promChanged
		if e = d.save(); e != nil {
			return e
		}
	}
	if !fresh {
		if _, e = d.compose(ctx, "stop", "receiver"); e != nil {
			return e
		}
	}
	for name, b := range files {
		if e = d.Journal.Write(filepath.Join(root, name), b, 0600); e != nil {
			return e
		}
	}
	if fresh {
		if e = d.ProvisionGrafana(); e != nil {
			return e
		}
	}
	if _, e = d.compose(ctx, "config", "--quiet"); e != nil {
		return e
	}
	if fresh || d.O.Install {
		if _, e = d.compose(ctx, "up", "-d"); e != nil {
			return e
		}
	} else {
		args := []string{"up", "-d", "--no-deps", "receiver"}
		if promChanged {
			args = []string{"up", "-d", "--no-deps", "--force-recreate", "receiver", "prometheus"}
		}
		for _, name := range common.SS(d.State["central_image_services"]) {
			if !common.Contains(args, name) {
				args = append(args, name)
			}
		}
		if _, e = d.compose(ctx, args...); e != nil {
			return e
		}
	}
	if e = progress.Stage(ctx, progress.Host(d.C.Raw), "等待主服务器接收服务就绪", d.waitReady); e != nil {
		return e
	}
	if e = progress.Stage(ctx, progress.Host(d.C.Raw), "配置 Grafana 账号、数据源和看板", d.ConfigureGrafana); e != nil {
		return e
	}
	// Verify the new receiver while every remaining legacy collector still runs.
	if !d.O.CentralOnly && len(common.M(d.State["rollout"])) == 0 {
		for _, n := range d.C.Selected(d.O.Node) {
			state := common.M(common.M(d.State["nodes"])[common.S(n["id"])])
			if common.S(state["go_release"]) == Release && common.S(state["phase"]) == "complete" {
				continue
			}
			r, err := d.remote(ctx, n)
			if err != nil {
				return err
			}
			present, err := existingCollector(ctx, r)
			if err != nil {
				return err
			}
			if !present {
				progress.Info(ctx, progress.Node(n)+" 采集器尚未运行，文件与投递验收将在节点安装后执行")
				continue
			}
			if err := progress.Stage(ctx, progress.Node(n), "验证主服务器接收现有采集器事件", func(ctx context.Context) error { return d.AcceptNode(ctx, n) }); err != nil {
				return err
			}
			state["central_legacy_verified"] = common.Map{"release": Release, "time": common.Now()}
		}
	}
	d.State["central_installed"], d.State["step"] = true, "central-go-ready"
	d.State["central_runtime_release"] = Release
	if rollout := common.M(d.State["rollout"]); len(rollout) > 0 {
		rollout["main_ready"] = true
		d.State["active"] = active
	}
	delete(d.State, "central_uninstalled")
	delete(d.State, "central_uninstall_pending")
	return d.save()
}
func (d *Deploy) waitReady(ctx context.Context) error {
	port := common.I(common.M(common.M(d.C.Raw["central"])["event_service"])["port"])
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		_, v, e := common.Request(ctx, d.HTTP, "GET", fmt.Sprintf("http://127.0.0.1:%d/ready", port), nil, nil)
		if e == nil && common.B(common.M(v)["ready"]) {
			if d.O.AddNode && common.I(common.M(v)["event_protocol"]) > 1 {
				return errors.New("add_node_requires_installed_compatible_main")
			}
			return nil
		}
		if !common.Sleep(ctx, 2*time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("central_ready_timeout")
}
func LokiConfig(c *Config) common.Map {
	return common.Map{"auth_enabled": false, "server": common.Map{"http_listen_address": "0.0.0.0", "http_listen_port": 3100}, "common": common.Map{"path_prefix": "/loki", "replication_factor": 1, "ring": common.Map{"kvstore": common.Map{"store": "inmemory"}}, "storage": common.Map{"filesystem": common.Map{"chunks_directory": "/loki/chunks", "rules_directory": "/loki/rules"}}}, "schema_config": common.Map{"configs": []any{common.Map{"from": "2024-01-01", "store": "tsdb", "object_store": "filesystem", "schema": "v13", "index": common.Map{"prefix": "index_", "period": "24h"}}}}, "compactor": common.Map{"working_directory": "/loki/compactor", "retention_enabled": true, "delete_request_store": "filesystem"}, "limits_config": common.Map{"retention_period": fmt.Sprint(common.I(common.M(c.Raw["retention"])["loki_days"])*24) + "h"}}
}
func (d *Deploy) ProvisionGrafana() error {
	root := d.C.CentralRoot()
	data := common.Map{"apiVersion": 1, "datasources": []any{common.Map{"name": "Webscan Prometheus", "uid": "webscan-prom", "type": "prometheus", "access": "proxy", "url": "http://webscan-v1-prometheus:19190", "editable": false}, common.Map{"name": "Webscan Loki", "uid": "webscan-loki", "type": "loki", "access": "proxy", "url": func() string {
		if u := common.S(d.State["external_loki_url"]); u != "" {
			return u
		}
		return "http://loki:3100"
	}(), "editable": false}}}
	files := map[string][]byte{"datasources/webscan.yml": YAML(data), "dashboards/webscan.yml": YAML(common.Map{"apiVersion": 1, "providers": []any{common.Map{"name": "webscan", "type": "file", "options": common.Map{"path": "/etc/grafana/provisioning/webscan-dashboards"}, "allowUiUpdates": false, "disableDeletion": true}}})}
	entries, _ := assets.Files.ReadDir(".")
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "dashboard-") {
			continue
		}
		b, e := assets.Files.ReadFile(entry.Name())
		if e != nil {
			return e
		}
		v, e := common.Decode(b)
		if e != nil {
			return e
		}
		dashboard := common.M(v)
		dashboard["timezone"] = common.M(common.M(d.C.Raw["central"])["grafana"])["timezone"]
		files["webscan-dashboards/"+strings.TrimPrefix(entry.Name(), "dashboard-")] = common.JSON(dashboard)
	}
	for name, b := range files {
		provision := filepath.Join(root, "provisioning")
		if p := common.S(d.State["grafana_provision"]); p != "" {
			provision = p
		}
		path := filepath.Join(provision, name)
		if e := d.Journal.Write(path, b, 0644); e != nil {
			return e
		}
		if e := os.Chmod(filepath.Dir(path), 0755); e != nil {
			return e
		}
	}
	provision := filepath.Join(root, "provisioning")
	if p := common.S(d.State["grafana_provision"]); p != "" {
		provision = p
	}
	return os.Chmod(provision, 0755)
}

var _ = sort.Strings

// Fresh nodes have no collector to produce compatibility test events yet.
func existingCollector(ctx context.Context, r *Remote) (bool, error) {
	b, err := r.Run(ctx, "if systemctl is-active --quiet webscan-agent-v1.service 2>/dev/null || [ \"$(docker inspect --format '{{.State.Running}}' webscan-agent-go 2>/dev/null)\" = true ]; then printf installed; else printf fresh; fi")
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(b)) {
	case "installed":
		return true, nil
	case "fresh":
		return false, nil
	default:
		return false, errors.New("node_existing_collector_check_failed")
	}
}
