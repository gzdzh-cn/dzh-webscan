package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	"webscan/internal/progress"
)

// An addition never consumes or clears the agent database, JSONL or Vector buffer.
// Disabling the unit removes both boot and Docker Wants links, so a reboot during
// preparation cannot start the HTTP sink with a token the receiver doesn't know.
const holdVectorCommand = "set -eu; if systemctl cat webscan-vector-v1.service >/dev/null 2>&1; then systemctl disable --now webscan-vector-v1; fi; if docker inspect webscan-vector-v1 >/dev/null 2>&1; then docker stop -t 30 webscan-vector-v1 >/dev/null; fi"
const startVectorCommand = "set -eu; systemctl enable webscan-vector-v1; systemctl start webscan-vector-v1"

func (d *Deploy) addingNode() bool { return len(common.M(d.State["node_addition"])) > 0 }

// A confirmed automatic rollback can begin a new attempt with a fixed package.
// Other unfinished runs still require their original resume/rollback operation.
func (d *Deploy) canRetryAddition() bool {
	failure := common.M(d.State["last_failure"])
	s := common.M(d.State["node_addition"])
	if !d.O.AddNode || d.O.Resume || d.O.Node == "" || d.O.Node != common.S(d.State["target_node"]) || !common.B(d.State["target_add_node"]) || common.S(d.State["step"]) != "addition-rolled-back" || common.S(failure["stage"]) != "node-addition" || !common.B(failure["rollback_confirmed"]) {
		return false
	}
	for _, key := range []string{"local_ready", "registration_started", "files_written", "registered", "transport_ready", "accepted"} {
		if common.B(s[key]) {
			return false
		}
	}
	n := common.M(common.M(d.State["nodes"])[d.O.Node])
	if common.S(n["phase"]) == "uninstalled" {
		u := common.M(d.State["single_uninstall"])
		if common.S(u["node"]) != d.O.Node || !common.B(u["complete"]) || !common.B(u["node_removed"]) || (common.B(u["central_present"]) && !common.B(u["central_updated"])) || common.Contains(common.SS(d.State["active"]), d.O.Node) {
			return false
		}
	} else if common.S(n["go_run_id"]) == common.S(d.State["run_id"]) && common.S(n["phase"]) != "go-rolled-back" {
		return false
	}
	return len(s) > 0 && common.S(d.State["go_release"]) == common.S(d.State["previous_go_release"]) && common.S(d.State["config_hash"]) == common.S(s["previous_config_hash"]) && string(common.JSON(common.SS(d.State["active"]))) == string(common.JSON(common.SS(s["previous_active"]))) && string(common.JSON(d.State["image_lock"])) == string(common.JSON(d.State["previous_image_lock"]))
}

// Only an explicitly selected, inactive node can take this conservative path.
// Main configuration, old nodes and the receiver's immutable image must match.
// Agent and extracted deployment tools may advance independently of the running receiver.
func (d *Deploy) canAddNode() bool {
	if d.O.Node == "" || d.O.CentralOnly || d.O.Reinstall || !common.Contains([]string{"complete", "rolled-back"}, common.S(d.State["step"])) || !common.B(d.State["central_installed"]) || common.S(d.State["go_release"]) == "" || (!d.O.AddNode && common.Contains(common.SS(d.State["active"]), d.O.Node)) {
		return false
	}
	previous := common.M(d.State["configuration"])
	if len(previous) == 0 || len(d.C.Selected(d.O.Node)) != 1 {
		return false
	}
	normalize := func(raw common.Map) []byte {
		m := common.Clone(common.M(Redact(raw)))
		nodes := []any{}
		for _, v := range common.A(m["nodes"]) {
			if common.S(common.M(v)["id"]) != d.O.Node {
				nodes = append(nodes, v)
			}
		}
		m["nodes"] = nodes
		dep := common.M(m["deployment"])
		order := []string{}
		for _, id := range common.SS(dep["node_order"]) {
			if id != d.O.Node {
				order = append(order, id)
			}
		}
		dep["node_order"] = order
		delete(common.M(m["images"]), "agent")
		delete(common.M(m["images"]), "deployer")
		return common.JSON(m)
	}
	if (!d.O.AddNode && !bytes.Equal(normalize(previous), normalize(d.C.Raw))) || common.B(common.M(d.C.Raw["deployment"])["upgrade_existing_components"]) {
		return false
	}
	root := d.C.CentralRoot()
	composeBytes, err := os.ReadFile(filepath.Join(root, "compose.yml"))
	if err != nil {
		return false
	}
	var compose common.Map
	if yaml.Unmarshal(composeBytes, &compose) != nil {
		return false
	}
	image := common.S(common.M(common.M(compose["services"])["receiver"])["image"])
	if image == "" || image != common.S(common.M(d.State["image_lock"])["central"]) {
		return false
	}
	// Compare real runtime too: the saved configuration deliberately omits secrets.
	// This also catches an edited webhook/token that needs the regular main update.
	actual, err := common.ReadJSON(filepath.Join(root, "runtime.json"))
	if err != nil {
		return false
	}
	expected := d.centralRuntime(common.SS(d.State["active"]))
	if f, err := resolvedFeishu(common.M(d.C.Raw["feishu"])); err == nil {
		expected["feishu"] = f
	} else {
		return false
	}
	normalizeRuntime := func(raw common.Map) []byte {
		m := common.Clone(raw)
		delete(common.M(m["nodes"]), d.O.Node)
		sources := []string{}
		host := common.S(d.C.Selected(d.O.Node)[0]["host"]) + "/32"
		for _, source := range common.SS(common.M(m["https"])["allowed_sources"]) {
			if source != host {
				sources = append(sources, source)
			}
		}
		common.M(m["https"])["allowed_sources"] = sources
		return common.JSON(m)
	}
	if !d.O.AddNode && !bytes.Equal(normalizeRuntime(actual), normalizeRuntime(expected)) {
		return false
	}
	_, err = os.Stat(filepath.Join(root, "pki", "ca.key"))
	return err == nil
}

// Each operation must be idempotent across a crash before its checkpoint. The
// registration operation additionally records service identities before restart.
type additionStep struct {
	key, host, label string
	run              func(context.Context) error
}

func (d *Deploy) additionSteps(ctx context.Context, steps []additionStep) error {
	state := common.M(d.State["node_addition"])
	for _, step := range steps {
		if common.B(state[step.key]) {
			progress.Info(ctx, step.label+" 已完成，继续下一阶段")
			continue
		}
		if err := progress.Stage(ctx, step.host, step.label, step.run); err != nil {
			return err
		}
		state[step.key] = true
		if err := d.save(); err != nil {
			return err
		}
	}
	return nil
}

func (d *Deploy) deployAddition(ctx context.Context) (err error) {
	n := d.C.Selected(d.O.Node)[0]
	progress.Info(ctx, "新增节点流程：节点安装与清单 → 主服务器登记与采集配置 → 启用传输 → 文件和消息验收；沿用主服务器镜像与 Grafana")
	if err = d.waitReady(ctx); err != nil {
		return err
	}
	defer func() {
		if err == nil {
			return
		}
		progress.Warn(ctx, "新增节点失败，恢复本次节点服务和主服务器登记；保留数据库、事件及队列")
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 180*time.Second)
		defer cancel()
		rollbackErr := d.rollbackAddition(recovery)
		d.State["last_failure"] = common.Map{"stage": "node-addition", "time": common.Now(), "rollback_confirmed": rollbackErr == nil}
		if rollbackErr != nil {
			_ = d.save()
			err = fmt.Errorf("node_addition_rollback_not_confirmed: %w", err)
			return
		}
		// Retain the same target and backup for --resume after an automatic rollback.
		d.State["step"] = "addition-rolled-back"
		if saveErr := d.save(); saveErr != nil {
			err = fmt.Errorf("node_addition_state_save_failed: %w", err)
		}
	}()
	err = d.additionSteps(ctx, []additionStep{
		{"local_ready", progress.Node(n), "安装新节点并建立本地文件清单（暂缓传输）", func(ctx context.Context) error {
			if err := d.InstallNode(ctx, n); err != nil {
				return err
			}
			return d.waitStagedNode(ctx, n)
		}},
		{"registered", progress.Host(d.C.Raw), "一次更新主服务器节点登记与 Prometheus 采集配置", d.registerAddition},
		{"transport_ready", progress.Node(n), "启用 Vector 传输并确认采集组件正常", func(ctx context.Context) error {
			if e := d.waitStagedNode(ctx, n); e != nil {
				return e
			}
			r, e := d.remote(ctx, n)
			if e != nil {
				return e
			}
			if _, e = r.ExecVisible(ctx, startVectorCommand, nil, "服务状态"); e != nil {
				return e
			}
			return d.WaitNodeSidecars(ctx, n)
		}},
		{"accepted", progress.Node(n), "测试文件检测、扫描和飞书/Loki 投递", func(ctx context.Context) error { return d.AcceptNode(ctx, n) }},
	})
	if err != nil {
		return err
	}
	// Always recheck current health, even when resuming after acceptance.
	if err = progress.Stage(ctx, progress.Node(n), "核对全部健康指标与待投递队列", func(ctx context.Context) error { return d.WaitHealth(ctx, n) }); err != nil {
		return err
	}
	state := common.M(common.M(d.State["nodes"])[d.O.Node])
	state["phase"], state["go_release"] = "complete", Release
	d.State["step"] = "notifying"
	if err = d.save(); err != nil {
		return err
	}
	// Notification failures leave healthy monitoring in place, as in a full deploy.
	// The recovery defer above only covers installation and acceptance.
	err = nil
	return nil
}

// Local readiness deliberately ignores Vector and central probe delivery while
// the transport is held. The mTLS scrape also proves the exporter is reachable.
func stagedNodeHealthy(m map[string]float64) bool {
	return m["webscan_collector_ready"] == 1 && m["webscan_baseline_completed"] == 1 && m["webscan_coverage_ok"] == 1 && common.Now()-m["webscan_agent_heartbeat_seconds"] < 90
}

func (d *Deploy) waitStagedNode(ctx context.Context, n common.Map) error {
	if err := d.WaitNodeReady(ctx, n); err != nil {
		return err
	}
	deadline := time.Now().Add(45 * time.Second)
	notice := time.Now().Add(-10 * time.Second)
	for time.Now().Before(deadline) {
		m, err := d.metrics(ctx, n)
		if err == nil && stagedNodeHealthy(m) {
			return nil
		}
		if time.Since(notice) >= 10*time.Second {
			if err != nil {
				progress.Info(ctx, "文件清单已完成，等待主服务器通过 HTTPS 读取节点指标："+progress.Explain(err))
			} else {
				progress.Info(ctx, "文件清单已完成，等待指标采集器发布最新监控状态")
			}
			notice = time.Now()
		}
		if !common.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("node_staged_exporter_not_ready")
}

func (d *Deploy) serviceIdentity(ctx context.Context, service string) (string, error) {
	b, err := d.compose(ctx, "ps", "-q", service)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" || strings.ContainsAny(id, " \n\r\t") {
		return "", errors.New("addition_main_service_missing")
	}
	b, err = RunCommand(ctx, nil, "docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}} {{.State.Running}}", id)
	if err != nil {
		return "", err
	}
	identity := strings.TrimSpace(string(b))
	if !strings.HasSuffix(identity, " true") {
		return "", errors.New("addition_main_service_not_running")
	}
	return identity, nil
}

func (d *Deploy) registerAddition(ctx context.Context) error {
	s := common.M(d.State["node_addition"])
	root := d.C.CentralRoot()
	active := common.SS(s["previous_active"])
	if !common.Contains(active, d.O.Node) {
		active = append(active, d.O.Node)
	}
	if !common.B(s["registration_started"]) {
		for _, name := range []string{"runtime.json", "prometheus.yml"} {
			if err := d.Journal.Remember(filepath.Join(root, name)); err != nil {
				return err
			}
		}
		for _, service := range []string{"receiver", "prometheus"} {
			id, err := d.serviceIdentity(ctx, service)
			if err != nil {
				return err
			}
			s[service+"_before"] = id
		}
		s["registration_started"] = true
		if err := d.save(); err != nil {
			return err
		}
	}
	if !common.B(s["files_written"]) {
		// Preserve all running receiver settings (including resolved Feishu secrets).
		runtime, err := common.ReadJSON(filepath.Join(d.Journal.Dir, common.S(common.M(d.Journal.Index[filepath.Join(root, "runtime.json")])["backup"])))
		if err != nil {
			return err
		}
		n := d.C.Selected(d.O.Node)[0]
		common.M(runtime["nodes"])[d.O.Node] = common.Map{"host": n["host"], "name": n["name"], "token": common.M(common.M(d.Secrets["nodes"])[d.O.Node])["token"]}
		runtime["active_nodes"] = active
		if len(common.SS(common.M(common.M(d.C.Raw["central"])["event_service"])["allowed_source_cidrs"])) == 0 {
			https := common.M(runtime["https"])
			sources := common.SS(https["allowed_sources"])
			source := common.S(n["host"]) + "/32"
			if !common.Contains(sources, source) {
				sources = append(sources, source)
			}
			https["allowed_sources"] = sources
		}
		if err = d.Journal.Write(filepath.Join(root, "runtime.json"), common.JSON(runtime), 0600); err != nil {
			return err
		}
		promBytes, err := os.ReadFile(filepath.Join(d.Journal.Dir, common.S(common.M(d.Journal.Index[filepath.Join(root, "prometheus.yml")])["backup"])))
		if err != nil {
			return err
		}
		var prom common.Map
		if err = yaml.Unmarshal(promBytes, &prom); err != nil {
			return err
		}
		mergeScrapeNodes(prom, Prometheus(d.C, active), []string{d.O.Node})
		if err = d.Journal.Write(filepath.Join(root, "prometheus.yml"), YAML(prom), 0600); err != nil {
			return err
		}
		s["files_written"] = true
		if err = d.save(); err != nil {
			return err
		}
	}
	for _, service := range []string{"receiver", "prometheus"} {
		if common.B(s[service+"_restarted"]) {
			continue
		}
		current, err := d.serviceIdentity(ctx, service)
		// A new identity means the previous process finished the recreation but died
		// before checkpointing it. Don't recreate the same service a second time.
		if err != nil || current == common.S(s[service+"_before"]) {
			if _, err = d.compose(ctx, "up", "-d", "--no-deps", "--pull", "never", "--force-recreate", service); err != nil {
				return err
			}
		}
		s[service+"_restarted"] = true
		if err = d.save(); err != nil {
			return err
		}
	}
	if err := d.waitReady(ctx); err != nil {
		return err
	}
	d.State["active"] = active
	return d.save()
}

func (d *Deploy) rollbackAddition(ctx context.Context) error {
	s := common.M(d.State["node_addition"])
	n := d.C.Selected(common.S(d.State["target_node"]))
	if len(n) != 1 {
		return errors.New("addition_rollback_node_missing")
	}
	nodeState := common.M(common.M(d.State["nodes"])[common.S(n[0]["id"])])
	// Don't restore a backup from an earlier run if this run failed before backup.
	if common.S(nodeState["go_run_id"]) == common.S(d.State["run_id"]) {
		if err := d.RollbackNode(ctx, n[0], false); err != nil {
			return err
		}
	}
	if common.B(s["registration_started"]) {
		if err := d.Journal.Rollback(); err != nil {
			return err
		}
		if _, err := d.compose(ctx, "up", "-d", "--no-deps", "--force-recreate", "receiver", "prometheus"); err != nil {
			return err
		}
		if err := d.waitReady(ctx); err != nil {
			return err
		}
	}
	d.State["active"] = common.SS(s["previous_active"])
	d.State["configuration"], d.State["config_hash"] = s["previous_configuration"], s["previous_config_hash"]
	d.State["go_release"], d.State["image_lock"] = d.State["previous_go_release"], d.State["previous_image_lock"]
	d.State["step"] = "rolled-back"
	for _, key := range []string{"local_ready", "registration_started", "files_written", "receiver_before", "prometheus_before", "receiver_restarted", "prometheus_restarted", "registered", "transport_ready", "accepted"} {
		delete(s, key)
	}
	return d.save()
}
