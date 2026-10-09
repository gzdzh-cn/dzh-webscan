package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	"webscan/internal/progress"
)

// Build the node-only target from the installed snapshot, not pending global
// YAML edits. Only the selected node and download credentials come from YAML.
// The caller's YAML is never modified and remains the target for a full upgrade.
func (d *Deploy) useInstalledMain() error {
	previous := common.M(d.State["configuration"])
	if !common.B(d.State["central_installed"]) || len(previous) == 0 || !strings.HasPrefix(common.S(d.State["go_release"]), "v2.") {
		return errors.New("add_node_requires_installed_compatible_main")
	}
	selected := d.C.Selected(d.O.Node)
	if len(selected) != 1 {
		return errors.New("selected_node_not_enabled")
	}
	// Locate the deployed files using the saved installation directory. Changing
	// directories in YAML is a global upgrade, not a node-add operation.
	root := (&Config{Raw: previous}).CentralRoot()
	b, err := os.ReadFile(filepath.Join(root, "compose.yml"))
	if err != nil {
		return errors.New("add_node_requires_installed_compatible_main")
	}
	var compose common.Map
	if yaml.Unmarshal(b, &compose) != nil {
		return errors.New("add_node_requires_installed_compatible_main")
	}
	image := lockedServiceImage(common.M(common.M(compose["services"])["receiver"]))
	if image == "" || image != common.S(common.M(d.State["image_lock"])["central"]) {
		return errors.New("add_node_requires_installed_compatible_main")
	}
	runtime, err := common.ReadJSON(filepath.Join(root, "runtime.json"))
	if err != nil || common.S(runtime["alert_token"]) == "" {
		return errors.New("add_node_requires_installed_compatible_main")
	}
	if common.S(runtime["data_dir"]) != common.S(common.M(previous["central"])["data_dir"]) {
		return errors.New("add_node_requires_installed_compatible_main")
	}
	raw := common.Clone(previous)
	if common.S(d.State["central_runtime_release"]) == "" {
		d.State["central_runtime_release"] = d.State["go_release"]
	}
	raw["registry"] = common.Clone(common.M(d.C.Raw["registry"]))
	common.M(raw["images"])["agent"] = common.M(d.C.Raw["images"])["agent"]
	delete(common.M(raw["images"]), "deployer")
	raw["feishu"] = common.Clone(common.M(runtime["feishu"]))
	// Preserve the actual API identity and old node tokens across the operation.
	d.Secrets["alert_token"] = runtime["alert_token"]
	for id, v := range common.M(runtime["nodes"]) {
		entry := common.M(common.M(d.Secrets["nodes"])[id])
		entry["token"] = common.M(v)["token"]
		common.M(d.Secrets["nodes"])[id] = entry
	}
	nodes := []common.Map{}
	for _, v := range common.A(previous["nodes"]) {
		n := common.Clone(common.M(v))
		if common.S(n["id"]) == d.O.Node {
			continue
		}
		nodes = append(nodes, n)
	}
	nodes = append(nodes, common.Clone(selected[0]))
	values := []any{}
	for _, n := range nodes {
		values = append(values, n)
	}
	raw["nodes"] = values
	order := common.SS(common.M(raw["deployment"])["node_order"])
	if !common.Contains(order, d.O.Node) {
		order = append(order, d.O.Node)
	}
	common.M(raw["deployment"])["node_order"] = order
	// A node-only operation cannot upgrade unrelated third-party components.
	common.M(raw["deployment"])["upgrade_existing_components"] = false
	d.C = &Config{Raw: raw, Nodes: nodes, Path: d.C.Path}
	for _, n := range d.C.Nodes {
		common.M(n["metrics"])["tls_enabled"] = d.C.SSLEnabled()
	}
	return nil
}

func (d *Deploy) showScope(ctx context.Context) {
	if d.O.AddNode {
		progress.Info(ctx, "操作范围：仅安装或更新 "+progress.Node(d.C.Selected(d.O.Node)[0])+"；沿用主服务器当前镜像和配置，忽略 YAML 中待应用的主服务器修改")
		progress.Info(ctx, "主服务器变更：仅此节点登记和采集目标；receiver、Prometheus 各最多重建一次；Grafana、Loki、Alertmanager 与其他节点保持运行")
		progress.Info(ctx, "主服务器沿用镜像："+common.S(common.M(d.State["image_lock"])["central"]))
		return
	}
	progress.Info(ctx, "操作范围：主服务器按 YAML 安装或升级；接收服务升级与所选节点登记合并；已有 Prometheus 仅在采集配置变化时重建")
	if d.O.CentralOnly {
		progress.Info(ctx, "子服务器变更：无")
		return
	}
	names := []string{}
	for _, n := range d.C.Selected(d.O.Node) {
		names = append(names, progress.Node(n))
	}
	progress.Info(ctx, "子服务器变更："+strings.Join(names, "、"))
}
