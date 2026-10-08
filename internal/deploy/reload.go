package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/progress"
)

type ruleUpdate struct {
	Node, Runtime, Status     common.Map
	Yara, OldYara, OldRuntime []byte
	Version, Container        string
	Remote                    *Remote
	Staged                    bool
}

func withoutRules(c common.Map) common.Map {
	out := common.Clone(c)
	// Compare effective nodes: addition snapshots can contain expanded defaults
	// while YAML uses inheritance. Image publication is independent of rules.
	nodes := []any{}
	for _, v := range common.A(out["nodes"]) {
		node := common.Merge(common.M(out["node_defaults"]), common.M(v))
		// Connections still validate the requested fingerprint or persisted trust.
		delete(common.M(node["ssh"]), "host_key_sha256")
		m := common.M(node["monitor"])
		if policy, err := common.NewPolicy(m); err == nil {
			m = policy.Monitor
		}
		for _, key := range common.RuleFields {
			delete(m, key)
		}
		node["monitor"] = m
		nodes = append(nodes, node)
	}
	out["nodes"] = nodes
	delete(out, "node_defaults")
	delete(out, "images")
	return out
}

// Commit only applied filter fields. Preserve images, credentials and other
// pending settings, including the original inheritance of non-rule fields.
func configurationWithRules(previous, current common.Map) common.Map {
	out := common.Clone(previous)
	copyRules := func(dst, src common.Map) {
		monitor := common.M(dst["monitor"])
		for _, key := range common.RuleFields {
			delete(monitor, key)
			if value, ok := common.M(src["monitor"])[key]; ok {
				monitor[key] = value
			}
		}
		dst["monitor"] = monitor
	}
	copyRules(common.M(out["node_defaults"]), common.M(current["node_defaults"]))
	byID := map[string]common.Map{}
	for _, value := range common.A(current["nodes"]) {
		node := common.M(value)
		byID[common.S(node["id"])] = node
	}
	for _, value := range common.A(out["nodes"]) {
		node := common.M(value)
		copyRules(node, byID[common.S(node["id"])])
	}
	return out
}

func (d *Deploy) ReloadRules(ctx context.Context) error {
	// The deployment tool may advance while already-installed GoFrame agents
	// keep running; the live protocol and runtime are checked before any writes.
	if common.S(d.State["step"]) != "complete" || common.S(d.State["go_release"]) == "" {
		return errors.New("complete_matching_goframe_deployment_required")
	}
	previous := common.M(d.State["configuration"])
	current := common.M(Redact(d.C.Raw))
	if string(common.JSON(withoutRules(previous))) != string(common.JSON(withoutRules(current))) {
		return errors.New("reload_rules_only_allows_filter_changes")
	}
	progress.Info(ctx, "规则热更新：仅下发过滤规则和指定的 YARA 内容；沿用运行中的镜像，不重建任何监控服务")
	if string(common.JSON(previous["images"])) != string(common.JSON(current["images"])) {
		progress.Info(ctx, "YAML 镜像与已部署记录不同，本次不升级镜像，也不把这些镜像变更记为已部署")
	}
	selected := d.C.Selected(d.O.Node)
	for _, n := range d.C.Selected("") {
		if d.O.Node != "" && common.S(n["id"]) != d.O.Node {
			for _, old := range common.A(previous["nodes"]) {
				if common.S(common.M(old)["id"]) == common.S(n["id"]) {
					oldNode := common.Merge(common.M(previous["node_defaults"]), common.M(old))
					p, e := common.NewPolicy(common.M(oldNode["monitor"]))
					if e != nil {
						return e
					}
					if string(common.JSON(p.Monitor)) != string(common.JSON(n["monitor"])) {
						return errors.New("global_rules_change_requires_all_affected_nodes")
					}
				}
			}
		}
	}
	var override []byte
	var e error
	if d.O.YaraRules != "" {
		override, e = os.ReadFile(d.O.YaraRules)
		if e != nil {
			return e
		}
		if len(override) > 1048576 {
			return errors.New("yara_rules_exceed_1mib")
		}
	}
	updates := []*ruleUpdate{}
	for _, n := range selected {
		r, e := d.remote(ctx, n)
		if e != nil {
			return e
		}
		raw, e := r.Read(ctx, "/etc/webscan-v1/runtime.json")
		if e != nil {
			return e
		}
		v, e := common.Decode(raw)
		if e != nil {
			return e
		}
		runtime := common.M(v)
		b, e := r.Read(ctx, "/var/lib/webscan-v1/rules-status.json")
		if e != nil {
			return e
		}
		sv, e := common.Decode(b)
		if e != nil {
			return e
		}
		status := common.M(sv)
		if common.S(status["state"]) != "applied" || common.S(status["implementation"]) != "goframe" {
			return errors.New("node_has_unapplied_or_non_goframe_rules")
		}
		oldYara, e := r.Read(ctx, common.S(runtime["yara_rules"]))
		if e != nil {
			return e
		}
		yara := oldYara
		if override != nil {
			yara = override
		}
		candidate := common.Clone(runtime)
		monitor := common.M(candidate["monitor"])
		policy, e := common.NewPolicy(common.M(n["monitor"]))
		if e != nil {
			return e
		}
		for _, key := range common.RuleFields {
			monitor[key] = policy.Monitor[key]
		}
		if string(common.JSON(monitor)) != string(common.JSON(policy.Monitor)) {
			return errors.New("node_nonrule_monitor_configuration_mismatch")
		}
		container, e := r.Run(ctx, "docker inspect --format '{{.Id}} {{.State.StartedAt}} {{.State.Pid}}' webscan-agent-go")
		if e != nil {
			return e
		}
		updates = append(updates, &ruleUpdate{Node: n, Runtime: candidate, Status: status, Yara: yara, OldYara: oldYara, OldRuntime: raw, Version: policy.Version(yara), Container: string(container), Remote: r})
	}
	id := "rules-" + time.Now().UTC().Format("20060102T150405Z") + "-" + common.ID()[:8]
	for _, u := range updates {
		backup := "/var/lib/webscan-deploy/rule-updates/" + id
		if e = u.Remote.Write(ctx, backup+"/runtime.json", u.OldRuntime, 0600); e != nil {
			break
		}
		if e = u.Remote.Write(ctx, backup+"/php-webshell.yar", u.OldYara, 0600); e != nil {
			break
		}
		stage := "/etc/webscan-v1/.candidate-" + common.ID() + ".yar"
		if e = u.Remote.Write(ctx, stage, u.Yara, 0600); e != nil {
			break
		}
		nodeState := common.M(common.M(d.State["nodes"])[common.S(u.Node["id"])])
		image := common.S(nodeState["go_image"])
		if image == "" {
			e = errors.New("node_agent_image_missing")
			break
		}
		_, e = u.Remote.Run(ctx, "docker run --rm --network none --read-only -v /etc/webscan-v1:/etc/webscan-v1:ro --entrypoint yara "+Q(image)+" -w "+Q(stage)+" /dev/null")
		u.Remote.Run(context.WithoutCancel(ctx), "rm -f -- "+Q(stage))
		if e != nil {
			e = errors.New("candidate_yara_invalid_not_replaced")
			break
		}
		u.Staged = true
		if e = u.Remote.Write(ctx, common.S(u.Runtime["yara_rules"]), u.Yara, 0600); e != nil {
			break
		}
		if e = u.Remote.Write(ctx, "/etc/webscan-v1/runtime.json", common.JSON(u.Runtime), 0600); e != nil {
			break
		}
		if e = d.waitRules(ctx, u, u.Version); e != nil {
			break
		}
		fmt.Println(common.S(u.Node["id"]) + " 规则热加载成功；容器、启动时间和进程保持不变。")
	}
	if e != nil {
		rollbackFailed := false
		for i := len(updates) - 1; i >= 0; i-- {
			u := updates[i]
			if !u.Staged {
				continue
			}
			restore := context.WithoutCancel(ctx)
			err := u.Remote.Write(restore, common.S(u.Runtime["yara_rules"]), u.OldYara, 0600)
			if err == nil {
				err = u.Remote.Write(restore, "/etc/webscan-v1/runtime.json", u.OldRuntime, 0600)
			}
			if err == nil {
				err = d.waitRules(restore, u, common.S(u.Status["version"]))
			}
			if err != nil {
				rollbackFailed = true
				fmt.Println(common.S(u.Node["id"]) + " 回退未确认，请检查正式备份和节点状态。")
			}
		}
		if rollbackFailed {
			return errors.New("rule_update_failed_rollback_not_confirmed")
		}
		return e
	}
	applied := configurationWithRules(previous, current)
	d.State["configuration"], d.State["config_hash"] = applied, common.Hash(common.JSON(applied))
	d.State["last_rules_update"] = common.Map{"id": id, "time": common.Now()}
	for _, u := range updates {
		common.M(common.M(d.State["nodes"])[common.S(u.Node["id"])])["rules_update"] = common.Map{"version": u.Version, "id": id}
	}
	if e = d.save(); e != nil {
		return e
	}
	fmt.Println("规则更新完成；Agent、Vector、exporter 和主服务器服务均未重启。")
	return nil
}
func (d *Deploy) waitRules(ctx context.Context, u *ruleUpdate, version string) error {
	deadline := time.Now().Add(30 * time.Minute)
	notice := time.Now()
	for time.Now().Before(deadline) {
		b, e := u.Remote.Read(ctx, "/var/lib/webscan-v1/rules-status.json")
		if e != nil {
			return e
		}
		v, e := common.Decode(b)
		if e != nil {
			return e
		}
		s := common.M(v)
		container, e := u.Remote.Run(ctx, "docker inspect --format '{{.Id}} {{.State.StartedAt}} {{.State.Pid}}' webscan-agent-go")
		if e != nil {
			return e
		}
		if string(container) != u.Container || common.S(s["instance_id"]) != common.S(u.Status["instance_id"]) {
			return errors.New("agent_restarted_during_rule_update")
		}
		if common.S(s["state"]) == "applied" && common.S(s["version"]) == version && common.I(s["coverage_ok"]) == 1 {
			return nil
		}
		if common.S(s["state"]) == "rejected" && !strings.HasPrefix(version, "restore") {
			if common.S(s["version"]) != version {
				return errors.New("node_rejected_rules")
			}
		}
		if time.Since(notice) > time.Minute {
			fmt.Println(common.S(u.Node["id"]) + " 等待规则加载与目录覆盖；监控仍运行。")
			notice = time.Now()
		}
		if !common.Sleep(ctx, 2*time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("rules_reload_confirmation_timeout")
}

var _ = filepath.Join
