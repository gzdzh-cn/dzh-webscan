package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	"webscan/internal/progress"
)

// Keep unrelated and manually added scrape jobs. Replace only the selected jobs.
func mergeScrapeNodes(current, desired common.Map, ids []string) {
	jobs := []any{}
	for _, v := range common.A(current["scrape_configs"]) {
		replace := false
		for _, id := range ids {
			if common.S(common.M(v)["job_name"]) == "webscan-node-"+id {
				replace = true
			}
		}
		if !replace {
			jobs = append(jobs, v)
		}
	}
	for _, v := range common.A(desired["scrape_configs"]) {
		for _, id := range ids {
			if common.S(common.M(v)["job_name"]) == "webscan-node-"+id {
				jobs = append(jobs, v)
			}
		}
	}
	current["scrape_configs"] = jobs
}

func (d *Deploy) stagingNodes() bool { return d.addingNode() || len(common.M(d.State["rollout"])) > 0 }

func (d *Deploy) plannedActive() []string {
	active := common.SS(d.State["active"])
	if len(common.M(d.State["rollout"])) > 0 {
		for _, n := range d.C.Selected(d.O.Node) {
			id := common.S(n["id"])
			if !common.Contains(active, id) {
				active = append(active, id)
			}
		}
	}
	return active
}

// Current Go installations and fresh installations stage their nodes before
// one main update. Legacy Python migration keeps its main-first compatibility check.
func (d *Deploy) canStageRollout() bool {
	return !d.O.AddNode && !d.addingNode() && !d.O.CentralOnly && len(d.C.Selected(d.O.Node)) > 0 && (!common.B(d.State["central_installed"]) || common.S(d.State["go_release"]) != "" || strings.HasPrefix(common.S(d.State["central_runtime_release"]), "v2."))
}

func (d *Deploy) deployRollout(ctx context.Context) (err error) {
	if d.RunID == "" || d.Journal == nil || d.RunID != common.S(d.State["run_id"]) || common.S(d.State["target_release"]) != Release || d.O.AddNode || d.addingNode() {
		return errors.New("rollout_requires_initialized_deployment")
	}
	s := common.M(d.State["rollout"])
	if len(s) == 0 {
		s = common.Map{"previous_active": common.SS(d.State["active"]), "previous_central_installed": d.State["central_installed"], "prepared": common.Map{}, "accepted": common.Map{}}
		d.State["rollout"] = s
		if err = d.save(); err != nil {
			return err
		}
	}
	defer func() {
		if err == nil {
			return
		}
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 180*time.Second)
		defer cancel()
		rollbackErr := d.rollbackRollout(recovery)
		d.State["last_failure"] = common.Map{"stage": "rollout", "rollback_confirmed": rollbackErr == nil, "time": common.Now()}
		_ = d.save()
		if rollbackErr != nil {
			err = errors.New("rollout_rollback_not_confirmed")
		}
	}()
	return d.runRolloutSteps(ctx,
		func(ctx context.Context, n common.Map) error {
			if e := d.InstallNode(ctx, n); e != nil {
				return e
			}
			return d.waitStagedNode(ctx, n)
		}, d.Central,
		func(ctx context.Context, n common.Map) error {
			r, e := d.remote(ctx, n)
			if e != nil {
				return e
			}
			if _, e = r.ExecVisible(ctx, startVectorCommand, nil, "服务状态"); e != nil {
				return e
			}
			if e = d.WaitNodeSidecars(ctx, n); e != nil {
				return e
			}
			if e = d.AcceptNode(ctx, n); e != nil {
				return e
			}
			return d.WaitHealth(ctx, n)
		})
}

// Persist each boundary before allowing transmission. These operations also
// let isolated tests prove that an interrupted run cannot restart main twice.
func (d *Deploy) runRolloutSteps(ctx context.Context, prepare func(context.Context, common.Map) error, main func(context.Context) error, accept func(context.Context, common.Map) error) error {
	s := common.M(d.State["rollout"])
	for _, n := range d.C.Selected(d.O.Node) {
		id := common.S(n["id"])
		if common.B(common.M(s["prepared"])[id]) {
			continue
		}
		if err := progress.Stage(ctx, progress.Node(n), "准备节点监控、扫描和清单（暂缓传输）", func(ctx context.Context) error { return prepare(ctx, n) }); err != nil {
			return err
		}
		common.M(s["prepared"])[id] = true
		if err := d.save(); err != nil {
			return err
		}
	}
	if !common.B(s["main_ready"]) {
		if !common.B(s["main_started"]) {
			for _, service := range []string{"receiver", "prometheus"} {
				identity, _ := d.serviceIdentity(ctx, service)
				s[service+"_before"] = identity
			}
		}
		s["main_started"] = true
		if err := d.save(); err != nil {
			return err
		}
		if err := progress.Stage(ctx, progress.Host(d.C.Raw), "合并主服务器升级、节点登记和采集配置（一次生效）", main); err != nil {
			return err
		}
		s["main_ready"] = true
		if err := d.save(); err != nil {
			return err
		}
	}
	for _, n := range d.C.Selected(d.O.Node) {
		id := common.S(n["id"])
		if common.B(common.M(s["accepted"])[id]) {
			continue
		}
		if err := progress.Stage(ctx, progress.Node(n), "启用节点传输并验收文件、扫描和消息投递", func(ctx context.Context) error { return accept(ctx, n) }); err != nil {
			return err
		}
		common.M(s["accepted"])[id] = true
		ns := common.M(common.M(d.State["nodes"])[id])
		ns["phase"], ns["go_release"] = "complete", Release
		if err := d.save(); err != nil {
			return err
		}
	}
	d.State["step"] = "notifying"
	return d.save()
}

// Docker may finish before the last state write. Verify the exact planned files
// and changed service identities before treating that interrupted update as done.
func (d *Deploy) rolloutMainApplied(ctx context.Context) bool {
	s := common.M(d.State["rollout"])
	hashes := common.M(s["main_config_hashes"])
	if len(hashes) == 0 {
		return false
	}
	for name, hash := range hashes {
		b, err := os.ReadFile(filepath.Join(d.C.CentralRoot(), name))
		if err != nil || common.Hash(b) != common.S(hash) {
			return false
		}
	}
	services := []string{"receiver", "prometheus"}
	changedImages := common.SS(d.State["central_image_services"])
	for _, name := range changedImages {
		if !common.Contains(services, name) {
			services = append(services, name)
		}
	}
	for _, service := range services {
		if service == "prometheus" && !common.B(s["prom_changed"]) && !common.Contains(changedImages, service) && common.S(s["prometheus_before"]) != "" {
			continue
		}
		identity, err := d.serviceIdentity(ctx, service)
		if err != nil || identity == common.S(s[service+"_before"]) {
			return false
		}
	}
	return true
}

func (d *Deploy) rollbackRollout(ctx context.Context) error {
	s := common.M(d.State["rollout"])
	active := common.SS(s["previous_active"])
	for _, n := range d.C.Selected(d.O.Node) {
		id := common.S(n["id"])
		if common.B(common.M(s["accepted"])[id]) {
			if !common.Contains(active, id) {
				active = append(active, id)
			}
			continue
		}
		if common.S(common.M(common.M(d.State["nodes"])[id])["go_run_id"]) == d.RunID {
			if e := progress.Stage(ctx, progress.Node(n), "恢复未通过验收的节点（保留数据）", func(ctx context.Context) error { return d.RollbackNode(ctx, n, false) }); e != nil {
				return e
			}
		}
		delete(common.M(s["prepared"]), id)
	}
	if common.B(s["main_started"]) {
		if !common.B(s["main_ready"]) {
			if err := progress.Stage(ctx, progress.Host(d.C.Raw), "恢复主服务器原配置和服务", func(ctx context.Context) error {
				if e := d.restoreCentral(ctx, d.Journal, false); e != nil {
					return e
				}
				if _, e := os.Stat(filepath.Join(d.C.CentralRoot(), "compose.yml")); e == nil {
					_, e = d.compose(ctx, "up", "-d", "--no-deps", "--pull", "never", "prometheus")
					return e
				}
				return nil
			}); err != nil {
				return err
			}
		} else {
			if err := progress.Stage(ctx, progress.Host(d.C.Raw), "撤销未通过验收节点的登记（保留已通过节点）", func(ctx context.Context) error {
				root := d.C.CentralRoot()
				runtime, e := common.ReadJSON(filepath.Join(root, "runtime.json"))
				if e != nil {
					return e
				}
				runtime["active_nodes"] = active
				b, e := os.ReadFile(filepath.Join(root, "prometheus.yml"))
				if e != nil {
					return e
				}
				var prom common.Map
				if e = yaml.Unmarshal(b, &prom); e != nil {
					return e
				}
				for _, n := range d.C.Selected(d.O.Node) {
					id := common.S(n["id"])
					if !common.Contains(active, id) {
						removeNodeRegistration(runtime, prom, id)
					}
				}
				if e = common.AtomicJSON(filepath.Join(root, "runtime.json"), runtime); e != nil {
					return e
				}
				if e = common.Atomic(filepath.Join(root, "prometheus.yml"), YAML(prom), 0600); e != nil {
					return e
				}
				_, e = d.compose(ctx, "up", "-d", "--no-deps", "--pull", "never", "--force-recreate", "receiver", "prometheus")
				if e != nil {
					return e
				}
				return d.waitReady(ctx)
			}); err != nil {
				return err
			}
		}
	}
	d.State["active"] = active
	if !common.B(s["main_ready"]) {
		d.State["central_installed"] = s["previous_central_installed"]
	}
	s["main_ready"], s["main_started"] = false, false
	return d.save()
}
