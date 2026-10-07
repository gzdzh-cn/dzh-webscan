package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	"webscan/internal/progress"
)

func withoutNode(ids []string, node string) []string {
	out := []string{}
	for _, id := range ids {
		if id != node {
			out = append(out, id)
		}
	}
	return out
}

// Change only registration/health and the selected scrape job. Runtime YAML may
// contain un-applied settings, so never regenerate main configuration from it.
func removeNodeRegistration(runtime common.Map, prom common.Map, node string) {
	delete(common.M(runtime["nodes"]), node)
	runtime["active_nodes"] = withoutNode(common.SS(runtime["active_nodes"]), node)
	jobs := []any{}
	for _, v := range common.A(prom["scrape_configs"]) {
		if common.S(common.M(v)["job_name"]) != "webscan-node-"+node {
			jobs = append(jobs, v)
		}
	}
	prom["scrape_configs"] = jobs
}

func (d *Deploy) singleUninstallPreflight(ctx context.Context) error {
	root := d.C.CentralRoot()
	b, err := os.ReadFile(filepath.Join(root, "compose.yml"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = d.compose(ctx, "config", "--quiet"); err != nil {
		return errors.New("uninstall_main_compose_invalid")
	}
	var compose common.Map
	if err = yaml.Unmarshal(b, &compose); err != nil {
		return err
	}
	for _, service := range []string{"receiver", "prometheus"} {
		image := common.S(common.M(common.M(compose["services"])[service])["image"])
		if image == "" {
			return errors.New("uninstall_main_service_missing")
		}
		if _, err = RunCommand(ctx, nil, "docker", "image", "inspect", image); err != nil {
			return errors.New("uninstall_main_image_not_available_locally")
		}
	}
	return nil
}

func (d *Deploy) prepareSingleUninstall(ctx context.Context) (common.Map, error) {
	s := common.M(d.State["single_uninstall"])
	if len(s) > 0 && !common.B(s["complete"]) {
		if common.S(s["node"]) != d.O.Node {
			return nil, errors.New("single_uninstall_pending_use_original_node")
		}
		progress.Info(ctx, "继续上次单节点卸载；复用原备份，只处理未完成步骤")
		return s, nil
	}
	id := "maintenance-" + time.Now().UTC().Format("20060102T150405Z") + "-" + common.ID()[:8]
	backup := filepath.Join(StateRoot, "maintenance", id)
	if err := os.MkdirAll(backup, 0700); err != nil {
		return nil, err
	}
	if err := common.AtomicJSON(filepath.Join(backup, "state-before.json"), d.State); err != nil {
		return nil, err
	}
	if err := common.AtomicJSON(filepath.Join(backup, "credentials.json"), d.Secrets); err != nil {
		return nil, err
	}
	s = common.Map{"node": d.O.Node, "id": id, "complete": false, "previous_active": common.SS(d.State["active"])}
	root := d.C.CentralRoot()
	if _, err := os.Stat(filepath.Join(root, "compose.yml")); err == nil {
		runtime, err := common.ReadJSON(filepath.Join(root, "runtime.json"))
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(filepath.Join(root, "prometheus.yml"))
		if err != nil {
			return nil, err
		}
		var prom common.Map
		if err = yaml.Unmarshal(b, &prom); err != nil {
			return nil, err
		}
		j, err := NewJournal(filepath.Join(backup, "central"))
		if err != nil {
			return nil, err
		}
		for _, name := range []string{"runtime.json", "prometheus.yml"} {
			if err = j.Remember(filepath.Join(root, name)); err != nil {
				return nil, err
			}
		}
		removeNodeRegistration(runtime, prom, d.O.Node)
		if err = common.AtomicJSON(filepath.Join(backup, "target-runtime.json"), runtime); err != nil {
			return nil, err
		}
		if err = common.Atomic(filepath.Join(backup, "target-prometheus.yml"), YAML(prom), 0600); err != nil {
			return nil, err
		}
		s["central_present"], s["port"] = true, runtime["port"]
		for _, service := range []string{"receiver", "prometheus"} {
			identity, err := d.serviceIdentity(ctx, service)
			if err != nil {
				return nil, err
			}
			s[service+"_before"] = identity
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	d.State["single_uninstall"] = s
	if err := d.save(); err != nil {
		return nil, err
	}
	progress.Info(ctx, "卸载备份："+backup+"；网站、数据库、事件队列及账号保留")
	return s, nil
}

func (d *Deploy) uninstallSingle(ctx context.Context) error {
	selected := d.C.UninstallNodes(d.O.Node)
	if len(selected) != 1 {
		return errors.New("selected_node_not_configured")
	}
	n := selected[0]
	if last := common.M(d.State["single_uninstall"]); common.S(last["node"]) == d.O.Node && common.B(last["complete"]) && common.S(common.M(common.M(d.State["nodes"])[d.O.Node])["phase"]) == "uninstalled" && !common.Contains(common.SS(d.State["active"]), d.O.Node) {
		progress.Info(ctx, "此节点已完成卸载及主服务器收尾；不重复操作容器")
		return nil
	}
	packagePath, err := filepath.Abs(d.C.Path)
	if err != nil {
		return err
	}
	if err := safeRuntimeRemoval(d.C.CentralRoot(), filepath.Dir(packagePath), common.S(common.M(d.C.Raw["central"])["data_dir"]), common.S(common.M(d.C.Raw["central"])["backup_dir"]), StateRoot); err != nil {
		return err
	}
	if err := progress.Stage(ctx, progress.Host(d.C.Raw), "检查单节点卸载环境（使用本地镜像，不下载）", d.singleUninstallPreflight); err != nil {
		return err
	}
	s, err := d.prepareSingleUninstall(ctx)
	if err != nil {
		return err
	}
	if !common.B(s["node_removed"]) {
		if err = progress.Stage(ctx, progress.Node(n), "通过 SSH 卸载节点监控并保留数据", func(ctx context.Context) error {
			r, e := d.remote(ctx, n)
			if e != nil {
				return e
			}
			_, e = r.Exec(ctx, "bash -se", strings.NewReader(nodeUninstallScript(filepath.Join(StateRoot, "maintenance", common.S(s["id"])))))
			return e
		}); err != nil {
			return err
		}
		s["node_removed"] = true
		nodeState := common.M(common.M(d.State["nodes"])[d.O.Node])
		nodeState["phase"] = "uninstalled"
		common.M(d.State["nodes"])[d.O.Node] = nodeState
		d.State["active"] = withoutNode(common.SS(d.State["active"]), d.O.Node)
		if err = d.save(); err != nil {
			return err
		}
	}
	if common.B(s["central_present"]) && !common.B(s["central_updated"]) {
		err = progress.Stage(ctx, progress.Host(d.C.Raw), "撤销节点登记和采集目标（沿用原镜像及设置）", func(ctx context.Context) error { return d.finishSingleUninstall(ctx, s) })
		if err != nil {
			progress.Warn(ctx, "此节点已卸载，主服务器收尾尚未完成；再次执行 --uninstall --node "+d.O.Node+" 继续，不能视为全部成功")
			return fmt.Errorf("single_uninstall_main_cleanup_pending: %w", err)
		}
		s["central_updated"] = true
	}
	s["complete"], s["completed_at"] = true, common.Now()
	if err = d.save(); err != nil {
		return err
	}
	progress.Info(ctx, "选中节点已卸载并撤销主服务器登记；其他节点继续监控，数据及备份保留")
	return nil
}

func (d *Deploy) finishSingleUninstall(ctx context.Context, s common.Map) error {
	root := d.C.CentralRoot()
	backup := filepath.Join(StateRoot, "maintenance", common.S(s["id"]))
	j, err := NewJournal(filepath.Join(backup, "central"))
	if err != nil {
		return err
	}
	for _, pair := range [][2]string{{"runtime.json", "target-runtime.json"}, {"prometheus.yml", "target-prometheus.yml"}} {
		path := filepath.Join(root, pair[0])
		desired, err := os.ReadFile(filepath.Join(backup, pair[1]))
		if err != nil {
			return err
		}
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Equal(current, desired) {
			continue
		}
		// A later manual edit must not be overwritten during a retry.
		original, err := os.ReadFile(filepath.Join(j.Dir, common.S(common.M(j.Index[path])["backup"])))
		if err != nil {
			return err
		}
		if !bytes.Equal(current, original) {
			return errors.New("single_uninstall_main_configuration_changed")
		}
		if err = j.Write(path, desired, 0600); err != nil {
			return err
		}
	}
	for _, service := range []string{"receiver", "prometheus"} {
		if common.B(s[service+"_restarted"]) {
			continue
		}
		current, err := d.serviceIdentity(ctx, service)
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
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		_, v, e := common.Request(ctx, d.HTTP, "GET", "http://127.0.0.1:"+strconv.Itoa(common.I(s["port"]))+"/ready", nil, nil)
		if e == nil && common.B(common.M(v)["ready"]) {
			req, e := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19190/-/ready", nil)
			if e != nil {
				return e
			}
			resp, e := d.HTTP.Do(req)
			if e == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					return nil
				}
			}
		}
		if !common.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
	}
	return errors.New("single_uninstall_main_health_not_ready")
}
