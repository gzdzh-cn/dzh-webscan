package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/assets"
	"webscan/internal/common"
	"webscan/internal/progress"
)

func actionName(o Options) string {
	if o.AddNode {
		return "add-node"
	}
	if o.Uninstall {
		return "uninstall"
	}
	if o.Reinstall {
		return "reinstall"
	}
	if o.Upgrade {
		return "upgrade"
	}
	if o.Resume {
		return "resume"
	}
	return "install"
}

func (d *Deploy) selectInstallMode() {
	if d.canRetryRollout() {
		d.O.Upgrade = true
		return
	}
	run, step := common.S(d.State["run_id"]), common.S(d.State["step"])
	if strings.HasPrefix(run, "go-") && step != "complete" && step != "rolled-back" {
		d.O.Resume = true
		return
	}
	if common.S(d.State["go_release"]) != "" || common.B(d.State["central_installed"]) {
		// Reconcile missing containers too, including a manually removed container.
		d.O.Upgrade = true
	}
}

func (d *Deploy) maintenanceNodes() ([]common.Map, error) {
	if d.O.CentralOnly {
		return nil, nil
	}
	selected := d.C.UninstallNodes(d.O.Node)
	if d.O.Node != "" {
		return selected, nil
	}
	for id, value := range common.M(d.State["nodes"]) {
		s := common.M(value)
		if common.S(s["go_run_id"]) == "" || common.S(s["phase"]) == "uninstalled" {
			continue
		}
		found := false
		for _, n := range d.C.Nodes {
			if common.S(n["id"]) != id {
				continue
			}
			found = true
			included := false
			for _, existing := range selected {
				included = included || common.S(existing["id"]) == id
			}
			if !included {
				selected = append(selected, n)
			}
		}
		if !found {
			return nil, errors.New("uninstall_node_missing_from_yaml_" + id)
		}
	}
	return selected, nil
}

func safeRuntimeRemoval(path string, preserved ...string) error {
	path = filepath.Clean(path)
	if path == "/" || !filepath.IsAbs(path) {
		return errors.New("unsafe_uninstall_path")
	}
	for _, keep := range preserved {
		if keep == "" {
			continue
		}
		var err error
		keep, err = filepath.Abs(keep)
		if err != nil {
			return err
		}
		keep = filepath.Clean(keep)
		if common.Inside(keep, path) || common.Inside(path, keep) {
			return errors.New("uninstall_path_overlaps_preserved_data")
		}
	}
	return nil
}

// Preserve all data, queues, images, credentials and website paths. Backups
// precede deletion; global Docker pruning and volume deletion are never used.
func (d *Deploy) Uninstall(ctx context.Context) error {
	if d.O.Node != "" {
		return d.uninstallSingle(ctx)
	}
	if pending := common.M(d.State["single_uninstall"]); len(pending) > 0 && !common.B(pending["complete"]) {
		return errors.New("single_uninstall_pending_use_original_node")
	}

	nodes, err := d.maintenanceNodes()
	if err != nil {
		return err
	}
	center := common.M(d.C.Raw["central"])
	packagePath, err := filepath.Abs(d.C.Path)
	if err != nil {
		return err
	}
	if err = safeRuntimeRemoval(d.C.CentralRoot(), filepath.Dir(packagePath), common.S(center["data_dir"]), common.S(center["backup_dir"]), StateRoot); err != nil {
		return err
	}
	for _, n := range nodes {
		if err := progress.Stage(ctx, progress.Node(n), "卸载前确认 SSH 身份与连接", func(ctx context.Context) error { _, e := d.remote(ctx, n); return e }); err != nil {
			return err
		}
	}
	id := "maintenance-" + time.Now().UTC().Format("20060102T150405Z") + "-" + common.ID()[:8]
	backup := filepath.Join(StateRoot, "maintenance", id)
	if err = os.MkdirAll(backup, 0700); err != nil {
		return err
	}
	if err = common.AtomicJSON(filepath.Join(backup, "state-before.json"), d.State); err != nil {
		return err
	}
	if err = common.AtomicJSON(filepath.Join(backup, "credentials.json"), d.Secrets); err != nil {
		return err
	}
	progress.Info(ctx, "卸载备份："+backup+"；数据库、Vector 缓冲、Grafana/Loki/Prometheus 数据、凭据和部署包保留")
	for _, n := range nodes {
		if err = progress.Stage(ctx, progress.Node(n), "停止监控、备份配置与数据库、移除容器和服务", func(ctx context.Context) error {
			r, e := d.remote(ctx, n)
			if e != nil {
				return e
			}
			_, e = r.Exec(ctx, "bash -se", strings.NewReader(nodeUninstallScript(filepath.Join(StateRoot, "maintenance", id))))
			return e
		}); err != nil {
			return err
		}
		node := common.S(n["id"])
		s := common.M(common.M(d.State["nodes"])[node])
		s["phase"] = "uninstalled"
		common.M(d.State["nodes"])[node] = s
		active := []string{}
		for _, old := range common.SS(d.State["active"]) {
			if old != node {
				active = append(active, old)
			}
		}
		d.State["active"] = active
		if err = d.save(); err != nil {
			return err
		}
	}
	if d.O.CentralOnly {
		if _, err := os.Stat(filepath.Join(d.C.CentralRoot(), "pki")); err == nil {
			retained := filepath.Join(backup, "pki")
			if err = copyPKI(filepath.Join(d.C.CentralRoot(), "pki"), retained); err != nil {
				return err
			}
			d.State["retained_pki"] = retained
		} else if !os.IsNotExist(err) {
			return err
		}
		// Save identity before removing runtime, including on interruption.
		d.State["central_uninstall_pending"] = true
		if err = d.save(); err != nil {
			return err
		}
	}
	err = progress.Stage(ctx, progress.Host(d.C.Raw), "备份并移除主服务器监控容器与运行配置", func(ctx context.Context) error {
		_, err := RunCommand(ctx, strings.NewReader(centralUninstallScript(backup, d.C.CentralRoot(), common.S(center["data_dir"]), "webscan-v1", common.S(d.State["external_network"]))), "bash", "-se")
		return err
	})
	if err != nil {
		return err
	}
	if err = common.AtomicJSON(filepath.Join(backup, "uninstalled.json"), common.Map{"time": common.Stamp(), "preserve_data": true, "configuration": Redact(d.C.Raw)}); err != nil {
		return err
	}
	if d.O.CentralOnly {
		d.State["central_installed"], d.State["central_uninstalled"] = false, true
		d.State["last_run_before_central_uninstall"] = d.State["run_id"]
		d.State["run_id"], d.State["step"] = "", "central-uninstalled"
		delete(d.State, "central_uninstall_pending")
		if err = d.save(); err != nil {
			return err
		}
		progress.Info(ctx, "主服务器监控已卸载；子服务器保持采集并缓存事件。账号、节点记录和 HTTPS 证书已保留，恢复主服务器后继续补传。")
		return nil
	}
	if err = os.Remove(stateFile()); err != nil && !os.IsNotExist(err) {
		return err
	}
	d.State = common.Map{"nodes": common.Map{}, "active": []string{}}
	progress.Info(ctx, "卸载完成：监控容器、自动启动服务与运行配置已移除；部署包、数据、凭据和备份保留。可选择 1 安装恢复。")
	return nil
}

func copyPKI(source, dest string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("invalid_retained_pki_file")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return common.Atomic(target, b, 0600)
	})
}

func (d *Deploy) restoreRetainedPKI() error {
	source := common.S(d.State["retained_pki"])
	if source == "" {
		return nil
	}
	if !common.Inside(filepath.Clean(source), filepath.Join(StateRoot, "maintenance")) {
		return errors.New("invalid_retained_pki_path")
	}
	if !common.B(d.State["central_uninstalled"]) && !common.B(d.State["central_uninstall_pending"]) {
		_, certErr := os.Stat(filepath.Join(d.C.CentralRoot(), "pki", "ca.crt"))
		_, keyErr := os.Stat(filepath.Join(d.C.CentralRoot(), "pki", "ca.key"))
		if certErr == nil && keyErr == nil {
			return nil
		}
		if certErr != nil && !os.IsNotExist(certErr) {
			return certErr
		}
		if keyErr != nil && !os.IsNotExist(keyErr) {
			return keyErr
		}
	}
	return copyPKI(source, filepath.Join(d.C.CentralRoot(), "pki"))
}

func nodeUninstallScript(backup string) string {
	body, _ := assets.Files.ReadFile("uninstall-node.sh")
	return "TASK_BACKUP=" + Q(backup) + "\n" + string(body)
}
func centralUninstallScript(backup, root, data, project, externalNetwork string) string {
	body, _ := assets.Files.ReadFile("uninstall-central.sh")
	return "TASK_BACKUP=" + Q(backup) + "\nTASK_RUNTIME=" + Q(root) + "\nTASK_DATA=" + Q(data) + "\nTASK_PROJECT=" + Q(project) + "\nTASK_EXTERNAL_NETWORK=" + Q(externalNetwork) + "\n" + string(body)
}
