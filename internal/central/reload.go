package central

import (
	"errors"
	"fmt"
	"webscan/internal/common"
	"webscan/internal/notify"
	"webscan/internal/telemetry"
)

func configPathFrom(c common.Map) string { return common.S(c["runtime_path"]) }

var errRuntimeSettingsUnavailable = errors.New("runtime_settings_unavailable")

func (s *Store) reloadSettings(path string) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if path == "" {
		return errors.New("运行配置路径缺失")
	}
	c, e := common.ReadJSON(path)
	if e != nil {
		return e
	}
	old := s.Snapshot()
	if common.S(common.M(c["monitoring"])["mode"]) != common.S(common.M(old["monitoring"])["mode"]) {
		return errors.New("架构切换必须通过部署执行")
	}
	for _, key := range []string{"data_dir", "bind", "port", "https", "public_http", "nodes", "active_nodes", "management_socket"} {
		if string(common.JSON(old[key])) != string(common.JSON(c[key])) {
			return fmt.Errorf("连接或节点变化需要部署应用（字段：%s）", key)
		}
	}
	wm, previous := common.M(c["website_monitor"]), common.M(old["website_monitor"])
	for _, key := range []string{"enabled", "host_port", "ssl_enabled", "bind_address"} {
		if string(common.JSON(wm[key])) != string(common.JSON(previous[key])) {
			return fmt.Errorf("后台监听变化需要重建（字段：website_monitor.%s）", key)
		}
	}
	c["runtime_path"] = path
	if s.Telemetry != nil {
		settings := common.M(c["monitoring"])
		nodes := []telemetry.Node{}
		for _, v := range common.A(settings["nodes"]) {
			n := common.M(v)
			nodes = append(nodes, telemetry.Node{ID: common.S(n["id"]), Name: common.S(n["name"]), Host: common.S(n["host"]), URL: common.S(n["url"]), Active: common.B(n["active"]), Central: common.B(n["central"])})
		}
		if e = s.Telemetry.Configure(settings, nodes); e != nil {
			return fmt.Errorf("%w: %w", errRuntimeSettingsUnavailable, e)
		}
	}
	if s.Websites != nil {
		next := common.Clone(wm)
		next["notification_config"] = common.Map{"feishu": c["feishu"], "email": c["email"]}
		s.Websites.Configure(next, notify.Enabled(c))
	}
	s.runtime.Store(&c)
	return nil
}
