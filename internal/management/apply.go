package management

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/deploy"
)

func (s *Service) apply(ctx context.Context, id string) error {
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		return e
	}
	state, e := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
	if e != nil {
		return e
	}
	previous := common.M(state["configuration"])
	if len(previous) == 0 {
		return userError("需要先通过 webscan 安装主服务器")
	}
	runtimePath := filepath.Join(c.CentralRoot(), "runtime.json")
	runtime, e := common.ReadJSON(runtimePath)
	if e != nil {
		return e
	}
	old, e := os.ReadFile(runtimePath)
	if e != nil {
		return e
	}
	// Applying networking or node changes requires the deployment engine, not a partial hot update.
	oldCenter, newCenter := common.M(previous["central"]), common.M(c.Raw["central"])
	summary := s.configurationStatus(c, state)
	restart := common.S(summary["scope"]) == "full" || common.S(summary["scope"]) == "nodes"
	for id, status := range common.M(s.configurationStatus(c, state)["statuses"]) {
		if id != "central" && common.S(status) == "pending" {
			restart = true
		}
	}
	centralRestart := false
	if string(common.JSON(oldCenter["metrics_allowed_source_ip"])) != string(common.JSON(newCenter["metrics_allowed_source_ip"])) {
		restart = true
	}
	for _, key := range []string{"memory_mib", "go_memory_mib"} {
		if string(common.JSON(common.M(oldCenter["monitoring"])[key])) != string(common.JSON(common.M(newCenter["monitoring"])[key])) {
			centralRestart = true
		}
	}
	for _, key := range []string{"host_port", "bind_address", "enabled"} {
		if string(common.JSON(common.M(oldCenter["website_monitor"])[key])) != string(common.JSON(common.M(newCenter["website_monitor"])[key])) {
			centralRestart = true
		}
	}
	if deploy.OnlyRuleChanges(previous, common.M(config.Redact(c.Raw))) {
		binary, e := os.Executable()
		if e != nil {
			return e
		}
		var revision string
		s.DB.QueryRow("SELECT revision FROM jobs WHERE id=?", id).Scan(&revision)
		return s.command(ctx, id, binary, []string{"deploy", "--config", s.ConfigPath, "--reload-rules", "--non-interactive", "--expected-revision", revision})
	}
	if restart || centralRestart {
		binary, e := os.Executable()
		if e != nil {
			return e
		}
		var revision string
		if e = s.DB.QueryRow("SELECT revision FROM jobs WHERE id=?", id).Scan(&revision); e != nil {
			return e
		}
		args := []string{"deploy", "--config", s.ConfigPath, "--non-interactive", "--upgrade", "--keep-images", "--expected-revision", revision}
		if !restart {
			args = append(args, "--central-only")
		}
		return s.command(ctx, id, binary, args)
	}
	unlock, e := s.lock()
	if e != nil {
		return e
	}
	defer unlock()
	var expected string
	if e = s.DB.QueryRowContext(ctx, "SELECT revision FROM jobs WHERE id=?", id).Scan(&expected); e != nil {
		return e
	}
	raw, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		return e
	}
	if common.Hash(raw) != expected {
		return userError("配置已被修改，请刷新后重新预览应用")
	}
	credentials, e := common.ReadJSON(filepath.Join(s.StateDir, "credentials.json"))
	if e != nil {
		return e
	}
	next := deploy.CentralRuntime(c, credentials, common.SS(state["active"]))
	for _, key := range []string{"nodes", "active_nodes", "website_monitor"} {
		if key != "website_monitor" {
			next[key] = runtime[key]
		}
	}
	wm := common.M(next["website_monitor"])
	for _, key := range []string{"password_hash", "admin_username", "console_url"} {
		wm[key] = common.M(runtime["website_monitor"])[key]
	}
	if e = common.Atomic(runtimePath, common.JSON(next), 0600); e != nil {
		return e
	}
	port := common.I(common.M(newCenter["event_service"])["port"])
	req, e := http.NewRequestWithContext(ctx, "POST", (&url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(port), Path: "/reload-settings"}).String(), strings.NewReader("{}"))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+common.S(runtime["alert_token"]))
	client := &http.Client{Timeout: 15e9}
	resp, e := client.Do(req)
	if e != nil {
		common.Atomic(runtimePath, old, 0600)
		return userError("后台暂不可用，热加载失败，已恢复原运行配置")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		common.Atomic(runtimePath, old, 0600)
		return userError("后台拒绝热加载，请检查待应用配置")
	}
	applied := common.M(config.Redact(c.Raw))
	applied["images"] = previous["images"]
	state["configuration"] = applied
	config.RecordApplied(state, config.ApplicationInput(c.Raw, c.Nodes), "", true)
	state["config_hash"] = common.Hash(common.JSON(state["configuration"]))
	if e = common.AtomicJSON(filepath.Join(s.StateDir, "state.json"), state); e != nil {
		return e
	}
	_, e = logWriter{s, id, nil}.Write([]byte("配置已热加载，无需重建容器。\n"))
	return e
}
