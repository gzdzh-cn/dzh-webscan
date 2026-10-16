package tool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"webscan/internal/agent"
	"webscan/internal/common"
	"webscan/internal/deploy"
	"webscan/internal/diagnostic"
	"webscan/internal/persist"
)

func Run(ctx context.Context, action, input, output string, uninstall bool) error {
	switch action {
	case "deployment-probe":
		if input != "-" {
			return errors.New("检测参数只能通过标准输入传入")
		}
		return diagnostic.Run(ctx, os.Stdin, os.Stdout)
	case "validate-native-service":
		b, err := os.ReadFile("/etc/systemd/system/webscan-agent-native.service")
		if err != nil {
			return err
		}
		r := common.Map{}
		for _, line := range strings.Split(string(b), "\n") {
			if key, value, ok := strings.Cut(line, "="); ok {
				if key == "MemoryMax" {
					v, e := strconv.Atoi(strings.TrimSuffix(value, "M"))
					if e != nil {
						return e
					}
					r["agent_memory_mib"] = v
				}
				if key == "CPUQuota" {
					v, e := strconv.ParseFloat(strings.TrimSuffix(value, "%"), 64)
					if e != nil {
						return e
					}
					r["cpus"] = v / 100
				}
			}
		}
		b, err = deploy.RunCommand(ctx, nil, "systemctl", "show", "webscan-agent-native", "-p", "MemoryMax", "-p", "CPUQuotaPerSecUSec", "-p", "LimitNOFILE")
		if err != nil {
			return err
		}
		return deploy.VerifyNativeLimits(string(b), r)
	case "import-agent-logs":
		return agent.ImportLegacyLogs(ctx, "/var/lib/webscan-v1", "/var/log/webscan-v1")
	case "legacy-agent-delivery":
		return agent.PrepareLegacyDelivery(ctx, "/var/lib/webscan-v1", "/var/log/webscan-v1")
	case "inspect-db":
		db, err := persist.OpenDB(input)
		if err != nil {
			return err
		}
		defer db.Close()
		result := common.Map{}
		queries := map[string]string{
			"events":               "SELECT count(*) FROM events",
			"pending_deliveries":   "SELECT count(*) FROM tasks WHERE done IS NULL",
			"attempted_deliveries": "SELECT count(*) FROM tasks WHERE attempts>0",
			"matched_scans":        "SELECT count(*) FROM events WHERE json_extract(payload,'$.scan.status')='matched'",
			"pending_events":       "SELECT count(*) FROM events WHERE accepted IS NULL",
			"pending_scans":        "SELECT count(*) FROM scans",
			"manifest_files":       "SELECT count(*) FROM manifest",
		}
		for name, query := range queries {
			var count int
			if err = db.QueryRowContext(ctx, query).Scan(&count); err == nil {
				result[name] = count
			}
		}
		fmt.Println(string(common.JSON(result)))
		return nil
	case "retire-python":
		if _, err := deploy.RunCommand(ctx, nil, "systemctl", "is-active", "--quiet", "webscan-agent-v1"); err == nil {
			return errors.New("legacy_agent_still_active")
		}
		for _, name := range []string{"agent.py", "common.py"} {
			if err := os.Remove(filepath.Join("/opt/webscan-agent-v1", name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	case "snapshot-db":
		db, e := persist.OpenDB(input)
		if e != nil {
			return e
		}
		defer db.Close()
		return persist.BackupDB(db, output)
	case "backup-node":
		return backupNode(ctx, output)
	case "pin-compose-images":
		return deploy.EnsureComposeImages(ctx, output)
	case "restore-node":
		return restoreNode(ctx, output, uninstall)
	default:
		return errors.New("unknown_tool_action")
	}
}
func backupNode(ctx context.Context, dir string) (err error) {
	if !strings.HasPrefix(dir, "/var/lib/webscan-deploy/runs/go-") {
		return errors.New("invalid_node_backup_directory")
	}
	j, e := deploy.NewJournal(dir)
	if e != nil {
		return e
	}
	files := []string{"/var/lib/webscan-v1/transport-paused", "/etc/webscan-v1/clamd.conf", "/etc/webscan-v1/runtime.json", "/etc/webscan-v1/php-webshell.yar", "/etc/webscan-v1/compose.yml", "/etc/webscan-v1/vector.yml", "/etc/webscan-v1/exporter.yml", "/etc/webscan-v1/pki/ca.crt", "/etc/webscan-v1/pki/server.crt", "/etc/webscan-v1/pki/server.key", "/opt/webscan-agent-v1/agent.py", "/opt/webscan-agent-v1/common.py"}
	services := []string{"webscan-agent-native", "webscan-agent-v1", "webscan-vector-v1", "webscan-exporter-v1", "webscan-firewall-v1"}
	state := common.Map{"services": common.Map{}, "agent_go_active": false, "containers": common.Map{}}
	for _, name := range services {
		path := "/etc/systemd/system/" + name + ".service"
		files = append(files, path)
		enabled, _ := deploy.RunCommand(ctx, nil, "systemctl", "is-enabled", name)
		active, _ := deploy.RunCommand(ctx, nil, "systemctl", "is-active", name)
		common.M(state["services"])[name] = common.Map{"enabled": strings.TrimSpace(string(enabled)) == "enabled", "active": strings.TrimSpace(string(active)) == "active"}
	}
	if _, err := os.Stat("/etc/webscan-v1/compose.yml"); err == nil {
		if _, e = deploy.RunCommand(ctx, nil, "docker", "info"); e != nil {
			return errors.New("old_node_docker_daemon_unavailable")
		}
		for _, name := range []string{"webscan-agent-go", "webscan-vector-v1", "webscan-exporter-v1"} {
			if b, err := deploy.RunCommand(ctx, nil, "docker", "inspect", "--format", "{{json .}}", name); err == nil {
				value, err := common.Decode(b)
				if err != nil {
					return err
				}
				m := common.M(value)
				active := common.B(common.M(m["State"])["Running"])
				policy := common.M(common.M(m["HostConfig"])["RestartPolicy"])
				restart := common.S(policy["Name"])
				if restart == "" {
					restart = "no"
				}
				if restart == "on-failure" && common.I(policy["MaximumRetryCount"]) > 0 {
					restart += fmt.Sprintf(":%d", common.I(policy["MaximumRetryCount"]))
				}
				common.M(state["containers"])[name] = common.Map{"active": active, "restart": restart}
				if name == "webscan-agent-go" {
					state["agent_go_active"] = active
				}
			}
		}
	}

	for _, path := range files {
		if e = j.Remember(path); e != nil {
			return e
		}
	}
	if e = common.AtomicJSON(filepath.Join(dir, "node-state.json"), state); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			for name, value := range common.M(state["services"]) {
				if common.B(common.M(value)["active"]) {
					deploy.RunCommand(context.WithoutCancel(ctx), nil, "systemctl", "start", name)
				}
			}
			for name, value := range common.M(state["containers"]) {
				if common.B(common.M(value)["active"]) {
					deploy.RunCommand(context.WithoutCancel(ctx), nil, "docker", "start", name)
				}
			}
		}
	}()
	for name, value := range common.M(state["services"]) {
		if common.B(common.M(value)["active"]) {
			if _, e = deploy.RunCommand(ctx, nil, "systemctl", "stop", name); e != nil {
				return e
			}
		}
	}
	for name, value := range common.M(state["containers"]) {
		if common.B(common.M(value)["active"]) {
			if _, e = deploy.RunCommand(ctx, nil, "docker", "stop", "-t", "30", name); e != nil {
				return e
			}
		}
	}

	dbPath := "/var/lib/webscan-v1/agent.sqlite3"
	if _, e = os.Stat(dbPath); e == nil {
		db, e := persist.OpenDB(dbPath)
		if e != nil {
			return e
		}
		backup := filepath.Join(dir, "agent-before-switch.sqlite3")
		if _, statErr := os.Stat(backup); os.IsNotExist(statErr) {
			e = persist.BackupDB(db, backup)
		} else {
			e = statErr
		}
		db.Close()
		if e != nil {
			return e
		}
	}
	if e = common.AtomicJSON(filepath.Join(dir, "node-state.json"), state); e != nil {
		return e
	}
	return common.Atomic(filepath.Join(dir, "backup-complete"), []byte("complete\n"), 0600)
}
func restoreNode(ctx context.Context, dir string, uninstall bool) error {
	if !strings.HasPrefix(dir, "/var/lib/webscan-deploy/runs/go-") {
		return errors.New("invalid_node_restore_directory")
	}
	state, e := common.ReadJSON(filepath.Join(dir, "node-state.json"))
	if e != nil {
		return e
	}
	j, e := deploy.NewJournal(dir)
	if e != nil {
		return e
	}
	for name := range common.M(state["services"]) {
		if _, err := deploy.RunCommand(ctx, nil, "systemctl", "cat", name); err == nil {
			if _, err = deploy.RunCommand(ctx, nil, "systemctl", "disable", "--now", name); err != nil {
				return err
			}
		}
	}
	if !uninstall {
		if _, err := os.Stat("/var/lib/webscan-v1/agent.sqlite3"); err == nil {
			if e = agent.PrepareLegacyDelivery(ctx, "/var/lib/webscan-v1", "/var/log/webscan-v1"); e != nil {
				return e
			}
		}
	}
	if e = j.Rollback(); e != nil {
		return e
	}
	if _, e = deploy.RunCommand(ctx, nil, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	if uninstall {
		for name := range common.M(state["services"]) {
			deploy.RunCommand(ctx, nil, "systemctl", "disable", "--now", name)
		}
		fmt.Println("monitor services stopped; data retained")
		return nil
	}
	for name, value := range common.M(state["services"]) {
		s := common.M(value)
		if common.B(s["enabled"]) {
			if _, e = deploy.RunCommand(ctx, nil, "systemctl", "enable", name); e != nil {
				return e
			}
		}
		if common.B(s["active"]) {
			if _, e = deploy.RunCommand(ctx, nil, "systemctl", "start", name); e != nil {
				return e
			}
		}
	}
	if common.B(state["agent_go_active"]) {
		if e = deploy.EnsureComposeImages(ctx, "/etc/webscan-v1/compose.yml"); e != nil {
			return e
		}
		if _, e = deploy.RunCommand(ctx, nil, "docker", "compose", "-f", "/etc/webscan-v1/compose.yml", "up", "-d", "--pull", "never", "--no-deps", "agent"); e != nil {
			return e
		}
	}
	for name, value := range common.M(state["containers"]) {
		info := common.M(value)
		if _, e = deploy.RunCommand(ctx, nil, "docker", "update", "--restart="+common.S(info["restart"]), name); e != nil {
			return e
		}
		if common.B(info["active"]) {
			if _, e = deploy.RunCommand(ctx, nil, "docker", "start", name); e != nil {
				return e
			}
		}
	}
	fmt.Println("previous monitoring restored; databases and queues retained")
	return nil
}
