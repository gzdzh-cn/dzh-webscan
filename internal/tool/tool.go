package tool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"webscan/internal/common"
	"webscan/internal/deploy"
	"webscan/internal/persist"
)

func Run(ctx context.Context, action, input, output string, uninstall bool) error {
	switch action {
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
	case "restore-node":
		return restoreNode(ctx, output, uninstall)
	default:
		return errors.New("unknown_tool_action")
	}
}
func backupNode(ctx context.Context, dir string) error {
	if !strings.HasPrefix(dir, "/var/lib/webscan-deploy/runs/go-") {
		return errors.New("invalid_node_backup_directory")
	}
	j, e := deploy.NewJournal(dir)
	if e != nil {
		return e
	}
	files := []string{"/etc/webscan-v1/runtime.json", "/etc/webscan-v1/php-webshell.yar", "/etc/webscan-v1/compose.yml", "/etc/webscan-v1/vector.yml", "/etc/webscan-v1/exporter.yml", "/etc/webscan-v1/pki/ca.crt", "/etc/webscan-v1/pki/server.crt", "/etc/webscan-v1/pki/server.key", "/opt/webscan-agent-v1/agent.py", "/opt/webscan-agent-v1/common.py"}
	services := []string{"webscan-agent-v1", "webscan-vector-v1", "webscan-exporter-v1", "webscan-firewall-v1"}
	state := common.Map{"services": common.Map{}, "agent_go_active": false}
	for _, name := range services {
		path := "/etc/systemd/system/" + name + ".service"
		files = append(files, path)
		enabled, _ := deploy.RunCommand(ctx, nil, "systemctl", "is-enabled", name)
		active, _ := deploy.RunCommand(ctx, nil, "systemctl", "is-active", name)
		common.M(state["services"])[name] = common.Map{"enabled": strings.TrimSpace(string(enabled)) == "enabled", "active": strings.TrimSpace(string(active)) == "active"}
	}
	if b, e := deploy.RunCommand(ctx, nil, "docker", "inspect", "--format", "{{.State.Running}}", "webscan-agent-go"); e == nil && strings.TrimSpace(string(b)) == "true" {
		state["agent_go_active"] = true
	}
	for _, path := range files {
		if e = j.Remember(path); e != nil {
			return e
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
	return common.AtomicJSON(filepath.Join(dir, "node-state.json"), state)
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
		if _, e = deploy.RunCommand(ctx, nil, "docker", "compose", "-f", "/etc/webscan-v1/compose.yml", "up", "-d", "--no-deps", "agent"); e != nil {
			return e
		}
	}
	fmt.Println("previous monitoring restored; databases and queues retained")
	return nil
}
