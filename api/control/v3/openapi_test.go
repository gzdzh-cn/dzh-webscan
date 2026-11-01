package controlv3

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestImplementedAPIContract(t *testing.T) {
	var doc struct {
		Version string                    `yaml:"openapi"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "3.1.0" {
		t.Fatal(doc.Version)
	}
	for path, method := range map[string]string{
		"/api/v3/migration-history":           "get",
		"/api/v3/migration-history/sessions":  "get",
		"/api/v3/legacy-history":              "get",
		"/api/v3/servers/{id}/metric-devices": "get", "/api/v3/servers/{id}/device-metrics": "get",
		"/api/v3/notifications/{id}": "get", "/api/v3/notifications/{id}/attempts": "get", "/api/v3/notifications/test-preview": "post", "/api/v3/notifications/tests": "post", "/api/v3/notifications/tests/{id}": "get",
		"/api/v3/account/password": "post", "/api/v3/monitoring/rules": "put", "/api/v3/monitoring/rules/preview": "post",
		"/api/v3/configuration-applications": "post", "/api/v3/configuration-applications/{id}/resume": "post", "/api/v3/configuration-applications/{id}/rollback": "post", "/api/v3/configuration-applications/{id}/cancel": "post", "/api/v3/configuration-applications/{id}": "get", "/api/v3/configuration-applications/{id}/logs": "get",
		"/api/v3/configuration-backups/{id}/restore-preview": "post", "/api/v3/configuration-restores": "post", "/api/v3/configuration-restores/{id}": "get",
		"/api/v3/configuration-restores/{id}/check": "post", "/api/v3/configuration-restores/{id}/prepare": "post", "/api/v3/configuration-restores/{id}/commit": "post", "/api/v3/configuration-restores/{id}/cancel": "post",
		"/api/v3/settings": "get", "/api/v3/settings/preview": "post", "/api/v3/settings/confirm": "post",
		"/api/v3/configuration-backups": "post", "/api/v3/configuration-backups/import": "post", "/api/v3/configuration-backups/import-age": "post",
		"/api/v3/configuration-backups/{id}/export": "get", "/api/v3/configuration-backups/{id}/export-age": "post",
		"/api/v3/configuration-backups/delete-preview": "post", "/api/v3/configuration-backups/delete": "post",
		"/api/v3/configuration-backups/delete-jobs": "get", "/api/v3/configuration-backups/delete-jobs/{id}": "get",
		"/api/v3/website-backups": "post", "/api/v3/website-backups/import": "post", "/api/v3/website-backups/delete": "post",
		"/api/v3/website-backups/{id}/export": "get", "/api/v3/website-backups/{id}/preview": "post", "/api/v3/website-backups/{id}/restore": "post",
		"/api/v3/retention/preview": "post", "/api/v3/retention/export": "post", "/api/v3/retention/cleanup": "post",
		"/api/v3/retention/jobs/{id}": "get", "/api/v3/retention/jobs/{id}/download": "get", "/api/v3/notifications": "get", "/api/v3/audit": "get",
		"/api/v3/retention/policy": "put", "/api/v3/retention/status": "get", "/api/v3/retention/jobs": "get",
		"/api/v3/alerts/current": "get", "/api/v3/alerts/history": "get",
		"/api/v3/servers/{id}/ssh-credential": "post", "/api/v3/servers/{id}/ssh-fingerprint": "post", "/api/v3/servers/{id}/deployment-preview": "post", "/api/v3/deployment-preparations/{id}": "get", "/api/v3/deployments/{id}/resume": "post", "/api/v3/deployments/{id}/rollback": "post", "/api/v3/deployments": "get", "/api/v3/deployments/{id}": "get", "/api/v3/deployments/{id}/logs": "get",
		"/api/v3/deployments/history-delete-preview": "post", "/api/v3/deployments/history-delete": "post", "/api/v3/deployments/history-delete-jobs/{id}": "get",
		"/api/v3/websites": "post", "/api/v3/websites/{id}": "put", "/api/v3/websites/delete": "post", "/api/v3/websites/overview": "get", "/api/v3/websites/{id}/check": "post", "/api/v3/websites/{id}/incidents": "get", "/api/v3/incidents": "get",
		"/healthz": "get", "/api/v3/login": "post", "/api/v3/session": "get", "/api/v3/logout": "post", "/api/v3/servers": "post", "/api/v3/events": "get", "/api/v3/dashboard": "get", "/api/v3/metrics": "get", "/api/v3/capabilities": "get", "/api/v3/openapi.yaml": "get",
	} {
		if _, ok := doc.Paths[path][method]; !ok {
			t.Fatalf("missing %s %s", method, path)
		}
	}
}

func openAPIContract(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func openAPIObject(t *testing.T, value map[string]any, path ...string) map[string]any {
	t.Helper()
	for _, key := range path {
		next, ok := value[key].(map[string]any)
		if !ok {
			t.Fatalf("missing OpenAPI object %s", strings.Join(path, " / "))
		}
		value = next
	}
	return value
}

func openAPIContains(t *testing.T, value any, expected string) {
	t.Helper()
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("expected array containing %s, got %T", expected, value)
	}
	for _, item := range list {
		if item == expected {
			return
		}
	}
	t.Fatalf("array %v does not contain %s", list, expected)
}

func TestUninstallUsesFixedInstallationScope(t *testing.T) {
	doc := openAPIContract(t)
	for _, suffix := range []string{"ssh-fingerprint", "ssh-credential", "deployment-preview"} {
		op := openAPIObject(t, doc, "paths", "/api/v3/servers/{id}/"+suffix, "post")
		body := openAPIObject(t, op, "requestBody", "content", "application/json", "schema")
		if body["additionalProperties"] != false {
			t.Fatalf("%s accepts unknown target fields", suffix)
		}
		properties := openAPIObject(t, body, "properties")
		openAPIContains(t, openAPIObject(t, properties, "kind")["enum"], "uninstall")
		for _, forbidden := range []string{"host", "endpoint", "mode", "installation", "command"} {
			if _, ok := properties[forbidden]; ok {
				t.Fatalf("%s exposes caller-selected uninstall %s", suffix, forbidden)
			}
		}
		parameters := op["parameters"].([]any)
		for _, ref := range []string{"CSRF", "DeploymentIdempotency"} {
			found := false
			for _, p := range parameters {
				if p.(map[string]any)["$ref"] == "#/components/parameters/"+ref {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s lacks %s", suffix, ref)
			}
		}
	}
	get := openAPIObject(t, doc, "paths", "/api/v3/servers/{id}/ssh-credential", "get")
	found := false
	for _, raw := range get["parameters"].([]any) {
		p := raw.(map[string]any)
		if p["name"] == "kind" && p["in"] == "query" {
			openAPIContains(t, openAPIObject(t, p, "schema")["enum"], "uninstall")
			found = true
		}
	}
	if !found {
		t.Fatal("credential read lacks uninstall scope")
	}
	schemas := openAPIObject(t, doc, "components", "schemas")
	installed := openAPIObject(t, schemas, "InstalledTarget")
	if installed["readOnly"] != true || openAPIObject(t, installed, "properties", "ssh_port")["readOnly"] != true {
		t.Fatal("actual installation target and SSH port must remain read-only")
	}
	for _, key := range []string{"job", "plan_digest", "release", "sha256", "mode", "endpoint", "host", "ssh_port"} {
		openAPIContains(t, installed["required"], key)
	}
	for _, state := range []string{"confirmed_removed", "still_installed", "unknown"} {
		openAPIContains(t, openAPIObject(t, schemas, "SSHCredentialState", "properties", "outcome")["enum"], state)
	}
	for _, field := range []string{"can_uninstall", "uninstall_reason", "lifecycle"} {
		if openAPIObject(t, schemas, "Node", "properties", field)["readOnly"] != true {
			t.Fatalf("node %s must be read-only", field)
		}
	}
	for _, kind := range []string{"install", "upgrade", "recover", "uninstall"} {
		openAPIContains(t, openAPIObject(t, schemas, "DeploymentJob", "properties", "kind")["enum"], kind)
	}
	openAPIContains(t, openAPIObject(t, schemas, "DeploymentPreview", "properties", "kind")["enum"], "uninstall")
}

func TestDeploymentHistoryDeleteContractPreservesRecovery(t *testing.T) {
	doc := openAPIContract(t)
	paths := openAPIObject(t, doc, "paths")
	if _, ok := paths["/api/v3/deployments/history-delete-jobs"]; ok {
		t.Fatal("delete task list is not an implemented API")
	}
	for _, path := range []string{"history-delete-preview", "history-delete"} {
		op := openAPIObject(t, paths, "/api/v3/deployments/"+path, "post")
		body := openAPIObject(t, op, "requestBody", "content", "application/json", "schema")
		if body["additionalProperties"] != false {
			t.Fatal("history delete accepts unknown request fields")
		}
		for _, ref := range []string{"CSRF", "DeploymentIdempotency"} {
			found := false
			for _, raw := range op["parameters"].([]any) {
				if raw.(map[string]any)["$ref"] == "#/components/parameters/"+ref {
					found = true
				}
			}
			if !found {
				t.Fatalf("history %s lacks %s", path, ref)
			}
		}
	}
	preview := openAPIObject(t, paths, "/api/v3/deployments/history-delete-preview", "post")
	records := openAPIObject(t, preview, "requestBody", "content", "application/json", "schema", "properties", "records")
	if records["minItems"] != 1 || records["maxItems"] != 200 || records["uniqueItems"] != true {
		t.Fatal("history selection must be bounded and explicit")
	}
	confirm := openAPIObject(t, paths, "/api/v3/deployments/history-delete", "post")
	description := confirm["description"].(string)
	for _, evidence := range []string{"v3_deployment_jobs", "proof", "recovery", "日志"} {
		if !strings.Contains(description, evidence) {
			t.Fatalf("history delete must document preserved evidence %s", evidence)
		}
	}
	if openAPIObject(t, confirm, "requestBody", "content", "application/json", "schema", "properties", "confirm")["const"] != true {
		t.Fatal("history delete requires explicit confirmation")
	}
	schemas := openAPIObject(t, doc, "components", "schemas")
	for _, field := range []string{"record_key", "can_delete", "delete_reason"} {
		if openAPIObject(t, schemas, "DeploymentJob", "properties", field)["readOnly"] != true {
			t.Fatalf("history %s is a read-only server decision", field)
		}
	}
	for _, status := range []string{"queued", "running", "succeeded", "partial", "cancelled"} {
		openAPIContains(t, openAPIObject(t, schemas, "DeploymentHistoryDeleteJob", "properties", "status")["enum"], status)
	}
	for _, status := range []string{"eligible", "protected", "pending", "deleted", "skipped", "failed"} {
		openAPIContains(t, openAPIObject(t, schemas, "DeploymentHistoryDeleteItem", "properties", "status")["enum"], status)
	}
}

func TestDeviceHistoryContractIsBoundedAndReadOnly(t *testing.T) {
	doc := openAPIContract(t)
	paths := openAPIObject(t, doc, "paths")
	for _, suffix := range []string{"metric-devices", "device-metrics"} {
		path := openAPIObject(t, paths, "/api/v3/servers/{id}/"+suffix)
		if len(path) != 1 || path["get"] == nil {
			t.Fatalf("%s must remain a read-only endpoint", suffix)
		}
		op := openAPIObject(t, path, "get")
		for _, raw := range op["parameters"].([]any) {
			parameter := raw.(map[string]any)
			if name, ok := parameter["name"].(string); ok && name != "id" && name != "devices" {
				t.Fatalf("%s exposes arbitrary query parameter %s", suffix, name)
			}
			if parameter["name"] == "devices" {
				schema := openAPIObject(t, parameter, "schema")
				if parameter["required"] != true || parameter["explode"] != true || schema["minItems"] != 1 || schema["maxItems"] != 8 || schema["uniqueItems"] != true {
					t.Fatal("device selection must be explicit, repeated, unique, and limited to eight")
				}
			}
		}
		for _, evidence := range []string{"31 天", "10 秒"} {
			if !strings.Contains(op["description"].(string), evidence) {
				t.Fatalf("%s does not document %s", suffix, evidence)
			}
		}
	}
	schemas := openAPIObject(t, doc, "components", "schemas")
	if openAPIObject(t, schemas, "ConsoleDeviceInventory", "properties", "items")["maxItems"] != 512 {
		t.Fatal("inventory must document the two bounded device classes")
	}
	trend := openAPIObject(t, schemas, "ConsoleDeviceTrend", "properties")
	for field, limit := range map[string]int{"devices": 8, "series": 64, "points": 1000} {
		if openAPIObject(t, trend, field)["maxItems"] != limit {
			t.Fatalf("device trend %s bound must be %d", field, limit)
		}
	}
	metrics := openAPIObject(t, trend, "series", "items", "properties", "metric")["enum"].([]any)
	if len(metrics) != 10 {
		t.Fatalf("device metric whitelist unexpectedly changed: %v", metrics)
	}
	for _, metric := range []string{"disk_read", "disk_write_iops", "net_receive_errors", "net_transmit_drops"} {
		openAPIContains(t, metrics, metric)
	}
	values := openAPIObject(t, trend, "points", "items", "properties", "values")
	if values["maxProperties"] != 64 || !strings.Contains(values["description"].(string), "不补零") {
		t.Fatal("sparse series must remain bounded and must not synthesize zero")
	}
}

func TestHostWatchdogDashboardContractOnlyExposesEvidence(t *testing.T) {
	doc := openAPIContract(t)
	schemas := openAPIObject(t, doc, "components", "schemas")
	sections := openAPIObject(t, doc, "paths", "/api/v3/dashboard", "get", "responses", "200", "content", "application/json", "schema", "properties", "summary", "properties", "sections", "properties")
	for name, ref := range map[string]string{"host_watchdog": "HostWatchdogObservation", "services": "DashboardServiceEvidence"} {
		if openAPIObject(t, sections, name, "properties", "data")["$ref"] != "#/components/schemas/"+ref {
			t.Fatalf("dashboard %s lacks actual evidence schema", name)
		}
	}
	for _, field := range []string{"configured", "available", "fresh", "reason", "status"} {
		openAPIContains(t, openAPIObject(t, schemas, "HostWatchdogObservation")["required"], field)
	}
	status := openAPIObject(t, schemas, "HostWatchdogStatus", "properties")
	for _, forbidden := range []string{"socket", "state_directory", "spec_file", "vault", "credentials", "config", "command", "url"} {
		if _, ok := status[forbidden]; ok {
			t.Fatalf("watchdog dashboard exposes private field %s", forbidden)
		}
	}
	if !strings.Contains(openAPIObject(t, status, "pending")["description"].(string), "queued/sending") {
		t.Fatal("pending is the host notice queue, not pending PostgreSQL transactions")
	}
	roles := openAPIObject(t, schemas, "DashboardServiceEvidence", "properties", "roles")
	for _, evidence := range []string{"notify-email", "notify-feishu", "notification-tests", "空队列"} {
		if !strings.Contains(roles["description"].(string), evidence) {
			t.Fatalf("service heartbeat evidence must document %s", evidence)
		}
	}
	for path := range openAPIObject(t, doc, "paths") {
		if strings.Contains(path, "watchdog") || strings.HasPrefix(path, "/v1/") {
			t.Fatalf("host control RPC is private, not a business endpoint: %s", path)
		}
	}
}

func TestCollectorAndBackupRuntimeFieldContract(t *testing.T) {
	doc := openAPIContract(t)
	schema := openAPIObject(t, doc, "components", "schemas", "RuntimeSettingsValues")
	properties := openAPIObject(t, schema, "properties")
	for field, limits := range map[string][2]int{"collector.interval_seconds": {10, 3600}, "backup.keep_days": {1, 3650}} {
		property := openAPIObject(t, properties, field)
		if property["type"] != "integer" || property["minimum"] != limits[0] || property["maximum"] != limits[1] {
			t.Fatalf("invalid actual runtime limits for %s", field)
		}
	}
	if openAPIObject(t, properties, "backup.enabled")["type"] != "boolean" || openAPIObject(t, properties, "backup.time")["pattern"] != "^([01][0-9]|2[0-3]):[0-5][0-9]$" || openAPIObject(t, properties, "backup.timezone")["maxLength"] != 128 {
		t.Fatal("backup fields must retain strict enabled, time and explicit timezone controls")
	}
	for _, unavailable := range []string{"storage.raw_hours", "storage.history_days", "metrics.raw_hours", "metrics.history_days"} {
		if _, ok := properties[unavailable]; ok {
			t.Fatalf("unimplemented retention split is not an editable runtime field: %s", unavailable)
		}
	}
	for _, evidence := range []string{"save 只保存", "monitoring.interval_seconds", "collector.interval_seconds", "03:00", "UTC", "keep_days=7", "显式升级维护程序"} {
		if !strings.Contains(schema["description"].(string), evidence) {
			t.Fatalf("runtime settings must document %s", evidence)
		}
	}
}

func TestAllLocalOpenAPIReferencesResolve(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["$ref"].(string); ok && strings.HasPrefix(ref, "#/") {
				var target any = doc
				for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
					part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
					object, ok := target.(map[string]any)
					if !ok {
						t.Fatalf("invalid reference %s", ref)
					}
					target, ok = object[part]
					if !ok {
						t.Fatalf("unresolved reference %s", ref)
					}
				}
			}
			for _, value := range x {
				walk(value)
			}
		case []any:
			for _, value := range x {
				walk(value)
			}
		}
	}
	walk(doc)
}
