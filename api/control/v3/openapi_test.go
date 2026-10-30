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
		"/api/v3/websites": "post", "/api/v3/websites/{id}": "put", "/api/v3/websites/delete": "post", "/api/v3/websites/overview": "get", "/api/v3/websites/{id}/check": "post", "/api/v3/websites/{id}/incidents": "get", "/api/v3/incidents": "get",
		"/healthz": "get", "/api/v3/login": "post", "/api/v3/session": "get", "/api/v3/logout": "post", "/api/v3/servers": "post", "/api/v3/events": "get", "/api/v3/dashboard": "get", "/api/v3/metrics": "get", "/api/v3/capabilities": "get", "/api/v3/openapi.yaml": "get",
	} {
		if _, ok := doc.Paths[path][method]; !ok {
			t.Fatalf("missing %s %s", method, path)
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
