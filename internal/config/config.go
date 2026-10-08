package config

import (
	"bytes"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"webscan/internal/assets"
	"webscan/internal/common"
)

type Config struct {
	Raw   common.Map
	Nodes []common.Map
	Path  string
}

func Load(path string) (_ *Config, err error) {
	field := "配置文件"
	defer func() {
		if err != nil {
			err = WithField(err, field)
		}
	}()
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, errors.New("cannot_read_yaml")
	}
	var m common.Map
	d := yaml.NewDecoder(bytes.NewReader(raw))
	if e = d.Decode(&m); e != nil {
		if e == io.EOF {
			return nil, errors.New("expected_yaml_mapping")
		}
		return nil, syntaxError(e)
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return nil, errors.New("yaml_requires_single_document")
	}
	if m == nil {
		return nil, errors.New("expected_yaml_mapping")
	}
	base, _ := assets.Files.ReadFile("schema.yaml")
	var schema common.Map
	if e = yaml.Unmarshal(base, &schema); e != nil {
		return nil, e
	}
	schema["registry"] = common.Map{"prefix": "", "auth_required": true, "username": "", "password": "", "mirrors": []any{""}}
	schema["images"] = common.Map{"central": "", "agent": ""}
	// Accept the former field when loading old deployment packages, but never
	// use or include it in effective configuration. Tools now come from central.
	if images, ok := m["images"].(common.Map); ok {
		delete(images, "deployer")
	}
	if e = validateShape(m, schema, ""); e != nil {
		return nil, e
	}
	field = "config_version"
	version := common.I(m["config_version"])
	if version != 2 {
		return nil, errors.New("config_version_must_be_2")
	}
	for _, key := range []string{"central", "feishu", "node_defaults", "nodes", "health", "retention", "backup", "deployment", "optional_components", "registry", "images"} {
		if _, ok := m[key]; !ok {
			return nil, WithField(fmt.Errorf("missing_section_%s", key), key)
		}
	}
	if _, ok := common.M(m["registry"])["mirrors"]; !ok {
		common.M(m["registry"])["mirrors"] = []any{}
	}
	m = common.Merge(schema, m)
	c := &Config{Raw: m, Path: path}
	reg := common.M(m["registry"])
	field = "registry.mirrors"
	if e := ValidateMirrors(common.SS(reg["mirrors"])); e != nil {
		return nil, e
	}

	field = "registry.prefix"
	prefix := common.S(reg["prefix"])
	if !regexp.MustCompile(`^[a-zA-Z0-9.-]+(?::[0-9]+)?/[a-zA-Z0-9_./-]+$`).MatchString(prefix) || strings.Contains(prefix, "..") {
		return nil, errors.New("invalid_registry_prefix")
	}
	field = "registry.username / registry.password"
	if common.B(reg["auth_required"]) && (common.S(reg["username"]) == "" || common.S(reg["password"]) == "") {
		return nil, errors.New("private_registry_credentials_required")
	}
	for _, v := range []any{reg["username"], reg["password"]} {
		if strings.ContainsAny(common.S(v), "\x00\r\n") {
			return nil, errors.New("invalid_registry_credentials")
		}
	}
	for _, role := range []string{"central", "agent"} {
		field = "images." + role
		ref := common.S(common.M(m["images"])[role])
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(?::[a-zA-Z0-9._-]+|(?::[a-zA-Z0-9._-]+)?@sha256:[a-f0-9]{64})$`).MatchString(ref) {
			return nil, errors.New("images_require_explicit_version_or_digest")
		}
	}
	central := common.M(m["central"])
	field = "central.public_url"
	public, e := url.Parse(common.S(central["public_url"]))
	if e != nil || public.Scheme != "https" || net.ParseIP(public.Hostname()) == nil || public.User != nil || public.RawQuery != "" || public.Fragment != "" || public.Path != "" && public.Path != "/" {
		return nil, errors.New("central_requires_ip_https_url")
	}
	event := common.M(central["event_service"])
	field = "central.public_url / central.event_service.https_port"
	if public.Port() != fmt.Sprint(common.I(event["https_port"])) {
		return nil, errors.New("central_https_port_mismatch")
	}
	for _, k := range []string{"install_dir", "data_dir", "log_dir", "backup_dir"} {
		field = "central." + k
		if e = ValidPath(common.S(central[k])); e != nil {
			return nil, e
		}
	}
	field = "central.install_dir / data_dir / log_dir / backup_dir"
	dirs := []string{}
	for _, k := range []string{"install_dir", "data_dir", "log_dir", "backup_dir"} {
		path := common.S(central[k])
		for _, prior := range dirs {
			if common.Inside(prior, path) || common.Inside(path, prior) {
				return nil, errors.New("central_directories_overlap")
			}
		}
		dirs = append(dirs, path)
	}
	grafana := common.M(central["grafana"])
	delete(grafana, "public_url")
	for _, key := range []string{"admin_username", "viewer_username"} {
		field = "central.grafana." + key
		if !regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`).MatchString(common.S(grafana[key])) {
			return nil, errors.New("invalid_grafana_username")
		}
	}
	for _, key := range []string{"admin_password", "viewer_password"} {
		field = "central.grafana." + key
		password := common.S(grafana[key])
		if password != "" && (len(password) < 8 || len(password) > 256 || strings.ContainsAny(password, "\x00\r\n")) {
			return nil, errors.New("invalid_grafana_password")
		}
	}
	field = "central.grafana.admin_username / central.grafana.viewer_username"
	if common.S(grafana["admin_username"]) == common.S(grafana["viewer_username"]) {
		return nil, errors.New("grafana_users_must_differ")
	}
	field = "central.event_service.port / https_port / central.grafana.host_port"
	ports := map[int]bool{}
	for _, p := range []int{common.I(event["port"]), common.I(event["https_port"]), common.I(grafana["host_port"]), 19190, 19193, 19110, 3100} {
		if p < 1024 || p > 65535 || ports[p] {
			return nil, errors.New("invalid_or_conflicting_central_port")
		}
		ports[p] = true
	}
	field = "central.event_service.bind_address"
	if common.S(event["bind_address"]) != "127.0.0.1" {
		return nil, errors.New("internal_service_must_bind_loopback")
	}
	field = "central.event_service.allowed_source_cidrs"
	for _, cidr := range common.SS(event["allowed_source_cidrs"]) {
		if _, _, e = net.ParseCIDR(cidr); e != nil {
			return nil, errors.New("invalid_allowed_source_cidr")
		}
	}
	defaults := common.M(m["node_defaults"])
	seen := map[string]bool{}
	for index, value := range common.A(m["nodes"]) {
		nodeField := fmt.Sprintf("nodes[%d]", index)
		field = nodeField + ".id"
		n := common.Merge(defaults, common.M(value))
		id := common.S(n["id"])
		if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(id) || seen[id] {
			return nil, errors.New("invalid_or_duplicate_node_id")
		}
		seen[id] = true
		field = nodeField + ".host"
		if net.ParseIP(common.S(n["host"])) == nil {
			return nil, errors.New("node_requires_ip_address")
		}
		ssh := common.M(n["ssh"])
		field = nodeField + ".ssh.port"
		if common.I(ssh["port"]) < 1 || common.I(ssh["port"]) > 65535 {
			return nil, errors.New("invalid_ssh_port")
		}
		field = nodeField + ".ssh.username"
		if common.S(ssh["username"]) != "root" {
			return nil, errors.New("node_ssh_requires_root")
		}
		field = nodeField + ".ssh.auth_method"
		switch common.S(ssh["auth_method"]) {
		case "key":
			field = nodeField + ".ssh.private_key_path"
			if !filepath.IsAbs(common.S(ssh["private_key_path"])) {
				return nil, errors.New("ssh_key_requires_absolute_path")
			}
		case "password":
			field = nodeField + ".ssh.password"
			if common.S(ssh["password"]) == "" {
				return nil, errors.New("ssh_password_required")
			}
		default:
			return nil, errors.New("invalid_ssh_auth_method")
		}
		field = nodeField + ".ssh.host_key_sha256"
		if pin := common.S(ssh["host_key_sha256"]); pin != "" && !strings.HasPrefix(pin, "SHA256:") {
			return nil, errors.New("ssh_host_fingerprint_invalid")
		}
		field = nodeField + ".resources"
		resources := common.M(n["resources"])
		memory, goMemory := common.I(resources["agent_memory_mib"]), common.I(resources["go_memory_mib"])
		if memory < 128 || memory > 8192 || goMemory < 32 || goMemory > memory-32 || common.F(resources["cpus"]) < 0.1 || common.F(resources["cpus"]) > 16 || common.I(resources["gomaxprocs"]) < 1 || common.I(resources["gomaxprocs"]) > 32 {
			return nil, errors.New("invalid_agent_resource_limits")
		}
		field = nodeField + ".monitor"
		p, e := common.NewPolicy(common.M(n["monitor"]))
		if e != nil {
			return nil, e
		}
		for index, root := range p.Roots {
			field = fmt.Sprintf("%s.monitor.roots[%d]", nodeField, index)
			if e = ValidPath(root); e != nil {
				return nil, e
			}
		}
		n["monitor"] = p.Monitor
		for _, tool := range []string{"yara", "clamav"} {
			field = nodeField + ".scan." + tool
			scan := common.M(common.M(n["scan"])[tool])
			if common.I(scan["workers"]) < 1 || common.I(scan["workers"]) > 16 || common.I(scan["timeout_seconds"]) < 1 || common.I(scan["timeout_seconds"]) > 600 || common.I(scan["max_file_mib"]) < 1 {
				return nil, errors.New("invalid_scan_limits")
			}
		}
		field = nodeField + ".monitor.reconciliation"
		reconcile := common.M(p.Monitor["reconciliation"])
		if common.I(reconcile["interval_hours"]) < 1 || common.I(reconcile["max_read_mib_per_second"]) < 1 {
			return nil, errors.New("invalid_reconciliation_limits")
		}
		field = nodeField + ".metrics.allowed_source_ip"
		metrics := common.M(n["metrics"])
		if net.ParseIP(common.S(metrics["allowed_source_ip"])) == nil {
			return nil, errors.New("metrics_allowed_source_requires_ip")
		}
		field = nodeField + ".metrics.port / tls_enabled"
		if common.I(metrics["port"]) < 1024 || common.I(metrics["port"]) > 65535 || !common.B(metrics["tls_enabled"]) {
			return nil, errors.New("metrics_require_tls_nonprivileged_port")
		}
		c.Nodes = append(c.Nodes, n)
	}
	field = "nodes"
	if len(c.Nodes) == 0 {
		return nil, errors.New("nodes_required")
	}
	field = "deployment.node_order"
	for _, id := range common.SS(common.M(m["deployment"])["node_order"]) {
		if !seen[id] {
			return nil, errors.New("unknown_node_order_id")
		}
	}
	for _, n := range c.Nodes {
		if common.B(n["enabled"]) && !common.Contains(common.SS(common.M(m["deployment"])["node_order"]), common.S(n["id"])) {
			return nil, errors.New("enabled_node_missing_from_order")
		}
	}
	field = "deployment.max_parallel_nodes"
	if common.I(common.M(m["deployment"])["max_parallel_nodes"]) != 1 {
		return nil, errors.New("serial_node_deployment_required")
	}
	if err = validateValues(m, ""); err != nil {
		return nil, err
	}
	if err = validateFeishu(common.M(m["feishu"])); err != nil {
		return nil, err
	}

	return c, nil
}
func ValidPath(path string) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") || common.Contains(strings.Split(path, "/"), "..") {
		return errors.New("invalid_absolute_path")
	}
	if common.Contains([]string{"/", "/etc", "/usr", "/var", "/root", "/home", "/www"}, filepath.Clean(path)) {
		return errors.New("path_too_broad")
	}
	return nil
}
func validateShape(actual, expected any, path string) error {
	switch schema := expected.(type) {
	case common.Map:
		obj, ok := actual.(common.Map)
		if !ok {
			return fmt.Errorf("expected_mapping_%s", path)
		}
		keys := make([]string, 0, len(obj))
		for key := range obj {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			v := obj[key]
			if path == "central.grafana." && key == "public_url" {
				continue
			}
			want, ok := schema[key]
			if !ok {
				return fmt.Errorf("unknown_field_%s%s", path, key)
			}
			if key == "nodes" && path == "" {
				list, ok := v.([]any)
				if !ok {
					return errors.New("nodes_must_be_list")
				}
				nodeSchema := common.Merge(common.M(schema["node_defaults"]), common.M(common.A(want)[0]))
				for i, n := range list {
					if e := validateShape(n, nodeSchema, fmt.Sprintf("nodes[%d].", i)); e != nil {
						return e
					}
				}
				continue
			}
			if e := validateShape(v, want, path+key+"."); e != nil {
				return e
			}
		}
	case []any:
		array, ok := actual.([]any)
		if !ok {
			return fmt.Errorf("expected_list_%s", path)
		}
		var item any = "" // Empty schema lists are lists of path/ID strings.
		if len(schema) > 0 {
			item = schema[0]
		}
		for i, v := range array {
			if e := validateShape(v, item, fmt.Sprintf("%s[%d].", strings.TrimSuffix(path, "."), i)); e != nil {
				return e
			}
		}
	case string:
		if _, ok := actual.(string); !ok {
			return fmt.Errorf("expected_string_%s", path)
		}
	case bool:
		if _, ok := actual.(bool); !ok {
			return fmt.Errorf("expected_boolean_%s", path)
		}
	case float64:
		switch actual.(type) {
		case int, float64:
		default:
			return fmt.Errorf("expected_number_%s", path)
		}
	case int:
		if _, ok := actual.(int); !ok {
			return fmt.Errorf("expected_integer_%s", path)
		}
	}
	return nil
}
func (c *Config) Image(role string) string {
	return strings.TrimRight(common.S(common.M(c.Raw["registry"])["prefix"]), "/") + "/" + common.S(common.M(c.Raw["images"])[role])
}
func (c *Config) CentralRoot() string {
	return filepath.Join(common.S(common.M(c.Raw["central"])["install_dir"]), "webscan-v1")
}
func (c *Config) Selected(node string) []common.Map {
	out := []common.Map{}
	for _, id := range common.SS(common.M(c.Raw["deployment"])["node_order"]) {
		for _, n := range c.Nodes {
			if common.S(n["id"]) == id && common.B(n["enabled"]) && (node == "" || node == id) {
				out = append(out, n)
			}
		}
	}
	return out
}

// Uninstall selection includes configured disabled nodes and nodes outside
// deployment.node_order, so their remaining services can also be removed.
func (c *Config) UninstallNodes(id string) []common.Map {
	out := []common.Map{}
	for _, n := range c.Nodes {
		if id == "" || common.S(n["id"]) == id {
			out = append(out, n)
		}
	}
	return out
}
func Redact(v any) any {
	switch x := v.(type) {
	case common.Map:
		m := common.Map{}
		for k, v := range x {
			if common.Contains([]string{"password", "admin_password", "viewer_password", "signing_secret", "webhook_url", "token", "alert_token"}, k) {
				continue
			}
			m[k] = Redact(v)
			if k == "registry" {
				delete(common.M(m[k]), "username")
			}
		}
		return m
	case []any:
		a := []any{}
		for _, v := range x {
			a = append(a, Redact(v))
		}
		return a
	default:
		return x
	}
}
