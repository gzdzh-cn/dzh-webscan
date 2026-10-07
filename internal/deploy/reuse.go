package deploy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"webscan/internal/common"
)

// Existing deployments use the legacy container names and bind provisioning.
// Foreign services are only touched when explicitly selected for reuse.
func (d *Deploy) detectReuse(ctx context.Context) error {
	reuse := common.M(common.M(d.C.Raw["central"])["reuse_existing"])
	var networks map[string]bool
	for _, role := range []string{"grafana", "loki"} {
		if !common.B(reuse[role]) {
			continue
		}
		b, err := RunCommand(ctx, nil, "docker", "inspect", "webscan-"+role)
		if err != nil {
			return fmt.Errorf("existing_%s_container_required", role)
		}
		value, err := common.Decode(b)
		if err != nil {
			return err
		}
		items := common.A(value)
		if len(items) != 1 {
			return errors.New("existing_container_inspection_failed")
		}
		info := common.M(items[0])
		available := map[string]bool{}
		for name := range common.M(common.M(info["NetworkSettings"])["Networks"]) {
			if !common.Contains([]string{"host", "bridge", "none"}, name) {
				available[name] = true
			}
		}
		if networks == nil {
			networks = available
		} else {
			for name := range networks {
				if !available[name] {
					delete(networks, name)
				}
			}
		}
		if role == "loki" {
			d.State["external_loki_url"] = "http://webscan-loki:3100"
			continue
		}
		g := common.M(common.M(d.C.Raw["central"])["grafana"])
		bindings := common.A(common.M(common.M(info["HostConfig"])["PortBindings"])["3000/tcp"])
		matched := false
		for _, value := range bindings {
			binding := common.M(value)
			matched = matched || common.S(binding["HostPort"]) == fmt.Sprint(common.I(g["host_port"])) && (common.S(binding["HostIp"]) == common.S(g["bind_address"]) || common.S(binding["HostIp"]) == "" && common.S(g["bind_address"]) == "0.0.0.0")
		}
		if !matched {
			return errors.New("existing_grafana_port_must_match_yaml")
		}
		env := map[string]string{}
		for _, line := range common.SS(common.M(info["Config"])["Env"]) {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				env[key] = value
			}
		}
		user, password := common.S(g["admin_username"]), common.S(g["admin_password"])
		if password == "" {
			password = env["GF_SECURITY_ADMIN_PASSWORD"]
		}
		if user == "" {
			user = env["GF_SECURITY_ADMIN_USER"]
		}
		if user == "" {
			user = "admin"
		}
		v, err := d.grafana(ctx, "GET", "/api/user", nil, auth(user, password))
		if err != nil || !common.B(common.M(v)["isGrafanaAdmin"]) {
			return errors.New("existing_grafana_credentials_required_in_yaml")
		}
		d.Secrets["admin_username"], d.Secrets["admin_password"] = user, password
		for _, mount := range common.A(info["Mounts"]) {
			m := common.M(mount)
			if common.S(m["Destination"]) == "/etc/grafana/provisioning" && common.S(m["Type"]) == "bind" && common.B(m["RW"]) {
				path := common.S(m["Source"])
				if !filepath.IsAbs(path) || validPath(path) != nil {
					return errors.New("existing_grafana_provisioning_path_invalid")
				}
				d.State["grafana_provision"] = path
			}
		}
		if common.S(d.State["grafana_provision"]) == "" {
			return errors.New("existing_grafana_writable_bind_provisioning_required")
		}
	}
	if networks != nil {
		for name := range networks {
			d.State["external_network"] = name
			return nil
		}
		return errors.New("reused_services_require_shared_user_defined_network")
	}
	return nil
}
