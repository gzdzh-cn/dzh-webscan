package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"webscan/internal/assets"
	"webscan/internal/common"
)

// ValidateComposeConfiguration checks prerequisites without contacting servers.
func ValidateComposeConfiguration(c *Config) error {
	if common.B(common.M(common.M(c.Raw["central"])["reuse_existing"])["grafana"]) || common.B(common.M(common.M(c.Raw["central"])["reuse_existing"])["loki"]) {
		return errors.New("compose_fresh_packages_do_not_reuse_external_components")
	}
	if common.B(common.M(c.Raw["registry"])["auth_required"]) {
		return errors.New("compose_packages_require_public_registry")
	}
	for _, n := range c.Selected("") {
		if common.Contains([]string{"central", "private"}, common.S(n["id"])) {
			return errors.New("compose_node_id_collides_with_package_directory")
		}
	}
	if common.S(common.M(c.Raw["registry"])["prefix"]) != "docker.io/gzdzh" {
		return errors.New("compose_packages_require_dockerhub_gzdzh")
	}
	_, err := resolvedFeishu(common.M(c.Raw["feishu"]))
	return err
}

// PrepareCompose makes fresh standalone packages. It does not invoke Docker,
// SSH, the deployment journal, or an API, and never exports registry/SSH secrets.
func PrepareCompose(c *Config, output string, launcher []byte) error {
	if err := ValidateComposeConfiguration(c); err != nil {
		return err
	}
	dir, err := filepath.Abs(output)
	if err != nil {
		return errors.New("compose_output_path_invalid")
	}
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		return errors.New("compose_output_exists_use_new_directory")
	}
	if err = os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return errors.New("compose_output_parent_unwritable")
	}
	stage, err := os.MkdirTemp(filepath.Dir(dir), ".webscan-compose-")
	if err != nil {
		return errors.New("compose_staging_failed")
	}
	defer os.RemoveAll(stage)
	if err = prepareComposeFiles(c, stage, launcher); err != nil {
		return err
	}
	// All files are prepared before the output becomes visible. Refuse replacement.
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		return errors.New("compose_output_exists_use_new_directory")
	}
	if err = os.Rename(stage, dir); err != nil {
		return errors.New("compose_output_publish_failed")
	}
	return nil
}

func prepareComposeFiles(c *Config, base string, launcher []byte) error {
	write := func(path string, data []byte) error {
		if err := common.Atomic(filepath.Join(base, path), data, 0600); err != nil {
			return errors.New("compose_file_write_failed")
		}
		return nil
	}
	selected := c.Selected("")
	paths := []string{"central/data", "central/backups"}
	if !Native(c) {
		paths = append(paths, "central/data/grafana", "central/data/loki", "central/data/prometheus", "central/data/alertmanager")
	}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Join(base, path), 0700); err != nil {
			return errors.New("compose_data_directory_failed")
		}
	}
	for _, n := range selected {
		for _, path := range []string{"data/textfile", "logs", "probe", "vector-data"} {
			if err := os.MkdirAll(filepath.Join(base, common.S(n["id"]), path), 0700); err != nil {
				return errors.New("compose_data_directory_failed")
			}
		}
	}
	active := []string{}
	secrets := common.Map{"alert_token": common.ID() + common.ID(), "nodes": common.Map{}}
	if err := websiteSeedCredentials(c, secrets); err != nil {
		return err
	}
	for _, n := range selected {
		id := common.S(n["id"])
		active = append(active, id)
		common.M(secrets["nodes"])[id] = common.Map{"token": common.ID() + common.ID()}
	}
	f, err := resolvedFeishu(common.M(c.Raw["feishu"]))
	if err != nil {
		return err
	}
	images := common.Map{"central": c.Image("central"), "agent": c.Image("agent")}
	for role, image := range VendorImages {
		images[role] = "docker.io/" + image
	}
	// Issue certificates into the package, rather than /opt on this local machine.
	certConfig := &Config{Raw: common.Clone(c.Raw), Nodes: c.Nodes}
	common.M(certConfig.Raw["central"])["install_dir"] = filepath.Join(base, ".certificates")
	if err = certificates(certConfig); err != nil {
		return errors.New("compose_certificate_generation_failed")
	}
	certDir := filepath.Join(certConfig.CentralRoot(), "pki")
	copyCert := func(source, target string) error {
		b, err := os.ReadFile(filepath.Join(certDir, source))
		if err != nil {
			return errors.New("compose_certificate_read_failed")
		}
		return write(target, b)
	}
	// The CA private key is retained only in a private local directory, never in a
	// host package. Node packages contain only that node's metrics server key.
	if c.SSLEnabled() {
		if err = copyCert("ca.key", "private/ca.key"); err != nil {
			return err
		}
		if err = copyCert("ca.crt", "private/ca.crt"); err != nil {
			return err
		}
		if !Native(c) {
			for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
				if err = copyCert(name, "central/config/pki/prometheus/"+name); err != nil {
					return err
				}
			}
		}

	}
	central := common.M(c.Raw["central"])
	runtime := CentralRuntime(c, secrets, active)
	runtime["feishu"] = f
	runtime["management_socket"] = ""
	if c.SSLEnabled() {
		for _, entry := range []string{"ca.crt", "client.crt", "client.key"} {
			if err = copyCert(entry, "central/config/pki/"+entry); err != nil {
				return err
			}
		}
		// ReceiverRuntime's cert names use the public IP; take them from its output.
		https := common.M(runtime["https"])
		for _, key := range []string{"cert_file", "key_file"} {
			name := filepath.Base(common.S(https[key]))
			if err = copyCert(name, "central/config/pki/"+name); err != nil {
				return err
			}
		}

	}
	g := common.M(central["grafana"])
	centralFiles := map[string][]byte{
		"website-credentials.json": common.JSON(common.Map{"url": WebsiteURL(c), "username": secrets["website_username"], "password": secrets["website_password"], "initialization_only": true}),
		"config/runtime.json":      common.JSON(runtime),
		"config/alert-token":       []byte(common.S(secrets["alert_token"])),
	}
	if !Native(c) {
		password := common.S(g["admin_password"])
		if password == "" {
			password = common.ID() + common.ID()[:8]
		}
		for name, data := range map[string][]byte{
			"config/prometheus.yml":         YAML(Prometheus(c, active)),
			"config/rules.yml":              YAML(AlertRules(c)),
			"config/alertmanager.yml":       YAML(Alertmanager(c)),
			"config/loki.yml":               YAML(LokiConfig(c)),
			"config/grafana.ini":            GrafanaINI(c),
			"config/grafana.env":            []byte("GF_SECURITY_ADMIN_USER=" + common.S(g["admin_username"]) + "\nGF_SECURITY_ADMIN_PASSWORD__FILE=/etc/grafana/admin-password\n"),
			"config/grafana-admin-password": []byte(password),
			"grafana-credentials.json":      common.JSON(common.Map{"admin_username": g["admin_username"], "admin_password": password}),
		} {
			centralFiles[name] = data
		}
	}
	for name, data := range centralFiles {
		if err = write("central/"+name, data); err != nil {
			return err
		}
	}
	centralCompose := ComposeCentral(c, images)
	standaloneImage(common.M(common.M(centralCompose["services"])["receiver"]), common.S(images["central"]))
	if !Native(c) && !c.SSLEnabled() {
		prometheus := common.M(common.M(centralCompose["services"])["prometheus"])
		filtered := []string{}
		for _, mount := range common.SS(prometheus["volumes"]) {
			if !strings.Contains(mount, "/pki/prometheus:") {
				filtered = append(filtered, mount)
			}
		}
		prometheus["volumes"] = filtered
	}
	centralCompose["name"] = "webscan-compose-central"
	// Avoid colliding with a SH-managed stack on the same host/network.
	common.M(common.M(centralCompose["networks"])["monitor"])["name"] = "webscan-compose-monitor"
	for _, v := range common.M(centralCompose["services"]) {
		s := common.M(v)
		s["platform"] = "linux/amd64"
		volumes := []string{}
		for _, v := range common.SS(s["volumes"]) {
			if !strings.HasPrefix(v, "/run/webscan-management:") {
				volumes = append(volumes, v)
			}
		}
		s["volumes"] = volumes
		packageMounts(s, map[string]string{
			c.CentralRoot():                 "./config",
			common.S(central["data_dir"]):   "./data",
			common.S(central["backup_dir"]): "./backups",
		})
		if env, ok := s["env_file"]; ok {
			paths := []string{}
			for _, path := range common.SS(env) {
				paths = append(paths, "./config/"+filepath.Base(path))
			}
			s["env_file"] = paths
		}
	}
	hostConfig := common.Clone(c.Raw)
	hostConfig["feishu"] = f
	for _, v := range common.A(hostConfig["nodes"]) {
		ssh := common.M(common.M(v)["ssh"])
		ssh["password"] = ""
		if common.S(ssh["auth_method"]) == "password" {
			ssh["auth_method"] = "key"
			ssh["private_key_path"] = "/root/.ssh/id_ed25519"
		}
	}
	defaults := common.M(common.M(hostConfig["node_defaults"])["ssh"])
	defaults["password"] = ""
	if common.S(defaults["auth_method"]) == "password" {
		defaults["auth_method"] = "key"
		defaults["private_key_path"] = "/root/.ssh/id_ed25519"
	}
	common.M(hostConfig["registry"])["password"] = ""
	common.M(hostConfig["registry"])["username"] = ""
	if Native(c) {
		helper := `#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 && $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo '请在 Linux amd64 主服务器以 root 执行' >&2; exit 1; }
base=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$base"
[[ -f management.yaml && ! -L management.yaml ]] || { echo 'management.yaml 缺失或不是普通文件' >&2; exit 1; }
chmod 600 management.yaml
mkdir -p /usr/local/lib/webscan
chmod 700 /usr/local/lib/webscan
image=$(docker compose -f services.yaml images -q receiver)
[[ -n $image ]] || { echo '请先启动本包 receiver 容器' >&2; exit 1; }
container=$(docker create "$image")
trap 'docker rm "$container" >/dev/null 2>&1 || true' EXIT
docker cp "$container:/usr/local/bin/webscan" /usr/local/lib/webscan/adoption-tool
chmod 700 /usr/local/lib/webscan/adoption-tool
/usr/local/lib/webscan/adoption-tool adopt-compose --config "$base/management.yaml"
echo '宿主机管理接管完成；刷新后台可管理配置及节点。'
`
		if err = write("central/enable-management.sh", []byte(helper)); err != nil {
			return err
		}
	}
	if err = write("central/management.yaml", YAML(hostConfig)); err != nil {
		return err
	}
	if err = write("central/services.yaml", YAML(centralCompose)); err != nil {
		return err
	}
	if !Native(c) {
		provision := common.Map{"apiVersion": 1, "datasources": []any{
			common.Map{"name": "Webscan Prometheus", "uid": "webscan-prom", "type": "prometheus", "access": "proxy", "url": "http://webscan-v1-prometheus:19190", "editable": false},
			common.Map{"name": "Webscan Loki", "uid": "webscan-loki", "type": "loki", "access": "proxy", "url": "http://loki:3100", "editable": false},
		}}
		if err = write("central/config/provisioning/datasources/webscan.yml", YAML(provision)); err != nil {
			return err
		}
		providers := common.Map{"apiVersion": 1, "providers": []any{common.Map{"name": "webscan", "type": "file", "options": common.Map{"path": "/etc/grafana/provisioning/webscan-dashboards"}, "disableDeletion": true}}}
		if err = write("central/config/provisioning/dashboards/webscan.yml", YAML(providers)); err != nil {
			return err
		}
		entries, _ := assets.Files.ReadDir(".")
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), "dashboard-") {
				continue
			}
			b, err := assets.Files.ReadFile(entry.Name())
			if err != nil {
				return errors.New("compose_dashboard_read_failed")
			}
			v, err := common.Decode(b)
			if err != nil {
				return err
			}
			dashboard := common.M(v)
			dashboard["timezone"] = g["timezone"]
			if err = write("central/config/provisioning/webscan-dashboards/"+strings.TrimPrefix(entry.Name(), "dashboard-"), common.JSON(dashboard)); err != nil {
				return err
			}
		}
	}
	if err = writeLauncher(write, "central", launcher); err != nil {
		return err
	}
	for _, n := range selected {
		if err = prepareNodeCompose(c, n, secrets, images, write, copyCert, launcher); err != nil {
			return err
		}
	}
	// Staging certificates include other nodes' keys. Do not leave a duplicate set.
	if err = os.RemoveAll(filepath.Join(base, ".certificates")); err != nil {
		return errors.New("compose_certificate_staging_cleanup_failed")
	}
	return nil
}

func writeLauncher(write func(string, []byte) error, host string, launcher []byte) error {
	if err := write(host+"/compose.yaml", launcher); err != nil {
		return err
	}
	return write(host+"/.env", []byte("WEBSCAN_COMPOSE_FILE=./services.yaml\nWEBSCAN_COMPOSE_PROJECT=webscan-compose-"+host+"\n"))
}

// Long bind syntax catches missing config/website paths instead of creating
// empty directories. Data directories are created explicitly by the generator.
func packageMounts(s common.Map, mapping map[string]string) {
	out := []any{}
	for _, mount := range common.SS(s["volumes"]) {
		parts := strings.SplitN(mount, ":", 3)
		source := parts[0]
		for host, relative := range mapping {
			if source == host || strings.HasPrefix(source, host+"/") {
				source = relative + strings.TrimPrefix(source, host)
				break
			}
		}
		bind := common.Map{"create_host_path": false}
		m := common.Map{"type": "bind", "source": strings.ReplaceAll(source, "$", "$$"), "target": strings.ReplaceAll(parts[1], "$", "$$"), "bind": bind}
		if len(parts) == 3 {
			for _, option := range strings.Split(parts[2], ",") {
				if option == "ro" {
					m["read_only"] = true
				}
				if option == "rslave" {
					bind["propagation"] = "rslave"
				}
			}
		}
		out = append(out, m)
	}
	s["volumes"] = out
}

func prepareNodeCompose(c *Config, n, secrets, images common.Map, write func(string, []byte) error, copyCert func(string, string) error, launcher []byte) error {
	id := common.S(n["id"])
	if c.SSLEnabled() {
		for source, target := range map[string]string{"ca.crt": "ca.crt", id + ".crt": "server.crt", id + ".key": "server.key"} {
			if err := copyCert(source, id+"/config/pki/"+target); err != nil {
				return err
			}
		}

	}
	runtime := NodeRuntime(c, n, secrets)
	yara, err := assets.Files.ReadFile("php-webshell.yar")
	if err != nil {
		return errors.New("compose_yara_read_failed")
	}
	runtime["deployment_mode"] = nodeMode(n)
	runtime["clamav_config"] = "/etc/webscan-v1/clamd.conf"
	if nodeMode(n) == "native" {
		runtime["host_metrics"] = common.Map{"proc": "/proc", "sys": "/sys", "root": "/"}
		runtime["scanner_tools"] = common.Map{"yara": "/opt/webscan-go/standalone/tools/bin/yara", "clamav": "/opt/webscan-go/standalone/tools/bin/clamdscan"}
	}
	for name, b := range map[string][]byte{"runtime.json": common.JSON(runtime), "php-webshell.yar": yara, "clamd.conf": []byte("LocalSocket /run/clamav/clamd.ctl\n")} {
		if err := write(id+"/config/"+name, b); err != nil {
			return err
		}
	}
	if nodeMode(n) == "native" {
		script, e := assets.Files.ReadFile("install-native-node.sh")
		if e != nil {
			return e
		}
		if e = write(id+"/install-native.sh", append([]byte("TASK_CLAMAV="+strconv.FormatBool(common.B(common.M(common.M(n["scan"])["clamav"])["enabled"]))+"\n"), script...)); e != nil {
			return e
		}
		if e = write(id+"/webscan-agent-native.service", []byte(NativeNodeUnit(n, "/opt/webscan-go/standalone"))); e != nil {
			return e
		}
		probe := common.S(common.M(c.Raw["health"])["probe_directory"])
		if e = write(id+"/prepare-directories.sh", []byte("#!/bin/bash\nset -eu\numask 077\nmkdir -p "+Q(probe)+"\n")); e != nil {
			return e
		}
		return write(id+"/README.md", []byte("# 直接运行 Go\n从同版本主服务器镜像取得 agent-native.tar.gz 与 SHA256，复制到本机。执行 `bash install-native.sh agent-native.tar.gz <SHA256>`。无需 Docker；仅用于全新安装，升级及切换方式请使用中心后台。配置和凭据仅限 root；开启 ClamAV 需已有扫描服务。\n"))
	}
	compose := ComposeAgent(c, n, common.S(images["agent"]))
	compose["name"] = "webscan-compose-" + id
	services := common.M(compose["services"])
	agent := common.M(services["agent"])
	standaloneImage(agent, common.S(images["agent"]))
	probe := common.S(common.M(c.Raw["health"])["probe_directory"])
	agent["platform"] = "linux/amd64"
	packageMounts(agent, map[string]string{"/etc/webscan-v1": "./config", "/var/lib/webscan-v1": "./data", "/var/log/webscan-v1": "./logs", probe: "./probe"})
	if err := write(id+"/services.yaml", YAML(compose)); err != nil {
		return err
	}
	return writeLauncher(write, id, launcher)
}

// Offline packages have not pulled or pinned images on the destination host.
// Let Compose fetch the configured reference; explicit digests stay explicit.
func standaloneImage(service common.Map, image string) {
	service["image"] = image
	delete(service, "pull_policy")
	delete(common.M(service["labels"]), imageLockLabel)
}
