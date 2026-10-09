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
	for _, path := range []string{"central/data/grafana", "central/data/loki", "central/data/prometheus", "central/data/alertmanager", "central/backups"} {
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
		for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
			if err = copyCert(name, "central/config/pki/prometheus/"+name); err != nil {
				return err
			}
		}

	}
	central := common.M(c.Raw["central"])
	runtime := CentralRuntime(c, secrets, active)
	runtime["feishu"] = f
	if c.SSLEnabled() {
		for _, entry := range []string{"ca.crt"} {
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
	password := common.S(g["admin_password"])
	if password == "" {
		password = common.ID() + common.ID()[:8]
	}
	centralFiles := map[string][]byte{
		"website-credentials.json":      common.JSON(common.Map{"url": WebsiteURL(c), "username": secrets["website_username"], "password": secrets["website_password"], "initialization_only": true}),
		"config/runtime.json":           common.JSON(runtime),
		"config/alert-token":            []byte(common.S(secrets["alert_token"])),
		"config/prometheus.yml":         YAML(Prometheus(c, active)),
		"config/rules.yml":              YAML(AlertRules(c)),
		"config/alertmanager.yml":       YAML(Alertmanager(c)),
		"config/loki.yml":               YAML(LokiConfig(c)),
		"config/grafana.ini":            GrafanaINI(c),
		"config/grafana.env":            []byte("GF_SECURITY_ADMIN_USER=" + common.S(g["admin_username"]) + "\nGF_SECURITY_ADMIN_PASSWORD__FILE=/etc/grafana/admin-password\n"),
		"config/grafana-admin-password": []byte(password),
		"grafana-credentials.json":      common.JSON(common.Map{"admin_username": g["admin_username"], "admin_password": password}),
	}
	for name, data := range centralFiles {
		if err = write("central/"+name, data); err != nil {
			return err
		}
	}
	centralCompose := ComposeCentral(c, images)
	standaloneImage(common.M(common.M(centralCompose["services"])["receiver"]), common.S(images["central"]))
	if !c.SSLEnabled() {
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
	if err = write("central/services.yaml", YAML(centralCompose)); err != nil {
		return err
	}
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
	exporterConfig := ExporterWebConfig(c)
	for name, b := range map[string][]byte{"runtime.json": common.JSON(runtime), "php-webshell.yar": yara, "vector.yml": YAML(VectorConfig(c, n, secrets)), "exporter.yml": YAML(exporterConfig)} {
		if err := write(id+"/config/"+name, b); err != nil {
			return err
		}
	}
	compose := ComposeAgent(c, n, common.S(images["agent"]))
	compose["name"] = "webscan-compose-" + id
	services := common.M(compose["services"])
	agent := common.M(services["agent"])
	standaloneImage(agent, common.S(images["agent"]))
	// All three services use the host network, as the existing deployment does.
	vector := service(common.S(images["vector"]))
	vector["container_name"] = "webscan-vector-v1"
	vector["network_mode"] = "host"
	vector["user"] = "0:0"
	vector["volumes"] = []string{"/etc/webscan-v1/vector.yml:/etc/vector/vector.yaml:ro", "/var/log/webscan-v1:/var/log/webscan-v1:ro", "/var/lib/webscan-vector-v1:/var/lib/vector"}
	if c.SSLEnabled() {
		vector["volumes"] = append(common.SS(vector["volumes"]), "/etc/webscan-v1/pki/ca.crt:/etc/webscan-v1/pki/ca.crt:ro")
	}
	vector["depends_on"] = []string{"agent"}
	exporter := service(common.S(images["exporter"]))
	exporter["container_name"] = "webscan-exporter-v1"
	exporter["network_mode"] = "host"
	exporter["user"] = "0:0"
	exporter["pid"] = "host"
	exporter["command"] = []string{"--web.listen-address=:" + strconv.Itoa(common.I(common.M(n["metrics"])["port"])), "--web.config.file=/etc/webscan-v1/exporter.yml", "--path.procfs=/host/proc", "--path.sysfs=/host/sys", "--path.rootfs=/rootfs", "--collector.textfile.directory=/textfile"}
	exporter["volumes"] = []string{"/proc:/host/proc:ro", "/sys:/host/sys:ro", "/:/rootfs:ro,rslave", "/var/lib/webscan-v1/textfile:/textfile:ro", "/etc/webscan-v1/exporter.yml:/etc/webscan-v1/exporter.yml:ro"}
	if c.SSLEnabled() {
		exporter["volumes"] = append(common.SS(exporter["volumes"]), "/etc/webscan-v1/pki:/etc/webscan-v1/pki:ro")
	}
	services["vector"], services["exporter"] = vector, exporter
	probe := common.S(common.M(c.Raw["health"])["probe_directory"])
	for _, s := range []common.Map{agent, vector, exporter} {
		s["platform"] = "linux/amd64"
		packageMounts(s, map[string]string{"/etc/webscan-v1": "./config", "/var/lib/webscan-v1": "./data", "/var/log/webscan-v1": "./logs", "/var/lib/webscan-vector-v1": "./vector-data", probe: "./probe"})
	}
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
