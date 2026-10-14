package deploy

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/website"
)

// AdoptCompose is an explicit host command. It records the existing package
// layout and immutable image identities before enabling the host supervisor.
func AdoptCompose(ctx context.Context, path string) error {
	if os.Geteuid() != 0 {
		return errors.New("接管 Compose 需要在主服务器以 root 执行")
	}
	if e := requireManagementHost(); e != nil {
		return e
	}
	absolute, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	base := filepath.Dir(absolute)
	if e = os.MkdirAll(StateRoot, 0700); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(StateRoot, "deploy.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("存在正在执行的部署")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if state, e := common.ReadJSON(stateFile()); e == nil && common.S(state["step"]) == "compose-adoption-pending" {
		if common.S(state["adoption_config"]) != absolute {
			return errors.New("请保持原 Compose 配置路径继续")
		}
		c, e := Load(absolute)
		if e != nil {
			return e
		}
		secrets, e := common.ReadJSON(filepath.Join(StateRoot, "credentials.json"))
		if e != nil {
			return e
		}
		return finishAdoption(ctx, c, absolute, state, secrets)
	}
	if PendingState() {
		return errors.New("存在已有部署或未完成任务，请先使用原部署入口")
	}
	if state, e := common.ReadJSON(stateFile()); e == nil && common.B(state["central_installed"]) {
		return errors.New("主服务器已受管理，不重复接管")
	}
	c, e := Load(absolute)
	if e != nil {
		return e
	}
	if !Native(c) {
		return errors.New("请先迁移旧组件，当前接管入口只接受新的 Go Compose 包")
	}
	if c.SSLEnabled() {
		pki := filepath.Join(base, "config", "pki")
		info, e := os.Lstat(filepath.Join(pki, "ca.key"))
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("HTTPS Compose 接管前，请把生成包 private/ca.key 安全复制到主服务器 config/pki/ca.key，并设置权限 0600；不能生成新 CA 替换现有节点证书")
		}
		if _, e = tls.LoadX509KeyPair(filepath.Join(pki, "ca.crt"), filepath.Join(pki, "ca.key")); e != nil {
			return errors.New("Compose CA 私钥与原证书不匹配")
		}
	}
	oldRuntime, e := common.ReadJSON(filepath.Join(base, "config", "runtime.json"))
	if e != nil {
		return e
	}
	raw, e := os.ReadFile(filepath.Join(base, "services.yaml"))
	if e != nil {
		return e
	}
	var oldCompose common.Map
	if e = yaml.Unmarshal(raw, &oldCompose); e != nil {
		return e
	}
	center := common.M(c.Raw["central"])
	center["managed_runtime_dir"] = filepath.Join(base, "config")
	center["managed_compose_name"] = common.S(oldCompose["name"])
	center["install_dir"] = base
	center["data_dir"] = filepath.Join(base, "data")
	center["backup_dir"] = filepath.Join(base, "backups")
	center["log_dir"] = filepath.Join(base, "logs")
	if !strings.HasPrefix(common.S(center["managed_compose_name"]), "webscan-") {
		return errors.New("不是本项目的 Compose 部署包")
	}
	if e = os.MkdirAll(StateRoot, 0700); e != nil {
		return e
	}
	original, e := os.ReadFile(absolute)
	if e != nil {
		return e
	}
	backup := filepath.Join(base, "backups", "before-management-"+common.ID())
	if e = os.MkdirAll(backup, 0700); e != nil {
		return e
	}
	for name, data := range map[string][]byte{"management.yaml": original, "services.yaml": raw, "runtime.json": common.JSON(oldRuntime)} {
		if e = common.Atomic(filepath.Join(backup, name), data, 0600); e != nil {
			return e
		}
	}
	db, e := persist.OpenDB(filepath.Join(base, "data", "events-v1.sqlite3"))
	if e != nil {
		return e
	}
	e = persist.BackupDB(db, filepath.Join(backup, "events.sqlite3"))
	db.Close()
	if e != nil {
		return e
	}
	docker, e := NewDocker(ctx, c, false)
	if e != nil {
		return e
	}
	defer docker.Close()
	images := common.Map{}
	for name, role := range map[string]string{"receiver": "central", "host-exporter": "exporter"} {
		service := common.M(common.M(oldCompose["services"])[name])
		ref, e := docker.Resolve(ctx, common.S(service["image"]))
		if e != nil {
			return e
		}
		images[role] = ref
	}
	secrets := common.Map{"alert_token": oldRuntime["alert_token"], "website_username": common.M(oldRuntime["website_monitor"])["admin_username"], "website_password_hash": common.M(oldRuntime["website_monitor"])["password_hash"], "nodes": common.Map{}}
	active := common.SS(oldRuntime["active_nodes"])
	for id, v := range common.M(oldRuntime["nodes"]) {
		common.M(secrets["nodes"])[id] = common.Map{"token": common.M(v)["token"]}
	}
	state := common.Map{"nodes": common.Map{}, "active": active, "central_installed": true, "step": "complete", "go_release": Release, "central_runtime_release": Release, "image_lock": images, "configuration": Redact(c.Raw), "config_hash": common.Hash(common.JSON(Redact(c.Raw))), "managed_networks": oldCompose["networks"]}
	state["adoption_config"] = absolute
	state["adoption_backup"] = backup
	if e = websiteSeedCredentials(c, secrets); e != nil {
		return e
	}
	// No node software is changed. The new central mounts the same host data directory.
	for _, n := range c.Nodes {
		if common.Contains(active, common.S(n["id"])) {
			common.M(state["nodes"])[common.S(n["id"])] = common.Map{"phase": "complete", "go_release": Release}
		}
	}
	d := &Deploy{C: c, O: Options{Config: absolute}, State: state, Secrets: secrets, Images: images, Docker: docker}
	if e = d.InstallManagement(ctx); e != nil {
		return e
	}
	if e = common.Atomic(absolute, YAML(c.Raw), 0600); e != nil {
		return e
	}
	// Persist state and credentials before restarting: interruption remains recoverable.
	state["step"] = "compose-adoption-pending"
	if e = common.AtomicJSON(filepath.Join(StateRoot, "credentials.json"), secrets); e != nil {
		return e
	}
	if e = d.save(); e != nil {
		return e
	}
	return finishAdoption(ctx, c, absolute, state, secrets)
}

// Restore the package layout while preserving the current databases and account.
func rollbackAdoption(ctx context.Context, c *Config, state common.Map) error {
	path := common.S(state["adoption_config"])
	base := filepath.Dir(path)
	backup := common.S(state["adoption_backup"])
	if path == "" || backup == "" {
		return errors.New("Compose 接管回退记录缺失")
	}
	lock, e := os.OpenFile(filepath.Join(StateRoot, "deploy.lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return errors.New("存在正在执行的部署")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if _, e = RunCommand(ctx, nil, "docker", "compose", "-f", filepath.Join(base, "services.yaml"), "stop", "receiver"); e != nil {
		return e
	}
	account, accountErr := website.AccountAt(filepath.Join(base, "data", "events-v1.sqlite3"))
	if accountErr != nil && accountErr != sql.ErrNoRows {
		return accountErr
	}
	for name, target := range map[string]string{"management.yaml": path, "runtime.json": filepath.Join(base, "config", "runtime.json"), "services.yaml": filepath.Join(base, "services.yaml")} {
		raw, e := os.ReadFile(filepath.Join(backup, name))
		if e != nil {
			return e
		}
		if e = common.Atomic(target, raw, 0600); e != nil {
			return e
		}
	}
	if accountErr == nil {
		if e = preserveWebsiteAccount(filepath.Join(base, "config", "runtime.json"), account); e != nil {
			return e
		}
	}
	if _, e = RunCommand(ctx, nil, "systemctl", "disable", "--now", "webscan-management"); e != nil {
		return errors.New("Compose 服务已恢复，但宿主机管理服务停止失败；请执行 systemctl disable --now webscan-management 后重试回退")
	}
	state["central_installed"] = false
	state["step"] = "rolled-back"
	if e = common.AtomicJSON(stateFile(), state); e != nil {
		return e
	}
	if _, e = RunCommand(ctx, nil, "docker", "compose", "-f", filepath.Join(base, "services.yaml"), "up", "-d", "--force-recreate", "receiver"); e != nil {
		return e
	}
	return nil
}
func finishAdoption(ctx context.Context, c *Config, path string, state, secrets common.Map) error {
	base := filepath.Dir(path)
	d := &Deploy{C: c, O: Options{Config: path}, State: state, Secrets: secrets, Images: common.M(state["image_lock"])}
	compose := ComposeCentral(c, d.Images)
	compose["name"] = common.M(c.Raw["central"])["managed_compose_name"]
	compose["networks"] = state["managed_networks"]
	active := common.SS(state["active"])
	h, e := common.HTTPClient("", 15e9)
	if e != nil {
		return e
	}
	d.HTTP = h
	defer h.CloseIdleConnections()
	runtime := CentralRuntime(c, secrets, active)
	common.M(runtime["monitoring"])["verify_after"] = time.Now().Unix()
	if e = common.AtomicJSON(filepath.Join(c.CentralRoot(), "runtime.json"), runtime); e != nil {
		return e
	}
	if e = common.Atomic(filepath.Join(c.CentralRoot(), "compose.yml"), YAML(compose), 0600); e != nil {
		return e
	}
	if e = common.Atomic(filepath.Join(base, "services.yaml"), YAML(compose), 0600); e != nil {
		return e
	}
	if _, e = d.compose(ctx, "up", "-d", "--force-recreate", "receiver"); e != nil {
		return e
	}
	if e = d.waitReady(ctx); e != nil {
		return e
	}
	if e = d.verifyWebsite(ctx); e != nil {
		return e
	}
	if e = d.waitNativeMetrics(ctx); e != nil {
		return e
	}
	state["step"] = "complete"
	return d.save()
}
func PendingState() bool {
	state, e := common.ReadJSON(stateFile())
	if os.IsNotExist(e) {
		return false
	}
	if e != nil {
		return true
	}
	step := common.S(state["step"])
	return step != "" && step != "complete" && step != "rolled-back"
}
