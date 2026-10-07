package deploy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
)

func (d *Deploy) grafanaAPI() string {
	g := common.M(common.M(d.C.Raw["central"])["grafana"])
	host := "127.0.0.1"
	if bind := common.S(g["bind_address"]); bind != "0.0.0.0" && bind != "127.0.0.1" {
		host = bind
	}
	return "http://" + host + ":" + strconv.Itoa(common.I(g["host_port"]))
}
func auth(user, password string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))}
}
func (d *Deploy) grafana(ctx context.Context, method, path string, payload any, headers map[string]string) (any, error) {
	_, v, e := common.Request(ctx, d.HTTP, method, d.grafanaAPI()+path, payload, headers)
	return v, e
}
func (d *Deploy) ConfigureGrafana(ctx context.Context) error {
	g := common.M(common.M(d.C.Raw["central"])["grafana"])
	headers := auth(common.S(d.Secrets["admin_username"]), common.S(d.Secrets["admin_password"]))
	deadline := time.Now().Add(180 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		health, e := d.grafana(ctx, "GET", "/api/health", nil, nil)
		if e == nil && common.S(common.M(health)["database"]) == "ok" {
			user, e := d.grafana(ctx, "GET", "/api/user", nil, headers)
			if e == nil && common.B(common.M(user)["isGrafanaAdmin"]) {
				ready = true
				break
			}
		}
		if !common.Sleep(ctx, 2*time.Second) {
			return ctx.Err()
		}
	}
	if !ready {
		return errors.New("grafana_admin_or_database_ready_timeout")
	}
	if !common.B(d.State["central_installed"]) {
		for _, part := range []string{"datasources", "dashboards"} {
			if _, e := d.grafana(ctx, "POST", "/api/admin/provisioning/"+part+"/reload", common.Map{}, headers); e != nil {
				return e
			}
		}
	}
	if !common.B(g["create_viewer"]) {
		return nil
	}
	v, e := d.grafana(ctx, "GET", "/api/users", nil, headers)
	if e != nil {
		return e
	}
	var viewer common.Map
	for _, value := range common.A(v) {
		user := common.M(value)
		if common.S(user["login"]) == common.S(g["viewer_username"]) {
			viewer = user
			break
		}
	}
	if viewer == nil {
		v, e = d.grafana(ctx, "POST", "/api/admin/users", common.Map{"name": "Webscan viewer", "login": g["viewer_username"], "password": d.Secrets["viewer_password"]}, headers)
		if e != nil {
			return e
		}
		id := common.I(common.M(v)["id"])
		if id < 1 {
			return errors.New("grafana_viewer_create_invalid_id")
		}
		if _, e = d.grafana(ctx, "PATCH", "/api/org/users/"+strconv.Itoa(id), common.Map{"role": "Viewer"}, headers); e != nil {
			return e
		}
	} else {
		if common.B(viewer["isAdmin"]) {
			return errors.New("grafana_viewer_is_administrator")
		}
		v, e = d.grafana(ctx, "GET", "/api/org/users", nil, headers)
		if e != nil {
			return e
		}
		ok := false
		for _, value := range common.A(v) {
			user := common.M(value)
			if common.S(user["login"]) == common.S(g["viewer_username"]) && common.S(user["role"]) == "Viewer" {
				ok = true
			}
		}
		if !ok {
			return errors.New("grafana_existing_user_is_not_viewer")
		}
	}
	d.Secrets["viewer_username"] = g["viewer_username"]
	return common.AtomicJSON(filepath.Join(StateRoot, "credentials.json"), d.Secrets)
}
func (d *Deploy) ShowGrafana(ctx context.Context) error {
	user, password := common.S(d.Secrets["admin_username"]), common.S(d.Secrets["admin_password"])
	v, e := d.grafana(ctx, "GET", "/api/user", nil, auth(user, password))
	if e != nil || !common.B(common.M(v)["isGrafanaAdmin"]) {
		return errors.New("grafana_credentials_verification_failed")
	}
	message := "Grafana: " + GrafanaURL(d.C) + "\n管理员: " + user + "\n密码: " + password + "\n"
	g := common.M(common.M(d.C.Raw["central"])["grafana"])
	if common.B(g["create_viewer"]) {
		viewer, pwd := common.S(d.Secrets["viewer_username"]), common.S(d.Secrets["viewer_password"])
		if viewer != "" && pwd != "" {
			if v, e = d.grafana(ctx, "GET", "/api/user", nil, auth(viewer, pwd)); e == nil && !common.B(common.M(v)["isGrafanaAdmin"]) {
				message += "只读账号: " + viewer + "\n只读密码: " + pwd + "\n"
			}
		}
	}
	fmt.Print(message)
	b, e := d.compose(ctx, "ps", "-q", "grafana")
	if e == nil && strings.TrimSpace(string(b)) != "" {
		_, e = RunCommand(ctx, strings.NewReader("\n"+message), "docker", "exec", "-i", strings.TrimSpace(string(b)), "sh", "-c", "cat > /proc/1/fd/1")
		if e != nil {
			return errors.New("grafana_credentials_log_write_failed")
		}
	}
	return nil
}
func (d *Deploy) SyncGrafana(ctx context.Context) error {
	if !common.B(d.State["central_installed"]) {
		return errors.New("central_installation_required")
	}
	if common.B(common.M(common.M(d.C.Raw["central"])["reuse_existing"])["grafana"]) {
		return errors.New("external_grafana_credentials_managed_externally")
	}
	g := common.M(common.M(d.C.Raw["central"])["grafana"])
	oldUser, oldPass := common.S(d.Secrets["admin_username"]), common.S(d.Secrets["admin_password"])
	pending := common.M(d.Secrets["grafana_pending"])
	targetUser := common.S(g["admin_username"])
	targetPass := common.S(g["admin_password"])
	if targetPass == "" {
		targetPass = common.S(pending["admin_password"])
	}
	if targetPass == "" {
		targetPass = oldPass
	}
	var administrator common.Map
	var currentUser, currentPass string
	var headers map[string]string
	for _, user := range []string{oldUser, common.S(pending["admin_username"])} {
		if user == "" {
			continue
		}
		for _, pwd := range []string{oldPass, common.S(pending["admin_password"])} {
			if pwd == "" {
				continue
			}
			v, e := d.grafana(ctx, "GET", "/api/user", nil, auth(user, pwd))
			if e == nil && common.B(common.M(v)["isGrafanaAdmin"]) {
				administrator = common.M(v)
				currentUser, currentPass = user, pwd
				headers = auth(user, pwd)
				break
			}
		}
		if administrator != nil {
			break
		}
	}
	if administrator == nil {
		return errors.New("saved_grafana_admin_cannot_authenticate")
	}
	v, e := d.grafana(ctx, "GET", "/api/users", nil, headers)
	if e != nil {
		return e
	}
	var viewer common.Map
	for _, value := range common.A(v) {
		user := common.M(value)
		if strings.EqualFold(common.S(user["login"]), targetUser) && common.I(user["id"]) != common.I(administrator["id"]) {
			return errors.New("grafana_target_username_taken")
		}
		if common.S(user["login"]) == common.S(g["viewer_username"]) {
			viewer = user
		}
	}
	if common.B(g["create_viewer"]) {
		if viewer == nil || common.B(viewer["isAdmin"]) || common.I(viewer["id"]) == common.I(administrator["id"]) {
			return errors.New("existing_viewer_required")
		}
		org, e := d.grafana(ctx, "GET", "/api/org/users", nil, headers)
		if e != nil {
			return e
		}
		ok := false
		for _, value := range common.A(org) {
			user := common.M(value)
			if common.S(user["login"]) == common.S(g["viewer_username"]) && common.S(user["role"]) == "Viewer" {
				ok = true
			}
		}
		if !ok {
			return errors.New("viewer_role_not_verified")
		}
	}
	d.Secrets["grafana_pending"] = common.Map{"admin_username": targetUser, "admin_password": targetPass, "admin_id": administrator["id"]}
	if e = common.AtomicJSON(filepath.Join(StateRoot, "credentials.json"), d.Secrets); e != nil {
		return e
	}
	if viewer != nil && common.S(g["viewer_password"]) != "" {
		password := common.S(g["viewer_password"])
		if _, e = d.grafana(ctx, "PUT", "/api/admin/users/"+strconv.Itoa(common.I(viewer["id"]))+"/password", common.Map{"password": password}, headers); e != nil {
			return e
		}
		v, e = d.grafana(ctx, "GET", "/api/user", nil, auth(common.S(g["viewer_username"]), password))
		if e != nil || common.I(common.M(v)["id"]) != common.I(viewer["id"]) {
			return errors.New("viewer_password_update_verification_failed")
		}
		d.Secrets["viewer_password"], d.Secrets["viewer_username"] = password, g["viewer_username"]
		if e = common.AtomicJSON(filepath.Join(StateRoot, "credentials.json"), d.Secrets); e != nil {
			return e
		}
	}
	id := strconv.Itoa(common.I(administrator["id"]))
	if currentUser != targetUser {
		if _, e = d.grafana(ctx, "PUT", "/api/users/"+id, common.Map{"login": targetUser, "name": administrator["name"], "email": administrator["email"]}, headers); e != nil {
			return e
		}
		headers = auth(targetUser, currentPass)
	}
	if currentPass != targetPass {
		if _, e = d.grafana(ctx, "PUT", "/api/admin/users/"+id+"/password", common.Map{"password": targetPass}, headers); e != nil {
			return e
		}
	}
	v, e = d.grafana(ctx, "GET", "/api/user", nil, auth(targetUser, targetPass))
	if e != nil || common.I(common.M(v)["id"]) != common.I(administrator["id"]) {
		return errors.New("admin_update_verification_failed")
	}
	d.Secrets["admin_username"], d.Secrets["admin_password"] = targetUser, targetPass
	delete(d.Secrets, "grafana_pending")
	if e = common.AtomicJSON(filepath.Join(StateRoot, "credentials.json"), d.Secrets); e != nil {
		return e
	}
	if e = common.Atomic(filepath.Join(d.C.CentralRoot(), "grafana-admin-password"), []byte(targetPass), 0600); e != nil {
		return e
	}
	if e = common.Atomic(filepath.Join(d.C.CentralRoot(), "grafana.env"), []byte("GF_SECURITY_ADMIN_USER="+targetUser+"\nGF_SECURITY_ADMIN_PASSWORD__FILE=/etc/grafana/admin-password\n"), 0600); e != nil {
		return e
	}
	fmt.Println("Grafana 凭据已更新、验证并保存；监控服务未重启。")
	return d.ShowGrafana(ctx)
}
func (d *Deploy) UpdateGrafana(ctx context.Context) error {
	if !d.O.Upgrade || !common.B(d.State["central_installed"]) {
		return errors.New("grafana_only_requires_existing_installation_and_upgrade")
	}
	if common.B(common.M(common.M(d.C.Raw["central"])["reuse_existing"])["grafana"]) {
		return errors.New("external_grafana_port_managed_externally")
	}
	b, e := os.ReadFile(filepath.Join(d.C.CentralRoot(), "compose.yml"))
	if e != nil {
		return e
	}
	var compose common.Map
	if e = yaml.Unmarshal(b, &compose); e != nil {
		return e
	}
	g := common.M(common.M(d.C.Raw["central"])["grafana"])
	if common.S(g["admin_username"]) != common.S(d.Secrets["admin_username"]) {
		return errors.New("sync_admin_credentials_before_port_update")
	}
	id := "grafana-" + common.ID()
	j, e := NewJournal(filepath.Join(StateRoot, "grafana-runs", id))
	if e != nil {
		return e
	}
	service := common.M(common.M(compose["services"])["grafana"])
	service["ports"] = []string{common.S(g["bind_address"]) + ":" + strconv.Itoa(common.I(g["host_port"])) + ":3000"}
	old := common.Clone(common.M(common.M(common.M(d.State["configuration"])["central"])["grafana"]))
	if e = j.Write(filepath.Join(d.C.CentralRoot(), "compose.yml"), YAML(compose), 0600); e != nil {
		return e
	}
	if e = j.Write(filepath.Join(d.C.CentralRoot(), "grafana.ini"), GrafanaINI(d.C), 0600); e != nil {
		return e
	}
	_, e = d.compose(ctx, "up", "-d", "--no-deps", "grafana")
	if e == nil {
		e = d.ConfigureGrafana(ctx)
	}
	if e != nil {
		j.Rollback()
		d.compose(context.WithoutCancel(ctx), "up", "-d", "--no-deps", "grafana")
		return e
	}
	previous := common.M(d.State["configuration"])
	common.M(common.M(previous["central"])["grafana"])["host_port"] = g["host_port"]
	common.M(common.M(previous["central"])["grafana"])["bind_address"] = g["bind_address"]
	d.State["config_hash"] = common.Hash(common.JSON(Redact(previous)))
	d.State["grafana_update"] = common.Map{"time": common.Now(), "previous": Redact(old), "journal": j.Dir}
	if e = d.save(); e != nil {
		return e
	}
	return d.ShowGrafana(ctx)
}
