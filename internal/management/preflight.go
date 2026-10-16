package management

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/deploy"
)

func (s *Service) preflight(w http.ResponseWriter, r *http.Request) {
	var edit Edit
	if err := decode(r, &edit); err != nil {
		failure(w, err)
		return
	}
	if edit.Node == nil {
		failure(w, userError("请选择要检查的子服务器"))
		return
	}
	owner := operationOwner(r)
	s.mu.Lock()
	if s.running || s.pending() || s.removalPending() || len(s.preflightOwners) >= 2 || s.preflightOwners[owner] {
		s.mu.Unlock()
		failure(w, userError("部署或连接检查正在执行，请稍后重试"))
		return
	}
	if s.preflightOwners == nil {
		s.preflightOwners = map[string]bool{}
	}
	s.preflightOwners[owner] = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.preflightOwners, owner); s.mu.Unlock() }()
	// Take the deployment lock for the read-only session so CLI deployment cannot race it.
	unlock, err := s.lock()
	if err != nil {
		failure(w, err)
		return
	}
	defer unlock()
	raw, _, err := prepare(s.ConfigPath, edit)
	if err != nil {
		failure(w, err)
		return
	}
	c, err := validateBytes(s.ConfigPath, raw)
	if err != nil {
		failure(w, err)
		return
	}
	var node common.Map
	for _, n := range c.Nodes {
		if common.S(n["id"]) == common.S(edit.Node["id"]) {
			node = n
			break
		}
	}
	if node == nil {
		failure(w, userError("节点不存在"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	results := []common.Map{}
	ok := true
	add := func(name, status, message string) {
		results = append(results, common.Map{"name": name, "status": status, "message": message})
		if status == "failed" {
			ok = false
		}
	}
	remote, err := deploy.CheckConnection(ctx, node, filepath.Join(s.StateDir, "ssh_known_hosts"), edit.SSHPrivateKeyContent)
	if err != nil {
		add("SSH 连接与认证", "failed", userMessage(err))
		reply(w, 200, common.Map{"ok": false, "items": results, "checked_at": time.Now().Unix()})
		return
	}
	defer remote.Close()
	add("SSH 连接与认证", "passed", "root 身份验证通过；未写入配置或私钥")
	add("SSH 主机指纹", "passed", remote.Fingerprint+"；首次连接的指纹将在正式部署时记录")
	mode := deploy.ResolveNodeMode(node, s.state())
	checks := []struct{ name, cmd string }{
		{"Linux amd64 与 root", "test \"$(id -u)\" = 0 && test \"$(uname -s)\" = Linux && test \"$(uname -m)\" = x86_64"},
		{"磁盘剩余空间", "df -Pk /var | awk 'NR==2 { if ($4 < 524288) exit 1; print $4 \" KiB available\" }'"},
	}
	if mode == "native" {
		checks = append(checks, struct{ name, cmd string }{"systemd 与资源控制", "test -d /run/systemd/system && command -v systemctl >/dev/null && (test -f /sys/fs/cgroup/cgroup.controllers && grep -qw cpu /sys/fs/cgroup/cgroup.controllers && grep -qw memory /sys/fs/cgroup/cgroup.controllers || test -d /sys/fs/cgroup/cpu && test -d /sys/fs/cgroup/memory)"})
	} else {
		checks = append(checks, struct{ name, cmd string }{"Docker 环境", "if command -v docker >/dev/null; then docker info >/dev/null 2>&1 && docker compose version >/dev/null; else . /etc/os-release; case \"$ID\" in debian|ubuntu) echo install-on-deploy;; *) exit 1;; esac; fi"})
	}
	for _, check := range checks {
		out, e := remote.Exec(ctx, check.cmd, nil)
		if e != nil {
			add(check.name, "failed", "检查未通过，请核对环境或权限；超时也会终止检查")
		} else if strings.Contains(string(out), "install-on-deploy") {
			add(check.name, "pending", "未安装 Docker，正式部署时按现有流程安装")
		} else {
			add(check.name, "passed", "检查通过")
		}
	}
	for _, root := range common.SS(common.M(node["monitor"])["roots"]) {
		_, e := remote.Exec(ctx, "test -d "+deploy.Q(root)+" && test -r "+deploy.Q(root), nil)
		if e != nil {
			add("监控目录", "failed", fmt.Sprintf("目录不存在或不可读：%s", root))
		} else {
			add("监控目录", "passed", root)
		}
	}
	add("指标端口与投递验收", "pending", "正式部署后按当前 HTTP / HTTPS 设置验收；此检查不启动服务、不更改防火墙")
	reply(w, 200, common.Map{"ok": ok, "items": results, "checked_at": time.Now().Unix(), "mode": mode})
}
