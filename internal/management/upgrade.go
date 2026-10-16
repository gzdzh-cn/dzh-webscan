package management

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/deploy"
)

const upgradeSchema = `CREATE TABLE IF NOT EXISTS upgrade_previews(token TEXT PRIMARY KEY,owner TEXT,node TEXT,revision TEXT,state_hash TEXT,image TEXT,version TEXT,expires INTEGER);
CREATE TABLE IF NOT EXISTS upgrade_jobs(job TEXT PRIMARY KEY,image TEXT,version TEXT);`

func releaseCompare(a, b string) (int, bool) {
	parse := func(s string) ([3]int, bool) {
		var v [3]int
		p := strings.Split(strings.TrimPrefix(s, "v"), ".")
		if len(p) != 3 {
			return v, false
		}
		for i := range v {
			n, e := strconv.Atoi(p[i])
			if e != nil || n < 0 {
				return v, false
			}
			v[i] = n
		}
		return v, true
	}
	x, ok := parse(a)
	y, yes := parse(b)
	if !ok || !yes {
		return 0, false
	}
	for i := range x {
		if x[i] < y[i] {
			return -1, true
		}
		if x[i] > y[i] {
			return 1, true
		}
	}
	return 0, true
}
func upgradeStateHash(state common.Map) string { return common.Hash(common.JSON(state)) }
func (s *Service) upgradeNode(c *config.Config, state common.Map, id string) (common.Map, error) {
	selected := c.Selected(id)
	if id == "" || id == "central" || len(selected) != 1 {
		return nil, userError("请选择一个已启用的子服务器")
	}
	n := selected[0]
	old := common.M(common.M(state["nodes"])[id])
	if !common.Contains(common.SS(state["active"]), id) || !common.Contains([]string{"complete", "go-rolled-back"}, common.S(old["phase"])) || common.S(old["go_release"]) == "" {
		return nil, userError("子服务器尚未完成安装，请使用保存并部署")
	}
	mode := common.S(old["deployment_mode"])
	if mode == "" {
		mode = "docker"
	}
	if mode != deploy.ResolveNodeMode(n, state) {
		return nil, userError("部署方式已修改，请使用保存并部署，独立升级不切换部署方式")
	}
	if cmp, ok := releaseCompare(common.S(old["go_release"]), deploy.Release); ok && cmp > 0 {
		return nil, userError("当前子服务器版本高于宿主管理程序，拒绝降级，请先升级主服务器")
	}
	return n, nil
}
func (s *Service) resolveUpgradeImage(ctx context.Context, c *config.Config) (string, string, error) {
	if s.upgradeResolver != nil {
		return s.upgradeResolver(ctx, c)
	}
	d, e := deploy.NewDocker(ctx, c, false)
	if e != nil {
		return "", "", userError("无法检查主服务器 Docker，请检查管理服务环境")
	}
	defer d.Close()
	image := c.Image("agent")
	if strings.HasSuffix(image, ":latest") {
		image = strings.TrimSuffix(image, ":latest") + ":" + deploy.Release
	}
	locked, e := d.Pull(ctx, image)
	if e != nil {
		return "", "", userError("目标 Agent 镜像下载或摘要校验失败")
	}
	output, e := d.Exec(ctx, nil, "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint", "/usr/local/bin/webscan", locked, "version")
	if e != nil || strings.TrimSpace(string(output)) != deploy.Release {
		return "", "", userError("显式 Agent 镜像与宿主管理程序版本不兼容，请核对镜像配置")
	}
	if !strings.Contains(locked, "@sha256:") {
		return "", "", userError("目标 Agent 镜像缺少不可变摘要")
	}
	return locked, deploy.Release, nil
}
func (s *Service) upgradePreview(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/servers/"), "/upgrade-preview")
	var in struct {
		Revision string `json:"revision"`
	}
	if e := decode(r, &in); e != nil {
		failure(w, e)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.pending() || s.removalPending() {
		failure(w, userError("存在未完成部署，请先从原任务继续或回退"))
		return
	}
	unlock, e := s.lock()
	if e != nil {
		failure(w, e)
		return
	}
	defer unlock()
	raw, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		failure(w, e)
		return
	}
	if in.Revision != common.Hash(raw) {
		failure(w, userError("配置已被修改，请重新打开编辑窗口"))
		return
	}
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		failure(w, e)
		return
	}
	state := s.state()
	n, e := s.upgradeNode(c, state, id)
	if e != nil {
		failure(w, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	image, version, e := s.resolveUpgradeImage(ctx, c)
	if e != nil {
		failure(w, e)
		return
	}
	old := common.M(common.M(state["nodes"])[id])
	current := common.S(old["agent_image"])
	if current == "" {
		current = common.S(old["go_image"])
	}
	changes := []Change{}
	status := s.configurationStatus(c, state)
	for _, v := range status["changes"].([]Change) {
		if strings.HasPrefix(v.Field, "nodes."+id+".") || v.Field == "credentials_or_effective_config."+id {
			changes = append(changes, v)
		}
	}
	noChange := common.S(old["go_release"]) == version && strings.Contains(current, "@sha256:") && strings.SplitN(current, "@", 2)[1] == strings.SplitN(image, "@", 2)[1] && common.S(common.M(status["statuses"])[id]) == "applied"
	token := ""
	if !noChange {
		token = common.ID()
		_, e = s.DB.Exec("INSERT INTO upgrade_previews VALUES(?,?,?,?,?,?,?,?)", common.Hash([]byte(token)), operationOwner(r), id, in.Revision, upgradeStateHash(state), image, version, time.Now().Add(10*time.Minute).Unix())
		if e != nil {
			failure(w, e)
			return
		}
	}
	s.DB.Exec("DELETE FROM upgrade_previews WHERE expires<=?", time.Now().Unix())
	reply(w, 200, common.Map{"preview_token": token, "revision": in.Revision, "node": id, "name": n["name"], "mode": deploy.ResolveNodeMode(n, state), "current_version": old["go_release"], "current_image": current, "target_version": version, "target_image": image, "changes": changes, "baseline_known": common.B(status["known"]) && common.S(common.M(status["statuses"])[id]) != "unknown", "no_change": noChange, "scope": "仅升级此子服务器，使用已保存配置；不保存弹窗草稿，不重建中心"})
}
func (s *Service) checkUpgrade(r *http.Request, input Start, c *config.Config) (string, string, error) {
	if input.Edit != nil {
		return "", "", userError("独立升级不允许携带 edit，不保存弹窗草稿")
	}
	state := s.state()
	if _, e := s.upgradeNode(c, state, input.Node); e != nil {
		return "", "", e
	}
	var owner, node, revision, hash, image, version string
	var expires int64
	e := s.DB.QueryRow("SELECT owner,node,revision,state_hash,image,version,expires FROM upgrade_previews WHERE token=?", common.Hash([]byte(input.PreviewToken))).Scan(&owner, &node, &revision, &hash, &image, &version, &expires)
	if e != nil || owner != operationOwner(r) || node != input.Node || revision != input.Revision || hash != upgradeStateHash(state) || expires <= time.Now().Unix() || version != deploy.Release {
		return "", "", userError("升级预览已失效，请重新预览")
	}
	return image, version, nil
}

func (s *Service) upgradeLockForJob(id string) (string, error) {
	for depth := 0; depth < 30 && id != ""; depth++ {
		var image string
		e := s.DB.QueryRow("SELECT image FROM upgrade_jobs WHERE job=?", id).Scan(&image)
		if e == nil {
			return image, nil
		}
		if e != sql.ErrNoRows {
			return "", e
		}
		var kind string
		if err := s.DB.QueryRow("SELECT kind FROM jobs WHERE id=?", id).Scan(&kind); err != nil {
			return "", err
		}
		if kind == "upgrade-node" {
			return "", userError("升级目标摘要缺失，请核对原任务，不允许重新解析标签")
		}
		var parent string
		if e = s.DB.QueryRow("SELECT parent FROM job_workflow WHERE job=?", id).Scan(&parent); e != nil {
			return "", e
		}
		id = parent
	}
	return "", nil
}
