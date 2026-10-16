package management

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/deploy"
	"webscan/internal/progress"
)

type preflightInput struct {
	Edit
	Async        bool   `json:"async,omitempty"`
	Active       bool   `json:"active,omitempty"`
	Kind         string `json:"kind,omitempty"`
	PreviewToken string `json:"preview_token,omitempty"`
}
type preflightRecord struct {
	cancel                          context.CancelFunc
	ID                              string             `json:"id"`
	Status                          string             `json:"status"`
	Report                          deploy.CheckReport `json:"report"`
	Expires                         int64              `json:"expires"`
	Owner, Revision, Binding, State string             `json:"-"`
	Active                          bool               `json:"-"`
}

func preflightBinding(c *config.Config, node, content, target string) string {
	return common.Hash(common.JSON(common.Map{"configuration": c.Raw, "node": node, "key_content_hash": common.Hash([]byte(content)), "target": target}))
}
func (s *Service) checkNode(ctx context.Context, c *config.Config, n common.Map, content string, active bool, emit func(deploy.CheckItem)) deploy.CheckReport {
	if s.preflightRunner != nil {
		return s.preflightRunner(ctx, c, n, content, active, emit)
	}
	report := deploy.CheckReport{OK: true, Items: []deploy.CheckItem{}, Mode: deploy.ResolveNodeMode(n, s.state())}
	add := func(v deploy.CheckItem) {
		if v.Status == "running" {
			if emit != nil {
				emit(v)
			}
			return
		}
		report.Items = append(report.Items, v)
		if v.Status == "failed" {
			report.OK = false
		}
		if emit != nil {
			emit(v)
		}
	}
	started := time.Now()
	r, e := deploy.CheckConnection(ctx, n, filepath.Join(s.StateDir, "ssh_known_hosts"), content)
	if e != nil {
		add(deploy.CheckItem{Name: "SSH 连接与认证", Status: "failed", Message: progress.Explain(e), Suggestion: "核对 SSH 端口、root 认证和主机指纹；连接超时请检查安全组及防火墙", DurationMS: time.Since(started).Milliseconds()})
		report.CheckedAt = time.Now().Unix()
		return report
	}
	defer r.Close()
	add(deploy.CheckItem{Name: "SSH 连接与认证", Status: "passed", Message: "root 认证通过；主机指纹 " + r.Fingerprint + "；未保存配置或私钥", DurationMS: time.Since(started).Milliseconds()})
	n = common.Clone(n)
	n["deployment"] = common.Map{"mode": report.Mode}
	deploy.CheckNodePrerequisites(ctx, r, n, add)
	if report.OK {
		if active {
			deploy.CheckNodeNetwork(ctx, c, n, r, add)
		} else {
			add(deploy.CheckItem{Name: "指标与事件连接", Status: "pending", Message: "只读检查未启动监听，端口尚未监听时无法确认；正式部署前将主动检测"})
		}
	}
	if ctx.Err() != nil && report.OK {
		add(deploy.CheckItem{Name: "检查完成状态", Status: "failed", Message: "检查已取消或超时，请重新检查"})
	}
	report.CheckedAt = time.Now().Unix()
	return report
}
func (s *Service) preflight(w http.ResponseWriter, r *http.Request) {
	var in preflightInput
	if e := decode(r, &in); e != nil {
		failure(w, e)
		return
	}
	owner := operationOwner(r)
	s.mu.Lock()
	if s.running || s.pending() || s.removalPending() || len(s.preflightOwners) >= 2 || s.preflightOwners[owner] {
		s.mu.Unlock()
		failure(w, userError("部署或连接检查正在执行，请稍后重试"))
		return
	}
	unlock, e := s.lock()
	if e != nil {
		s.mu.Unlock()
		failure(w, e)
		return
	}
	fail := func(e error) { unlock(); s.mu.Unlock(); failure(w, e) }
	raw, _, e := prepare(s.ConfigPath, in.Edit)
	if e != nil {
		fail(e)
		return
	}
	c, e := validateBytes(s.ConfigPath, raw)
	if e != nil {
		fail(e)
		return
	}
	node := in.NodeID
	if in.Node != nil {
		node = common.S(in.Node["id"])
	}
	var selected common.Map
	for _, n := range c.Nodes {
		if common.S(n["id"]) == node {
			selected = n
		}
	}
	if selected == nil {
		fail(userError("请选择要检查的子服务器"))
		return
	}
	target := deploy.Release
	if in.Kind == "upgrade-node" {
		if in.Node != nil || in.SSHPrivateKeyContent != "" || len(in.Patch) > 0 || len(in.Clear) > 0 {
			fail(userError("独立升级检查使用已保存配置，不允许携带表单草稿"))
			return
		}
		image, version, e := s.checkUpgrade(r, Start{Kind: in.Kind, Node: node, Revision: in.Revision, PreviewToken: in.PreviewToken}, c)
		if e != nil {
			fail(e)
			return
		}
		target = image + "/" + version
	}
	// Node-only operations use the currently applied main settings, keeping pending
	// listener/protocol/directory changes out of this scope.
	checking := nodeCheckConfig(c, s.state())
	if s.preflightOwners == nil {
		s.preflightOwners = map[string]bool{}
	}
	if s.preflights == nil {
		s.preflights = map[string]*preflightRecord{}
	}
	now := time.Now().Unix()
	for id, v := range s.preflights {
		if v.Expires <= now {
			delete(s.preflights, id)
		}
	}
	if len(s.preflights) >= 64 {
		fail(userError("检查记录过多，请稍后重试"))
		return
	}
	operationCtx, cancelOperation := context.WithCancel(context.Background())
	releaseLock := sync.OnceFunc(unlock)
	record := &preflightRecord{cancel: cancelOperation, ID: common.ID(), Status: "running", Report: deploy.CheckReport{Items: []deploy.CheckItem{}}, Owner: owner, Revision: in.Revision, Binding: preflightBinding(c, node, in.SSHPrivateKeyContent, target), State: common.Hash(common.JSON(s.state())), Active: in.Active, Expires: now + 600}
	s.preflights[record.ID] = record
	s.preflightOwners[owner] = true
	s.mu.Unlock()
	run := func(ctx context.Context) {
		defer cancelOperation()
		defer releaseLock()
		ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
		defer cancel()
		report := s.checkNode(ctx, checking, selected, in.SSHPrivateKeyContent, in.Active, func(item deploy.CheckItem) {
			s.mu.Lock()
			found := false
			for i, old := range record.Report.Items {
				if old.Name == item.Name && old.Status == "running" {
					record.Report.Items[i] = item
					found = true
					break
				}
			}
			if !found {
				record.Report.Items = append(record.Report.Items, item)
			}
			s.mu.Unlock()
		})
		releaseLock()
		s.mu.Lock()
		record.Report = report
		delete(s.preflightOwners, owner)
		record.Status = "complete"
		record.Expires = time.Now().Unix() + 600
		s.mu.Unlock()
	}
	if in.Async {
		go run(operationCtx)
		reply(w, 202, common.Map{"id": record.ID, "status": "running", "expires": now + 600})
		return
	}
	stop := context.AfterFunc(r.Context(), cancelOperation)
	defer stop()
	run(operationCtx)
	reply(w, 200, record.Report)
}
func (s *Service) preflightStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/servers/preflight/")
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.preflights[id]
	if v == nil || v.Owner != operationOwner(r) || v.Expires <= time.Now().Unix() {
		reply(w, 404, common.Map{"message": "检查已失效，请重新检查"})
		return
	}
	if r.Method == "DELETE" {
		if v.Status == "running" && v.cancel != nil {
			v.Active = false
			v.cancel()
		}
		reply(w, 200, common.Map{"message": "已请求取消检查"})
		return
	}
	reply(w, 200, v)
}
func nodeCheckConfig(c *config.Config, state common.Map) *config.Config {
	previous := common.M(state["configuration"])
	if !common.B(state["central_installed"]) || len(previous) == 0 {
		return c
	}
	out := *c
	out.Raw = common.Clone(c.Raw)
	out.Raw["central"] = common.Clone(common.M(previous["central"]))
	out.Raw["ssl"] = common.Clone(common.M(previous["ssl"]))
	return &out
}
func (s *Service) checkDeployment(r *http.Request, input Start, c *config.Config, target string) error {
	if input.Kind != "add-node" && input.Kind != "upgrade-node" {
		return nil
	}
	content := ""
	normalized := c
	if input.Edit != nil {
		content = input.Edit.SSHPrivateKeyContent
		raw, _, e := prepare(s.ConfigPath, *input.Edit)
		if e != nil {
			return e
		}
		normalized, e = validateBytes(s.ConfigPath, raw)
		if e != nil {
			return e
		}
	}
	binding := preflightBinding(normalized, input.Node, content, target)
	var report deploy.CheckReport
	if input.PreflightToken != "" {
		v := s.preflights[input.PreflightToken]
		if v == nil || v.Owner != operationOwner(r) || v.Status != "complete" || !v.Active || v.Expires <= time.Now().Unix() || v.Revision != input.Revision || v.Binding != binding || v.State != common.Hash(common.JSON(s.state())) {
			return userError("部署前检查已失效，请重新检查")
		}
		report = v.Report
	} else {
		// Older API clients still receive an automatic check before any YAML commit.
		var n common.Map
		for _, candidate := range c.Nodes {
			if common.S(candidate["id"]) == input.Node {
				n = candidate
			}
		}
		if n == nil {
			return userError("请选择一个有效节点")
		}
		ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
		defer cancel()
		if s.preflightOwners == nil {
			s.preflightOwners = map[string]bool{}
		}
		owner := operationOwner(r)
		s.preflightOwners[owner] = true
		checking := nodeCheckConfig(c, s.state())
		s.mu.Unlock()
		report = s.checkNode(ctx, checking, n, content, true, nil)
		s.mu.Lock()
		delete(s.preflightOwners, owner)
	}
	if !report.OK {
		for _, item := range report.Items {
			if item.Status == "failed" {
				return userError(item.Name + "：" + item.Message + "；" + item.Suggestion)
			}
		}
		return userError("部署前检查未通过，请查看检查详情")
	}
	for _, item := range report.Items {
		if item.Status == "warning" && !input.AcknowledgeWarnings {
			return userError("部署前检查存在警告，请确认后继续：" + item.Message)
		}
	}
	return nil
}
func (s *Service) requirements(w http.ResponseWriter, r *http.Request) {
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		failure(w, e)
		return
	}
	c = nodeCheckConfig(c, s.state())
	v := deploy.DeploymentRequirements(c)
	v["revision"] = func() string { b, _ := os.ReadFile(s.ConfigPath); return common.Hash(b) }()
	reply(w, 200, v)
}
