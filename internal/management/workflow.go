package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
	"webscan/internal/persist"
)

const workflowSchema = `CREATE TABLE IF NOT EXISTS job_workflow(job TEXT PRIMARY KEY,parent TEXT,run_id TEXT);
CREATE TABLE IF NOT EXISTS job_progress(job TEXT,step INTEGER,phase TEXT,host TEXT,title TEXT,status TEXT,message TEXT,time INTEGER,PRIMARY KEY(job,phase,step,host));
CREATE TABLE IF NOT EXISTS recovery_previews(token TEXT PRIMARY KEY,owner TEXT,job TEXT,kind TEXT,state_hash TEXT,revision TEXT,expires INTEGER);`

func (s *Service) initWorkflow() error {
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('job_workflow','upgrade_previews','upgrade_jobs')").Scan(&count); err != nil {
		return err
	}
	if count < 3 {
		dir := filepath.Join(s.StateDir, "database-backups")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := persist.BackupDB(s.DB, filepath.Join(dir, "workflow-before-"+common.ID()+".sqlite3")); err != nil {
			return err
		}
	}
	_, err := s.DB.Exec(workflowSchema + upgradeSchema)
	return err
}
func (s *Service) state() common.Map {
	v, _ := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
	return v
}
func (s *Service) bindJobRun(id string) {
	state := s.state()
	if common.S(state["management_job"]) == id {
		s.DB.Exec("UPDATE job_workflow SET run_id=? WHERE job=?", common.S(state["run_id"]), id)
	}
}
func recoveryScope(state common.Map) string {
	if n := common.S(state["target_node"]); n != "" {
		return "仅节点 " + n
	}
	if common.B(state["target_central_only"]) {
		return "仅主服务器"
	}
	return "主服务器和原任务启用节点"
}
func (s *Service) recoveryStatus() common.Map {
	state := s.state()
	var running int
	s.DB.QueryRow("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").Scan(&running)
	pending := s.pending()
	id := common.S(state["management_job"])
	if running > 0 {
		s.DB.QueryRow("SELECT id FROM jobs WHERE status IN ('queued','running') ORDER BY created DESC LIMIT 1").Scan(&id)
	}
	if pending && id == "" {
		id = "current"
	}
	reason := ""
	if !pending {
		reason = "当前没有需要恢复的部署"
	}
	if running > 0 {
		reason = "部署正在执行"
	}
	if s.removalPending() {
		reason = "请从卸载移除任务详情继续"
	}
	can := pending && running == 0 && !s.removalPending() && common.S(state["run_id"]) != ""
	if pending && common.S(state["run_id"]) == "" {
		reason = "部署记录不完整，无法确认恢复范围，请检查宿主管理记录"
	}
	return common.Map{"job_id": id, "pending": pending, "running": running > 0, "node": state["target_node"], "scope": recoveryScope(state), "phase": state["step"], "can_resume": can, "can_rollback": can, "reason": reason, "release": state["target_release"]}
}
func (s *Service) decorateJob(j *Job) {
	s.DB.QueryRow("SELECT parent FROM job_workflow WHERE job=?", j.ID).Scan(&j.ParentID)
	r := s.recoveryStatus()
	j.Scope = "主服务器 / 配置范围"
	if j.Node != "" {
		j.Scope = "仅节点 " + j.Node
	}
	if common.S(r["job_id"]) == j.ID {
		j.CanResume = common.B(r["can_resume"])
		j.CanRollback = common.B(r["can_rollback"])
		j.RecoveryReason = common.S(r["reason"])
		j.Scope = common.S(r["scope"])
	} else {
		j.RecoveryReason = "任务已结束或已由后续任务接管"
	}
	if j.Kind == "migrate" {
		j.CanResume = (j.Status == "failed" || j.Status == "interrupted") && !common.B(r["running"]) && !s.pending() && !s.removalPending()
		j.CanRollback = false
	}
	if j.Kind == "remove-nodes" {
		j.CanResume = (j.Status == "failed" || j.Status == "interrupted") && s.removalPending()
		j.CanRollback = false
	}
}
func (s *Service) recoveryPreview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind string `json:"kind"`
	}
	if err := decode(r, &in); err != nil {
		failure(w, err)
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/jobs/"), "/recovery-preview")
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock()
	if err != nil {
		failure(w, err)
		return
	}
	defer unlock()
	status := s.recoveryStatus()
	if (in.Kind != "resume" && in.Kind != "rollback") || common.S(status["job_id"]) != id || !common.B(status["can_"+in.Kind]) {
		failure(w, userError("任务状态已变化或当前不允许此操作，请刷新"))
		return
	}
	if id != "current" {
		j, e := scanJob(s.DB.QueryRow("SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
		if e != nil {
			failure(w, userError("任务不存在"))
			return
		}
		s.decorateJob(&j)
		if in.Kind == "rollback" && !j.CanRollback {
			failure(w, userError("此任务不支持回退"))
			return
		}
	}
	raw, err := os.ReadFile(s.ConfigPath)
	if err != nil {
		failure(w, err)
		return
	}
	state := s.state()
	token := common.ID()
	expires := time.Now().Add(10 * time.Minute).Unix()
	s.DB.Exec("DELETE FROM recovery_previews WHERE expires<?", time.Now().Unix())
	_, err = s.DB.Exec("INSERT INTO recovery_previews VALUES(?,?,?,?,?,?,?)", token, operationOwner(r), id, in.Kind, common.Hash(common.JSON(state)), common.Hash(raw), expires)
	if err != nil {
		failure(w, err)
		return
	}
	changes := []Change{}
	if in.Kind == "rollback" {
		previous := common.M(state["previous_configuration"])
		if len(previous) > 0 {
			if c, e := validateBytes(s.ConfigPath, raw); e == nil {
				before, after := effectiveMap(common.M(config.Redact(config.ApplicationInput(c.Raw, c.Nodes))), state), effectiveMap(previous, state)
				node := common.S(state["target_node"])
				if node != "" {
					before = common.M(common.M(before["nodes"])[node])
					after = common.M(common.M(after["nodes"])[node])
				} else if common.B(state["target_central_only"]) {
					delete(before, "nodes")
					delete(after, "nodes")
				}
				changes = configChanges(before, after)
				for i := range changes {
					if changes[i].Field == "" {
						changes[i].Field = "节点配置"
					}
					changes[i].Effect = "涉及原任务的回退配置，具体以执行前校验为准"
				}
			}
		}
	}
	reply(w, 200, common.Map{"token": token, "expires": expires, "revision": common.Hash(raw), "node": state["target_node"], "scope": recoveryScope(state), "target_release": state["target_release"], "previous_release": state["previous_go_release"], "changes": changes, "phase": state["step"], "node_state": common.M(common.M(state["nodes"])[common.S(state["target_node"])])["phase"], "message": "仅恢复原任务范围；具体回退资料由部署执行器再次校验。历史数据库不使用旧快照覆盖。"})
}
func (s *Service) checkRecovery(r *http.Request, in *Start, state common.Map) error {
	status := s.recoveryStatus()
	if !common.B(status["can_"+in.Kind]) {
		return userError("当前没有可继续或回退的任务")
	}
	id := common.S(status["job_id"])
	if in.OriginalJob != "" && in.OriginalJob != id {
		return userError("原任务已被接管，请重新预览")
	}
	in.OriginalJob = id
	if in.RecoveryToken != "" {
		var owner, job, kind, hash, revision string
		var expires int64
		err := s.DB.QueryRow("SELECT owner,job,kind,state_hash,revision,expires FROM recovery_previews WHERE token=?", in.RecoveryToken).Scan(&owner, &job, &kind, &hash, &revision, &expires)
		if err != nil || owner != operationOwner(r) || job != id || kind != in.Kind || hash != common.Hash(common.JSON(state)) || revision != in.Revision || expires < time.Now().Unix() {
			return userError("恢复预览已失效，请重新预览")
		}
	}
	if id != "current" {
		j, err := scanJob(s.DB.QueryRow("SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
		if err != nil {
			return userError("原任务不存在")
		}
		s.decorateJob(&j)
		if in.Kind == "rollback" && !j.CanRollback {
			return userError("此任务不支持回退")
		}
	}
	return nil
}
func (s *Service) recordProgress(id, raw string) error {
	var event struct {
		Step    int    `json:"step"`
		Phase   string `json:"phase"`
		Host    string `json:"host"`
		Title   string `json:"title"`
		Status  string `json:"status"`
		Message string `json:"message"`
		Time    int64  `json:"time"`
	}
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return err
	}
	s.bindJobRun(id)
	if event.Step == 0 || event.Title == "" || event.Status == "信息" || event.Status == "重试" {
		return nil
	}
	_, err := s.DB.Exec("INSERT OR REPLACE INTO job_progress VALUES(?,?,?,?,?,?,?,?)", id, event.Step, event.Phase, event.Host, event.Title, event.Status, event.Message, event.Time)
	return err
}
func (s *Service) jobStages(id string) []common.Map {
	out := []common.Map{}
	rows, err := s.DB.Query("SELECT step,phase,host,title,status,message,time FROM job_progress WHERE job=? ORDER BY step,time", id)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var step, tm int64
		var phase, host, title, status, message string
		if rows.Scan(&step, &phase, &host, &title, &status, &message, &tm) == nil {
			out = append(out, common.Map{"step": step, "phase": phase, "host": host, "title": title, "status": status, "message": message, "time": tm})
		}
	}
	return out
}
func (s *Service) downloadLogs(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/jobs/"), "/logs/download")
	j, err := scanJob(s.DB.QueryRow("SELECT "+jobColumns+" FROM jobs WHERE id=? AND id NOT IN (SELECT id FROM job_archives)", id))
	if err != nil {
		reply(w, 404, common.Map{"message": "任务不存在"})
		return
	}
	rows, err := s.DB.Query("SELECT message FROM logs WHERE job=? ORDER BY id", j.ID)
	if err != nil {
		failure(w, err)
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=deployment-%s.log", j.ID))
	for rows.Next() {
		var msg string
		if rows.Scan(&msg) == nil {
			fmt.Fprint(w, msg)
		}
	}
}
func effectiveMap(raw common.Map, states ...common.Map) common.Map {
	snapshots := config.ApplicationSnapshots(raw, states...)
	out := common.Clone(common.M(snapshots["central"]))
	nodes := common.Map{}
	for id, v := range snapshots {
		if id == "central" {
			continue
		}
		n := common.Clone(common.M(v))
		ssh := common.M(n["ssh"])
		for key := range ssh {
			if secret(key) || strings.Contains(key, "private_key") {
				delete(ssh, key)
			}
		}
		n["ssh"] = ssh
		nodes[id] = n
	}
	out["nodes"] = nodes
	return out
}
func (s *Service) configurationStatus(c *config.Config, state common.Map) common.Map {
	old := common.M(state["configuration"])
	statuses := common.Map{}
	changes := []Change{}
	known := len(old) > 0
	if known {
		changes = configChanges(effectiveMap(old, state), effectiveMap(common.M(config.Redact(config.ApplicationInput(c.Raw, c.Nodes))), state))
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Field < changes[j].Field })
	scope := "runtime"
	restart := false
	affected := map[string]bool{}
	rank := map[string]int{"runtime": 0, "central": 1, "nodes": 2, "full": 3}
	for i := range changes {
		sc, effect, r := effectFor(changes[i].Field)
		changes[i].Effect = effect
		if rank[sc] > rank[scope] {
			scope = sc
		}
		restart = restart || r
		p := strings.Split(changes[i].Field, ".")
		if len(p) > 1 && p[0] == "nodes" {
			affected[p[1]] = true
		}
	}
	current := config.ApplicationFingerprints(config.ApplicationInput(c.Raw, c.Nodes), common.S(state["fingerprint_key"]), state)
	saved := common.M(state["applied_fingerprints"])
	for id, signature := range current {
		status := "unknown"
		if common.S(saved[id]) != "" {
			status = "applied"
			if saved[id] != signature {
				status = "pending"
			}
		}
		if affected[id] || scope == "full" {
			status = "pending"
		}
		if id == "central" {
			for _, change := range changes {
				if !strings.HasPrefix(change.Field, "nodes.") {
					status = "pending"
				}
			}
		}
		statuses[id] = status
		if status == "pending" && !affected[id] && (id != "central" || len(changes) == 0) {
			changes = append(changes, Change{Field: "credentials_or_effective_config." + id, Before: "已应用配置", After: "内容已变更（不展示凭据）", Effect: "重新校验并应用对应范围"})
			if id != "central" {
				affected[id] = true
				if scope != "full" {
					scope = "nodes"
				}
				restart = true
			}
		}
	}
	nodes := []string{}
	for id := range affected {
		nodes = append(nodes, id)
	}
	if scope == "full" {
		nodes = []string{}
		for _, n := range c.Selected("") {
			nodes = append(nodes, common.S(n["id"]))
		}
	}
	sort.Strings(nodes)
	return common.Map{"known": known, "changes": changes, "scope": scope, "restart": restart, "nodes": nodes, "statuses": statuses, "credential_note": "凭据仅通过服务器内部摘要比较。旧节点缺少应用摘要时显示无法确认；成功应用后建立基准。"}
}
