package management

import (
	"context"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
)

const removalSchema = `CREATE TABLE IF NOT EXISTS node_removal_previews(token TEXT PRIMARY KEY,owner TEXT,revision TEXT,nodes TEXT,expires INTEGER);
CREATE TABLE IF NOT EXISTS node_removals(job TEXT PRIMARY KEY,owner TEXT,nodes TEXT,cursor INTEGER DEFAULT 0,stage TEXT DEFAULT 'uninstall',revision TEXT,desired BLOB,complete INTEGER DEFAULT 0);`

func (s *Service) removalPending() bool {
	if s.DB == nil {
		return false
	}
	var n int
	e := s.DB.QueryRow("SELECT count(*) FROM node_removals WHERE complete=0").Scan(&n)
	return e != nil || n > 0
}
func (s *Service) centerNodeRequest(ctx context.Context, node string, detach bool) (common.Map, error) {
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		return nil, e
	}
	runtime, e := common.ReadJSON(filepath.Join(c.CentralRoot(), "runtime.json"))
	if e != nil {
		return nil, e
	}
	if !detach {
		wanted := common.S(common.M(common.M(c.Raw["central"])["monitoring"])["mode"])
		if actual := common.S(common.M(runtime["monitoring"])["mode"]); actual != "" && wanted != actual {
			return nil, userError("架构模式尚未应用，请先完成迁移后再移除节点")
		}
		registered := common.M(common.M(runtime["nodes"])[node])
		if host := common.S(registered["host"]); host != "" {
			for _, n := range c.Nodes {
				if common.S(n["id"]) == node && common.S(n["host"]) != host {
					return nil, userError("节点地址尚未应用，不能卸载与已登记地址不一致的主机")
				}
			}
		}
	}
	port := common.I(runtime["port"])
	code, v, e := common.Request(ctx, &http.Client{Timeout: 20 * time.Second}, "POST", "http://127.0.0.1:"+strconv.Itoa(port)+"/node-removal", common.Map{"node": node, "detach": detach}, map[string]string{"Authorization": "Bearer " + common.S(runtime["alert_token"])})
	if e != nil || code != 200 {
		return nil, userError("中心网站关联检查失败，未移除节点配置")
	}
	return common.M(v), nil
}
func (s *Service) removeNodesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		reply(w, 405, common.Map{"message": "请求方法不正确"})
		return
	}
	var in struct {
		IDs      []string `json:"ids"`
		Revision string   `json:"revision"`
		Token    string   `json:"token"`
		Key      string   `json:"request_key"`
		Confirm  bool     `json:"confirm"`
		Job      string   `json:"job"`
	}
	if e := decode(r, &in); e != nil {
		failure(w, e)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		failure(w, userError("部署正在执行"))
		return
	}
	if r.URL.Path == "/nodes/remove/continue" {
		var owner, ids string
		var complete bool
		if e := s.DB.QueryRow("SELECT owner,nodes,complete FROM node_removals WHERE job=?", in.Job).Scan(&owner, &ids, &complete); e != nil || owner != operationOwner(r) || complete {
			failure(w, userError("没有可继续的本账号移除任务"))
			return
		}
		s.running = true
		go s.run(in.Job, "remove-nodes", "")
		reply(w, 202, common.Map{"id": in.Job})
		return
	}
	if in.Key != "" {
		if j, e := scanJob(s.DB.QueryRow("SELECT "+jobColumns+" FROM jobs WHERE request_key=?", in.Key)); e == nil {
			reply(w, 200, j)
			return
		}
	}
	if s.pending() || s.removalPending() {
		failure(w, userError("存在未完成任务，请先继续原范围"))
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 20 {
		failure(w, userError("请选择 1～20 台子服务器"))
		return
	}
	raw, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		failure(w, e)
		return
	}
	if common.Hash(raw) != in.Revision {
		failure(w, userError("配置已修改，请重新预览"))
		return
	}
	c, e := config.Load(s.ConfigPath)
	if e != nil {
		failure(w, e)
		return
	}
	seen := map[string]bool{}
	ids := []string{}
	affected := []common.Map{}
	for _, id := range in.IDs {
		if id == "" || id == "central" || seen[id] {
			failure(w, userError("主服务器禁止移除，节点编号必须唯一"))
			return
		}
		seen[id] = true
		exists := false
		for _, n := range c.Nodes {
			if common.S(n["id"]) == id {
				exists = true
				break
			}
		}
		if !exists {
			failure(w, userError("所选子服务器不在配置中"))
			return
		}
		var active int
		if e = s.DB.QueryRow("SELECT count(*) FROM jobs WHERE node=? AND status IN ('queued','running')", id).Scan(&active); e != nil || active > 0 {
			failure(w, userError("节点存在冲突部署任务"))
			return
		}
		info, e := s.centerNodeRequest(r.Context(), id, false)
		if e != nil {
			failure(w, e)
			return
		}
		affected = append(affected, common.Map{"node": id, "websites": info["websites"]})
		ids = append(ids, id)
	}
	scope := string(common.JSON(ids))
	if r.URL.Path == "/nodes/remove/preview" {
		token := common.ID()
		_, e = s.DB.Exec("INSERT INTO node_removal_previews VALUES(?,?,?,?,?)", token, operationOwner(r), in.Revision, scope, time.Now().Unix()+600)
		if e != nil {
			failure(w, e)
			return
		}
		reply(w, 200, common.Map{"token": token, "nodes": affected, "message": "逐台卸载监控并验收后移除 YAML；保留远端数据库、业务目录及历史，关联网站转由主服务器检测"})
		return
	}
	if r.URL.Path != "/nodes/remove" || !in.Confirm || in.Key == "" || len(in.Key) > 128 {
		failure(w, userError("请确认移除范围并提供有效提交标识"))
		return
	}
	var count int
	e = s.DB.QueryRow("SELECT count(*) FROM node_removal_previews WHERE token=? AND owner=? AND revision=? AND nodes=? AND expires>?", in.Token, operationOwner(r), in.Revision, scope, time.Now().Unix()).Scan(&count)
	if e != nil || count != 1 {
		failure(w, userError("移除预览过期，请重新预览"))
		return
	}
	if _, e = s.backup(raw, "部署前"); e != nil {
		failure(w, e)
		return
	}
	id := common.ID()
	now := time.Now().Unix()
	tx, e := s.DB.Begin()
	if e != nil {
		failure(w, e)
		return
	}
	defer tx.Rollback()
	_, e = tx.Exec("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)", id, in.Key, "remove-nodes", strings.Join(ids, ","), "queued", now, now, in.Revision, "")
	if e == nil {
		_, e = tx.Exec("INSERT INTO node_removals(job,owner,nodes,revision) VALUES(?,?,?,?)", id, operationOwner(r), scope, in.Revision)
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		failure(w, e)
		return
	}
	s.running = true
	go s.run(id, "remove-nodes", "")
	reply(w, 202, common.Map{"id": id})
}
func removeNodeYAML(raw []byte, id string) ([]byte, error) {
	var doc yaml.Node
	if e := yaml.Unmarshal(raw, &doc); e != nil {
		return nil, e
	}
	var values common.Map
	if e := doc.Decode(&values); e != nil {
		return nil, e
	}
	nodes := []any{}
	for _, v := range common.A(values["nodes"]) {
		if common.S(common.M(v)["id"]) != id {
			nodes = append(nodes, v)
		}
	}
	order := []string{}
	for _, v := range common.SS(common.M(values["deployment"])["node_order"]) {
		if v != id {
			order = append(order, v)
		}
	}
	if e := set(&doc, []string{"nodes"}, nodes); e != nil {
		return nil, e
	}
	if e := set(&doc, []string{"deployment", "node_order"}, order); e != nil {
		return nil, e
	}
	return yaml.Marshal(&doc)
}
func (s *Service) performRemoval(ctx context.Context, job string) error {
	for {
		var scope, stage, rev string
		var cursor int
		var desired []byte
		var complete bool
		e := s.DB.QueryRow("SELECT nodes,cursor,stage,revision,desired,complete FROM node_removals WHERE job=?", job).Scan(&scope, &cursor, &stage, &rev, &desired, &complete)
		if e != nil {
			return e
		}
		if complete {
			return nil
		}
		var ids []string
		if e := jsonUnmarshal([]byte(scope), &ids); e != nil {
			return e
		}
		if cursor >= len(ids) {
			_, e = s.DB.Exec("UPDATE node_removals SET complete=1 WHERE job=?", job)
			return e
		}
		id := ids[cursor]
		raw, e := os.ReadFile(s.ConfigPath)
		if e != nil {
			return e
		}
		if common.Hash(raw) != rev && !(stage == "save" && len(desired) > 0 && common.Hash(raw) == common.Hash(desired)) {
			return userError("配置已修改，移除任务暂停；请恢复原配置后继续")
		}
		switch stage {
		case "uninstall":
			if s.execute != nil {
				e = s.execute(ctx, job, "uninstall", id)
			} else {
				binary, err := os.Executable()
				if err != nil {
					return err
				}
				e = s.command(ctx, job, binary, []string{"deploy", "--config", s.ConfigPath, "--non-interactive", "--uninstall", "--node", id, "--expected-revision", rev})
			}
			if e != nil {
				return e
			}
			if s.execute == nil {
				state, e := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
				if e != nil || !common.B(common.M(state["single_uninstall"])["complete"]) {
					return userError("节点卸载收尾尚未验收，请继续原任务")
				}
			}
			_, e = s.DB.Exec("UPDATE node_removals SET stage='detach' WHERE job=?", job)
			if e != nil {
				return e
			}
		case "detach":
			if _, e = s.centerNodeRequest(ctx, id, true); e != nil {
				return e
			}
			s.mu.Lock()
			unlock, err := s.lock()
			if err != nil {
				s.mu.Unlock()
				return err
			}
			desired, e = removeNodeYAML(raw, id)
			if e == nil {
				_, e = validateBytes(s.ConfigPath, desired)
			}
			if e == nil {
				_, e = s.backup(raw, "移除前")
			}
			if e == nil {
				_, e = s.DB.Exec("UPDATE node_removals SET stage='save',desired=? WHERE job=?", desired, job)
			}
			unlock()
			s.mu.Unlock()
			if e != nil {
				return e
			}
		case "save":
			s.mu.Lock()
			unlock, err := s.lock()
			if err != nil {
				s.mu.Unlock()
				return err
			}
			e = common.Atomic(s.ConfigPath, desired, 0600)
			if e == nil && s.execute == nil {
				state, err := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
				if err != nil {
					e = err
				} else {
					previous := common.M(state["configuration"])
					list := []any{}
					for _, n := range common.A(previous["nodes"]) {
						if common.S(common.M(n)["id"]) != id {
							list = append(list, n)
						}
					}
					previous["nodes"] = list
					state["configuration"] = previous
					state["config_hash"] = common.Hash(common.JSON(previous))
					e = common.AtomicJSON(filepath.Join(s.StateDir, "state.json"), state)
				}
			}
			if e == nil {
				_, e = s.DB.Exec("UPDATE node_removals SET cursor=cursor+1,stage='uninstall',revision=?,desired=NULL WHERE job=?", common.Hash(desired), job)
			}
			unlock()
			s.mu.Unlock()
			if e != nil {
				return e
			}
			logWriter{s, job, nil}.Write([]byte("子服务器 " + id + " 已卸载并移除；数据与网站历史保留。\n"))
		default:
			return userError("移除任务阶段无效，未继续执行")
		}
	}
}

// Keep decoding private persisted scope separate from request parsing.
var jsonUnmarshal = json.Unmarshal
