package central

import (
	"bytes"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"webscan/internal/common"
	"webscan/internal/telemetry"
)

func runtimeRevision(c common.Map) string {
	v := common.Clone(c)
	delete(v, "runtime_path")
	return common.Hash(common.JSON(v))
}
func withoutID(values []string, id string) []string {
	out := []string{}
	for _, v := range values {
		if v != id {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func withoutNode(values []any, id string) []any {
	out := []any{}
	for _, v := range values {
		if common.S(common.M(v)["id"]) != id {
			out = append(out, v)
		}
	}
	return out
}

// After removing only this node's permitted fields, the complete runtime must
// match. In particular certificates, listener settings and other nodes are fixed.
func nodeReloadAllowed(old, next common.Map, id string) bool {
	ips := map[string]bool{}
	auto := common.B(common.M(old["https"])["sources_auto"])
	for _, c := range []common.Map{old, next} {
		n := common.M(common.M(c["nodes"])[id])
		host := common.S(n["host"])
		if host != "" {
			if net.ParseIP(host) == nil || common.S(n["token"]) == "" {
				return false
			}
			if auto {
				ips[host+"/32"] = true
			}
		}
	}
	registered := common.M(common.M(next["nodes"])[id])
	active := common.Contains(common.SS(next["active_nodes"]), id)
	count := 0
	if active && len(registered) == 0 {
		return false
	}
	// A target cannot impersonate the center or scrape a different host.
	for _, v := range common.A(common.M(next["monitoring"])["nodes"]) {
		n := common.M(v)
		if common.S(n["id"]) != id {
			continue
		}
		count++
		u, e := url.Parse(common.S(n["url"]))
		if e != nil {
			return false
		}
		host := common.S(common.M(common.M(next["nodes"])[id])["host"])
		scheme := "http"
		if common.I(common.M(old["https"])["port"]) > 0 {
			scheme = "https"
		}
		if common.B(n["active"]) != active {
			return false
		}
		port, perr := strconv.Atoi(u.Port())
		if perr != nil || port < 1 || port > 65535 {
			return false
		}
		if common.B(n["central"]) || e != nil || u.Scheme != scheme || u.Hostname() != host || u.User != nil || u.Path != "/metrics" || u.RawQuery != "" {
			return false
		}
	}
	if count > 1 || (len(registered) > 0 && count != 1) || (len(registered) == 0 && count != 0) {
		return false
	}
	// Shared sources remain required by other nodes.
	for other, v := range common.M(old["nodes"]) {
		if other == id {
			continue
		}
		source := common.S(common.M(v)["host"]) + "/32"
		if common.Contains(common.SS(common.M(old["https"])["allowed_sources"]), source) && !common.Contains(common.SS(common.M(next["https"])["allowed_sources"]), source) {
			return false
		}
	}
	normalize := func(c common.Map) common.Map {
		c = common.Clone(c)
		delete(c, "runtime_path")
		delete(common.M(c["nodes"]), id)
		c["active_nodes"] = withoutID(common.SS(c["active_nodes"]), id)
		m := common.M(c["monitoring"])
		m["nodes"] = withoutNode(common.A(m["nodes"]), id)
		m["maintenance_nodes"] = withoutID(common.SS(m["maintenance_nodes"]), id)
		h := common.M(c["https"])
		sources := []string{}
		for _, v := range common.SS(h["allowed_sources"]) {
			if !ips[v] {
				sources = append(sources, v)
			}
		}
		sort.Strings(sources)
		h["allowed_sources"] = sources
		return c
	}
	return bytes.Equal(common.JSON(normalize(old)), common.JSON(normalize(next)))
}
func (s *Store) reloadNodes(w http.ResponseWriter, r *http.Request, in common.Map) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	old := s.Snapshot()
	id := common.S(in["node"])
	if id == "" || id == "central" || !s.native() || s.Telemetry == nil {
		write(w, 400, common.Map{"message": "此中心不支持节点动态登记"})
		return
	}
	next, e := common.ReadJSON(configPathFrom(old))
	if e != nil {
		write(w, 503, common.Map{"message": "运行配置暂时不可读"})
		return
	}
	revision := runtimeRevision(next)
	if revision != common.S(in["revision"]) {
		write(w, 409, common.Map{"message": "磁盘配置已变化，请按原任务重新核对"})
		return
	}
	if runtimeRevision(old) == revision {
		write(w, 200, common.Map{"ok": true, "revision": revision})
		return
	}
	if runtimeRevision(old) != common.S(in["expected_revision"]) {
		write(w, 409, common.Map{"message": "中心运行配置版本已变化"})
		return
	}
	if !nodeReloadAllowed(old, next, id) {
		write(w, 400, common.Map{"message": "热加载仅允许目标节点登记、采集及来源限制变化"})
		return
	}
	settings := common.M(next["monitoring"])
	nodes := []telemetry.Node{}
	for _, v := range common.A(settings["nodes"]) {
		n := common.M(v)
		nodes = append(nodes, telemetry.Node{ID: common.S(n["id"]), Name: common.S(n["name"]), Host: common.S(n["host"]), URL: common.S(n["url"]), Active: common.B(n["active"]), Central: common.B(n["central"])})
	}
	if e = s.Telemetry.Configure(settings, nodes); e != nil {
		write(w, 503, common.Map{"message": "指标配置暂时无法应用，请重试"})
		return
	}
	next["runtime_path"] = configPathFrom(old)
	if s.Websites != nil {
		s.Websites.UpdateNodes(common.M(next["nodes"]))
	}
	s.runtime.Store(&next)
	write(w, 200, common.Map{"ok": true, "revision": revision})
}
