package management

import (
	"bytes"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"webscan/internal/common"
	"webscan/internal/config"
)

var editable = []string{"email", "ssl.enabled", "central.name", "central.public_url", "central.metrics_allowed_source_ip", "central.event_service.allowed_source_cidrs", "central.website_monitor.bind_address", "central.website_monitor.host_port", "central.website_monitor.interval_seconds", "central.website_monitor.timeout_seconds", "central.website_monitor.max_concurrent", "central.monitoring", "feishu.enabled", "feishu.webhook_url", "feishu.signing_enabled", "feishu.signing_secret", "feishu.notifications", "feishu.rate_limit", "feishu.retry", "node_defaults.monitor", "node_defaults.deployment", "health", "retention", "backup"}

func allowed(path string) bool {
	for _, p := range editable {
		if path == p || strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
}
func secret(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "token") || strings.Contains(k, "webhook")
}
func Redact(m common.Map) common.Map {
	out := common.Clone(m)
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case common.Map:
			for k, value := range x {
				if secret(k) || strings.Contains(k, "private_key") {
					x[k] = ""
					x[k+"_configured"] = common.S(value) != ""
				} else {
					walk(value)
				}
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(out)
	return out
}
func set(root *yaml.Node, path []string, value any) error {
	if root.Kind == yaml.DocumentNode {
		root = root.Content[0]
	}
	for _, k := range path[:len(path)-1] {
		if root.Kind != yaml.MappingNode {
			return userError("配置字段不能嵌套在普通值中")
		}
		var child *yaml.Node
		for i := 0; i < len(root.Content); i += 2 {
			if root.Content[i].Value == k {
				child = root.Content[i+1]
				break
			}
		}
		if child == nil {
			child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, child)
		}
		root = child
	}
	last := path[len(path)-1]
	b, e := yaml.Marshal(yamlValue(value))
	if e != nil {
		return e
	}
	var doc yaml.Node
	if e = yaml.Unmarshal(b, &doc); e != nil {
		return e
	}
	v := doc.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == last {
			old := root.Content[i+1]
			preserveComments(old, v)
			root.Content[i+1] = v
			return nil
		}
	}
	root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: last}, v)
	return nil
}

func preserveComments(old, next *yaml.Node) {
	next.HeadComment, next.LineComment, next.FootComment = old.HeadComment, old.LineComment, old.FootComment
	if old.Kind != next.Kind {
		return
	}
	if next.Kind == yaml.MappingNode {
		for i := 0; i < len(next.Content); i += 2 {
			for j := 0; j < len(old.Content); j += 2 {
				if next.Content[i].Value == old.Content[j].Value {
					preserveComments(old.Content[j], next.Content[i])
					preserveComments(old.Content[j+1], next.Content[i+1])
					break
				}
			}
		}
	} else if next.Kind == yaml.SequenceNode {
		id := func(n *yaml.Node) string {
			if n.Kind == yaml.MappingNode {
				for i := 0; i < len(n.Content); i += 2 {
					if n.Content[i].Value == "id" {
						return n.Content[i+1].Value
					}
				}
			}
			return ""
		}
		for i, child := range next.Content {
			key := id(child)
			if key != "" {
				for _, previous := range old.Content {
					if id(previous) == key {
						preserveComments(previous, child)
						break
					}
				}
			} else if i < len(old.Content) {
				preserveComments(old.Content[i], child)
			}
		}
	}
}

type Change struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
	Effect string `json:"effect"`
}
type Edit struct {
	Revision string     `json:"revision"`
	Patch    common.Map `json:"patch"`
	Clear    []string   `json:"clear_fields"`
	Node     common.Map `json:"node,omitempty"`
	NodeID   string     `json:"node_id,omitempty"`
}
type Preview struct {
	Revision string   `json:"revision"`
	Changes  []Change `json:"changes"`
	Scope    string   `json:"scope"`
	Nodes    []string `json:"nodes"`
	Restart  bool     `json:"restart"`
	URL      string   `json:"url,omitempty"`
}

func valueAt(m common.Map, path string) any {
	parts := strings.Split(path, ".")
	var v any = m
	for _, p := range parts {
		v = common.M(v)[p]
	}
	return v
}
func publicValue(path string, v any) any {
	for _, p := range strings.Split(path, ".") {
		if sensitive(p) {
			if common.S(v) == "" {
				return "未配置"
			}
			return "已配置"
		}
	}
	if m, ok := v.(common.Map); ok {
		return Redact(m)
	}
	if a, ok := v.([]any); ok {
		out := []any{}
		for _, item := range a {
			if m := common.M(item); len(m) > 0 {
				out = append(out, Redact(m))
			} else {
				out = append(out, item)
			}
		}
		return out
	}
	return v
}
func prepare(path string, edit Edit) ([]byte, Preview, error) {
	preview := Preview{Changes: []Change{}, Nodes: []string{}, Scope: "runtime"}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, preview, userError("配置必须为普通文件且权限为 0600")
	}
	before, e := os.ReadFile(path)
	if e != nil {
		return nil, preview, e
	}
	preview.Revision = common.Hash(before)
	if edit.Revision != preview.Revision {
		return nil, preview, userError("配置已被修改，请刷新后重新预览")
	}
	c, e := config.Load(path)
	if e != nil {
		return nil, preview, e
	}
	var doc yaml.Node
	if e = yaml.Unmarshal(before, &doc); e != nil {
		return nil, preview, e
	}
	for field, value := range edit.Patch {
		if !allowed(field) {
			return nil, preview, userErrorf("字段 %s 不支持通过后台修改", field)
		}
		if (strings.Contains(field, "password") && field != "email.password") || field == "central.monitoring.mode" || (field == "central.monitoring" && common.M(value)["mode"] != nil) {
			return nil, preview, userError("密码或架构切换请使用专用操作")
		}
		if secret(strings.Split(field, ".")[len(strings.Split(field, "."))-1]) && common.S(value) == "" {
			continue
		}
		old := valueAt(c.Raw, field)
		if bytes.Equal(common.JSON(old), common.JSON(value)) {
			continue
		}
		effect := "热加载"
		if field == "ssl.enabled" || strings.HasPrefix(field, "central.public_url") || strings.HasPrefix(field, "central.event_service.") {
			preview.Scope = "full"
			preview.Restart = true
			effect = "更新主服务器和全部启用节点"
		} else if strings.HasPrefix(field, "central.website_monitor.bind_address") || strings.HasPrefix(field, "central.website_monitor.host_port") {
			if preview.Scope != "full" {
				preview.Scope = "central"
			}
			preview.Restart = true
			effect = "重建主服务器"
		} else if strings.HasPrefix(field, "node_defaults.monitor") || strings.HasPrefix(field, "node_defaults.deployment") {
			if preview.Scope != "full" {
				preview.Scope = "nodes"
			}
			effect = "更新继承此配置的节点"
			if strings.Contains(field, "roots") || strings.Contains(field, "critical_paths") {
				preview.Restart = true
			}
		}
		preview.Changes = append(preview.Changes, Change{field, publicValue(field, old), publicValue(field, value), effect})
		if e = set(&doc, strings.Split(field, "."), value); e != nil {
			return nil, preview, e
		}
	}
	for _, field := range edit.Clear {
		if !allowed(field) || !secret(field) {
			return nil, preview, userError("此字段不允许清空")
		}
		if e = set(&doc, strings.Split(field, "."), ""); e != nil {
			return nil, preview, e
		}
		preview.Changes = append(preview.Changes, Change{field, "已配置", "清空", "热加载"})
	}
	if edit.Node != nil {
		nodes := common.A(c.Raw["nodes"])
		id := common.S(edit.Node["id"])
		if id == "central" {
			return nil, preview, userError("节点 ID central 已保留给主服务器")
		}
		ssh := common.M(edit.Node["ssh"])
		for key := range ssh {
			if !common.Contains([]string{"username", "port", "auth_method", "private_key_path", "password"}, key) {
				return nil, preview, userErrorf("SSH 字段 %s 不允许修改", key)
			}
		}
		if u := common.S(ssh["username"]); u != "" && u != "root" {
			return nil, preview, userError("SSH 用户必须为 root")
		}
		monitor := common.M(edit.Node["monitor"])
		for key := range monitor {
			if _, ok := common.M(common.M(c.Raw["node_defaults"])["monitor"])[key]; !ok {
				return nil, preview, userErrorf("monitor 字段 %s 不允许修改", key)
			}
		}
		if edit.NodeID != "" && id != edit.NodeID {
			return nil, preview, userError("节点 ID 创建后不能修改")
		}
		for k := range edit.Node {
			if k != "id" && k != "name" && k != "host" && k != "enabled" && k != "ssh" && k != "monitor" && k != "deployment" {
				return nil, preview, userErrorf("节点字段 %s 不允许修改", k)
			}
		}
		found := false
		for i, v := range nodes {
			old := common.M(v)
			if common.S(old["id"]) == id {
				if edit.NodeID == "" {
					return nil, preview, userError("节点 ID 已存在")
				}
				next := common.Merge(old, edit.Node)
				if v, ok := edit.Node["monitor"]; ok && v == nil {
					delete(next, "monitor")
				}
				if common.S(common.M(next["ssh"])["password"]) == "" {
					common.M(next["ssh"])["password"] = common.M(old["ssh"])["password"]
				}
				if common.S(old["host"]) != common.S(next["host"]) {
					return nil, preview, userError("更换主机请添加新节点")
				}
				nodes[i] = next
				found = true
			} else if common.S(old["host"]) == common.S(edit.Node["host"]) {
				return nil, preview, userError("该服务器 IP 已配置")
			}
		}
		if edit.NodeID != "" && !found {
			return nil, preview, userError("节点不存在")
		}
		if !found {
			if len(nodes) >= 49 {
				return nil, preview, userError("本版最多支持主服务器及 49 台子服务器")
			}
			newNode := common.Clone(edit.Node)
			if newNode["monitor"] == nil {
				delete(newNode, "monitor")
			}
			nodes = append(nodes, newNode)
			order := common.SS(common.M(c.Raw["deployment"])["node_order"])
			order = append(order, id)
			if e = set(&doc, []string{"deployment", "node_order"}, order); e != nil {
				return nil, preview, e
			}
		}
		if e = set(&doc, []string{"nodes"}, nodes); e != nil {
			return nil, preview, e
		}
		preview.Scope = "node"
		preview.Nodes = []string{id}
		preview.Restart = true
		preview.Changes = append(preview.Changes, Change{"nodes." + id, nil, Redact(edit.Node), "安装或更新该节点"})
	}
	var buffer bytes.Buffer
	enc := yaml.NewEncoder(&buffer)
	enc.SetIndent(2)
	if e = enc.Encode(&doc); e != nil {
		return nil, preview, e
	}
	enc.Close()
	tmp, e := os.CreateTemp(filepath.Dir(path), ".console-check-*.yaml")
	if e != nil {
		return nil, preview, e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(buffer.Bytes()); e != nil {
		tmp.Close()
		return nil, preview, e
	}
	tmp.Close()
	if _, e = config.Load(name); e != nil {
		return nil, preview, e
	}
	return buffer.Bytes(), preview, nil
}

func yamlValue(v any) any {
	switch x := v.(type) {
	case json.Number:
		if n, e := strconv.ParseInt(string(x), 10, 64); e == nil {
			return n
		}
		if n, e := strconv.ParseFloat(string(x), 64); e == nil {
			return n
		}
		return string(x)
	case common.Map:
		out := common.Map{}
		for k, v := range x {
			out[k] = yamlValue(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = yamlValue(v)
		}
		return out
	default:
		return v
	}
}

func effectFor(field string) (string, string, bool) {
	if field == "ssl.enabled" || field == "central.public_url" || strings.HasPrefix(field, "central.event_service.") || strings.HasPrefix(field, "central.metrics_allowed_source_ip") {
		return "full", "更新主服务器和全部启用节点", true
	}
	if strings.HasPrefix(field, "nodes") || strings.HasPrefix(field, "node_defaults.monitor") || strings.HasPrefix(field, "node_defaults.deployment") {
		return "nodes", "更新受影响节点；过滤规则可热加载，目录挂载需要重建", true
	}
	if field == "central.website_monitor.bind_address" || field == "central.website_monitor.host_port" || field == "central.website_monitor.enabled" || field == "central.monitoring.memory_mib" || field == "central.monitoring.go_memory_mib" {
		return "central", "重建主服务器", true
	}
	return "runtime", "热加载", false
}
func (s *Service) pendingPreview(raw []byte, p Preview) Preview {
	c, e := validateBytes(s.ConfigPath, raw)
	if e != nil {
		return p
	}
	state, e := common.ReadJSON(filepath.Join(s.StateDir, "state.json"))
	if e != nil {
		return p
	}
	old := common.M(state["configuration"])
	if len(old) == 0 {
		return p
	}
	applied := common.M(config.Redact(c.Raw))
	delete(applied, "images")
	old = common.Clone(old)
	delete(old, "images")
	seen := map[string]bool{}
	for _, change := range p.Changes {
		seen[change.Field] = true
	}
	for _, change := range configChanges(old, applied) {
		if !seen[change.Field] {
			p.Changes = append(p.Changes, change)
		}
	}
	rank := map[string]int{"runtime": 0, "central": 1, "node": 2, "nodes": 2, "full": 3}
	for i := range p.Changes {
		scope, effect, restart := effectFor(p.Changes[i].Field)
		p.Changes[i].Effect = effect
		if rank[scope] > rank[p.Scope] {
			p.Scope = scope
		}
		p.Restart = p.Restart || restart
	}
	if strings.Contains(p.Scope, "node") {
		p.Nodes = []string{}
		for _, n := range c.Selected("") {
			p.Nodes = append(p.Nodes, common.S(n["id"]))
		}
	}
	return p
}
