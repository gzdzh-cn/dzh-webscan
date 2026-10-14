package management

import (
	"bytes"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/config"
)

func validateBytes(path string, raw []byte) (*config.Config, error) {
	f, e := os.CreateTemp(filepath.Dir(path), ".console-check-*.yaml")
	if e != nil {
		return nil, e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return nil, e
	}
	if e = f.Close(); e != nil {
		return nil, e
	}
	return config.Load(f.Name())
}
func configChanges(before, after common.Map) []Change {
	changes := []Change{}
	var visit func(string, any, any)
	visit = func(path string, old, new any) {
		if bytes.Equal(common.JSON(old), common.JSON(new)) {
			return
		}
		a, b := common.M(old), common.M(new)
		if len(a) > 0 && len(b) > 0 {
			keys := map[string]bool{}
			for k := range a {
				keys[k] = true
			}
			for k := range b {
				keys[k] = true
			}
			for k := range keys {
				p := k
				if path != "" {
					p = path + "." + k
				}
				visit(p, a[k], b[k])
			}
			return
		}
		changes = append(changes, Change{path, publicValue(path, old), publicValue(path, new), "保存为待应用配置；按预览范围部署"})
	}
	visit("", before, after)
	return changes
}
func (s *Service) backupAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/backups/"), "/")
	if len(parts) != 2 || r.Method != "POST" {
		reply(w, 404, common.Map{"message": "备份操作不存在"})
		return
	}
	var input struct {
		Revision  string `json:"revision"`
		Token     string `json:"token"`
		Keep      *bool  `json:"keep_credentials"`
		Encrypted bool   `json:"encrypted"`
		Password  string `json:"password"`
		Confirm   string `json:"confirm_password"`
	}
	if e := decodeBackupRequest(w, r, &input); e != nil {
		failure(w, e)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, e := s.loadConfigBackup(r.Context(), parts[0])
	if e != nil {
		failure(w, e)
		return
	}
	if parts[1] == "export" {
		if !input.Encrypted {
			out, e := redactDocument(raw)
			if e != nil {
				failure(w, e)
				return
			}
			reply(w, 200, common.Map{"content": string(out), "filename": "webscan-config-" + parts[0] + ".yaml", "encrypted": false})
			return
		}
		if r.Header.Get("X-Webscan-Secure") != "true" {
			failure(w, userError("包含凭据的加密操作仅允许 HTTPS 后台"))
			return
		}
		var values common.Map
		if e = yaml.Unmarshal(raw, &values); e != nil {
			failure(w, e)
			return
		}
		doc := ConfigDocument{Format: 1, Created: time.Now().UTC().Format(time.RFC3339), Configuration: values}
		out, e := yaml.Marshal(doc)
		if e == nil {
			var encrypted string
			encrypted, e = encryptDocument(out, input.Password, input.Confirm)
			if e == nil {
				reply(w, 200, common.Map{"content": encrypted, "filename": "webscan-config-" + parts[0] + ".age", "encrypted": true})
				return
			}
		}
		failure(w, e)
		return
	}
	if parts[1] != "preview" && parts[1] != "restore" {
		reply(w, 404, common.Map{"message": "备份操作不存在"})
		return
	}
	if s.running || s.pending() || s.removalPending() {
		failure(w, userError("存在未完成部署，请先继续或回退"))
		return
	}
	unlock, e := s.lock()
	if e != nil {
		failure(w, e)
		return
	}
	defer unlock()
	current, e := os.ReadFile(s.ConfigPath)
	if e != nil {
		failure(w, e)
		return
	}
	if common.Hash(current) != input.Revision {
		failure(w, userError("配置已被修改，请重新预览"))
		return
	}
	keep := input.Keep == nil || *input.Keep
	var before, after common.Map
	if yaml.Unmarshal(current, &before) != nil || yaml.Unmarshal(raw, &after) != nil {
		failure(w, userError("备份配置无效"))
		return
	}
	mergeMissing(after, before, keep)
	merged, e := yaml.Marshal(after)
	if e != nil {
		failure(w, e)
		return
	}
	backup, e := validateBytes(s.ConfigPath, merged)
	if e != nil {
		failure(w, userError("备份缺少必要凭据或参数，请补全后再恢复"))
		return
	}
	for _, n := range backup.Nodes {
		ssh := common.M(n["ssh"])
		if key := common.S(ssh["private_key_path"]); key != "" && common.S(ssh["auth_method"]) == "key" {
			info, e := os.Lstat(key)
			if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				failure(w, userError("节点私钥路径不存在或权限不安全，请先在主服务器补全私钥"))
				return
			}
		}
	}
	if common.S(valueAt(before, "central.monitoring.mode")) != common.S(valueAt(after, "central.monitoring.mode")) {
		failure(w, userError("架构模式不同，请通过专用迁移或回退操作恢复"))
		return
	}
	preview := Preview{Revision: input.Revision, Changes: configChanges(before, after), Scope: "full", Restart: true, Nodes: []string{}}
	for _, n := range backup.Nodes {
		preview.Nodes = append(preview.Nodes, common.S(n["id"]))
	}
	digest := common.Hash(raw)
	if parts[1] == "preview" {
		token := common.ID()
		_, e = s.DB.Exec(`INSERT INTO config_backup_previews VALUES(?,?,?,?,?,?,?)`, token, parts[0], operationOwner(r), input.Revision, digest, keep, time.Now().Unix()+600)
		if e != nil {
			failure(w, e)
			return
		}
		reply(w, 200, common.Map{"revision": preview.Revision, "changes": preview.Changes, "scope": preview.Scope, "nodes": preview.Nodes, "restart": preview.Restart, "token": token, "expires": time.Now().Unix() + 600, "credentials": map[bool]string{true: "保留当前凭据；缺失字段按节点 ID 补齐", false: "使用备份凭据；备份中缺失字段保留当前值"}[keep], "path_notice": "本机路径、私钥及数据目录不会随配置包迁移，请核对后应用"})
		return
	}
	var n int
	e = s.DB.QueryRow(`SELECT count(*) FROM config_backup_previews WHERE token=? AND backup=? AND owner=? AND revision=? AND digest=? AND keep_credentials=? AND expires>?`, input.Token, parts[0], operationOwner(r), input.Revision, digest, keep, time.Now().Unix()).Scan(&n)
	if e != nil || n != 1 {
		failure(w, userError("恢复预览已过期或选项变化，请重新预览"))
		return
	}
	if _, e = s.backup(current, "恢复前"); e == nil {
		e = common.Atomic(s.ConfigPath, merged, 0600)
	}
	if e != nil {
		failure(w, e)
		return
	}
	_, e = s.DB.Exec(`INSERT INTO config_backup_details(id,restored,result) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET restored=excluded.restored,result=excluded.result`, parts[0], time.Now().Unix(), "已恢复为待应用配置")
	if e != nil {
		failure(w, e)
		return
	}
	s.DB.Exec("DELETE FROM config_backup_previews WHERE token=?", input.Token)
	reply(w, 200, common.Map{"saved": true, "revision": common.Hash(merged), "preview": preview, "message": "已恢复为待应用配置，尚未部署"})
}

func remove(root *yaml.Node, key string) {
	if root.Kind == yaml.DocumentNode {
		root = root.Content[0]
	}
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			root.Content = append(root.Content[:i], root.Content[i+2:]...)
			return
		}
	}
}
