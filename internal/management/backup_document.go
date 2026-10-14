package management

import (
	"bytes"
	"encoding/base64"
	"filippo.io/age"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"strings"
	"time"
	"webscan/internal/common"
)

const yamlLimit = 2 << 20
const encryptedLimit = 4 << 20

// Omitted fields are absent, never represented by a value that could become a credential.
type ConfigDocument struct {
	Format        int        `yaml:"format_version"`
	Created       string     `yaml:"created_at"`
	Configuration common.Map `yaml:"configuration"`
	Omitted       []string   `yaml:"omitted_fields,omitempty"`
}

func sensitive(k string) bool {
	k = strings.ToLower(k)
	return secret(k) || strings.Contains(k, "private_key") || k == "public_url" || k == "host" || k == "ip" || k == "server" || strings.Contains(k, "source_ip") || strings.Contains(k, "source_cidr") || k == "sender" || k == "recipients" || k == "username"
}
func redactDocument(raw []byte) ([]byte, error) {
	var values common.Map
	if e := yaml.Unmarshal(raw, &values); e != nil {
		return nil, userError("配置格式不正确")
	}
	doc := ConfigDocument{Format: 1, Created: time.Now().UTC().Format(time.RFC3339), Configuration: values, Omitted: []string{}}
	var walk func(common.Map, string)
	walk = func(m common.Map, path string) {
		for k, v := range m {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if sensitive(k) {
				delete(m, k)
				doc.Omitted = append(doc.Omitted, p)
				continue
			}
			switch x := v.(type) {
			case map[string]interface{}:
				walk(common.Map(x), p)

			case []interface{}:
				for i, item := range x {
					if child, ok := item.(map[string]interface{}); ok {
						walk(common.Map(child), fmt.Sprintf("%s[%d]", p, i))
					}

				}
			}
		}
	}
	walk(values, "")
	return yaml.Marshal(doc)
}
func parseDocument(raw []byte) (ConfigDocument, error) {
	var doc ConfigDocument
	if len(raw) > yamlLimit {
		return doc, userError("YAML 不能超过 2 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if e := d.Decode(&doc); e != nil {
		return doc, userError("备份 YAML 格式、重复键或字段不正确")
	}
	if d.Decode(new(any)) != io.EOF {
		return doc, userError("备份只能包含一份 YAML 文档")
	}
	if doc.Format != 1 || doc.Configuration == nil {
		return doc, userError("不支持的备份版本，仅支持 format_version: 1")
	}
	if _, e := time.Parse(time.RFC3339, doc.Created); e != nil {
		return doc, userError("备份创建时间格式不正确")
	}
	var rejectMask func(any) bool
	rejectMask = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, value := range x {
				if secret(k) {
					s := strings.TrimSpace(common.S(value))
					if s == "已配置" || s == "[已隐藏]" || s == "<redacted>" || s != "" && strings.Trim(s, "*•●") == "" {
						return true
					}
				}
				if rejectMask(value) {
					return true
				}
			}
		case []any:
			for _, value := range x {
				if rejectMask(value) {
					return true
				}
			}
		}
		return false
	}
	if rejectMask(doc.Configuration) {
		return doc, userError("遮罩文本不能作为真实凭据，请省略字段或填写有效值")
	}
	return doc, nil
}
func encryptDocument(raw []byte, password, confirm string) (string, error) {
	if len(password) < 12 || len(password) > 1024 || password != confirm {
		return "", userError("加密密码至少 12 字节且两次输入必须一致")
	}
	recipient, e := age.NewScryptRecipient(password)
	if e != nil {
		return "", e
	}
	var out bytes.Buffer
	w, e := age.Encrypt(&out, recipient)
	if e != nil {
		return "", e
	}
	if _, e = w.Write(raw); e != nil {
		return "", e
	}
	if e = w.Close(); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(out.Bytes()), nil
}
func decryptDocument(data, password string) ([]byte, error) {
	if len(data) > base64.StdEncoding.EncodedLen(encryptedLimit) {
		return nil, userError("加密包不能超过 4 MiB")
	}
	raw, e := base64.StdEncoding.DecodeString(data)
	if e != nil || len(raw) > encryptedLimit {
		return nil, userError("加密包格式或大小不正确")
	}
	identity, e := age.NewScryptIdentity(password)
	if e != nil {
		return nil, userError("加密密码不正确")
	}
	identity.SetMaxWorkFactor(18)
	reader, e := age.Decrypt(bytes.NewReader(raw), identity)
	if e != nil {
		return nil, userError("密码不正确或加密包损坏")
	}
	plain, e := io.ReadAll(io.LimitReader(reader, yamlLimit+1))
	if e != nil {
		return nil, userError("加密包损坏")
	}
	if len(plain) > yamlLimit {
		return nil, userError("解密后的 YAML 超过 2 MiB")
	}
	return plain, nil
}

// Node credentials match unique IDs, never array positions.
func mergeMissing(target, current common.Map, keepSecrets bool) {
	for k, v := range current {
		tv, ok := target[k]
		if (!ok && sensitive(k)) || (keepSecrets && (secret(k) || strings.Contains(k, "private_key"))) {
			target[k] = v
			continue
		}
		if k == "nodes" {
			lookup := map[string]common.Map{}
			for _, n := range common.A(v) {
				m := common.M(n)
				lookup[common.S(m["id"])] = m
			}
			for _, n := range common.A(tv) {
				m := common.M(n)
				if old := lookup[common.S(m["id"])]; old != nil {
					mergeMissing(m, old, keepSecrets)
				}
			}
		} else if child := common.M(tv); len(child) > 0 {
			mergeMissing(child, common.M(v), keepSecrets)
		}
	}
}
