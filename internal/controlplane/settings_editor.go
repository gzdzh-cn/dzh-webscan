package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"webscan/internal/common"
)

var errSettingsPreview = errors.New("设置预览已过期，或账号、配置、部署状态已变化，请重新预览")

type settingsEditorView struct {
	State          settingsDraftState `json:"state"`
	Fields         []settingsField    `json:"fields"`
	Values         map[string]any     `json:"values"`
	RuntimeValues  map[string]any     `json:"runtime_values"`
	Secrets        map[string]bool    `json:"secret_configured"`
	RuntimeSecrets map[string]bool    `json:"runtime_secret_configured"`
}

func projectSettingsValues(raw []byte) (map[string]any, map[string]bool, error) {
	var root configurationValues
	if decodeConfigurationObject(raw, &root) != nil {
		return nil, nil, errSettingsDraft
	}
	values := map[string]any{}
	secrets := map[string]bool{}
	for _, f := range settingsFields() {
		if v, ok := settingsPath(root, f.Path); ok {
			if !f.valid(v) {
				return nil, nil, errSettingsEdit
			}
			values[f.Path] = v
		}
	}
	for path := range settingsSecretLabels {
		v, _ := settingsPath(root, path)
		secrets[path] = common.S(v) != ""
	}
	return values, secrets, nil
}

func (s *Store) settingsEditor(ctx context.Context, user string, b *configurationEditBackup) (settingsEditorView, error) {
	var out settingsEditorView
	if b == nil || b.vault == nil {
		return out, errConfigurationBeforeEdit
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if e = configurationBackupAdmin(ctx, tx, user); e != nil {
		return out, e
	}
	d, e := readSettingsDraftTx(ctx, tx, false)
	if e != nil {
		return out, e
	}
	if e = checkSettingsDraftProof(b.vault, d); e != nil {
		return out, e
	}
	out.State = d.settingsDraftState
	out.Fields = settingsFields()
	if out.Values, out.Secrets, e = projectSettingsValues(d.Desired); e != nil {
		return out, e
	}
	out.RuntimeValues, out.RuntimeSecrets, e = projectSettingsValues(d.Runtime)
	return out, e
}

type settingsEditorRequest struct {
	Action             string       `json:"action"`
	ExpectedGeneration int64        `json:"expected_generation,string"`
	ExpectedRuntime    int64        `json:"expected_runtime_version"`
	Edit               settingsEdit `json:"edit"`
	Preview            string       `json:"preview,omitempty"`
}

func (settingsEditorRequest) String() string   { return "[private settings request]" }
func (settingsEditorRequest) GoString() string { return "[private settings request]" }

type settingsPreviewTicket struct {
	Key     string `json:"key"`
	Action  string `json:"action"`
	Expires int64  `json:"expires"`
	Nonce   string `json:"nonce"`
}
type settingsEditorPreview struct {
	Token                string    `json:"token"`
	Action               string    `json:"action"`
	Expires              time.Time `json:"expires_at"`
	Changed              []string  `json:"changed_fields"`
	RetentionShortened   bool      `json:"retention_shortened"`
	NotificationsEnabled bool      `json:"notifications_enabled"`
}

func settingsPreviewProof(v *Vault, t settingsPreviewTicket, user string, account int64, doc configurationDocument, target configurationValues, deployments json.RawMessage) (string, error) {
	if v == nil || len(v.receiptKeys[t.Key]) == 0 {
		return "", errSettingsPreview
	}
	doc.Created = "2000-01-01T00:00:00Z"
	type privateDocument configurationDocument
	raw, e := json.Marshal([]any{t, user, account, privateDocument(doc), target, deployments})
	if e != nil {
		return "", errSettingsPreview
	}
	defer clear(raw)
	h := hmac.New(sha256.New, v.receiptKeys[t.Key])
	h.Write([]byte("webscan-v3/settings-editor-preview/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Return a new private target under the same relation gate that protects the
// following backup/write. Preview and confirmation both reconstruct it; a safe
// display summary is never used as an executable patch.
func prepareSettingsEditorTx(ctx context.Context, tx *sql.Tx, b *configurationEditBackup, user string, in settingsEditorRequest) (privateSettingsDraft, configurationDocument, configurationValues, json.RawMessage, int64, []string, error) {
	var d privateSettingsDraft
	var doc configurationDocument
	bad := func(e error) (privateSettingsDraft, configurationDocument, configurationValues, json.RawMessage, int64, []string, error) {
		return d, doc, nil, nil, 0, nil, e
	}
	if in.Action != "save" && in.Action != "apply" || in.ExpectedGeneration < 0 || in.ExpectedRuntime < 1 {
		return bad(errSettingsEdit)
	}
	account, e := configurationRestoreAccount(ctx, tx, user)
	if e != nil {
		return bad(e)
	}
	d, e = readSettingsDraftTx(ctx, tx, true)
	if e != nil {
		return bad(e)
	}
	if e = checkSettingsDraftProof(b.vault, d); e != nil {
		return bad(e)
	}
	if d.Generation != in.ExpectedGeneration || d.RuntimeVersion != in.ExpectedRuntime {
		return bad(errSettingsPreview)
	}
	doc, e = captureConfigurationDocumentTx(ctx, tx, b.bootstrap, b.vault)
	if e != nil {
		return bad(e)
	}
	deployments, e := configurationRestoreDeployments(ctx, tx)
	if e != nil {
		return bad(e)
	}
	var target configurationValues
	changed := []string{}
	if in.Action == "save" {
		target, changed, e = editSettings(doc.Settings, in.Edit)
	} else {
		if len(in.Edit.Values) > 0 || len(in.Edit.Secrets) > 0 || !d.Pending {
			return bad(errSettingsEdit)
		}
		target, e = configurationMap(doc.Settings)
		if e == nil {
			_, _, e = editSettings(target, settingsEdit{})
		}
		var live configurationValues
		if decodeConfigurationObject(d.Runtime, &live) != nil {
			return bad(errSettingsDraft)
		}
		// Do not call an unknown/unimplemented runtime policy applied merely
		// because its bytes were written. Its dedicated coordinator is required.
		allowed := map[string]bool{}
		for _, f := range settingsFields() {
			allowed[f.Path] = true
		}
		for p := range settingsSecretLabels {
			allowed[p] = true
		}
		for _, p := range []string{"sqlite_events_days", "security_events_days", "website_incidents_days", "server_alerts_days", "delivery_records_days"} {
			allowed["retention."+p] = true
		}
		var walk func(string, any, any) error
		walk = func(path string, a, z any) error {
			if configurationRestoreEqual(a, z) {
				return nil
			}
			if allowed[path] {
				changed = append(changed, path)
				return nil
			}
			am, aok := a.(map[string]any)
			zm, zok := z.(map[string]any)
			if a == nil {
				aok = true
				am = map[string]any{}
			}
			if z == nil {
				zok = true
				zm = map[string]any{}
			}
			if !aok || !zok {
				return errSettingsEdit
			}
			keys := map[string]bool{}
			for k := range am {
				keys[k] = true
			}
			for k := range zm {
				keys[k] = true
			}
			for k := range keys {
				next := k
				if path != "" {
					next = path + "." + k
				}
				if e := walk(next, am[k], zm[k]); e != nil {
					return e
				}
			}
			return nil
		}
		if e == nil {
			e = walk("", map[string]any(live), map[string]any(target))
		}
	}
	if e != nil {
		return bad(e)
	}
	if validateSettingsDraft(b.bootstrap, common.JSON(target)) != nil {
		return bad(errSettingsEdit)
	}
	sort.Strings(changed)
	return d, doc, target, deployments, account, changed, nil
}

func (s *Store) previewSettingsEditor(ctx context.Context, user string, in settingsEditorRequest, b *configurationEditBackup) (settingsEditorPreview, error) {
	var out settingsEditorPreview
	if b == nil || b.vault == nil || in.Preview != "" {
		return out, errSettingsEdit
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if held, e := migrationHeld(ctx, tx); e != nil {
		return out, e
	} else if held {
		return out, ErrMigrationPending
	}
	if e = b.lock(ctx, tx, user); e != nil {
		return out, e
	}
	_, doc, target, deployments, account, changed, e := prepareSettingsEditorTx(ctx, tx, b, user, in)
	if e != nil {
		return out, e
	}
	var now time.Time
	if e = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return out, e
	}
	t := settingsPreviewTicket{Key: b.vault.active, Action: in.Action, Expires: now.Add(10 * time.Minute).Unix(), Nonce: token()}
	proof, e := settingsPreviewProof(b.vault, t, user, account, doc, target, deployments)
	if e != nil {
		return out, e
	}
	out = settingsEditorPreview{Token: base64.RawURLEncoding.EncodeToString(common.JSON(t)) + "." + proof, Action: in.Action, Expires: time.Unix(t.Expires, 0).UTC(), Changed: changed}
	var original configurationValues
	if in.Action == "apply" {
		d, e := readSettingsDraftTx(ctx, tx, false)
		if e != nil {
			return out, e
		}
		if decodeConfigurationObject(d.Runtime, &original) != nil {
			return out, errSettingsDraft
		}
	} else {
		original = doc.Settings
	}
	oldPolicy, e := retentionPolicy(original)
	if e != nil {
		return out, e
	}
	newPolicy, e := retentionPolicy(target)
	if e != nil {
		return out, e
	}
	out.RetentionShortened = newPolicy.Events < oldPolicy.Events || newPolicy.Security < oldPolicy.Security || newPolicy.Servers < oldPolicy.Servers || newPolicy.Websites < oldPolicy.Websites || newPolicy.Notifications < oldPolicy.Notifications
	for _, channel := range []string{"email", "feishu"} {
		if common.B(common.M(target[channel])["enabled"]) && !common.B(common.M(original[channel])["enabled"]) {
			out.NotificationsEnabled = true
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'settings-preview','settings',$2)`, user, common.JSON(map[string]any{"action": in.Action, "changed_fields": changed})); e != nil {
		return settingsEditorPreview{}, e
	}
	return out, tx.Commit()
}

func parseSettingsTicket(raw string) (settingsPreviewTicket, string, error) {
	var t settingsPreviewTicket
	if len(raw) > 2048 {
		return t, "", errSettingsPreview
	}
	payload, proof, ok := strings.Cut(raw, ".")
	if !ok || len(proof) != 64 {
		return t, "", errSettingsPreview
	}
	b, e := base64.RawURLEncoding.DecodeString(payload)
	if e != nil || json.Unmarshal(b, &t) != nil || !validArchiveSource(t.Nonce) || t.Expires < 1 {
		return t, "", errSettingsPreview
	}
	if _, e = hex.DecodeString(proof); e != nil {
		return t, "", errSettingsPreview
	}
	return t, proof, nil
}

func (s *Store) confirmSettingsEditor(ctx context.Context, user, key string, in settingsEditorRequest, b *configurationEditBackup) (json.RawMessage, error) {
	if b == nil || b.vault == nil {
		return nil, errConfigurationBeforeEdit
	}
	t, proof, e := parseSettingsTicket(in.Preview)
	if e != nil || t.Action != in.Action {
		return nil, errSettingsPreview
	}
	// The random signed preview is part of the request hash. Neither a plain
	// secret digest nor any private body enters a receipt or audit record.
	editRaw, e := json.Marshal(in.Edit)
	if e != nil {
		return nil, errSettingsEdit
	}
	defer clear(editRaw)
	return s.guardedMutation(ctx, user, key, "settings-"+in.Action, "settings", []any{in.Preview, digest(editRaw), in.ExpectedGeneration, in.ExpectedRuntime}, func(tx *sql.Tx) error { return b.lock(ctx, tx, user) }, func(tx *sql.Tx) (any, error) {
		d, doc, target, deployments, account, _, e := prepareSettingsEditorTx(ctx, tx, b, user, in)
		if e != nil {
			return nil, e
		}
		var now int64
		if e = tx.QueryRowContext(ctx, `SELECT extract(epoch FROM clock_timestamp())::bigint`).Scan(&now); e != nil {
			return nil, e
		}
		if t.Expires <= now || t.Expires > now+601 {
			return nil, errSettingsPreview
		}
		expected, e := settingsPreviewProof(b.vault, t, user, account, doc, target, deployments)
		if e != nil || !hmac.Equal([]byte(expected), []byte(proof)) {
			return nil, errSettingsPreview
		}
		if e = b.capture(ctx, tx, user, "settings-"+in.Action, "settings"); e != nil {
			return nil, e
		}
		if in.Action == "save" {
			return putSettingsDraftTx(ctx, tx, b.vault, common.JSON(target), d.RuntimeVersion, d.Runtime)
		}
		return applySettingsDraftTx(ctx, tx, b, d)
	})
}
