package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"webscan/internal/common"
)

const configurationBackupPartSize = 1 << 20

var ErrConfigurationBackupKey = errors.New("部署配置备份密钥不可用或存档校验失败，请检查独立密钥和备份资料")
var ErrConfigurationBackupPermission = errors.New("部署配置备份仅允许管理员操作")

// Only this whitelist is a public metadata model. It contains no digest of
// private configuration, vault identity, source YAML, credential or address.
type ConfigurationBackup struct {
	ID              string    `json:"id"`
	RecordKey       string    `json:"record_key"`
	Created         time.Time `json:"created_at"`
	Source          string    `json:"source"`
	DocumentCreated string    `json:"document_created_at"`
	SettingsVersion int64     `json:"settings_version"`
	NodeCount       int       `json:"node_count"`
	NeedsCompletion bool      `json:"needs_completion"`
	CanDelete       bool      `json:"can_delete"`
	DeleteReason    string    `json:"delete_reason"`
}

type privateConfigurationBackup struct {
	ConfigurationBackup
	KeyID    string
	Revision int64
	Nonce    []byte
	Bytes    int
}

func (privateConfigurationBackup) String() string   { return "[private configuration backup]" }
func (privateConfigurationBackup) GoString() string { return "[private configuration backup]" }
func (privateConfigurationBackup) MarshalJSON() ([]byte, error) {
	return nil, ErrConfigurationBackupKey
}

func configurationBackupAdmin(ctx context.Context, tx *sql.Tx, user string) error {
	if !identifier.MatchString(user) {
		return ErrConfigurationBackupPermission
	}
	var role string
	if err := tx.QueryRowContext(ctx, "SELECT role FROM v3_accounts WHERE username=$1 FOR SHARE", user).Scan(&role); err != nil {
		if err == sql.ErrNoRows {
			return ErrConfigurationBackupPermission
		}
		return err
	}
	if role != "admin" {
		return ErrConfigurationBackupPermission
	}
	return nil
}

func configurationBackupGuard(ctx context.Context, user string) func(*sql.Tx) error {
	return func(tx *sql.Tx) error { return configurationBackupAdmin(ctx, tx, user) }
}

func configurationBackupAAD(b privateConfigurationBackup) []byte {
	// Bind both the immutable identity and the meaningful metadata. Created
	// database timestamps and live deletion eligibility are not ciphertext data.
	return common.JSON([]any{"webscan-v3/configuration-backup/v1", b.ID, b.KeyID, b.Revision, b.Source, b.DocumentCreated, b.SettingsVersion, b.NodeCount, b.NeedsCompletion})
}

func sealConfigurationBackup(v *Vault, b *privateConfigurationBackup, raw []byte) ([]byte, error) {
	if v == nil || v.keys[v.active] == nil || len(raw) == 0 || len(raw) > configurationDocumentLimit || b.Revision < 1 {
		return nil, ErrConfigurationBackupKey
	}
	b.KeyID = v.active
	aead := v.keys[v.active]
	b.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(b.Nonce); err != nil {
		return nil, ErrConfigurationBackupKey
	}
	sealed := aead.Seal(nil, b.Nonce, raw, configurationBackupAAD(*b))
	b.Bytes = len(sealed)
	return sealed, nil
}

// Proofs are domain-separated and keyed. Neither stored receipts nor audits
// provide an offline oracle for an imported notification password.
func configurationBackupProof(v *Vault, raw []byte) (string, error) {
	if v == nil || len(v.receiptKeys[v.active]) == 0 {
		return "", ErrConfigurationBackupKey
	}
	h := hmac.New(sha256.New, v.receiptKeys[v.active])
	h.Write([]byte("webscan-v3/configuration-backup-request/v1\x00"))
	h.Write(raw)
	return v.active + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

func insertConfigurationBackup(ctx context.Context, tx *sql.Tx, v *Vault, user, source string, doc configurationDocument) (ConfigurationBackup, error) {
	raw, err := marshalConfigurationDocument(doc)
	if err != nil {
		return ConfigurationBackup{}, err
	}
	defer clear(raw)
	b := privateConfigurationBackup{ConfigurationBackup: ConfigurationBackup{ID: token(), Source: source, DocumentCreated: doc.Created, SettingsVersion: doc.SettingsVersion, NodeCount: len(doc.Nodes), NeedsCompletion: !doc.complete()}, Revision: 1}
	sealed, err := sealConfigurationBackup(v, &b, raw)
	if err != nil {
		return ConfigurationBackup{}, err
	}
	defer clear(sealed)
	if err = tx.QueryRowContext(ctx, `INSERT INTO v3_configuration_backups(id,source,created_by,document_created_at,settings_version,node_count,needs_completion,key_id,revision,nonce,ciphertext_bytes)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING created_at`, b.ID, source, user, b.DocumentCreated, b.SettingsVersion, b.NodeCount, b.NeedsCompletion, b.KeyID, b.Revision, b.Nonce, b.Bytes).Scan(&b.Created); err != nil {
		return ConfigurationBackup{}, err
	}
	if err = insertConfigurationBackupParts(ctx, tx, b.ID, sealed); err != nil {
		return ConfigurationBackup{}, err
	}
	b.RecordKey = "configuration-backup:" + b.ID
	// This is a creation receipt, not a live eligibility check. The list computes
	// protection again; callers must not use a receipt as a deletion preview.
	b.CanDelete, b.DeleteReason = false, "请刷新列表确认保护状态"
	return b.ConfigurationBackup, nil
}

func insertConfigurationBackupParts(ctx context.Context, tx *sql.Tx, id string, sealed []byte) error {
	for part, offset := 0, 0; offset < len(sealed); part, offset = part+1, offset+configurationBackupPartSize {
		end := min(offset+configurationBackupPartSize, len(sealed))
		if _, err := tx.ExecContext(ctx, "INSERT INTO v3_configuration_backup_parts(backup,part,payload) VALUES($1,$2,$3)", id, part, sealed[offset:end]); err != nil {
			return err
		}
	}
	return nil
}

func loadConfigurationBackup(ctx context.Context, tx *sql.Tx, v *Vault, id string, update bool) (configurationDocument, privateConfigurationBackup, error) {
	var b privateConfigurationBackup
	if !validArchiveSource(id) {
		return configurationDocument{}, b, sql.ErrNoRows
	}
	lock := " FOR SHARE"
	if update {
		lock = " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx, `SELECT id,created_at,source,document_created_at,settings_version,node_count,needs_completion,key_id,revision,nonce,ciphertext_bytes FROM v3_configuration_backups WHERE id=$1`+lock, id).Scan(&b.ID, &b.Created, &b.Source, &b.DocumentCreated, &b.SettingsVersion, &b.NodeCount, &b.NeedsCompletion, &b.KeyID, &b.Revision, &b.Nonce, &b.Bytes); err != nil {
		return configurationDocument{}, b, err
	}
	if v == nil || v.keys[b.KeyID] == nil || b.Bytes < 17 || b.Bytes > configurationDocumentLimit+16 || len(b.Nonce) != v.keys[b.KeyID].NonceSize() {
		return configurationDocument{}, b, ErrConfigurationBackupKey
	}
	rows, err := tx.QueryContext(ctx, "SELECT part,payload FROM v3_configuration_backup_parts WHERE backup=$1 ORDER BY part", id)
	if err != nil {
		return configurationDocument{}, b, err
	}
	defer rows.Close()
	sealed := make([]byte, 0, b.Bytes)
	defer func() { clear(sealed) }()
	part := 0
	for rows.Next() {
		var index int
		var payload []byte
		if err = rows.Scan(&index, &payload); err != nil {
			return configurationDocument{}, b, err
		}
		if index != part || len(payload) < 1 || len(payload) > configurationBackupPartSize || len(sealed)+len(payload) > b.Bytes {
			return configurationDocument{}, b, ErrConfigurationBackupKey
		}
		sealed = append(sealed, payload...)
		part++
	}
	if err = rows.Err(); err != nil {
		return configurationDocument{}, b, err
	}
	if len(sealed) != b.Bytes || part != (b.Bytes+configurationBackupPartSize-1)/configurationBackupPartSize {
		return configurationDocument{}, b, ErrConfigurationBackupKey
	}
	raw, err := v.keys[b.KeyID].Open(nil, b.Nonce, sealed, configurationBackupAAD(b))
	if err != nil {
		return configurationDocument{}, b, ErrConfigurationBackupKey
	}
	defer clear(raw)
	doc, err := parseConfigurationDocument(raw)
	if err != nil || doc.Created != b.DocumentCreated || doc.SettingsVersion != b.SettingsVersion || len(doc.Nodes) != b.NodeCount || !doc.complete() != b.NeedsCompletion {
		return configurationDocument{}, b, ErrConfigurationBackupKey
	}
	return doc, b, nil
}

// Capture and insert share the receipt's repeatable-read snapshot. Receipt
// replay skips capture, even if the live configuration has changed meanwhile.
func (s *Store) createConfigurationBackup(ctx context.Context, v *Vault, c Config, user, key string) (json.RawMessage, error) {
	if c.Validate() != nil {
		return nil, errConfigurationDocument
	}
	bootstrap, err := json.Marshal(c)
	if err != nil {
		return nil, errConfigurationDocument
	}
	proof, err := configurationBackupProof(v, bootstrap)
	if err != nil {
		return nil, err
	}
	return s.guardedMutationOptions(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, user, key, "configuration-backup-create", "manual", proof, configurationBackupGuard(ctx, user), func(tx *sql.Tx) (any, error) {
		doc, err := captureConfigurationDocumentTx(ctx, tx, c, v)
		if err != nil {
			return nil, err
		}
		return insertConfigurationBackup(ctx, tx, v, user, "manual", doc)
	})
}

// Import only archives a document. No live settings, node, account, task,
// credential identity or applied version is changed by this operation.
func (s *Store) importConfigurationBackup(ctx context.Context, v *Vault, user, key string, raw []byte) (json.RawMessage, error) {
	doc, err := parseConfigurationDocument(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := marshalConfigurationDocument(doc)
	if err != nil {
		return nil, err
	}
	defer clear(canonical)
	proof, err := configurationBackupProof(v, canonical)
	if err != nil {
		return nil, err
	}
	return s.guardedMutation(ctx, user, key, "configuration-backup-import", "import", proof, configurationBackupGuard(ctx, user), func(tx *sql.Tx) (any, error) { return insertConfigurationBackup(ctx, tx, v, user, "import", doc) })
}

// The caller must enforce HTTPS/admission before using password encryption.
// These internal store primitives are not public HTTP endpoints.
func (s *Store) importEncryptedConfigurationBackup(ctx context.Context, v *Vault, user, key string, raw []byte, password string) (json.RawMessage, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	doc, err := decryptConfigurationDocument(raw, password)
	if err != nil {
		return nil, err
	}
	plain, err := marshalConfigurationDocument(doc)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return s.importConfigurationBackup(ctx, v, user, key, plain)
}

func (s *Store) configurationBackups(ctx context.Context, user string, before retentionCursor, limit int) ([]ConfigurationBackup, error) {
	if limit < 1 || limit > 200 {
		return nil, errConfigurationDocument
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return nil, err
	}
	stamp := before.Time
	if stamp.IsZero() {
		stamp = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rows, err := tx.QueryContext(ctx, `SELECT b.id,b.created_at,b.source,b.document_created_at,b.settings_version,b.node_count,b.needs_completion,
 EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending),
 COALESCE((SELECT kind FROM v3_configuration_backup_pins p WHERE p.backup=b.id AND (expires_at IS NULL OR expires_at>clock_timestamp()) ORDER BY CASE kind WHEN 'rollback' THEN 0 WHEN 'deployment' THEN 1 WHEN 'restore' THEN 2 ELSE 3 END LIMIT 1),CASE WHEN EXISTS(SELECT 1 FROM v3_configuration_delete_items i WHERE i.backup=b.id AND i.status='pending') THEN 'delete' ELSE '' END)
 FROM v3_configuration_backups b WHERE (created_at,id)<($1,$2) ORDER BY created_at DESC,id DESC LIMIT $3`, stamp, before.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ConfigurationBackup{}
	for rows.Next() {
		var b ConfigurationBackup
		var frozen bool
		var pin string
		if err = rows.Scan(&b.ID, &b.Created, &b.Source, &b.DocumentCreated, &b.SettingsVersion, &b.NodeCount, &b.NeedsCompletion, &frozen, &pin); err != nil {
			return nil, err
		}
		b.RecordKey = "configuration-backup:" + b.ID
		b.CanDelete = !frozen && pin == ""
		if frozen {
			b.DeleteReason = "数据迁移期间保护备份"
		} else {
			b.DeleteReason = configurationBackupPinReason(pin)
		}
		items = append(items, b)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

func configurationBackupPinReason(kind string) string {
	switch kind {
	case "export":
		return "正在导出"
	case "restore":
		return "恢复流程引用"
	case "deployment":
		return "部署任务引用"
	case "rollback":
		return "回退需要"
	case "delete":
		return "删除任务处理中"
	}
	return ""
}

// Pin is durable before expensive projection/encryption begins; a process
// crash leaves bounded protection rather than a permanently undeletable file.
func (s *Store) withConfigurationBackup(ctx context.Context, v *Vault, user, id, mode string, output func(configurationDocument) ([]byte, error)) ([]byte, error) {
	out, release, err := s.prepareConfigurationBackupExport(ctx, v, user, id, mode, output)
	if err != nil {
		return nil, err
	}
	defer release()
	return out, nil
}

func (s *Store) prepareConfigurationBackupExport(ctx context.Context, v *Vault, user, id, mode string, output func(configurationDocument) ([]byte, error)) ([]byte, func(), error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return nil, nil, err
	}
	doc, _, err := loadConfigurationBackup(ctx, tx, v, id, false)
	if err != nil {
		return nil, nil, err
	}
	ref := token()
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_configuration_backup_pins(backup,kind,reference,expires_at) VALUES($1,'export',$2,clock_timestamp()+interval '5 minutes')", id, ref); err != nil {
		return nil, nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, err
	}
	release := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = s.DB.ExecContext(cleanup, "DELETE FROM v3_configuration_backup_pins WHERE backup=$1 AND kind='export' AND reference=$2", id, ref)
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	out, err := output(doc)
	if err != nil {
		clear(out)
		return nil, nil, err
	}
	if ctx.Err() != nil {
		clear(out)
		return nil, nil, ctx.Err()
	}
	// Prepared is deliberately distinct from an eventual HTTP download result.
	if _, err = s.DB.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-backup-export-prepared',$2,$3)", user, id, common.JSON(map[string]any{"mode": mode, "bytes": len(out)})); err != nil {
		clear(out)
		return nil, nil, err
	}
	success = true
	return out, release, nil
}

func (s *Store) exportConfigurationBackup(ctx context.Context, v *Vault, user, id string) ([]byte, error) {
	return s.withConfigurationBackup(ctx, v, user, id, "redacted", func(doc configurationDocument) ([]byte, error) {
		public, err := doc.redacted()
		if err != nil {
			return nil, err
		}
		return marshalConfigurationDocument(public)
	})
}

func (s *Store) exportEncryptedConfigurationBackup(ctx context.Context, v *Vault, user, id, password, confirm string) ([]byte, error) {
	return s.withConfigurationBackup(ctx, v, user, id, "age", func(doc configurationDocument) ([]byte, error) {
		return encryptConfigurationDocument(doc, password, confirm)
	})
}

// The future durable deletion worker calls this inside its fenced transaction.
// The parent-row lock serializes concurrent pin creation and cipher rewrapping.
func deleteConfigurationBackupTx(ctx context.Context, tx *sql.Tx, id string) (bool, string, error) {
	if !validArchiveSource(id) {
		return false, "备份编号不正确", errConfigurationDocument
	}
	if frozen, err := migrationHeld(ctx, tx); err != nil {
		return false, "", err
	} else if frozen {
		return false, "数据迁移期间保护备份", nil
	}
	var found string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM v3_configuration_backups WHERE id=$1 FOR UPDATE", id).Scan(&found); err != nil {
		if err == sql.ErrNoRows {
			return false, "备份不存在", nil
		}
		return false, "", err
	}
	var pin string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT kind FROM v3_configuration_backup_pins WHERE backup=$1 AND (expires_at IS NULL OR expires_at>clock_timestamp()) ORDER BY kind LIMIT 1),'')`, id).Scan(&pin); err != nil {
		return false, "", err
	}
	if pin != "" {
		return false, configurationBackupPinReason(pin), nil
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM v3_configuration_backups WHERE id=$1", id); err != nil {
		return false, "", err
	}
	return true, "", nil
}

func (s *Store) rewrapConfigurationBackup(ctx context.Context, v *Vault, id string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	doc, b, err := loadConfigurationBackup(ctx, tx, v, id, true)
	if err != nil {
		return err
	}
	if b.KeyID == v.active {
		return tx.Commit()
	}
	raw, err := marshalConfigurationDocument(doc)
	if err != nil {
		return err
	}
	defer clear(raw)
	b.Revision++
	sealed, err := sealConfigurationBackup(v, &b, raw)
	if err != nil {
		return err
	}
	defer clear(sealed)
	if _, err = tx.ExecContext(ctx, "DELETE FROM v3_configuration_backup_parts WHERE backup=$1", id); err != nil {
		return err
	}
	if err = insertConfigurationBackupParts(ctx, tx, id, sealed); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_configuration_backups SET key_id=$2,revision=$3,nonce=$4,ciphertext_bytes=$5 WHERE id=$1", id, b.KeyID, b.Revision, b.Nonce, b.Bytes); err != nil {
		return err
	}
	return tx.Commit()
}

var _ fmt.Stringer = privateConfigurationBackup{}
