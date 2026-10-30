package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode/utf8"

	"webscan/internal/common"
	"webscan/internal/website"
)

const websiteBackupImportLimit = 2 << 20
const websiteBackupStoredLimit = 24 << 20
const websiteBackupSitesLimit = 100000

var ErrBackupPreview = errors.New("恢复预览不存在、已过期或配置已变化，请重新预览")
var ErrWebsiteBackupInput = errors.New("网站备份参数不正确")

type WebsiteBackup struct {
	ID           string          `json:"id"`
	RecordKey    string          `json:"record_key"`
	Created      time.Time       `json:"created_at"`
	Source       string          `json:"source"`
	Count        int             `json:"count"`
	Restored     *time.Time      `json:"restored_at"`
	Result       json.RawMessage `json:"result"`
	CanDelete    bool            `json:"can_delete"`
	DeleteReason string          `json:"delete_reason"`
}

type WebsiteBackupPreview struct {
	Added     int      `json:"added"`
	Updated   int      `json:"updated"`
	Unchanged int      `json:"unchanged"`
	Unknown   []string `json:"unknown_nodes"`
	Token     string   `json:"token,omitempty"`
	Before    string   `json:"before_backup,omitempty"`
}

func lockWebsiteConfiguration(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(773376012)")
	return err
}

// Reject duplicate object keys before decoding a typed document. JSON's usual
// last-key-wins behavior is unsuitable for an operator's restore preview.
func uniqueBackupJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("备份 JSON 嵌套过深")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			k, e := d.Token()
			key, valid := k.(string)
			if e != nil || !valid || seen[key] {
				return errors.New("备份 JSON 包含重复或无效字段")
			}
			seen[key] = true
		}
		if err = uniqueBackupJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}

func parseWebsiteBackup(raw []byte, limit int) (website.BackupDocument, error) {
	var doc website.BackupDocument
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return doc, errors.New("网站备份须为有效 UTF-8 文本，不能为空或超过大小限制")
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if uniqueBackupJSON(check, 0) != nil {
		return doc, errors.New("网站备份 JSON 格式不正确或包含重复字段")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&doc) != nil || d.Decode(new(any)) != io.EOF || doc.Format != 1 || doc.Sites == nil || len(doc.Sites) > websiteBackupSitesLimit {
		return doc, errors.New("网站备份格式或版本不正确，仅接受 format_version: 1 和网站列表")
	}
	if _, err := time.Parse(time.RFC3339Nano, doc.Created); err != nil {
		return doc, errors.New("备份创建时间须为 RFC3339 时间")
	}
	seen := map[string]bool{}
	for i, v := range doc.Sites {
		in := SiteInput{Name: v.Name, URL: v.URL, Node: v.Node, Keyword: v.Keyword, Slow: v.Slow, Paused: v.Paused}
		if in.validate() != nil || seen[in.URL] {
			return doc, errors.New("网站备份包含无效配置或重复网址")
		}
		seen[in.URL] = true
		doc.Sites[i] = website.SiteConfig{Name: in.Name, URL: in.URL, Node: in.Node, Keyword: in.Keyword, Slow: in.Slow, Paused: in.Paused}
	}
	return doc, nil
}

func captureWebsiteBackup(ctx context.Context, tx *sql.Tx) (website.BackupDocument, error) {
	doc := website.BackupDocument{Format: 1, Sites: []website.SiteConfig{}}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return doc, err
	}
	doc.Created = now.UTC().Format(time.RFC3339Nano)
	rows, err := tx.QueryContext(ctx, "SELECT name,url,node,keyword,slow,paused FROM v3_websites WHERE NOT deleted ORDER BY id")
	if err != nil {
		return doc, err
	}
	defer rows.Close()
	size := 256
	for rows.Next() {
		var v website.SiteConfig
		if err = rows.Scan(&v.Name, &v.URL, &v.Node, &v.Keyword, &v.Slow, &v.Paused); err != nil {
			return doc, err
		}
		size += len(common.JSON(v)) + 1
		if size > websiteBackupStoredLimit || len(doc.Sites) >= websiteBackupSitesLimit {
			return doc, fmt.Errorf("%w：网站配置超过备份大小或数量限制，未创建备份", ErrWebsiteBackupInput)
		}
		doc.Sites = append(doc.Sites, v)
	}
	return doc, rows.Err()
}

func insertWebsiteBackup(ctx context.Context, tx *sql.Tx, doc website.BackupDocument, source string) (map[string]any, error) {
	raw := common.JSON(doc)
	if len(raw) > websiteBackupStoredLimit {
		return nil, fmt.Errorf("%w：网站配置超过备份大小限制", ErrWebsiteBackupInput)
	}
	id := token()
	if _, err := tx.ExecContext(ctx, "INSERT INTO v3_website_backups(id,source,payload,digest,count) VALUES($1,$2,$3,$4,$5)", id, source, raw, digest(raw), len(doc.Sites)); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "count": len(doc.Sites), "source": source}, nil
}

func (s *Store) CreateWebsiteBackup(ctx context.Context, user, key string) (json.RawMessage, error) {
	return s.mutation(ctx, user, key, "website-backup-create", "websites", nil, func(tx *sql.Tx) (any, error) {
		if err := lockWebsiteConfiguration(ctx, tx); err != nil {
			return nil, err
		}
		doc, err := captureWebsiteBackup(ctx, tx)
		if err != nil {
			return nil, err
		}
		return insertWebsiteBackup(ctx, tx, doc, "manual")
	})
}

func (s *Store) ImportWebsiteBackup(ctx context.Context, user, key string, raw []byte) (json.RawMessage, error) {
	doc, err := parseWebsiteBackup(raw, websiteBackupImportLimit)
	if err != nil {
		return nil, fmt.Errorf("%w：%s", ErrWebsiteBackupInput, err)
	}
	return s.mutation(ctx, user, key, "website-backup-import", "websites", digest(common.JSON(doc)), func(tx *sql.Tx) (any, error) {
		return insertWebsiteBackup(ctx, tx, doc, "import")
	})
}

func loadWebsiteBackup(ctx context.Context, tx *sql.Tx, id string) (website.BackupDocument, string, error) {
	var raw []byte
	var sum string
	if !validArchiveSource(id) {
		return website.BackupDocument{}, "", sql.ErrNoRows
	}
	if err := tx.QueryRowContext(ctx, "SELECT payload,digest FROM v3_website_backups WHERE id=$1 FOR SHARE", id).Scan(&raw, &sum); err != nil {
		return website.BackupDocument{}, "", err
	}
	doc, err := parseWebsiteBackup(raw, websiteBackupStoredLimit)
	if err != nil || digest(common.JSON(doc)) != sum {
		return website.BackupDocument{}, "", errors.New("备份校验失败，未读取配置")
	}
	return doc, sum, nil
}

func (s *Store) ExportWebsiteBackup(ctx context.Context, id string) (website.BackupDocument, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return website.BackupDocument{}, err
	}
	defer tx.Rollback()
	doc, _, err := loadWebsiteBackup(ctx, tx, id)
	if err != nil {
		return doc, err
	}
	return doc, tx.Commit()
}

// Versions, deleted identities and registry versions bind the preview. Probe
// results and leases are deliberately excluded, so normal checks do not expire
// it. SHARE prevents node edits while associations are resolved in this tx.
func websiteBackupRevision(ctx context.Context, tx *sql.Tx) (string, map[string]bool, error) {
	if _, err := tx.ExecContext(ctx, "LOCK TABLE v3_nodes IN SHARE MODE"); err != nil {
		return "", nil, err
	}
	h := sha256.New()
	e := json.NewEncoder(h)
	rows, err := tx.QueryContext(ctx, "SELECT id,version,deleted FROM v3_websites ORDER BY id")
	if err != nil {
		return "", nil, err
	}
	for rows.Next() {
		var id, version int64
		var deleted bool
		if err = rows.Scan(&id, &version, &deleted); err != nil {
			break
		}
		_ = e.Encode([]any{id, version, deleted})
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return "", nil, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT id,version FROM v3_nodes WHERE removed_at IS NULL ORDER BY id")
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	nodes := map[string]bool{"": true, "central": true}
	for rows.Next() {
		var id string
		var version int64
		if err = rows.Scan(&id, &version); err != nil {
			return "", nil, err
		}
		nodes[id] = true
		_ = e.Encode([]any{id, version})
	}
	return hex.EncodeToString(h.Sum(nil)), nodes, rows.Err()
}

func websiteBackupChanges(ctx context.Context, tx *sql.Tx, doc website.BackupDocument, nodes map[string]bool) (WebsiteBackupPreview, error) {
	out := WebsiteBackupPreview{Unknown: []string{}}
	unknown := map[string]bool{}
	current, err := captureWebsiteBackup(ctx, tx)
	if err != nil {
		return out, err
	}
	active := map[string]website.SiteConfig{}
	for _, v := range current.Sites {
		active[v.URL] = v
	}
	for _, v := range doc.Sites {
		if !nodes[v.Node] {
			unknown[v.Node] = true
			v.Node = ""
		}
		old, exists := active[v.URL]
		switch {
		case !exists:
			out.Added++
		case old == v:
			out.Unchanged++
		default:
			out.Updated++
		}
	}
	if len(active)+out.Added > websiteBackupSitesLimit {
		return out, fmt.Errorf("%w：合并后网站数量超过备份恢复限制", ErrWebsiteBackupInput)
	}
	for n := range unknown {
		out.Unknown = append(out.Unknown, n)
	}
	sort.Strings(out.Unknown)
	return out, nil
}

func (s *Store) PreviewWebsiteBackup(ctx context.Context, user, id string) (WebsiteBackupPreview, error) {
	var out WebsiteBackupPreview
	if !identifier.MatchString(user) {
		return out, errors.New("操作账号不正确")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return out, err
	} else if held {
		return out, ErrMigrationPending
	}
	if err = lockWebsiteConfiguration(ctx, tx); err != nil {
		return out, err
	}
	doc, sum, err := loadWebsiteBackup(ctx, tx, id)
	if err != nil {
		return out, err
	}
	revision, nodes, err := websiteBackupRevision(ctx, tx)
	if err != nil {
		return out, err
	}
	out, err = websiteBackupChanges(ctx, tx, doc, nodes)
	if err != nil {
		return out, err
	}
	out.Token = token()
	if _, err = tx.ExecContext(ctx, "DELETE FROM v3_website_backup_previews WHERE token_hash IN (SELECT token_hash FROM v3_website_backup_previews WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 200)"); err != nil {
		return out, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM v3_website_backup_previews WHERE username=$1 AND NOT used AND expires_at>clock_timestamp()", user).Scan(&count); err != nil {
		return out, err
	}
	if count >= 100 {
		return out, fmt.Errorf("%w：有效恢复预览过多，请等待旧预览过期", ErrWebsiteBackupInput)
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_website_backup_previews(token_hash,username,backup,digest,revision,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '10 minutes')", digest([]byte(out.Token)), user, id, sum, revision); err != nil {
		return WebsiteBackupPreview{}, err
	}
	return out, tx.Commit()
}

func (s *Store) RestoreWebsiteBackup(ctx context.Context, user, key, id, preview string) (json.RawMessage, error) {
	if !validArchiveSource(preview) || !validArchiveSource(id) {
		return nil, ErrBackupPreview
	}
	return s.mutation(ctx, user, key, "website-backup-restore", id, []string{id, digest([]byte(preview))}, func(tx *sql.Tx) (any, error) {
		if err := lockWebsiteConfiguration(ctx, tx); err != nil {
			return nil, err
		}
		doc, actual, err := loadWebsiteBackup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		var sum, revision string
		if err := tx.QueryRowContext(ctx, "SELECT digest,revision FROM v3_website_backup_previews WHERE token_hash=$1 AND username=$2 AND backup=$3 AND NOT used AND expires_at>clock_timestamp() FOR UPDATE", digest([]byte(preview)), user, id).Scan(&sum, &revision); err == sql.ErrNoRows {
			return nil, ErrBackupPreview
		} else if err != nil {
			return nil, err
		}
		current, nodes, err := websiteBackupRevision(ctx, tx)
		if err != nil {
			return nil, err
		}
		if actual != sum || current != revision {
			return nil, ErrBackupPreview
		}
		result, err := websiteBackupChanges(ctx, tx, doc, nodes)
		if err != nil {
			return nil, err
		}
		before, err := captureWebsiteBackup(ctx, tx)
		if err != nil {
			return nil, err
		}
		b, err := insertWebsiteBackup(ctx, tx, before, "before_restore")
		if err != nil {
			return nil, err
		}
		result.Before = b["id"].(string)
		for i, v := range doc.Sites {
			if !nodes[v.Node] {
				doc.Sites[i].Node = ""
			}
		}
		for start := 0; start < len(doc.Sites); start += 500 {
			end := min(start+500, len(doc.Sites))
			if err = restoreWebsiteBackupBatch(ctx, tx, doc.Sites[start:end]); err != nil {
				return nil, err
			}
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_website_backup_previews SET used=true WHERE token_hash=$1", digest([]byte(preview))); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE v3_website_backups SET restored_at=clock_timestamp(),result=$2 WHERE id=$1", id, common.JSON(result)); err != nil {
			return nil, err
		}
		return result, nil
	})
}

// Each statement handles at most 500 websites. All batches still belong to
// one transaction, so a failure never leaves a partly merged configuration.
func restoreWebsiteBackupBatch(ctx context.Context, tx *sql.Tx, sites []website.SiteConfig) error {
	raw := common.JSON(sites)
	const cfg = `WITH cfg AS (SELECT * FROM jsonb_to_recordset($1::jsonb) AS c(name text,url text,node text,keyword text,slow_alert boolean,paused boolean)), targets AS (SELECT c.*,(SELECT id FROM v3_websites w WHERE w.url=c.url ORDER BY deleted,id DESC LIMIT 1) id FROM cfg c) `
	rows, err := tx.QueryContext(ctx, cfg+`SELECT w.id FROM v3_websites w JOIN targets t ON t.id=w.id ORDER BY w.id FOR UPDATE OF w`, raw)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	const reset = `(w.deleted OR (w.keyword,w.slow,w.paused) IS DISTINCT FROM (t.keyword,t.slow_alert,t.paused))`
	if _, err = tx.ExecContext(ctx, cfg+`UPDATE v3_website_incidents i SET ended=GREATEST(i.started,floor(extract(epoch FROM clock_timestamp()))::bigint) FROM targets t JOIN v3_websites w ON w.id=t.id WHERE i.site=w.id AND i.ended IS NULL AND `+reset, raw); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, cfg+`UPDATE v3_websites w SET name=t.name,node=t.node,keyword=t.keyword,slow=t.slow_alert,paused=t.paused,deleted=false,version=w.version+1,lease_epoch=w.lease_epoch+1,lease_owner=NULL,lease_until=NULL,next_check=clock_timestamp(),updated_at=clock_timestamp(),state=CASE WHEN `+reset+` THEN '{"status":"pending"}'::jsonb ELSE w.state END FROM targets t WHERE w.id=t.id AND (w.deleted OR (w.name,w.node,w.keyword,w.slow,w.paused) IS DISTINCT FROM (t.name,t.node,t.keyword,t.slow_alert,t.paused))`, raw); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, cfg+`INSERT INTO v3_websites(name,url,node,keyword,slow,paused) SELECT name,url,node,keyword,slow_alert,paused FROM targets WHERE id IS NULL`, raw)
	return err
}

func (s *Store) WebsiteBackups(ctx context.Context, before retentionCursor, limit int) ([]WebsiteBackup, error) {
	if limit < 1 || limit > 200 {
		return nil, errors.New("每页数量须为 1～200")
	}
	stamp := before.Time
	if stamp.IsZero() {
		stamp = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT b.id,b.created_at,b.source,b.count,b.restored_at,b.result,
 EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending),EXISTS(SELECT 1 FROM v3_website_backup_previews p WHERE p.backup=b.id AND NOT used AND expires_at>clock_timestamp())
 FROM v3_website_backups b WHERE (created_at,id)<($1,$2) ORDER BY created_at DESC,id DESC LIMIT $3`, stamp, before.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WebsiteBackup{}
	for rows.Next() {
		var b WebsiteBackup
		var frozen, pinned bool
		if err = rows.Scan(&b.ID, &b.Created, &b.Source, &b.Count, &b.Restored, &b.Result, &frozen, &pinned); err != nil {
			return nil, err
		}
		b.RecordKey = "website-backup:" + b.ID
		b.CanDelete = !frozen && !pinned
		if frozen {
			b.DeleteReason = "数据迁移期间保护备份"
		} else if pinned {
			b.DeleteReason = "恢复预览仍有效"
		}
		items = append(items, b)
	}
	return items, rows.Err()
}

func (s *Store) DeleteWebsiteBackups(ctx context.Context, user, key string, ids []string) (json.RawMessage, error) {
	if len(ids) < 1 || len(ids) > 200 {
		return nil, fmt.Errorf("%w：请明确选择 1～200 个备份", ErrWebsiteBackupInput)
	}
	ids = append([]string(nil), ids...)
	sort.Strings(ids)
	for i, id := range ids {
		if !validArchiveSource(id) || i > 0 && id == ids[i-1] {
			return nil, fmt.Errorf("%w：备份编号不正确或重复", ErrWebsiteBackupInput)
		}
	}
	return s.mutation(ctx, user, key, "website-backup-delete", "selected", ids, func(tx *sql.Tx) (any, error) {
		deleted, skipped := 0, []map[string]string{}
		for _, id := range ids {
			var found string
			if err := tx.QueryRowContext(ctx, "SELECT id FROM v3_website_backups WHERE id=$1 FOR UPDATE", id).Scan(&found); err == sql.ErrNoRows {
				skipped = append(skipped, map[string]string{"id": id, "reason": "备份不存在"})
				continue
			} else if err != nil {
				return nil, err
			}
			var pinned bool
			if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_website_backup_previews WHERE backup=$1 AND NOT used AND expires_at>clock_timestamp())", id).Scan(&pinned); err != nil {
				return nil, err
			}
			if pinned {
				skipped = append(skipped, map[string]string{"id": id, "reason": "恢复预览仍有效"})
				continue
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM v3_website_backup_previews WHERE backup=$1", id); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM v3_website_backups WHERE id=$1", id); err != nil {
				return nil, err
			}
			deleted++
		}
		return map[string]any{"deleted": deleted, "skipped": skipped, "message": fmt.Sprintf("已删除 %d 个备份，跳过 %d 个受保护或不存在的备份；记录删除不等于磁盘空间释放", deleted, len(skipped))}, nil
	})
}
