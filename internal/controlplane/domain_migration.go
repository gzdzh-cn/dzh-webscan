package controlplane

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
	"webscan/internal/website"
)

type DomainImportReport struct {
	Source          string `json:"source"`
	Domain          string `json:"domain"`
	Processed       int64  `json:"processed"`
	Imported        int64  `json:"imported"`
	Complete        bool   `json:"complete"`
	ReadyForCutover bool   `json:"ready_for_cutover"`
}
type archivedValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type archivedRecord map[string]archivedValue

func (s *Store) renewImportLease(ctx context.Context, l Lease) (Lease, error) {
	err := s.DB.QueryRowContext(ctx, "UPDATE v3_leases SET expires_at=clock_timestamp()+interval '30 seconds' WHERE resource=$1 AND owner=$2 AND epoch=$3 AND expires_at>clock_timestamp() RETURNING expires_at", l.Resource, l.Owner, l.Epoch).Scan(&l.Expires)
	if err == sql.ErrNoRows {
		return l, ErrLeaseLost
	}
	return l, err
}

func (r archivedRecord) text(field string) (string, error) {
	v, ok := r[field]
	if !ok || v.Type != "text" {
		return "", errors.New("迁移源文本字段缺失或类型不正确")
	}
	return v.Value, nil
}
func (r archivedRecord) integer(field string) (int64, error) {
	v, ok := r[field]
	if !ok || v.Type != "integer" {
		return 0, errors.New("迁移源整数字段缺失或类型不正确")
	}
	return strconv.ParseInt(v.Value, 10, 64)
}
func (r archivedRecord) boolean(field string) (bool, error) {
	v, err := r.integer(field)
	if err != nil {
		return false, err
	}
	if v != 0 && v != 1 {
		return false, errors.New("迁移源布尔值不正确")
	}
	return v == 1, nil
}

// MapWebsiteArchive converts a verified immutable staging snapshot into live
// domain rows. Imported websites remain fenced from checks/edits until the
// future complete cutover reconciles notifications and all other domains.
func (s *Store) MapWebsiteArchive(ctx context.Context, source string) (DomainImportReport, error) {
	tables := []string{"website_admin", "website_sessions", "websites", "website_incidents", "website_outbox"}
	if !validArchiveSource(source) {
		return DomainImportReport{Source: source, Domain: "websites"}, errors.New("迁移源必须为已归档快照的 SHA256")
	}
	var outbox, queue bool
	if err := s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_imports WHERE source=$1 AND table_name='website_outbox'),EXISTS(SELECT 1 FROM v3_imports WHERE source=$1 AND table_name='tasks' AND complete)", source).Scan(&outbox, &queue); err != nil {
		return DomainImportReport{}, err
	}
	if outbox && !queue {
		return DomainImportReport{Source: source, Domain: "websites"}, errors.New("网站出箱需要同一快照的完整通知队列归档")
	}
	report, err := s.mapArchiveDomain(ctx, source, "", "websites", tables, []string{"website_admin", "websites"}, func(ctx context.Context, tx *sql.Tx) error {
		if queue {
			if err := bindMigrationDomain(ctx, tx, "notifications", source, "", []string{"v3_notifications", "v3_notification_attempts"}); err != nil {
				return err
			}
		}
		return bindMigrationDomain(ctx, tx, "websites", source, "", []string{"v3_websites", "v3_accounts", "v3_sessions", "v3_website_incidents", "v3_website_outbox"})
	}, func(ctx context.Context, tx *sql.Tx, table string, r archivedRecord) (bool, error) {
		return mapWebsiteRecord(ctx, tx, source, table, r)
	})
	if err == nil {
		// The migration fence blocks ID allocation while sequences catch up. This
		// final step is also idempotent after a lost completion response.
		for _, table := range []string{"v3_websites", "v3_website_incidents", "v3_website_outbox"} {
			_, err = s.DB.ExecContext(ctx, "SELECT setval(pg_get_serial_sequence($1,'id'),COALESCE(max(id),1),count(*)>0) FROM "+quotePG(table), quotePG(table))
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		report.Complete = false
	}
	return report, safeMappingError(err)
}

func mapWebsiteRecord(ctx context.Context, tx *sql.Tx, source, table string, r archivedRecord) (bool, error) {
	switch table {
	case "website_admin":
		id, err := r.integer("id")
		if err != nil || id != 1 {
			return false, errors.New("管理员记录编号不正确")
		}
		user, err := r.text("username")
		if err != nil || !identifier.MatchString(user) {
			return false, errors.New("管理员账号格式不正确")
		}
		hash, err := r.text("password_hash")
		if err != nil {
			return false, err
		}
		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil || cost > 16 {
			return false, errors.New("原管理员密码摘要不支持")
		}
		revision, err := r.integer("revision")
		if err != nil || revision < 1 {
			return false, errors.New("管理员版本不正确")
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO v3_accounts(username,password_hash,revision,role) VALUES($1,$2,$3,'admin')", user, hash, revision)
		return err == nil, err
	case "website_sessions":
		hash, err := r.text("token_hash")
		if err != nil {
			return false, err
		}
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != 32 {
			return false, errors.New("原会话令牌摘要不正确")
		}
		revision, err := r.integer("revision")
		if err != nil {
			return false, err
		}
		expires, err := r.integer("expires")
		if err != nil {
			return false, err
		}
		created, err := r.integer("created")
		if err != nil {
			return false, err
		}
		csrf, err := r.text("csrf")
		if err != nil || len(csrf) < 16 || len(csrf) > 128 {
			return false, errors.New("原会话校验令牌不正确")
		}
		if expires <= time.Now().Unix() {
			return false, nil
		}
		createdAt := time.Unix(0, created)
		if createdAt.After(time.Now().Add(time.Minute)) || time.Unix(expires, 0).After(createdAt.Add(12*time.Hour)) {
			return false, nil
		}
		// Expired/revoked sessions stay in the archive; importing never
		// extends their lifetime or revives an old account revision.
		res, err := tx.ExecContext(ctx, "INSERT INTO v3_sessions(token_hash,username,revision,csrf,expires_at,created_at) SELECT $1,username,$2,$3,$4,$5 FROM v3_accounts WHERE revision=$2", hash, revision, csrf, time.Unix(expires, 0), createdAt)
		if err != nil {
			return false, err
		}
		n, err := res.RowsAffected()
		return n == 1, err
	case "websites":
		id, err := r.integer("id")
		if err != nil || id < 1 {
			return false, errors.New("网站编号不正确")
		}
		name, err := r.text("name")
		if err != nil {
			return false, err
		}
		url, err := r.text("url")
		if err != nil {
			return false, err
		}
		node, err := r.text("node")
		if err != nil {
			return false, err
		}
		keyword, err := r.text("keyword")
		if err != nil {
			return false, err
		}
		slow, err := r.boolean("slow")
		if err != nil {
			return false, err
		}
		paused, err := r.boolean("paused")
		if err != nil {
			return false, err
		}
		deleted, err := r.boolean("deleted")
		if err != nil {
			return false, err
		}
		version, err := r.integer("version")
		if err != nil || version < 1 {
			return false, errors.New("网站配置版本不正确")
		}
		state, err := r.text("state")
		if err != nil {
			return false, err
		}
		var parsed website.State
		if json.Unmarshal([]byte(state), &parsed) != nil {
			return false, errors.New("网站状态格式不正确")
		}
		if len(name) > 1024 || len(url) > 8192 || len(keyword) > 4096 {
			return false, errors.New("网站配置超出支持范围")
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO v3_websites(id,name,url,node,keyword,slow,paused,deleted,version,state,migration_pending,next_check) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,'infinity')", id, name, url, node, keyword, slow, paused, deleted, version, []byte(state))
		return err == nil, err
	case "website_incidents":
		id, err := r.integer("id")
		if err != nil || id < 1 {
			return false, errors.New("故障编号不正确")
		}
		site, err := r.integer("site")
		if err != nil {
			return false, err
		}
		kind, err := r.text("kind")
		if err != nil {
			return false, err
		}
		start, err := r.integer("started")
		if err != nil {
			return false, err
		}
		reason, err := r.text("reason")
		if err != nil {
			return false, err
		}
		var ended any
		if r["ended"].Type != "null" {
			value, err := r.integer("ended")
			if err != nil {
				return false, err
			}
			ended = value
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO v3_website_incidents(id,site,kind,started,ended,reason) VALUES($1,$2,$3,$4,$5,$6)", id, site, kind, start, ended, reason)
		return err == nil, err
	case "website_outbox":
		return mapWebsiteOutboxRecord(ctx, tx, source, r)
	default:
		return false, errors.New("不支持的迁移领域表")
	}
}
