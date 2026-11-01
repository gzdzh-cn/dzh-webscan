package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"webscan/internal/common"
	"webscan/internal/notify"
	"webscan/internal/website"
)

var ErrSiteURLExists = errors.New("该网站网址已存在")
var ErrSiteNodeMissing = errors.New("关联服务器不存在，请重新选择")

type SiteInput struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Node    string `json:"node"`
	Keyword string `json:"keyword"`
	Slow    bool   `json:"slow_alert"`
	Paused  bool   `json:"paused"`
}

func (in *SiteInput) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.ID < 0 || in.Name == "" || strings.ContainsRune(in.Name, 0) || strings.ContainsRune(in.Keyword, 0) || !utf8.ValidString(in.Name) || !utf8.ValidString(in.Keyword) || utf8.RuneCountInString(in.Name) > 100 || utf8.RuneCountInString(in.Keyword) > 200 {
		return errors.New("网站编号、名称或关键词不正确；名称最多 100 字，关键词最多 200 字")
	}
	if in.Node != "" && !identifier.MatchString(in.Node) {
		return errors.New("关联服务器编号不正确")
	}
	u, err := website.NormalizeURL(in.URL)
	if err != nil {
		return err
	}
	in.URL = u
	return nil
}

const siteColumns = "id,name,url,node,keyword,slow,paused,version,state,migration_pending"

func scanWebsite(row interface{ Scan(...any) error }) (site website.Site, err error) {
	var raw []byte
	err = row.Scan(&site.ID, &site.Name, &site.URL, &site.Node, &site.Keyword, &site.Slow, &site.Paused, &site.Version, &raw, &site.MigrationPending)
	if err == nil {
		err = json.Unmarshal(raw, &site.State)
	}
	if site.State.Status == "" {
		site.State.Status = "pending"
	}
	return
}

type SiteFilter struct {
	After                 int64
	Keyword, Node, Status string
	Limit                 int
}

func (s *Store) Sites(ctx context.Context, f SiteFilter) ([]website.Site, error) {
	if f.Limit < 1 || f.Limit > 200 || f.After < 0 || len(f.Keyword) > 512 {
		return nil, errors.New("网站分页或查询参数不正确")
	}
	if f.Status != "" && f.Status != "normal" && f.Status != "down" && f.Status != "pending" && f.Status != "paused" && f.Status != "unknown" && f.Status != "migration_pending" {
		return nil, errors.New("网站状态不正确")
	}
	keyword := "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(f.Keyword) + "%"
	rows, err := s.DB.QueryContext(ctx, `SELECT `+siteColumns+` FROM v3_websites WHERE NOT deleted AND id>$1 AND (name ILIKE $2 ESCAPE '\' OR url ILIKE $2 ESCAPE '\') AND ($3='' OR node=$3) AND ($4='' OR CASE WHEN migration_pending THEN 'migration_pending' WHEN paused THEN 'paused' WHEN COALESCE(state->>'status','pending') IN ('normal','down','pending') THEN COALESCE(state->>'status','pending') ELSE 'unknown' END=$4) ORDER BY id LIMIT $5`, f.After, keyword, f.Node, f.Status, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []website.Site{}
	for rows.Next() {
		site, err := scanWebsite(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, site)
	}
	return items, rows.Err()
}
func (s *Store) Site(ctx context.Context, id int64) (website.Site, error) {
	return scanWebsite(s.DB.QueryRowContext(ctx, "SELECT "+siteColumns+" FROM v3_websites WHERE id=$1 AND NOT deleted", id))
}

// mutation commits the request receipt, domain change and credential-free
// audit together. A duplicate request replays its original result.
func (s *Store) mutation(ctx context.Context, user, key, kind, resource string, input any, change func(*sql.Tx) (any, error)) (json.RawMessage, error) {
	return s.guardedMutation(ctx, user, key, kind, resource, input, nil, change)
}

// Authorization guards run inside the same transaction even for receipt replay.
// In particular, a password reset or demotion must revoke a preview capability.
func (s *Store) guardedMutation(ctx context.Context, user, key, kind, resource string, input any, authorize func(*sql.Tx) error, change func(*sql.Tx) (any, error)) (json.RawMessage, error) {
	return s.guardedMutationOptions(ctx, nil, user, key, kind, resource, input, authorize, change)
}

func (s *Store) guardedMutationOptions(ctx context.Context, options *sql.TxOptions, user, key, kind, resource string, input any, authorize func(*sql.Tx) error, change func(*sql.Tx) (any, error)) (json.RawMessage, error) {
	if !identifier.MatchString(user) || !identifier.MatchString(key) {
		return nil, errors.New("操作账号或幂等键不正确")
	}
	raw, err := json.Marshal(struct {
		Kind  string
		Input any
	}{kind, input})
	if err != nil {
		return nil, err
	}
	hash := digest(raw)
	tx, err := s.DB.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return nil, err
	} else if held {
		return nil, ErrMigrationPending
	}
	if authorize != nil {
		if err := authorize(tx); err != nil {
			return nil, err
		}
	}
	res, err := tx.ExecContext(ctx, "INSERT INTO v3_requests(username,key,request_hash,response) VALUES($1,$2,$3,'{}') ON CONFLICT DO NOTHING", user, key, hash)
	if err != nil {
		return nil, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		var old string
		var response json.RawMessage
		if err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM v3_requests WHERE username=$1 AND key=$2", user, key).Scan(&old, &response); err != nil {
			return nil, err
		}
		if old != hash {
			return nil, ErrRequestConflict
		}
		return response, tx.Commit()
	}
	value, err := change(tx)
	if err != nil {
		return nil, err
	}
	response, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_requests SET response=$3 WHERE username=$1 AND key=$2", user, key, []byte(response)); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,$2,$3,$4)", user, kind, resource, []byte(response)); err != nil {
		return nil, err
	}
	return response, tx.Commit()
}

func (s *Store) SaveSite(ctx context.Context, user, key string, in SiteInput, expected int64) (json.RawMessage, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	if expected < 0 || (in.ID == 0) != (expected == 0) {
		return nil, errors.New("网站配置版本不正确")
	}
	return s.mutation(ctx, user, key, "save-website", fmt.Sprint(in.ID), struct {
		Site     SiteInput
		Expected int64
	}{in, expected}, func(tx *sql.Tx) (any, error) {
		if err := lockWebsiteConfiguration(ctx, tx); err != nil {
			return nil, err
		}
		if in.Node != "" && in.Node != "central" {
			var id string
			if err := tx.QueryRowContext(ctx, "SELECT id FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR SHARE", in.Node).Scan(&id); err == sql.ErrNoRows {
				return nil, ErrSiteNodeMissing
			} else if err != nil {
				return nil, err
			}
		}
		var id, version int64
		var err error
		if in.ID == 0 {
			err = tx.QueryRowContext(ctx, "INSERT INTO v3_websites(name,url,node,keyword,slow,paused) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,version", in.Name, in.URL, in.Node, in.Keyword, in.Slow, in.Paused).Scan(&id, &version)
		} else {
			err = tx.QueryRowContext(ctx, `UPDATE v3_websites SET name=$1,url=$2,node=$3,keyword=$4,slow=$5,paused=$6,version=version+1,lease_owner=NULL,lease_until=NULL,lease_epoch=lease_epoch+1,next_check=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$7 AND version=$8 AND NOT deleted AND NOT migration_pending RETURNING id,version`, in.Name, in.URL, in.Node, in.Keyword, in.Slow, in.Paused, in.ID, expected).Scan(&id, &version)
		}
		if err == sql.ErrNoRows {
			return nil, ErrConflict
		}
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return nil, ErrSiteURLExists
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "version": version, "message": "网站配置已保存"}, nil
	})
}

type SiteVersion struct {
	ID      int64 `json:"id"`
	Version int64 `json:"version"`
}

func (s *Store) DeleteSites(ctx context.Context, user, key string, selected []SiteVersion) (json.RawMessage, error) {
	if len(selected) < 1 || len(selected) > 200 {
		return nil, errors.New("请明确选择 1～200 个当前页网站")
	}
	selected = append([]SiteVersion(nil), selected...)
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })
	for i, v := range selected {
		if v.ID < 1 || v.Version < 1 || i > 0 && selected[i-1].ID == v.ID {
			return nil, errors.New("网站编号或版本不正确，不能重复选择")
		}
	}
	return s.mutation(ctx, user, key, "delete-websites", "selected", selected, func(tx *sql.Tx) (any, error) {
		if err := lockWebsiteConfiguration(ctx, tx); err != nil {
			return nil, err
		}
		// Verify and lock all selected versions before changing any row.
		for _, v := range selected {
			var version int64
			if err := tx.QueryRowContext(ctx, "SELECT version FROM v3_websites WHERE id=$1 AND NOT deleted AND NOT migration_pending FOR UPDATE", v.ID).Scan(&version); err == sql.ErrNoRows {
				return nil, ErrConflict
			} else if err != nil {
				return nil, err
			}
			if version != v.Version {
				return nil, ErrConflict
			}
		}
		for _, v := range selected {
			if _, err := tx.ExecContext(ctx, "UPDATE v3_websites SET deleted=true,version=version+1,lease_epoch=lease_epoch+1,lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE id=$1", v.ID); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, "UPDATE v3_website_incidents SET ended=GREATEST(started,extract(epoch FROM clock_timestamp())::bigint) WHERE site=$1 AND ended IS NULL", v.ID); err != nil {
				return nil, err
			}
		}
		return map[string]any{"deleted": len(selected), "message": "已软删除；故障历史及排队通知保留"}, nil
	})
}

type WebsiteJob struct {
	Site     website.Site
	Owner    string
	Epoch    int64
	Interval int
	Timeout  time.Duration
}

func websiteSettings(settings common.Map) (interval, timeout int) {
	c := common.M(settings["website_monitor"])
	interval, timeout = common.I(c["interval_seconds"]), common.I(c["timeout_seconds"])
	if interval == 0 {
		interval = 60
	}
	if timeout == 0 {
		timeout = 5
	}
	return min(3600, max(10, interval)), min(60, max(1, timeout))
}
func (s *Store) ClaimSites(ctx context.Context, owner string, limit int) ([]WebsiteJob, error) {
	if !identifier.MatchString(owner) || limit < 1 || limit > 256 {
		return nil, errors.New("网站工作器或批次不正确")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return nil, err
	} else if held {
		return []WebsiteJob{}, tx.Commit()
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, "SELECT payload FROM v3_settings WHERE id=1").Scan(&raw); err != nil {
		return nil, err
	}
	var settings common.Map
	if err = json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	if value, exists := common.M(settings["website_monitor"])["enabled"]; exists && !common.B(value) {
		return []WebsiteJob{}, tx.Commit()
	}
	// The configured limit applies to all website workers in the cluster.
	// Serialize only this short reservation, never the HTTP checks themselves.
	var dispatch bool
	if err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(773376003)").Scan(&dispatch); err != nil {
		return nil, err
	}
	if !dispatch {
		return []WebsiteJob{}, tx.Commit()
	}
	maximum := common.I(common.M(settings["website_monitor"])["max_concurrent"])
	if maximum == 0 {
		maximum = 128
	}
	maximum = min(1024, max(1, maximum))
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM v3_websites WHERE NOT deleted AND NOT paused AND lease_owner IS NOT NULL AND lease_until>clock_timestamp()").Scan(&active); err != nil {
		return nil, err
	}
	limit = min(limit, maximum-active)
	if limit < 1 {
		return []WebsiteJob{}, tx.Commit()
	}
	interval, timeout := websiteSettings(settings)
	rows, err := tx.QueryContext(ctx, `WITH due AS (SELECT id FROM v3_websites WHERE NOT deleted AND NOT paused AND NOT migration_pending AND next_check<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp()) ORDER BY next_check,id FOR UPDATE SKIP LOCKED LIMIT $2) UPDATE v3_websites w SET lease_owner=$1,lease_epoch=w.lease_epoch+1,lease_until=clock_timestamp()+interval '90 seconds' FROM due WHERE w.id=due.id RETURNING w.id,w.name,w.url,w.node,w.keyword,w.slow,w.paused,w.version,w.state,w.migration_pending,w.lease_epoch`, owner, limit)
	if err != nil {
		return nil, err
	}
	jobs := []WebsiteJob{}
	for rows.Next() {
		var job WebsiteJob
		var state []byte
		job.Owner = owner
		job.Interval = interval
		job.Timeout = time.Duration(timeout) * time.Second
		err = rows.Scan(&job.Site.ID, &job.Site.Name, &job.Site.URL, &job.Site.Node, &job.Site.Keyword, &job.Site.Slow, &job.Site.Paused, &job.Site.Version, &state, &job.Site.MigrationPending, &job.Epoch)
		if err == nil {
			err = json.Unmarshal(state, &job.Site.State)
		}
		if err != nil {
			rows.Close()
			return nil, err
		}
		jobs = append(jobs, job)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return jobs, tx.Commit()
}

func enqueueNotice(ctx context.Context, tx *sql.Tx, node, event string, payload common.Map, category, source string) error {
	if held, err := migrationHeld(ctx, tx); err != nil {
		return err
	} else if held {
		return ErrMigrationPending
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, "SELECT payload FROM v3_settings WHERE id=1").Scan(&raw); err != nil {
		return err
	}
	var settings common.Map
	if err := json.Unmarshal(raw, &settings); err != nil {
		return err
	}
	for _, channel := range []string{"feishu", "email"} {
		if !notify.Allows(settings, channel, category) {
			continue
		}
		recipients := []string{""}
		if channel == "email" {
			recipients = notify.Recipients(common.M(settings["email"]))
		}
		for _, recipient := range recipients {
			var notificationID int64
			err := tx.QueryRowContext(ctx, "INSERT INTO v3_notifications(node,event_id,channel,recipient,payload) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id", node, event, channel, recipient, common.JSON(payload)).Scan(&notificationID)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if err = projectNotificationTx(ctx, tx, notificationID, source); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) ApplySiteResult(ctx context.Context, job WebsiteJob, result website.Result) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return err
	} else if held {
		return ErrMigrationPending
	}
	// Keep notification policy stable through this transition; use the same
	// settings-before-site lock order as configuration application.
	if _, err = websiteNotificationSettings(ctx, tx); err != nil {
		return err
	}
	var epoch int64
	var owner sql.NullString
	var valid bool
	var raw []byte
	current := website.Site{}
	err = tx.QueryRowContext(ctx, "SELECT "+siteColumns+",lease_epoch,lease_owner,COALESCE(lease_until>clock_timestamp(),false) FROM v3_websites WHERE id=$1 AND NOT deleted AND NOT migration_pending FOR UPDATE", job.Site.ID).Scan(&current.ID, &current.Name, &current.URL, &current.Node, &current.Keyword, &current.Slow, &current.Paused, &current.Version, &raw, &current.MigrationPending, &epoch, &owner, &valid)
	if err == sql.ErrNoRows {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if !valid || !owner.Valid || owner.String != job.Owner || epoch != job.Epoch || current.Version != job.Site.Version || current.Paused {
		return ErrLeaseLost
	}
	if err = json.Unmarshal(raw, &current.State); err != nil {
		return err
	}
	if result.Time <= 0 || result.Time > time.Now().Add(time.Minute).Unix() {
		return errors.New("网站检查时间不正确")
	}
	effects := website.TransitionEffects{
		Open: func(kind string) (int64, error) {
			reason := result.Reason
			if kind == "slow" {
				reason = "网站响应超过 3 秒并持续 5 分钟"
			}
			if kind == "certificate" {
				reason = "HTTPS 证书剩余有效期不超过 7 天"
			}
			var id int64
			err := tx.QueryRowContext(ctx, "INSERT INTO v3_website_incidents(site,kind,started,reason) VALUES($1,$2,$3,$4) RETURNING id", current.ID, kind, result.Time, reason).Scan(&id)
			return id, err
		},
		Close: func(id int64) error {
			_, err := tx.ExecContext(ctx, "UPDATE v3_website_incidents SET ended=GREATEST(started,$2) WHERE id=$1 AND site=$3 AND ended IS NULL", id, result.Time, current.ID)
			return err
		},
		Notice: func(kind, message string) error {
			message = fmt.Sprintf("网站可用性提醒\n网站：%s\n地址：%s\n情况：%s\n发生时间：%s（北京时间）", current.Name, current.URL, message, time.Unix(result.Time, 0).In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05"))
			return insertWebsiteNotice(ctx, tx, current.ID, current.Node, kind, message)

		},
	}
	state, err := website.Transition(current, result, job.Interval, effects)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE v3_websites SET state=$2,next_check=clock_timestamp()+($3::double precision*interval '1 second'),lease_owner=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE id=$1", current.ID, common.JSON(state), max(10, job.Interval))
	if err != nil {
		return err
	}
	return tx.Commit()
}

type SiteIncident struct {
	SiteName     string `json:"site_name"`
	Node         string `json:"node"`
	ID           int64  `json:"id"`
	Site         int64  `json:"site"`
	Kind         string `json:"kind"`
	Started      int64  `json:"started"`
	Ended        *int64 `json:"ended"`
	Reason       string `json:"reason"`
	RecordKey    string `json:"record_key"`
	CanDelete    bool   `json:"can_delete"`
	DeleteReason string `json:"delete_reason"`
}

type SiteIncidentFilter struct {
	Site, Before int64
	Limit        int
	Node         string
	Current      bool
	Start, End   time.Time
}

// The original unbounded-by-time website history call remains compatible.
func (s *Store) SiteIncidents(ctx context.Context, site, before int64, limit int) ([]SiteIncident, error) {
	return s.FilteredSiteIncidents(ctx, SiteIncidentFilter{Site: site, Before: before, Limit: limit})
}

func (s *Store) FilteredSiteIncidents(ctx context.Context, f SiteIncidentFilter) ([]SiteIncident, error) {
	if f.Site < 0 || f.Before < 0 || f.Limit < 1 || f.Limit > 200 || f.Node != "" && !identifier.MatchString(f.Node) || f.Start.IsZero() != f.End.IsZero() || !f.Start.IsZero() && (!f.End.After(f.Start) || f.End.Sub(f.Start) > 31*24*time.Hour) {
		return nil, errors.New("故障查询参数不正确")
	}
	var start, end int64
	if !f.Start.IsZero() {
		start, end = f.Start.Unix(), f.End.Unix()
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT w.name,w.node,t.id,t.site,t.kind,t.started,t.ended,t.reason,"+historyDeleteReasonSQL(4, "t")+` FROM v3_website_incidents t JOIN v3_websites w ON w.id=t.site
 WHERE ($1=0 OR t.site=$1) AND ($2=0 OR t.id<$2) AND ($3='' OR w.node=$3)
 AND (NOT $4 OR (t.ended IS NULL AND NOT w.deleted AND NOT w.paused AND NOT w.migration_pending))
 AND ($5::bigint=0 OR t.started >= $5) AND ($6::bigint=0 OR t.started <= $6)
 ORDER BY t.id DESC LIMIT $7`, f.Site, f.Before, f.Node, f.Current, start, end, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SiteIncident{}
	for rows.Next() {
		var v SiteIncident
		if err = rows.Scan(&v.SiteName, &v.Node, &v.ID, &v.Site, &v.Kind, &v.Started, &v.Ended, &v.Reason, &v.DeleteReason); err != nil {
			return nil, err
		}
		v.RecordKey = fmt.Sprintf("website-incident:%d", v.ID)
		v.CanDelete = v.DeleteReason == ""
		items = append(items, v)
	}
	return items, rows.Err()
}
