package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *API) websiteRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	path := r.URL.Path
	if path != "/api/v3/incidents" && path != "/api/v3/websites" && !strings.HasPrefix(path, "/api/v3/websites/") {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if path == "/api/v3/incidents" {
		a.websiteIncidents(w, r, 0)
		return true
	}
	if path == "/api/v3/websites/overview" {
		if r.Method != "GET" {
			failure(w, 405, "method_not_allowed", "请使用 GET")
			return true
		}
		data, err := a.Store.WebsiteSummary(ctx)
		if err != nil {
			failure(w, 503, "query_failed", "网站统计暂时不可用")
		} else {
			reply(w, 200, data)
		}
		return true
	}
	if path == "/api/v3/websites/delete" {
		if r.Method != "POST" {
			failure(w, 405, "method_not_allowed", "请使用 POST")
			return true
		}
		var input struct {
			Records []SiteVersion `json:"records"`
		}
		if err := decode(w, r, &input); err != nil {
			failure(w, 400, "invalid_request", err.Error())
			return true
		}
		if len(input.Records) < 1 || len(input.Records) > 200 {
			failure(w, 400, "invalid_selection", "请明确选择 1～200 个当前页网站")
			return true
		}
		seen := map[int64]bool{}
		for _, v := range input.Records {
			if v.ID < 1 || v.Version < 1 || seen[v.ID] {
				failure(w, 400, "invalid_selection", "网站编号或版本不正确，不能重复选择")
				return true
			}
			seen[v.ID] = true
		}
		key, ok := mutationKey(w, r)
		if !ok {
			return true
		}
		data, err := a.Store.DeleteSites(ctx, id.Username, key, input.Records)
		mutationReply(w, data, err)
		return true
	}
	if path == "/api/v3/websites" {
		switch r.Method {
		case "GET":
			limit, err := pageSize(r, 20)
			if err != nil {
				failure(w, 400, "invalid_limit", err.Error())
				return true
			}
			after, err := decodeNumericCursor(r.URL.Query().Get("cursor"))
			if err != nil {
				failure(w, 400, "invalid_cursor", "分页游标不正确")
				return true
			}
			q := r.URL.Query()
			filter := SiteFilter{After: after, Limit: limit, Keyword: q.Get("q"), Node: q.Get("node"), Status: q.Get("status")}
			if len(filter.Keyword) > 512 || filter.Status != "" && filter.Status != "normal" && filter.Status != "down" && filter.Status != "pending" && filter.Status != "paused" && filter.Status != "unknown" && filter.Status != "migration_pending" {
				failure(w, 400, "invalid_filter", "网站筛选参数不正确")
				return true
			}
			items, err := a.Store.Sites(ctx, filter)
			if err != nil {
				failure(w, 503, "query_failed", "网站列表暂时不可用")
				return true
			}
			next := ""
			if len(items) == limit {
				next = encodeNumericCursor(items[len(items)-1].ID)
			}
			reply(w, 200, map[string]any{"items": items, "next_cursor": next, "limit": limit})
		case "POST":
			a.saveWebsite(w, r, id, 0)
		default:
			failure(w, 405, "method_not_allowed", "请使用 GET 或 POST")
		}
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/api/v3/websites/"), "/")
	site, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || site < 1 {
		failure(w, 400, "invalid_id", "网站编号不正确")
		return true
	}
	if len(parts) == 2 && parts[1] == "incidents" {
		a.websiteIncidents(w, r, site)
		return true
	}
	if len(parts) == 2 && parts[1] == "check" {
		if r.Method != "POST" {
			failure(w, 405, "method_not_allowed", "请使用 POST")
			return true
		}
		var input struct {
			Version int64 `json:"expected_version"`
		}
		if decode(w, r, &input) != nil || input.Version < 1 {
			failure(w, 400, "invalid_request", "请提供网站配置版本")
			return true
		}
		key, ok := mutationKey(w, r)
		if !ok {
			return true
		}
		data, err := a.Store.RequestSiteCheck(ctx, id.Username, key, site, input.Version)
		mutationReply(w, data, err)
		return true
	}
	if len(parts) != 1 {
		failure(w, 404, "not_found", "接口不存在")
		return true
	}
	switch r.Method {
	case "GET":
		value, err := a.Store.Site(ctx, site)
		if err == sql.ErrNoRows {
			failure(w, 404, "not_found", "网站不存在或已删除")
		} else if err != nil {
			failure(w, 503, "query_failed", "网站详情暂时不可用")
		} else {
			reply(w, 200, value)
		}
	case "PUT":
		a.saveWebsite(w, r, id, site)
	default:
		failure(w, 405, "method_not_allowed", "请使用 GET 或 PUT；删除请明确选择记录")
	}
	return true
}

func (a *API) saveWebsite(w http.ResponseWriter, r *http.Request, id identity, site int64) {
	var input struct {
		Site     SiteInput `json:"site"`
		Expected int64     `json:"expected_version"`
	}
	if err := decode(w, r, &input); err != nil {
		failure(w, 400, "invalid_request", err.Error())
		return
	}
	if input.Site.ID != site || input.Expected < 0 || (site == 0) != (input.Expected == 0) {
		failure(w, 400, "invalid_request", "网站编号或版本不正确")
		return
	}
	if err := input.Site.validate(); err != nil {
		failure(w, 400, "invalid_request", err.Error())
		return
	}
	key, ok := mutationKey(w, r)
	if !ok {
		return
	}
	data, err := a.Store.SaveSite(r.Context(), id.Username, key, input.Site, input.Expected)
	mutationReply(w, data, err)
}
func mutationKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := r.Header.Get("Idempotency-Key")
	if !identifier.MatchString(key) {
		failure(w, 400, "idempotency_key_required", "操作需要有效的幂等键，请重新提交")
		return "", false
	}
	return key, true
}
func mutationReply(w http.ResponseWriter, data json.RawMessage, err error) {
	if errors.Is(err, ErrMigrationPending) {
		failure(w, 503, "migration_pending", ErrMigrationPending.Error())
		return
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrRequestConflict) {
		failure(w, 409, "configuration_conflict", err.Error())
	} else if errors.Is(err, ErrSiteURLExists) || errors.Is(err, ErrSiteNodeMissing) {
		failure(w, 400, "invalid_website", err.Error())
	} else if err != nil {
		failure(w, 503, "operation_failed", "操作暂未完成，请检查连接后重试；相同操作请沿用原幂等键")
	} else {
		reply(w, 200, data)
	}
}
func encodeNumericCursor(v int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(v, 10)))
}
func decodeNumericCursor(v string) (int64, error) {
	if v == "" {
		return 0, nil
	}
	if len(v) > 32 {
		return 0, errors.New("游标超限")
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("游标不正确")
	}
	return n, nil
}
func (a *API) websiteIncidents(w http.ResponseWriter, r *http.Request, site int64) {
	if r.Method != "GET" {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	limit, err := pageSize(r, 20)
	if err != nil {
		failure(w, 400, "invalid_limit", err.Error())
		return
	}
	before, err := decodeNumericCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		failure(w, 400, "invalid_cursor", "分页游标不正确")
		return
	}
	q := r.URL.Query()
	f := SiteIncidentFilter{Site: site, Before: before, Limit: limit, Node: q.Get("node")}
	if f.Node != "" && !identifier.MatchString(f.Node) {
		failure(w, 400, "invalid_node", "服务器编号不正确")
		return
	}
	if value := q.Get("current"); value != "" {
		current, e := strconv.ParseBool(value)
		if e != nil {
			failure(w, 400, "invalid_current", "当前异常参数不正确")
			return
		}
		f.Current = current
	}
	if q.Get("start") != "" || q.Get("end") != "" {
		var e error
		f.Start, f.End, e = timeRange(r)
		if e != nil {
			failure(w, 400, "invalid_time", "时间范围不正确，最多 31 天")
			return
		}
	}
	items, err := a.Store.FilteredSiteIncidents(r.Context(), f)
	if err != nil {
		failure(w, 503, "query_failed", "网站故障历史暂时不可用")
		return
	}
	next := ""
	if len(items) == limit {
		next = encodeNumericCursor(items[len(items)-1].ID)
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next, "limit": limit})
}

func (s *Store) RequestSiteCheck(ctx context.Context, user, key string, site, version int64) (json.RawMessage, error) {
	if site < 1 || version < 1 {
		return nil, errors.New("网站编号或版本不正确")
	}
	return s.mutation(ctx, user, key, "check-website", strconv.FormatInt(site, 10), SiteVersion{site, version}, func(tx *sql.Tx) (any, error) {
		res, err := tx.ExecContext(ctx, "UPDATE v3_websites SET next_check=clock_timestamp() WHERE id=$1 AND version=$2 AND NOT deleted AND NOT paused AND NOT migration_pending AND (lease_until IS NULL OR lease_until<=clock_timestamp())", site, version)
		if err != nil {
			return nil, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, err
		}
		if n != 1 {
			return nil, ErrConflict
		}
		return map[string]any{"id": site, "message": "已加入检测队列"}, nil
	})
}
