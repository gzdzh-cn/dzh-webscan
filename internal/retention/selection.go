package retention

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
)

type reference struct {
	Source string `json:"source"`
	Node   string `json:"node"`
	ID     string `json:"id"`
}

func RecordKey(source, node, id string) string {
	return base64.RawURLEncoding.EncodeToString(common.JSON(reference{source, node, id}))
}
func (s *Service) locate(ctx context.Context, key string) (Scope, error) {
	var ref reference
	b, e := base64.RawURLEncoding.DecodeString(key)
	if e != nil || len(b) > 2048 || json.Unmarshal(b, &ref) != nil {
		return Scope{}, userError("记录标识不正确")
	}
	x, ok := s.source(ref.Source)
	if !ok {
		return Scope{}, userError("历史类别不正确")
	}
	where := "t.id=?"
	args := []any{ref.ID}
	switch ref.Source {
	case "events", "security":
		where += " AND t.node=?"
		args = append(args, ref.Node)
	case "migrated_events", "migrated_security", "website", "server", "notifications":
	default:
		return Scope{}, userError("此类别不支持选中删除")
	}
	var r record
	e = x.db.QueryRowContext(ctx, "SELECT t.rowid,"+x.node+","+x.tm+","+x.raw+" FROM "+x.table+" t WHERE "+where+" AND ("+x.condition+")", args...).Scan(&r.ID, &r.Node, &r.Time, &r.Raw)
	if e == sql.ErrNoRows {
		return Scope{}, userError("记录不存在或已变化")
	}
	if e != nil {
		return Scope{}, e
	}
	return Scope{Source: ref.Source, Before: time.Now().Unix() - 86400, Upper: r.ID, IDs: []int64{r.ID}, Fingerprints: map[string]string{strconv.FormatInt(r.ID, 10): common.Hash(common.JSON(r))}}, nil
}
func (s *Service) Describe(ctx context.Context, key string) common.Map {
	out := common.Map{"record_key": key, "can_delete": false, "delete_reason": "记录暂不可用"}
	sc, e := s.locate(ctx, key)
	if e != nil {
		return out
	}
	n, e := s.count(ctx, sc)
	if e != nil {
		return out
	}
	if n.Eligible == 1 {
		out["can_delete"] = true
		out["delete_reason"] = ""
	} else {
		out["delete_reason"] = "最近 24 小时、当前异常或未完成通知关联记录受保护"
	}
	return out
}
func (s *Service) selectedScope(ctx context.Context, f Filter) ([]Scope, error) {
	if len(f.Records) == 0 || len(f.Records) > 200 {
		return nil, userError("请选择 1～200 条记录")
	}
	scopes := []Scope{}
	seen := map[string]bool{}
	for _, key := range f.Records {
		if seen[key] {
			continue
		}
		seen[key] = true
		sc, e := s.locate(ctx, key)
		if e != nil {
			return nil, e
		}
		category := strings.TrimPrefix(sc.Source, "migrated_")
		if f.Category != "all" && f.Category != category {
			return nil, userError("记录类别与删除范围不一致")
		}
		scopes = append(scopes, sc)
	}
	return scopes, nil
}
