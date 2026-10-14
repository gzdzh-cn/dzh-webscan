package central

import (
	"context"
	"fmt"
	"strings"
	"webscan/internal/common"
	"webscan/internal/retention"
)

func (s *Store) decorateRecords(ctx context.Context, items []common.Map, source string) {
	if s.Retention == nil {
		return
	}
	for _, item := range items {
		kind := source
		if v := common.S(item["_record_source"]); v != "" {
			kind = v
		}
		delete(item, "_record_source")
		id := fmt.Sprint(item["id"])
		if kind == "website" {
			id = strings.TrimPrefix(id, "website:")
		}
		if kind == "events" || kind == "migrated_events" {
			p := common.M(item["event"])
			if common.S(p["operation"]) == "scan" && common.S(common.M(p["scan"])["status"]) == "matched" {
				if kind == "events" {
					kind = "security"
				} else {
					kind = "migrated_security"
				}
			}
		}
		for k, v := range s.Retention.Describe(ctx, retention.RecordKey(kind, common.S(item["node"]), id)) {
			item[k] = v
		}
	}
}
