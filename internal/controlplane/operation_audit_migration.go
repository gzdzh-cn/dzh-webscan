package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/common"
	"webscan/internal/recordops"
	"webscan/internal/retention"
)

// Completed v2 operations become audit evidence, never executable v3 jobs.
// Separate source-bound domains allow the old central and host-manager SQLite
// archives to contribute without confusing identical IDs from different files.
func (s *Store) MapOperationAuditArchive(ctx context.Context, source string) (DomainImportReport, error) {
	domain := "operation-audit-" + source
	return s.mapArchiveDomain(ctx, source, "", domain, []string{"record_operations", "retention_jobs"}, nil, func(ctx context.Context, tx *sql.Tx) error {
		var pending bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_legacy_records WHERE source=$1 AND ((table_name='record_operations' AND COALESCE(payload->'status'->>'value','') NOT IN ('complete','partial')) OR (table_name='retention_jobs' AND COALESCE(payload->'status'->>'value','') NOT IN ('complete','failed'))))`, source).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return errors.New("旧系统仍有未完成的记录操作或历史任务；先在旧系统完成，再重新归档，不自动迁移删除授权")
		}
		return bindMigrationDomain(ctx, tx, domain, source, "", nil)
	}, func(ctx context.Context, tx *sql.Tx, table string, r archivedRecord) (bool, error) {
		return mapOperationAuditRecord(ctx, tx, source, table, r)
	})
}

func mapOperationAuditRecord(ctx context.Context, tx *sql.Tx, source, table string, r archivedRecord) (bool, error) {
	id, err := archiveText(r, "id", 128)
	if err != nil || !eventText(id, 128) {
		return false, errors.New("旧操作编号不正确")
	}
	owner, err := archiveText(r, "owner", 128)
	if err != nil || !eventText(owner, 128) {
		return false, errors.New("旧操作账号不正确")
	}
	kind, err := archiveText(r, "kind", 64)
	if err != nil {
		return false, err
	}
	status, err := archiveText(r, "status", 64)
	if err != nil {
		return false, err
	}
	created, err := r.timestamp("created", false)
	if err != nil {
		return false, err
	}
	updated, err := r.timestamp("updated", false)
	if err != nil || updated.Before(*created) {
		return false, errors.New("旧操作时间不正确")
	}
	summary := common.Map{"migration_source": source, "legacy_table": table, "legacy_id": id, "operation": kind, "status": status, "created_at": created, "updated_at": updated}
	switch table {
	case "record_operations":
		switch kind {
		case "website", "website-backup", "deployment-backup", "deployment-job":
		default:
			return false, errors.New("旧记录操作类别不受支持")
		}
		if status != "complete" && status != "partial" {
			return false, errors.New("旧记录操作未结束，不能迁移为审计")
		}
		idsRaw, err := archiveText(r, "ids", 256<<10)
		if err != nil {
			return false, err
		}
		var ids []string
		if json.Unmarshal([]byte(idsRaw), &ids) != nil || len(ids) < 1 || len(ids) > 200 {
			return false, errors.New("旧记录操作选择范围不正确")
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if !eventText(id, 2048) || seen[id] {
				return false, errors.New("旧记录操作选择范围不正确")
			}
			seen[id] = true
		}
		cursor, err := r.integer("cursor")
		if err != nil || cursor != int64(len(ids)) {
			return false, errors.New("旧记录操作尚有未完成记录")
		}
		resultsRaw, err := archiveText(r, "results", 1<<20)
		if err != nil {
			return false, err
		}
		var results []recordops.Result
		if json.Unmarshal([]byte(resultsRaw), &results) != nil || len(results) != len(ids) {
			return false, errors.New("旧记录操作结果与选择范围不符")
		}
		deleted, skipped, failed := 0, 0, 0
		for i, v := range results {
			if v.ID != ids[i] {
				return false, errors.New("旧记录操作结果身份不符")
			}
			switch v.Status {
			case "deleted":
				deleted++
			case "skipped":
				skipped++
			case "failed":
				failed++
			default:
				return false, errors.New("旧记录操作结果状态不正确")
			}
		}
		if (status == "partial") != (failed > 0) {
			return false, errors.New("旧记录操作完成状态与结果不符")
		}
		summary["records"] = ids
		summary["selected"] = len(ids)
		summary["deleted"] = deleted
		summary["skipped"] = skipped
		summary["failed"] = failed
	case "retention_jobs":
		if kind != "cleanup" && kind != "export" || status != "complete" && status != "failed" {
			return false, errors.New("旧历史任务类别或状态不正确")
		}
		raw, err := archiveText(r, "scope", 1<<20)
		if err != nil {
			return false, err
		}
		var scopes []retention.Scope
		if json.Unmarshal([]byte(raw), &scopes) != nil || len(scopes) > 20 {
			return false, errors.New("旧历史任务范围不正确")
		}
		public := []common.Map{}
		for _, scope := range scopes {
			switch scope.Source {
			case "events", "security", "migrated_events", "migrated_security", "website", "server", "notifications", "notification_orphans", "server_batches":
			default:
				return false, errors.New("旧历史任务范围类别不正确")
			}
			if scope.Node != "" && !eventText(scope.Node, 512) || scope.Before < 0 || scope.Before > 253402300799 || scope.Upper < 0 || len(scope.IDs) > 200 {
				return false, errors.New("旧历史任务范围参数不正确")
			}
			seen := map[int64]bool{}
			for _, id := range scope.IDs {
				if id < 1 || seen[id] {
					return false, errors.New("旧历史任务选择范围不正确")
				}
				seen[id] = true
			}
			public = append(public, common.Map{"source": scope.Source, "node": scope.Node, "before": scope.Before, "upper": scope.Upper, "selected": len(scope.IDs)})
		}
		processed, err := r.integer("processed")
		if err != nil || processed < 0 {
			return false, errors.New("旧历史任务完成数量不正确")
		}
		skipped, err := r.integer("skipped")
		if err != nil || skipped < 0 {
			return false, errors.New("旧历史任务跳过数量不正确")
		}
		summary["scope_summary"] = public
		summary["processed"] = processed
		summary["skipped"] = skipped
		// Old export files and previews are not reauthorized by audit import.
		summary["download_available"] = false
	default:
		return false, errors.New("旧操作审计源表不受支持")
	}
	// Use the original completion time for the 365-day policy, not import time.
	resource := digest([]byte("v2-operation-audit:" + source + ":" + table + ":" + id))
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result,created_at) VALUES($1,$2,$3,$4,$5)`, owner, "legacy-"+table, resource, common.JSON(summary), updated)
	return err == nil, err
}

// Keep malformed archived timestamps out of API JSON encoders too.
func validAuditTime(t time.Time) bool { return !t.Before(time.Unix(0, 0)) && t.Year() <= 9999 }
