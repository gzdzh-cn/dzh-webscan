package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"

	"webscan/internal/common"
)

type MigrationLegacyHistoryItem struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	Table     string     `json:"legacy_table"`
	RecordKey int64      `json:"record_key"`
	Summary   common.Map `json:"summary"`
}
type MigrationLegacyHistoryPage struct {
	Items      []MigrationLegacyHistoryItem `json:"items"`
	NextCursor string                       `json:"next_cursor"`
	ReadOnly   bool                         `json:"read_only"`
}

// No ciphertext, path, original message, request token or source credential is
// returned by the public query. Parent IDs link only normalized history rows.
func (s *Store) ListMigrationLegacyHistory(ctx context.Context, session, role, table, after string, limit int) (out MigrationLegacyHistoryPage, err error) {
	out = MigrationLegacyHistoryPage{Items: []MigrationLegacyHistoryItem{}, ReadOnly: true}
	if !validArchiveSource(session) || after != "" && !validArchiveSource(after) || limit < 1 || limit > 200 {
		return out, ErrMigrationSession
	}
	if role != "" && role != "central" && role != "host-manager" {
		return out, ErrMigrationSession
	}
	if table != "" {
		if _, ok := migrationLegacyHistoryTables[table]; !ok {
			return out, ErrMigrationSession
		}
	}
	rows, e := s.DB.QueryContext(ctx, `SELECT id,role,table_name,record_key,payload FROM v3_legacy_history WHERE session=$1 AND ($2='' OR role=$2) AND ($3='' OR table_name=$3) AND ($4='' OR id COLLATE "C">$4 COLLATE "C") ORDER BY id COLLATE "C" LIMIT $5`, session, role, table, after, limit+1)
	if e != nil {
		return out, ErrMigrationSession
	}
	defer rows.Close()
	for rows.Next() {
		var item MigrationLegacyHistoryItem
		var raw []byte
		if e = rows.Scan(&item.ID, &item.Role, &item.Table, &item.RecordKey, &raw); e != nil {
			return out, ErrMigrationSession
		}
		if json.Unmarshal(raw, &item.Summary) != nil {
			return out, ErrMigrationSession
		}
		out.Items = append(out.Items, item)
	}
	if rows.Err() != nil {
		return out, ErrMigrationSession
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	return out, nil
}
func (s *Store) MigrationLegacyHistory(ctx context.Context, session, revision string) (MigrationLegacyHistoryReport, error) {
	var out MigrationLegacyHistoryReport
	var raw []byte
	if !validArchiveSource(session) || !validArchiveSource(revision) {
		return out, ErrMigrationSession
	}
	e := s.DB.QueryRowContext(ctx, `SELECT report FROM v3_migration_legacy_history_runs WHERE session=$1 AND revision=$2`, session, revision).Scan(&raw)
	if e == sql.ErrNoRows {
		return out, e
	}
	if e != nil || singleDecode(raw, &out) != nil || out.Session != session || out.Revision != revision {
		return MigrationLegacyHistoryReport{}, ErrMigrationSession
	}
	return out, nil
}
