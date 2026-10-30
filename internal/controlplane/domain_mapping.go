package controlplane

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var ErrMigrationPending = errors.New("数据迁移尚未完成，暂不接收新的业务写入")

// Shared by claim/evaluation and import initialization. Taking the exclusive
// form while binding an empty target prevents an already-started live write
// from slipping between the empty check and the durable migration fence.
func migrationHeld(ctx context.Context, tx *sql.Tx) (bool, error) {
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock_shared(773376002)"); err != nil {
		return false, err
	}
	var held bool
	err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending)").Scan(&held)
	return held, err
}
func validArchiveSource(source string) bool {
	raw, err := hex.DecodeString(source)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == source
}
func bindMigrationDomain(ctx context.Context, tx *sql.Tx, domain, source, related string, tables []string) error {
	var current, paired string
	var pending bool
	err := tx.QueryRowContext(ctx, "SELECT source,related_source,pending FROM v3_migration_domains WHERE domain=$1 FOR UPDATE", domain).Scan(&current, &paired, &pending)
	if err == nil {
		if current != source || related != "" && paired != "" && paired != related || !pending {
			return errors.New("迁移领域已绑定其他源或已生效，禁止覆盖")
		}
		if related != "" && paired == "" {
			_, err = tx.ExecContext(ctx, "UPDATE v3_migration_domains SET related_source=$2 WHERE domain=$1", domain, related)
		}
		return err
	}
	if err != sql.ErrNoRows {
		return err
	}
	for _, table := range tables {
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+quotePG(table)+" LIMIT 1)").Scan(&exists); err != nil {
			return err
		}
		if exists {
			return errors.New("目标领域已有运行数据，禁止覆盖")
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO v3_migration_domains(domain,source,related_source) VALUES($1,$2,$3)", domain, source, related)
	return err
}

func (s *Store) mapArchiveDomain(ctx context.Context, source, related, domain string, tables, required []string, initialize func(context.Context, *sql.Tx) error, mapper func(context.Context, *sql.Tx, string, archivedRecord) (bool, error)) (report DomainImportReport, err error) {
	return s.mapArchiveDomainBatched(ctx, source, related, domain, tables, required, 500, initialize, mapper)
}

// External backup documents can be much larger than their staged metadata.
// Their mapper commits one document at a time instead of collecting 500 large
// payloads in a transaction. Existing row-only domains retain their batch size.
func (s *Store) mapArchiveDomainBatched(ctx context.Context, source, related, domain string, tables, required []string, batchSize int, initialize func(context.Context, *sql.Tx) error, mapper func(context.Context, *sql.Tx, string, archivedRecord) (bool, error)) (report DomainImportReport, err error) {
	report.Source, report.Domain = source, domain
	if batchSize < 1 || batchSize > 500 {
		return report, errors.New("迁移批次大小不正确")
	}
	if !validArchiveSource(source) || related != "" && !validArchiveSource(related) {
		return report, errors.New("迁移源必须为已归档快照的 SHA256")
	}
	// Validate the whole manifest before reserving the target domain.
	counts := map[string]int64{}
	for _, table := range tables {
		var count int64
		var complete bool
		e := s.DB.QueryRowContext(ctx, "SELECT count,complete FROM v3_imports WHERE source=$1 AND table_name=$2", source, table).Scan(&count, &complete)
		if e == sql.ErrNoRows {
			missing := false
			for _, name := range required {
				if name == table {
					missing = true
				}
			}
			if missing {
				return report, errors.New("迁移所需的源表归档缺失")
			}
			continue
		}
		if e != nil {
			return report, e
		}
		if !complete {
			return report, errors.New("源表尚未归档完成")
		}
		counts[table] = count
	}
	if len(counts) == 0 {
		return report, errors.New("迁移源不包含所需领域")
	}
	defer func() {
		if err == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.DB.QueryRowContext(cleanup, "SELECT COALESCE(sum(processed),0),COALESCE(sum(imported),0) FROM v3_domain_imports WHERE source=$1 AND domain=$2", source, domain).Scan(&report.Processed, &report.Imported)
		report.Complete = false
		err = safeMappingError(err)
	}()
	l, e := s.Acquire(ctx, "domain-import/"+domain, "map-"+token()[:24])
	if e != nil {
		return report, e
	}
	defer func() {
		op, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Release(op, l)
	}()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return report, e
	}
	defer tx.Rollback()
	if e = s.Fence(ctx, tx, l); e != nil {
		return report, e
	}
	if _, e = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(773376002)"); e != nil {
		return report, e
	}
	if e = initialize(ctx, tx); e != nil {
		return report, e
	}
	if e = tx.Commit(); e != nil {
		return report, e
	}
	for _, table := range tables {
		count, exists := counts[table]
		if !exists {
			continue
		}
		for {
			if l, e = s.renewImportLease(ctx, l); e != nil {
				return report, e
			}
			done, e := s.mapDomainBatch(ctx, source, domain, table, count, l, batchSize, mapper)
			if e != nil {
				return report, e
			}
			if done {
				break
			}
		}
	}
	e = s.DB.QueryRowContext(ctx, "SELECT COALESCE(sum(processed),0),COALESCE(sum(imported),0),COALESCE(bool_and(complete),false) FROM v3_domain_imports WHERE source=$1 AND domain=$2", source, domain).Scan(&report.Processed, &report.Imported, &report.Complete)
	return report, e
}

// PostgreSQL DETAIL/CONTEXT may quote the original payload or a credential.
// Keep database failures private while returning our own validation messages.
func safeMappingError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return errors.New("迁移数据库操作失败；已提交批次保留，请检查数据库状态后继续")
	}
	return err
}

func (s *Store) mapDomainBatch(ctx context.Context, source, domain, table string, total int64, l Lease, batchSize int, mapper func(context.Context, *sql.Tx, string, archivedRecord) (bool, error)) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err = s.Fence(ctx, tx, l); err != nil {
		return false, err
	}
	var bound string
	var pending bool
	if err = tx.QueryRowContext(ctx, "SELECT source,pending FROM v3_migration_domains WHERE domain=$1 FOR SHARE", domain).Scan(&bound, &pending); err != nil {
		return false, err
	}
	if bound != source || !pending {
		return false, errors.New("迁移绑定已变化或领域已生效")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_domain_imports(source,domain,table_name) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", source, domain, table); err != nil {
		return false, err
	}
	var cursor string
	var processed, imported int64
	var complete bool
	if err = tx.QueryRowContext(ctx, "SELECT cursor,processed,imported,complete FROM v3_domain_imports WHERE source=$1 AND domain=$2 AND table_name=$3 FOR UPDATE", source, domain, table).Scan(&cursor, &processed, &imported, &complete); err != nil {
		return false, err
	}
	if complete {
		if processed != total {
			return false, errors.New("映射数量与源归档不一致")
		}
		return true, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, "SELECT record_key,payload,digest FROM v3_legacy_records WHERE source=$1 AND table_name=$2 AND ($3='' OR record_key::bigint>NULLIF($3,'')::bigint) ORDER BY record_key::bigint LIMIT $4", source, table, cursor, batchSize)
	if err != nil {
		return false, err
	}
	type item struct {
		key    string
		record archivedRecord
	}
	items := []item{}
	bytes := 0
	byteLimit := false
	for rows.Next() {
		var key, hash string
		var raw []byte
		if err = rows.Scan(&key, &raw, &hash); err != nil {
			break
		}
		if len(raw) > 8<<20 {
			err = errors.New("单条归档记录超过 8 MiB，请核对源数据")
			break
		}
		if len(items) > 0 && bytes+len(raw) > 8<<20 {
			byteLimit = true
			break
		}
		bytes += len(raw)
		var object map[string]any
		if json.Unmarshal(raw, &object) != nil {
			err = errors.New("归档记录格式不正确")
			break
		}
		canonical, _ := json.Marshal(object)
		if digest(canonical) != hash {
			err = errors.New("归档记录摘要发生变化")
			break
		}
		var r archivedRecord
		if json.Unmarshal(raw, &r) != nil {
			err = errors.New("归档字段格式不正确")
			break
		}
		items = append(items, item{key, r})
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return false, err
	}
	for _, v := range items {
		added, e := mapper(ctx, tx, table, v.record)
		if e != nil {
			return false, e
		}
		processed++
		if added {
			imported++
		}
		cursor = v.key
	}
	complete = len(items) < batchSize && !byteLimit
	if complete && processed != total {
		return false, errors.New("领域映射数量与归档不一致")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_domain_imports SET cursor=$4,processed=$5,imported=$6,complete=$7 WHERE source=$1 AND domain=$2 AND table_name=$3", source, domain, table, cursor, processed, imported, complete); err != nil {
		return false, err
	}
	if err = s.Fence(ctx, tx, l); err != nil {
		return false, err
	}
	return complete, tx.Commit()
}

func (r archivedRecord) timestamp(field string, nullable bool) (*time.Time, error) {
	v, ok := r[field]
	if !ok {
		return nil, errors.New("迁移源时间字段缺失")
	}
	if nullable && v.Type == "null" {
		return nil, nil
	}
	if v.Type != "integer" && v.Type != "real" {
		return nil, errors.New("迁移源时间字段类型不正确")
	}
	// Parse with an explicit range before converting float seconds to nanos.
	seconds, err := strconv.ParseFloat(v.Value, 64)
	if err != nil || !(seconds >= 0 && seconds < 253402300800) {
		return nil, errors.New("迁移源时间值不正确")
	}
	whole := int64(seconds)
	at := time.Unix(whole, int64((seconds-float64(whole))*1e9)).UTC()
	return &at, nil
}
