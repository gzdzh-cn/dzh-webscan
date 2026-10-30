package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"webscan/internal/persist"
)

type TableInventory struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}
type ArchiveReport struct {
	Snapshot        string           `json:"snapshot"`
	Source          string           `json:"source"`
	Tables          []TableInventory `json:"tables"`
	Archived        int64            `json:"archived"`
	WrittenThisRun  int64            `json:"written_this_run"`
	ReadyForCutover bool             `json:"ready_for_cutover"`
}

func InventorySQLite(ctx context.Context, path string) ([]TableInventory, error) {
	db, e := persist.OpenReadOnly(path)
	if e != nil {
		return nil, errors.New("无法只读打开源 SQLite")
	}
	defer db.Close()
	return inventory(ctx, db)
}
func inventory(ctx context.Context, db *sql.DB) ([]TableInventory, error) {
	rows, e := db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if e != nil {
		return nil, e
	}
	names := []string{}
	for rows.Next() {
		var name string
		if e = rows.Scan(&name); e != nil {
			break
		}
		if !identifier.MatchString(name) {
			rows.Close()
			return nil, errors.New("源表名不受支持")
		}
		names = append(names, name)
	}
	re := rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if re != nil {
		return nil, re
	}
	out := []TableInventory{}
	for _, name := range names {
		var n int64
		if e = db.QueryRowContext(ctx, `SELECT count(*) FROM "`+name+`"`).Scan(&n); e != nil {
			return nil, e
		}
		out = append(out, TableInventory{name, n})
	}
	return out, nil
}

// ArchiveSQLite performs the lossless staging step only. It deliberately does
// not mark a deployment ready: domain mapping and final delta reconciliation
// must complete before switching the active service.
func (s *Store) ArchiveSQLite(ctx context.Context, path, directory string) (ArchiveReport, error) {
	var result ArchiveReport
	if directory == "" || !filepath.IsAbs(directory) {
		return result, errors.New("备份目录必须为绝对路径")
	}
	if st, e := os.Lstat(directory); e == nil && !st.IsDir() {
		return result, errors.New("备份目录不正确")
	}
	if e := os.MkdirAll(directory, 0700); e != nil {
		return result, e
	}
	if e := os.Chmod(directory, 0700); e != nil {
		return result, e
	}
	source, e := persist.OpenReadOnly(path)
	if e != nil {
		return result, e
	}
	defer source.Close()
	snapshot := filepath.Join(directory, "v2-before-v3-"+token()[:20]+".sqlite3")
	if e = persist.BackupDB(source, snapshot); e != nil {
		return result, fmt.Errorf("一致性备份失败，已停止归档: %w", e)
	}
	return s.ArchiveSnapshot(ctx, snapshot)
}

// ArchiveSnapshot resumes the exact immutable backup, rather than taking a new
// snapshot of a source that may have changed since an interrupted run.
func (s *Store) ArchiveSnapshot(ctx context.Context, snapshot string) (ArchiveReport, error) {
	var result ArchiveReport
	st, e := os.Lstat(snapshot)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !filepath.IsAbs(snapshot) {
		return result, errors.New("归档快照必须是绝对路径的私有普通文件，不能为符号链接")
	}
	staged, e := persist.OpenReadOnly(snapshot)
	if e != nil {
		return result, e
	}
	defer staged.Close()
	result.Snapshot = snapshot
	result.Tables, e = inventory(ctx, staged)
	if e != nil {
		return result, e
	}
	// Bind checkpoints to snapshot content, not a mutable source filename.
	f, e := os.Open(snapshot)
	if e != nil {
		return result, e
	}
	h := sha256.New()
	_, e = io.Copy(h, f)
	f.Close()
	if e != nil {
		return result, e
	}
	result.Source = hex.EncodeToString(h.Sum(nil))
	owner := "archive-" + token()[:24]
	lease, e := s.Acquire(ctx, "archive/"+result.Source, owner)
	if e != nil {
		return result, errors.New("该快照正在归档或数据库不可用，请稍后重试")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Release(cleanup, lease)
	}()
	for _, table := range result.Tables {
		var cursor int64
		var saved string
		var count int64
		e = s.DB.QueryRowContext(ctx, "SELECT cursor,count FROM v3_imports WHERE source=$1 AND table_name=$2", result.Source, table.Name).Scan(&saved, &count)
		if e != nil && e != sql.ErrNoRows {
			return result, e
		}
		hasCursor := saved != ""
		if hasCursor {
			cursor, e = strconv.ParseInt(saved, 10, 64)
			if e != nil {
				return result, errors.New("归档检查点无效")
			}
		}
		for {
			lease, e = s.Acquire(ctx, lease.Resource, owner)
			if e != nil {
				return result, e
			}
			query := `SELECT rowid,* FROM "` + table.Name + `"`
			args := []any{}
			if hasCursor {
				query += " WHERE rowid>?"
				args = append(args, cursor)
			}
			rows, e := staged.QueryContext(ctx, query+" ORDER BY rowid LIMIT 500", args...)
			if e != nil {
				return result, errors.New("源表无法按稳定主键读取，已停止归档")
			}
			columns, e := rows.Columns()
			if e != nil {
				rows.Close()
				return result, e
			}
			type archived struct {
				id  int64
				raw []byte
			}
			batch := []archived{}
			for rows.Next() {
				values := make([]any, len(columns))
				ptr := make([]any, len(columns))
				for i := range ptr {
					ptr[i] = &values[i]
				}
				if e = rows.Scan(ptr...); e != nil {
					break
				}
				id, ok := values[0].(int64)
				if !ok {
					e = errors.New("源表行标识不正确")
					break
				}
				payload := map[string]any{}
				for i, name := range columns[1:] {
					v := values[i+1]
					switch x := v.(type) {
					case nil:
						payload[name] = map[string]any{"type": "null"}
					case int64:
						payload[name] = map[string]any{"type": "integer", "value": strconv.FormatInt(x, 10)}
					case float64:
						payload[name] = map[string]any{"type": "real", "value": strconv.FormatFloat(x, 'g', -1, 64)}
					case []byte:
						payload[name] = map[string]any{"type": "blob", "value": base64.StdEncoding.EncodeToString(x)}
					case string:
						if !utf8.ValidString(x) || strings.ContainsRune(x, 0) {
							e = errors.New("源数据含无效文本编码或 NUL 字符；原始快照已保留")
						} else {
							payload[name] = map[string]any{"type": "text", "value": x}
						}
					default:
						e = errors.New("源字段类型不受支持")
					}
					if e != nil {
						break
					}
				}
				if e != nil {
					break
				}
				raw, err := json.Marshal(payload)
				if err != nil {
					e = err
					break
				}
				batch = append(batch, archived{id, raw})
			}
			re := rows.Err()
			rows.Close()
			if e != nil {
				return result, e
			}
			if re != nil {
				return result, re
			}
			tx, e := s.DB.BeginTx(ctx, nil)
			if e != nil {
				return result, e
			}
			if e = s.Fence(ctx, tx, lease); e != nil {
				tx.Rollback()
				return result, e
			}
			written := int64(0)
			for _, v := range batch {
				var existing string
				e = tx.QueryRowContext(ctx, "INSERT INTO v3_legacy_records VALUES($1,$2,$3,$4,$5) ON CONFLICT(source,table_name,record_key) DO NOTHING RETURNING digest", result.Source, table.Name, strconv.FormatInt(v.id, 10), v.raw, digest(v.raw)).Scan(&existing)
				if e == sql.ErrNoRows {
					e = tx.QueryRowContext(ctx, "SELECT digest FROM v3_legacy_records WHERE source=$1 AND table_name=$2 AND record_key=$3", result.Source, table.Name, strconv.FormatInt(v.id, 10)).Scan(&existing)
				} else if e == nil {
					written++
				}
				if e != nil || existing != digest(v.raw) {
					tx.Rollback()
					return result, errors.New("归档写入或摘要校验失败")
				}
				cursor = v.id
				hasCursor = true
			}
			complete := len(batch) < 500
			count += written
			if complete && count != table.Count {
				tx.Rollback()
				return result, errors.New("归档数量与快照不一致，已停止")
			}
			checkpoint := ""
			if hasCursor {
				checkpoint = strconv.FormatInt(cursor, 10)
			}
			_, e = tx.ExecContext(ctx, "INSERT INTO v3_imports(source,table_name,cursor,count,complete) VALUES($1,$2,$3,$4,$5) ON CONFLICT(source,table_name) DO UPDATE SET cursor=excluded.cursor,count=excluded.count,complete=excluded.complete", result.Source, table.Name, checkpoint, count, complete)
			if e != nil {
				tx.Rollback()
				return result, e
			}
			if e = tx.Commit(); e != nil {
				return result, e
			}
			result.WrittenThisRun += written
			if complete {
				result.Archived += count
				break
			}
		}
	}
	return result, nil
}
