package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"webscan/internal/persist"
	"webscan/internal/telemetry"
)

func migrationPrometheusLogicalDigest(ctx context.Context, db *sql.DB) (string, error) {
	tables, err := inventory(ctx, db)
	if err != nil {
		return "", err
	}
	hash := digest(nil)
	for _, table := range tables {
		var schema string
		if db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", table.Name).Scan(&schema) != nil {
			return "", ErrMigrationPrometheus
		}
		hash = digest([]byte(hash + ":" + table.Name + ":" + schema))
		rows, err := db.QueryContext(ctx, `SELECT rowid,* FROM "`+strings.ReplaceAll(table.Name, `"`, `""`)+`" ORDER BY rowid`)
		if err != nil {
			return "", ErrMigrationPrometheus
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			return "", ErrMigrationPrometheus
		}
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if rows.Scan(dest...) != nil {
				rows.Close()
				return "", ErrMigrationPrometheus
			}
			key, raw, err := migrationArchiveRow(columns, values)
			if err != nil {
				rows.Close()
				return "", ErrMigrationPrometheus
			}
			hash = digest([]byte(hash + ":" + strconv.FormatInt(key, 10) + ":" + digest(raw)))
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return "", ErrMigrationPrometheus
		}
	}
	return hash, nil
}
func migrationPrometheusLogicalEqual(ctx context.Context, a, b *sql.DB) (bool, error) {
	aa, err := migrationPrometheusLogicalDigest(ctx, a)
	if err != nil {
		return false, err
	}
	bb, err := migrationPrometheusLogicalDigest(ctx, b)
	return aa == bb, err
}

func migrationPrometheusBindWorking(ctx context.Context, db *sql.DB, binding migrationPrometheusBinding, job, source string) error {
	id := "v3-prom-binding:" + job
	raw, _ := json.Marshal(binding)
	var saved string
	err := db.QueryRowContext(ctx, "SELECT payload FROM migrations WHERE id=?", id).Scan(&saved)
	if err == nil {
		var previous migrationPrometheusBinding
		if singleDecode([]byte(saved), &previous) != nil || !migrationPrometheusBindingEqual(previous, binding) {
			return ErrMigrationPrometheus
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return ErrMigrationPrometheus
	}
	// A crash immediately after the initial backup can be continued only if the
	// unbound working database is logically identical to the immutable source.
	fixed, err := openMigrationSnapshot(ctx, source)
	if err != nil {
		return ErrMigrationPrometheus
	}
	defer fixed.close()
	if fixed.sha != binding.SnapshotSHA256 {
		return ErrMigrationPrometheus
	}
	same, err := migrationPrometheusLogicalEqual(ctx, db, fixed.db)
	if err != nil || !same {
		return ErrMigrationPrometheus
	}
	tx, err := persist.BeginWrite(ctx, db)
	if err != nil {
		return ErrMigrationPrometheus
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "INSERT INTO migrations(id,payload) VALUES(?,?)", id, string(raw)); err != nil {
		return ErrMigrationPrometheus
	}
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO import_guards(id) VALUES(?)", "v3-prom:"+job); err != nil {
		return ErrMigrationPrometheus
	}
	if err := tx.Commit(); err != nil {
		return ErrMigrationPrometheus
	}
	return nil
}

func migrationPrometheusTaskID(job string, task migrationPrometheusTask) string {
	raw, _ := json.Marshal(task)
	return "v3-prom-task:" + job + ":" + digest(raw)
}

func migrationPrometheusTaskChildren(task migrationPrometheusTask) ([]migrationPrometheusTask, error) {
	a, b := task, task
	if task.Until-task.From > 30 {
		middle := task.From + ((task.Until-task.From)/60)*30
		if middle <= task.From || middle >= task.Until {
			return nil, ErrMigrationPrometheus
		}
		a.Until, b.From = middle, middle
		return []migrationPrometheusTask{a, b}, nil
	}
	if task.NodeUntil-task.NodeFrom > 1 {
		middle := (task.NodeFrom + task.NodeUntil) / 2
		a.NodeUntil, b.NodeFrom = middle, middle
		return []migrationPrometheusTask{a, b}, nil
	}
	return nil, ErrMigrationPrometheus
}

func migrationPrometheusPendingTask(ctx context.Context, db *sql.DB, job string, task migrationPrometheusTask) (migrationPrometheusTask, bool, error) {
	var raw string
	err := db.QueryRowContext(ctx, "SELECT payload FROM migrations WHERE id=?", migrationPrometheusTaskID(job, task)).Scan(&raw)
	if err == sql.ErrNoRows {
		return task, true, nil
	}
	if err != nil {
		return task, false, ErrMigrationPrometheus
	}
	var receipt migrationPrometheusReceipt
	if singleDecode([]byte(raw), &receipt) != nil || receipt.Task != task {
		return task, false, ErrMigrationPrometheus
	}
	if receipt.State == "done" {
		if !releaseDigest(receipt.ResponseSHA256) || receipt.Meaning != "legacy-query-evaluation-step30s-rates5m" {
			return task, false, ErrMigrationPrometheus
		}
		return task, false, nil
	}
	if receipt.State != "split" {
		return task, false, ErrMigrationPrometheus
	}
	children, err := migrationPrometheusTaskChildren(task)
	if err != nil {
		return task, false, err
	}
	for _, child := range children {
		next, found, err := migrationPrometheusPendingTask(ctx, db, job, child)
		if err != nil || found {
			return next, found, err
		}
	}
	return task, false, nil
}

func migrationPrometheusNext(ctx context.Context, db *sql.DB, binding migrationPrometheusBinding, job string) (migrationPrometheusTask, bool, error) {
	for from := binding.From; from < binding.Until; from += 3600 {
		until := min(from+3600, binding.Until)
		for page := 0; page < len(binding.Nodes); page += 100 {
			for query := range telemetry.HistoricalQueries {
				task := migrationPrometheusTask{From: from, Until: until, NodeFrom: page, NodeUntil: min(page+100, len(binding.Nodes)), Query: query}
				next, found, err := migrationPrometheusPendingTask(ctx, db, job, task)
				if err != nil || found {
					return next, found, err
				}
			}
		}
	}
	return migrationPrometheusTask{}, false, nil
}

func migrationPrometheusSaveTask(ctx context.Context, db *sql.DB, job string, receipt migrationPrometheusReceipt) error {
	if receipt.State == "split" {
		if _, err := migrationPrometheusTaskChildren(receipt.Task); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(receipt)
	if _, err := db.ExecContext(ctx, "INSERT INTO migrations(id,payload) VALUES(?,?)", migrationPrometheusTaskID(job, receipt.Task), string(raw)); err != nil {
		return ErrMigrationPrometheus
	}
	return nil
}

func migrationPrometheusImportTask(ctx context.Context, db *sql.DB, job string, task migrationPrometheusTask, response migrationPrometheusResponse) error {
	tx, err := persist.BeginWrite(ctx, db)
	if err != nil {
		return ErrMigrationPrometheus
	}
	defer tx.Rollback()
	type state struct {
		point  telemetry.Point
		raw    map[string]json.RawMessage
		node   string
		at     int64
		native bool
	}
	states := map[string]*state{}
	for _, sample := range response.Values {
		id := sample.Node + ":" + strconv.FormatInt(sample.At, 10)
		current := states[id]
		if current == nil {
			current = &state{point: telemetry.Point{Time: sample.At, OK: false, Values: map[string]float64{}}, raw: map[string]json.RawMessage{}, node: sample.Node, at: sample.At}
			var raw, source string
			err := tx.QueryRowContext(ctx, "SELECT payload,source FROM samples WHERE node=? AND time=? AND resolution=0", sample.Node, sample.At).Scan(&raw, &source)
			if err == nil {
				if source == "native" {
					current.native = true
				} else if source != "legacy" || json.Unmarshal([]byte(raw), &current.point) != nil || json.Unmarshal([]byte(raw), &current.raw) != nil || current.point.Time != sample.At {
					return ErrMigrationPrometheus
				}
			} else if err != sql.ErrNoRows {
				return ErrMigrationPrometheus
			}
			if current.point.Values == nil {
				current.point.Values = map[string]float64{}
			}
			states[id] = current
		}
		if current.native {
			continue
		}
		if old, exists := current.point.Values[sample.Key]; exists && old != sample.Value {
			return ErrMigrationPrometheus
		}
		current.point.Values[sample.Key] = sample.Value
		if sample.Key == "collect_up" {
			current.point.OK = sample.Value == 1
		}
		if len(current.point.Values) > 4096 {
			return ErrMigrationPrometheus
		}
	}
	query := telemetry.HistoricalQueries[task.Query]
	for _, current := range states {
		if current.native {
			continue
		}
		if query.Dimension != "" && (query.Dimension == "device" || query.Name == "disk_percent" || query.Name == "inode_percent") {
			total := float64(0)
			for key, value := range current.point.Values {
				if !strings.HasPrefix(key, query.Name+":") {
					continue
				}
				dimension := strings.TrimPrefix(key, query.Name+":")
				if query.Dimension == "device" {
					if strings.HasPrefix(query.Name, "net_") && (dimension == "lo" || strings.HasPrefix(dimension, "veth") || strings.HasPrefix(dimension, "docker") || strings.HasPrefix(dimension, "br-")) {
						continue
					}
					total += value
				} else {
					total = max(total, value)
				}
			}
			current.point.Values[query.Name] = total
		}
		current.raw["time"], _ = json.Marshal(current.point.Time)
		current.raw["ok"], _ = json.Marshal(current.point.OK)
		current.raw["values"], _ = json.Marshal(current.point.Values)
		raw, _ := json.Marshal(current.raw)
		if _, err := tx.ExecContext(ctx, "INSERT INTO samples(node,time,resolution,payload,source) VALUES(?,?,0,?,'legacy') ON CONFLICT(node,time,resolution) DO UPDATE SET payload=excluded.payload WHERE samples.source='legacy'", current.node, current.at, string(raw)); err != nil {
			return ErrMigrationPrometheus
		}
	}
	receipt := migrationPrometheusReceipt{Task: task, State: "done", ResponseSHA256: response.SHA256, Returned: int64(len(response.Values)), Missing: response.Missing, Meaning: "legacy-query-evaluation-step30s-rates5m"}
	raw, _ := json.Marshal(receipt)
	if _, err := tx.ExecContext(ctx, "INSERT INTO migrations(id,payload) VALUES(?,?)", migrationPrometheusTaskID(job, task), string(raw)); err != nil {
		return ErrMigrationPrometheus
	}
	if err := tx.Commit(); err != nil {
		return ErrMigrationPrometheus
	}
	return nil
}

func migrationPrometheusProgress(ctx context.Context, db *sql.DB, report MigrationPrometheusReport) (MigrationPrometheusReport, error) {
	rows, err := db.QueryContext(ctx, "SELECT payload FROM migrations WHERE id LIKE ?", "v3-prom-task:"+report.Job+":%")
	if err != nil {
		return report, ErrMigrationPrometheus
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			return report, ErrMigrationPrometheus
		}
		var receipt migrationPrometheusReceipt
		if singleDecode([]byte(raw), &receipt) != nil {
			return report, ErrMigrationPrometheus
		}
		if receipt.State == "done" {
			report.CompletedQueries++
			report.ReturnedValues += receipt.Returned
			report.MissingValues += receipt.Missing
		}
	}
	if rows.Err() != nil {
		return report, ErrMigrationPrometheus
	}
	return report, nil
}
func migrationPrometheusComplete(ctx context.Context, db *sql.DB, job string) error {
	tx, err := persist.BeginWrite(ctx, db)
	if err != nil {
		return ErrMigrationPrometheus
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM import_guards WHERE id=?", "v3-prom:"+job); err != nil {
		return ErrMigrationPrometheus
	}
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO migrations(id,payload) VALUES(?,?)", "v3-prom-complete:"+job, `{"meaning":"legacy-query-evaluation-step30s-rates5m","complete":true}`); err != nil {
		return ErrMigrationPrometheus
	}
	if err := tx.Commit(); err != nil {
		return ErrMigrationPrometheus
	}
	return nil
}

func migrationPrometheusPublishManifest(dir *os.File, raw []byte) error {
	name := ".manifest-" + token()
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return ErrMigrationPrometheus
	}
	defer unix.Unlinkat(int(dir.Fd()), name, 0)
	file := os.NewFile(uintptr(fd), name)
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrMigrationPrometheus
	}
	if err := unix.Linkat(int(dir.Fd()), name, int(dir.Fd()), "manifest.json", 0); err != nil {
		return ErrMigrationPrometheus
	}
	if err := dir.Sync(); err != nil {
		return ErrMigrationPrometheus
	}
	return nil
}
