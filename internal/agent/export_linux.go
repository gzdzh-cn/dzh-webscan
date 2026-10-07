//go:build linux

package agent

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
)

func (a *Agent) export(ctx context.Context) {
	for ctx.Err() == nil {
		if e := a.Export(ctx); e != nil {
			a.counter("transport_errors_total", 1, false)
			fmt.Println("export_error=" + common.SecretFree(e))
		}
		a.counter("export_heartbeat_seconds", common.Now(), true)
		if !common.Sleep(ctx, 2*time.Second) {
			return
		}
	}
}
func (a *Agent) logBytes() (int64, error) {
	files, e := os.ReadDir(a.Logs)
	if e != nil {
		return 0, e
	}
	var total int64
	for _, f := range files {
		if !f.Type().IsRegular() || !strings.HasSuffix(f.Name(), ".jsonl") {
			continue
		}
		info, e := f.Info()
		if e != nil {
			return 0, e
		}
		total += info.Size()
	}
	return total, nil
}
func (a *Agent) Export(ctx context.Context) error {
	rows, e := a.DB.QueryContext(ctx, "SELECT id,payload FROM events WHERE exported IS NULL AND accepted IS NULL ORDER BY created LIMIT 100")
	if e != nil {
		return e
	}
	pending := [][2]string{}
	for rows.Next() {
		var id, payload string
		if e = rows.Scan(&id, &payload); e != nil {
			rows.Close()
			return e
		}
		pending = append(pending, [2]string{id, payload})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	total, e := a.logBytes()
	if e != nil {
		return e
	}
	if len(pending) > 0 && total < int64(common.I(common.M(a.C["transport"])["local_log_max_mib"]))*1048576 {
		name := filepath.Join(a.Logs, "events-"+time.Now().UTC().Format("20060102-15")+".jsonl")
		f, e := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if e != nil {
			return e
		}
		for _, row := range pending {
			if _, e = f.WriteString(row[1] + "\n"); e != nil {
				f.Close()
				return e
			}
		}
		e = f.Sync()
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return e
		}
		a.writeMu.Lock()
		tx, e := a.DB.BeginTx(ctx, nil)
		if e == nil {
			_, e = tx.Exec("INSERT OR IGNORE INTO logfiles VALUES(?,?)", name, common.Now())
			for _, row := range pending {
				if e == nil {
					_, e = tx.Exec("UPDATE events SET exported=? WHERE id=?", name, row[0])
				}
			}
			if e == nil {
				e = tx.Commit()
			} else {
				tx.Rollback()
			}
		}
		a.writeMu.Unlock()
		if e != nil {
			return e
		}
	}
	rows, e = a.DB.QueryContext(ctx, "SELECT id FROM events WHERE exported IS NOT NULL AND accepted IS NULL ORDER BY created LIMIT 1000")
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(ids) > 0 {
		_, response, e := common.Request(ctx, a.HTTP, "POST", common.S(a.C["public_url"])+"/webscan/v1/receipts", common.Map{"event_ids": ids}, map[string]string{"Authorization": "Bearer " + common.S(a.C["token"])})
		if e != nil {
			return e
		}
		accepted := common.SS(common.M(response)["accepted"])
		a.writeMu.Lock()
		tx, e := a.DB.BeginTx(ctx, nil)
		if e == nil {
			for _, id := range accepted {
				if !common.Contains(ids, id) {
					continue
				}
				if _, e = tx.Exec("UPDATE events SET accepted=? WHERE id=?", common.Now(), id); e != nil {
					break
				}
			}
			if e == nil {
				e = tx.Commit()
			} else {
				tx.Rollback()
			}
		}
		a.writeMu.Unlock()
		if e != nil {
			return e
		}
	}
	return a.Prune()
}
func (a *Agent) Prune() error {
	total, e := a.logBytes()
	if e != nil {
		return e
	}
	rows, e := a.DB.Query("SELECT path,created FROM logfiles ORDER BY created")
	if e != nil {
		return e
	}
	type row struct {
		path    string
		created float64
	}
	files := []row{}
	for rows.Next() {
		var r row
		if e = rows.Scan(&r.path, &r.created); e != nil {
			rows.Close()
			return e
		}
		files = append(files, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	target := int64(common.F(common.M(a.C["transport"])["local_log_max_mib"]) * 1048576 * 0.8)
	for _, r := range files {
		var pending int
		e = a.DB.QueryRow("SELECT 1 FROM events WHERE exported=? AND accepted IS NULL LIMIT 1", r.path).Scan(&pending)
		if e != nil && e != sql.ErrNoRows {
			return e
		}
		if pending != 0 || r.created >= common.Now()-common.F(a.C["retention_days"])*86400 && total <= target {
			continue
		}
		if info, e := os.Lstat(r.path); e == nil && info.Mode().IsRegular() {
			if !common.Inside(r.path, a.Logs) {
				return fmt.Errorf("log_path_outside_directory")
			}
			if e = os.Remove(r.path); e != nil {
				return e
			}
			total -= info.Size()
		}
		a.writeMu.Lock()
		tx, e := a.DB.Begin()
		if e == nil {
			_, e = tx.Exec("DELETE FROM events WHERE exported=? AND accepted IS NOT NULL", r.path)
			if e == nil {
				_, e = tx.Exec("DELETE FROM logfiles WHERE path=?", r.path)
			}
			if e == nil {
				e = tx.Commit()
			} else {
				tx.Rollback()
			}
		}
		a.writeMu.Unlock()
		if e != nil {
			return e
		}
	}
	_, e = a.DB.Exec("PRAGMA wal_checkpoint(PASSIVE)")
	return e
}
func (a *Agent) metricLoop(ctx context.Context) {
	for ctx.Err() == nil {
		a.counter("agent_heartbeat_seconds", common.Now(), true)
		if e := a.Metrics(ctx); e != nil {
			fmt.Println("metrics_error=" + common.SecretFree(e))
		}
		if !common.Sleep(ctx, 15*time.Second) {
			return
		}
	}
}
func (a *Agent) Metrics(ctx context.Context) error {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()
	rows, e := a.DB.QueryContext(ctx, "SELECT key,value FROM counters")
	if e != nil {
		return e
	}
	var out strings.Builder
	for rows.Next() {
		var key string
		var v float64
		if e = rows.Scan(&key, &v); e != nil {
			rows.Close()
			return e
		}
		fmt.Fprintf(&out, "webscan_%s %g\n", key, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	var pending, scans int
	var oldest sql.NullFloat64
	if e = a.DB.QueryRow("SELECT COUNT(*),MIN(created) FROM events WHERE accepted IS NULL").Scan(&pending, &oldest); e != nil {
		return e
	}
	a.DB.QueryRow("SELECT COUNT(*) FROM scans").Scan(&scans)
	age := 0.0
	if oldest.Valid {
		age = max(common.Now()-oldest.Float64, 0)
	}
	a.watchMu.Lock()
	watches := len(a.watches)
	a.watchMu.Unlock()
	fmt.Fprintf(&out, "webscan_local_pending_events %d\nwebscan_local_oldest_pending_seconds %g\nwebscan_pending_scans %d\nwebscan_watches %d\n", pending, age, scans, watches)
	running := 0
	if a.inventoryRunning.Load() {
		running = 1
	}
	fmt.Fprintf(&out, "webscan_inventory_running %d\nwebscan_inventory_files_checked %d\n", running, a.inventoryChecked.Load())
	u := common.S(a.C["vector_metrics_url"])
	if u == "" {
		u = "http://127.0.0.1:19101/metrics"
	}
	request, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	raw, e := readText(request, a.HTTP, u, 2*1048576)
	if e == nil {
		out.WriteString(VectorMetrics(string(raw)))
		out.WriteString("webscan_vector_metrics_up 1\n")
	} else {
		out.WriteString("webscan_vector_metrics_up 0\n")
	}
	return common.Atomic(common.S(a.C["metrics_file"]), []byte(out.String()), 0644)
}
func VectorMetrics(text string) string {
	var out strings.Builder
	for _, line := range strings.Split(text, "\n") {
		match := false
		for _, name := range []string{"vector_component_discarded_events_total", "vector_buffer_events", "vector_buffer_byte_size", "vector_component_errors_total"} {
			match = match || strings.HasPrefix(line, name)
		}
		if !match {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			if _, e := strconv.ParseInt(fields[len(fields)-1], 10, 64); e == nil {
				if _, e = strconv.ParseFloat(fields[len(fields)-2], 64); e == nil {
					line = strings.TrimSuffix(strings.TrimSpace(line), fields[len(fields)-1])
					line = strings.TrimSpace(line)
				}
			}
		}
		out.WriteString(line + "\n")
	}
	return out.String()
}
func (a *Agent) probeLoop(ctx context.Context) {
	for ctx.Err() == nil {
		path := filepath.Join(a.Probe, "heartbeat.php")
		if e := os.WriteFile(path, []byte("<?php /* webscan probe "+common.ID()+" */"), 0600); e != nil {
			fmt.Println("probe_write_error=" + common.SecretFree(e))
		}
		if !common.Sleep(ctx, time.Duration(common.I(a.C["probe_seconds"]))*time.Second) {
			return
		}
	}
}

func readText(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	r, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return nil, e
	}
	resp, e := c.Do(r)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("metrics_http_status")
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
