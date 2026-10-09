package central

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/website"
)

func (s *Store) maintenance(ctx context.Context) {
	for ctx.Err() == nil {
		if e := s.QueryProbes(ctx); e != nil {
			fmt.Println("probe_query_error=" + common.SecretFree(e))
		}
		if e := s.Maintain(ctx); e != nil {
			fmt.Println("maintenance_error=" + common.SecretFree(e))
		}
		if !common.Sleep(ctx, 30*time.Second) {
			return
		}
	}
}
func (s *Store) Maintain(ctx context.Context) error {
	c := s.Config
	r := common.M(c["retention"])
	s.mu.Lock()
	_, e := s.DB.ExecContext(ctx, "INSERT INTO kv VALUES('heartbeat',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", strconv.FormatFloat(common.Now(), 'f', 6, 64))
	if e == nil {
		_, e = s.DB.ExecContext(ctx, "DELETE FROM delivery_records WHERE time<?", common.Now()-common.F(r["delivery_records_days"])*86400)
	}
	if e == nil {
		_, e = s.DB.ExecContext(ctx, "DELETE FROM events WHERE received<? AND NOT EXISTS(SELECT 1 FROM tasks WHERE tasks.node=events.node AND tasks.event_id=events.id AND done IS NULL)", common.Now()-common.F(r["sqlite_events_days"])*86400)
	}
	if e == nil {
		_, e = s.DB.ExecContext(ctx, "DELETE FROM tasks WHERE done IS NOT NULL AND done<?", common.Now()-common.F(r["delivery_records_days"])*86400)
	}
	s.mu.Unlock()
	if e != nil {
		return e
	}
	for _, purpose := range []string{"backup", "daily_test"} {
		settings := common.M(c["backup"])
		if purpose == "daily_test" {
			settings = common.M(common.M(c["feishu"])["daily_test"])
		}
		if !common.B(settings["enabled"]) {
			continue
		}
		zone, e := time.LoadLocation(common.S(settings["timezone"]))
		if e != nil {
			return e
		}
		local := time.Now().In(zone)
		key := purpose + ":" + local.Format("2006-01-02")
		var exists int
		s.DB.QueryRowContext(ctx, "SELECT 1 FROM kv WHERE key=?", key).Scan(&exists)
		if exists != 0 || local.Format("15:04") < common.S(settings["time"]) {
			continue
		}
		if purpose == "backup" {
			e = s.Backup()
		} else {
			e = s.Notice(ctx, key, "通知链路每日测试（不是业务文件变化）\n发生时间："+noticeTime(common.Stamp()))
		}
		if e != nil {
			return e
		}
		if _, e = s.DB.ExecContext(ctx, "INSERT OR IGNORE INTO kv VALUES(?,?)", key, "done"); e != nil {
			return e
		}
	}
	return nil
}
func ArchiveDirectory(source, target, root string) error {
	f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	e = filepath.WalkDir(source, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = filepath.Join(root, rel)
		if err = tw.WriteHeader(header); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			in, err := os.Open(path)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, in)
			in.Close()
			return err
		}
		return nil
	})
	for _, close := range []func() error{tw.Close, gz.Close, f.Sync, f.Close} {
		if err := close(); e == nil {
			e = err
		}
	}
	return e
}
func (s *Store) Backup() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	settings := common.M(s.Config["backup"])
	root := common.S(s.Config["backup_dir"])
	directory := filepath.Join(root, time.Now().UTC().Format("20060102-150405"))
	if e := os.MkdirAll(directory, 0700); e != nil {
		return e
	}
	if common.B(settings["include_sqlite"]) {
		if e := persist.BackupDB(s.DB, filepath.Join(directory, "events.sqlite3")); e != nil {
			return e
		}
	}
	if common.B(settings["include_runtime_config"]) {
		if e := common.AtomicJSON(filepath.Join(directory, "runtime.json"), s.backupRuntime()); e != nil {
			return e
		}
		if source := common.S(s.Config["runtime_dir"]); source != "" {
			if e := ArchiveDirectory(source, filepath.Join(directory, "runtime-files.tar.gz"), "webscan-v1"); e != nil {
				return e
			}
		}
	}
	if common.B(settings["include_sqlite"]) {
		source := filepath.Join(root, "website-config")
		if info, e := os.Stat(source); e == nil && info.IsDir() {
			if e = ArchiveDirectory(source, filepath.Join(directory, "website-config.tar.gz"), "website-config"); e != nil {
				return e
			}
		} else if e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	pattern := regexp.MustCompile(`^\d{8}-\d{6}$`)
	for _, entry := range entries {
		if !entry.IsDir() || !pattern.MatchString(entry.Name()) {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if time.Since(info.ModTime()) > time.Duration(common.I(settings["keep_days"]))*24*time.Hour {
			if e = os.RemoveAll(filepath.Join(root, entry.Name())); e != nil {
				return e
			}
		}
	}
	return nil
}

func (s *Store) backupRuntime() common.Map {
	config := common.Clone(s.Config)
	if a, e := website.ReadAccount(s.DB); e == nil {
		wm := common.M(config["website_monitor"])
		wm["admin_username"] = a.Username
		wm["password_hash"] = a.Hash
		config["website_monitor"] = wm
	}
	return config
}
