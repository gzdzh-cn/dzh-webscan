package controlplane

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

func legacyWebsiteBackupID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == id
}

// The caller supplies the directory through the offline CLI, never an HTTP
// request. Open each generated basename relative to this private descriptor.
func readLegacyWebsiteBackup(dir *os.File, id string) ([]byte, error) {
	if !legacyWebsiteBackupID(id) {
		return nil, errors.New("旧网站备份编号不正确")
	}
	fd, err := unix.Openat(int(dir.Fd()), id+".json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("旧网站备份文件缺失或无法安全读取；保留原文件后重试")
	}
	f := os.NewFile(uintptr(fd), id+".json")
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, errors.New("无法核对旧网站备份文件")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() <= 0 || st.Size() > websiteBackupStoredLimit {
		return nil, errors.New("旧网站备份须为运行账号所有的私有普通文件，且不超过 24 MiB")
	}
	raw, err := io.ReadAll(io.LimitReader(f, websiteBackupStoredLimit+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(raw)) != st.Size() || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
		return nil, errors.New("旧网站备份读取失败或读取期间发生变化")
	}
	return raw, nil
}

// MapWebsiteBackupArchive joins the frozen SQLite metadata to checksum-verified
// external snapshots. It does not merge websites or authorize an old preview.
func (s *Store) MapWebsiteBackupArchive(ctx context.Context, source, directory string) (DomainImportReport, error) {
	report := DomainImportReport{Source: source, Domain: "website-backups"}
	if !validArchiveSource(source) {
		return report, errors.New("迁移源必须为已归档快照的 SHA256")
	}
	st, err := os.Lstat(directory)
	if err != nil || !filepath.IsAbs(directory) || !st.IsDir() {
		return report, errors.New("旧网站备份目录必须是已有私有目录的绝对路径，不能为符号链接")
	}
	dir, err := privateDirectory(directory)
	if err != nil {
		return report, errors.New("旧网站备份目录必须属于运行账号且权限为 0700")
	}
	defer dir.Close()
	return s.mapArchiveDomainBatched(ctx, source, "", "website-backups", []string{"record_operations", "website_backups"}, []string{"website_backups"}, 1,
		func(ctx context.Context, tx *sql.Tx) error {
			// Refuse pending old deletion before binding the destination, so the
			// operator can finish it and take a new archive without a stale fence.
			rows, err := tx.QueryContext(ctx, "SELECT payload,digest FROM v3_legacy_records WHERE source=$1 AND table_name='record_operations' AND payload->'kind'->>'value'='website-backup'", source)
			if err != nil {
				return err
			}
			for rows.Next() {
				var raw []byte
				var hash string
				if err = rows.Scan(&raw, &hash); err == nil {
					var r archivedRecord
					r, err = decodedArchiveRecord(raw, hash)
					if err == nil {
						err = legacyWebsiteBackupOperation(r)
					}
				}
				if err != nil {
					break
				}
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
			if err != nil {
				return err
			}
			return bindMigrationDomain(ctx, tx, "website-backups", source, "", []string{"v3_website_backups", "v3_website_backup_previews"})
		}, func(ctx context.Context, tx *sql.Tx, table string, r archivedRecord) (bool, error) {
			if table == "record_operations" {
				return false, legacyWebsiteBackupOperation(r) // Audit remains archived.
			}
			return mapWebsiteBackupRecord(ctx, tx, source, dir, r)
		})
}

func legacyWebsiteBackupOperation(r archivedRecord) error {
	kind, err := r.text("kind")
	if err != nil {
		return err
	}
	status, err := r.text("status")
	if err != nil {
		return err
	}
	if kind == "website-backup" && status != "complete" && status != "partial" {
		return errors.New("旧网站备份存在未完成删除任务；先在旧系统完成任务，再重新归档")
	}
	return nil
}

func mapWebsiteBackupRecord(ctx context.Context, tx *sql.Tx, source string, dir *os.File, r archivedRecord) (bool, error) {
	id, err := r.text("id")
	if err != nil || !legacyWebsiteBackupID(id) {
		return false, errors.New("旧网站备份编号不正确")
	}
	sum, err := r.text("digest")
	if err != nil || !validArchiveSource(sum) {
		return false, errors.New("旧网站备份摘要不正确")
	}
	created, err := r.timestamp("created", false)
	if err != nil {
		return false, err
	}
	count, err := r.integer("count")
	if err != nil || count < 0 || count > websiteBackupSitesLimit {
		return false, errors.New("旧网站备份网站数量不正确")
	}
	origin, err := archiveText(r, "source", 128)
	if err != nil {
		return false, err
	}
	result, err := archiveText(r, "result", 8192)
	if err != nil {
		return false, err
	}
	stamp, err := r.timestamp("restored", false)
	if err != nil {
		return false, err
	}
	var restored *time.Time
	if stamp.Unix() != 0 {
		restored = stamp
	}
	raw, err := readLegacyWebsiteBackup(dir, id)
	if err != nil {
		return false, err
	}
	if digest(raw) != sum {
		return false, errors.New("旧网站备份文件与归档摘要不符，未导入此备份")
	}
	doc, err := parseWebsiteBackup(raw, websiteBackupStoredLimit)
	if err != nil || int64(len(doc.Sites)) != count {
		return false, errors.New("旧网站备份内容无效或数量与元数据不符")
	}
	payload := common.JSON(doc)
	key := digest([]byte("v2-website-backup:" + source + ":" + id))
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_website_backups(id,created_at,source,payload,digest,count,restored_at,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, key, created, origin, payload, digest(payload), count, restored, common.JSON(common.Map{"legacy_id": id, "legacy_result": result, "migration_source": source}))
	return err == nil, err
}
