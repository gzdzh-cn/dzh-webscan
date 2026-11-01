package controlplane

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
	configuration "webscan/internal/config"
)

func migrationLegacyHistoryArtifact(ctx context.Context, tx *sql.Tx, session, id string, r archivedRecord, in MigrationLegacyHistoryInput, v *Vault) (raw []byte, restored, reason string, err error) {
	expected, e := archiveText(r, "revision", 64)
	if e != nil || !releaseDigest(expected) {
		return nil, "", "legacy_configuration_backup_digest_invalid", nil
	}
	// A previously verified private copy remains valid after the source file is
	// moved away, but never after its indexed source digest changes.
	var key string
	var nonce, sealed []byte
	e = tx.QueryRowContext(ctx, `SELECT key_id,nonce,ciphertext FROM v3_migration_legacy_history_rows WHERE id=$1`, id).Scan(&key, &nonce, &sealed)
	if e == nil {
		old, e := migrationFinalOpen(v, key, migrationLegacyHistoryAAD(session, id), nonce, sealed)
		if e != nil {
			return nil, "", "", e
		}
		var envelope migrationLegacyHistoryEnvelope
		e = singleDecode(old, &envelope)
		clear(old)
		if e != nil {
			return nil, "", "", ErrMigrationSession
		}
		if len(envelope.Artifact) > 0 && digest(envelope.Artifact) == expected {
			raw = append([]byte{}, envelope.Artifact...)
			if envelope.RestoredSHA256 == expected {
				restored = expected
			}
		}
	} else if e != sql.ErrNoRows {
		return nil, "", "", e
	}
	if len(raw) == 0 {
		directory := in.ConfigurationBackupDirectories["host-manager"]
		if directory == "" {
			return nil, "", "legacy_configuration_backup_file_missing", nil
		}
		dir, e := privateDirectory(directory)
		if e != nil {
			return nil, "", "legacy_configuration_backup_directory_unsafe", nil
		}
		defer dir.Close()
		original, e := archiveText(r, "path", 4096)
		if e != nil || !filepath.IsAbs(original) || filepath.Clean(original) != original {
			return nil, "", "legacy_configuration_backup_path_invalid", nil
		}
		name := filepath.Base(original)
		if len(name) > 255 || !strings.HasSuffix(name, ".yaml") || strings.HasPrefix(name, ".") {
			return nil, "", "legacy_configuration_backup_path_invalid", nil
		}
		raw, e = migrationLegacyHistoryReadArtifact(dir, name)
		if e != nil {
			return nil, "", "legacy_configuration_backup_file_unsafe_or_missing", nil
		}
		if digest(raw) != expected {
			clear(raw)
			return nil, "", "legacy_configuration_backup_digest_mismatch", nil
		}
	}
	if _, e = configuration.Parse(raw, ""); e != nil {
		clear(raw)
		return nil, "", "legacy_configuration_backup_requires_valid_configuration", nil
	}
	if restored == "" {
		if in.RestoreVerificationDirectory == "" {
			return raw, "", "legacy_configuration_backup_restore_not_verified", nil
		}
		root, e := privateDirectory(in.RestoreVerificationDirectory)
		if e != nil {
			clear(raw)
			return nil, "", "legacy_configuration_restore_directory_unsafe", nil
		}
		root.Close()
		// A separate directory and actual config parser exercise reconstruction of
		// the stored bytes without overwriting any deployment or source backup.
		output := filepath.Join(in.RestoreVerificationDirectory, "restore-"+id+"-"+token())
		if e = os.Mkdir(output, 0700); e != nil {
			return nil, "", "", e
		}
		if e = metricsRetentionAtomicFile(output, "configuration.yaml", raw); e != nil {
			return nil, "", "", e
		}
		file, e := openTrustFile(filepath.Join(output, "configuration.yaml"), true, 2<<20)
		if e != nil {
			return nil, "", "", e
		}
		recovered, e := io.ReadAll(io.LimitReader(file, (2<<20)+1))
		file.Close()
		defer clear(recovered)
		if e != nil || digest(recovered) != expected {
			return nil, "", "", ErrMigrationSession
		}
		if _, e = configuration.Load(filepath.Join(output, "configuration.yaml")); e != nil {
			return nil, "", "", ErrMigrationSession
		}
		restored = expected
	}
	return raw, restored, "", nil
}

func migrationLegacyHistoryReadArtifact(dir *os.File, name string) ([]byte, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrMigrationSession
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, ErrMigrationSession
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() < 1 || st.Size() > 2<<20 {
		return nil, ErrMigrationSession
	}
	raw, e := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	after, se := f.Stat()
	if e != nil || se != nil || int64(len(raw)) != st.Size() || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
		clear(raw)
		return nil, ErrMigrationSession
	}
	return raw, nil
}

// Bind exact imported source histories to the real v2 snapshots used by the
// reverse sink. Changes to v3-only history remain an explicit rollback blocker.
func migrationLegacyHistoryBaselinesTx(ctx context.Context, tx *sql.Tx, session string, v *Vault) (map[string]string, error) {
	out := map[string]string{}
	revisions, e := tx.QueryContext(ctx, `SELECT DISTINCT ON(role) source_id,revision,role FROM v3_migration_legacy_history_runs WHERE session=$1 ORDER BY role,finished_version DESC`, session)
	if e != nil {
		return nil, e
	}
	type historySource struct{ source, revision, role string }
	sources := []historySource{}
	for revisions.Next() {
		var source historySource
		if e = revisions.Scan(&source.source, &source.revision, &source.role); e != nil {
			revisions.Close()
			return nil, e
		}
		sources = append(sources, source)
	}
	e = revisions.Err()
	revisions.Close()
	if e != nil {
		return nil, e
	}
	for _, source := range sources {
		verified, e := VerifyLegacyHistoryTx(ctx, tx, session, source.revision, v)
		if e != nil || !verified {
			return nil, ErrMigrationSession
		}
		rows, e := migrationLegacyHistoryLoadTx(ctx, tx, session, source.source, v, source.role)
		if e != nil {
			return nil, e
		}
		for id, row := range rows {
			var actual []byte
			if e = tx.QueryRowContext(ctx, `SELECT to_jsonb(h) FROM v3_legacy_history h WHERE id=$1`, id).Scan(&actual); e != nil {
				return nil, e
			}
			data, e := common.Decode(actual)
			if e != nil || !migrationLegacyValueEqual(string(common.JSON(common.M(data)["payload"])), string(common.JSON(row.Envelope.Public))) {
				return nil, ErrConflict
			}
			out[migrationLegacySourceKey("v3_legacy_history", common.Map{"id": id})] = digest(common.JSON(data))
		}
	}
	return out, nil
}
