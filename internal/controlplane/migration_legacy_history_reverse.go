package controlplane

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"

	"webscan/internal/common"
)

type migrationLegacyHistoryArtifactImage struct {
	ID, Name, SHA256 string
	Payload          []byte
}

func migrationLegacyHistoryArtifactsTx(ctx context.Context, tx *sql.Tx, session string, v *Vault) (map[string]migrationLegacyHistoryArtifactImage, error) {
	rows, e := tx.QueryContext(ctx, `SELECT DISTINCT ON(role) revision,source_id,role FROM v3_migration_legacy_history_runs WHERE session=$1 ORDER BY role,finished_version DESC`, session)
	if e != nil {
		return nil, e
	}
	type source struct{ revision, id, role string }
	sources := []source{}
	for rows.Next() {
		var s source
		if e = rows.Scan(&s.revision, &s.id, &s.role); e != nil {
			rows.Close()
			return nil, e
		}
		sources = append(sources, s)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	out := map[string]migrationLegacyHistoryArtifactImage{}
	for _, s := range sources {
		verified, e := VerifyLegacyHistoryTx(ctx, tx, session, s.revision, v)
		if e != nil || !verified {
			return nil, ErrMigrationSession
		}
		owned, e := migrationLegacyHistoryLoadTx(ctx, tx, session, s.id, v, s.role)
		if e != nil {
			return nil, e
		}
		for _, r := range owned {
			if r.Table != "config_backups" {
				continue
			}
			record, _, e := migrationLegacyHistoryArchive(r.Envelope.Source, r.ArchiveDigest)
			if e != nil {
				return nil, e
			}
			id, e := migrationLegacyHistoryRecordIdentity(record, "id")
			if e != nil {
				return nil, e
			}
			if len(r.Envelope.Artifact) == 0 || r.Envelope.RestoredSHA256 != digest(r.Envelope.Artifact) {
				return nil, ErrMigrationSession
			}
			out[id] = migrationLegacyHistoryArtifactImage{id, "legacy-" + digest([]byte(id)) + ".yaml", r.Envelope.RestoredSHA256, append([]byte{}, r.Envelope.Artifact...)}
		}
	}
	return out, nil
}

func (s *MigrationLegacySink) migrationLegacyStageArtifacts(ctx context.Context, artifacts map[string]migrationLegacyHistoryArtifactImage) error {
	if len(artifacts) == 0 {
		return nil
	}
	if !s.roles["host-manager"] {
		return ErrMigrationSession
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, a := range artifacts {
		if _, e = tx.ExecContext(ctx, `INSERT INTO migration_configuration_artifacts(id,name,payload,digest) VALUES(?,?,?,?)`, a.ID, a.Name, a.Payload, a.SHA256); e != nil {
			return e
		}
		result, e := tx.ExecContext(ctx, `UPDATE manager.config_backups SET path=? WHERE id=?`, filepath.Join(s.output, "config-backups", a.Name), a.ID)
		if e != nil {
			return e
		}
		count, e := result.RowsAffected()
		if e != nil || count != 1 {
			return ErrMigrationSession
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	return s.migrationLegacyExportArtifacts(ctx)
}

func (s *MigrationLegacySink) migrationLegacyExportArtifacts(ctx context.Context) error {
	rows, e := s.db.QueryContext(ctx, `SELECT id,name,payload,digest FROM migration_configuration_artifacts ORDER BY id`)
	if e != nil {
		return e
	}
	artifacts := []migrationLegacyHistoryArtifactImage{}
	for rows.Next() {
		var a migrationLegacyHistoryArtifactImage
		if e = rows.Scan(&a.ID, &a.Name, &a.Payload, &a.SHA256); e != nil {
			rows.Close()
			return e
		}
		artifacts = append(artifacts, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(artifacts) == 0 {
		return e
	}
	directory := filepath.Join(s.output, "config-backups")
	if e = os.Mkdir(directory, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	dir, e := privateDirectory(directory)
	if e != nil {
		return e
	}
	dir.Close()
	for _, a := range artifacts {
		if a.Name != "legacy-"+digest([]byte(a.ID))+".yaml" || digest(a.Payload) != a.SHA256 {
			return ErrMigrationSession
		}
		if e = metricsRetentionAtomicFile(directory, a.Name, a.Payload); e != nil {
			return e
		}
	}
	return nil
}

// Bind external reconstructed backup files to authenticated PostgreSQL source
// artifacts as well as to the actual attached v2 metadata. An opaque payload
// in a migration ledger alone never satisfies rollback verification.
func VerifyMigrationLegacyArtifactsTx(ctx context.Context, tx *sql.Tx, session string, sink *MigrationLegacySink, v *Vault) error {
	expected, e := migrationLegacyHistoryArtifactsTx(ctx, tx, session, v)
	if e != nil {
		return e
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var count int
	if e = sink.db.QueryRowContext(ctx, `SELECT count(*) FROM migration_configuration_artifacts`).Scan(&count); e != nil || count != len(expected) {
		return ErrMigrationSession
	}
	for id, a := range expected {
		var name, hash, path string
		var payload []byte
		if e = sink.db.QueryRowContext(ctx, `SELECT name,payload,digest FROM migration_configuration_artifacts WHERE id=?`, id).Scan(&name, &payload, &hash); e != nil || name != a.Name || hash != a.SHA256 || digest(payload) != a.SHA256 {
			return ErrMigrationSession
		}
		if e = sink.db.QueryRowContext(ctx, `SELECT path FROM manager.config_backups WHERE id=?`, id).Scan(&path); e != nil || path != filepath.Join(sink.output, "config-backups", a.Name) {
			return ErrMigrationSession
		}
		actual, e := readTrustData(path, true, 2<<20)
		if e != nil {
			return e
		}
		good := digest(actual) == a.SHA256
		clear(actual)
		if !good {
			return ErrMigrationSession
		}
	}
	return nil
}

func (s *MigrationLegacySink) migrationLegacyArtifactDigest(ctx context.Context) (string, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id,name,digest FROM migration_configuration_artifacts ORDER BY id`)
	if e != nil {
		return "", e
	}
	artifacts := []migrationLegacyHistoryArtifactImage{}
	for rows.Next() {
		var a migrationLegacyHistoryArtifactImage
		if e = rows.Scan(&a.ID, &a.Name, &a.SHA256); e != nil {
			rows.Close()
			return "", e
		}
		artifacts = append(artifacts, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return "", e
	}
	data := []any{}
	for _, a := range artifacts {
		if a.Name != "legacy-"+digest([]byte(a.ID))+".yaml" {
			return "", ErrMigrationSession
		}
		actual, e := readTrustData(filepath.Join(s.output, "config-backups", a.Name), true, 2<<20)
		if e != nil {
			return "", e
		}
		hash := digest(actual)
		clear(actual)
		if hash != a.SHA256 {
			return "", ErrMigrationSession
		}
		data = append(data, []any{a.ID, a.Name, hash})
	}
	return digest(common.JSON(data)), nil
}
