package controlplane

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
)

// This private manifest is never returned by an API or printed in a receipt.
// It describes existing writers; it cannot contain a shell command or URL.
type MigrationFreezeManifest struct {
	Format  int                     `json:"format"`
	Session string                  `json:"session"`
	Sources []MigrationFreezeSource `json:"sources"`
}
type MigrationFreezeSource struct {
	Role     string                  `json:"role"`
	SourceID string                  `json:"source_id"`
	SQLite   string                  `json:"sqlite"`
	Writers  []MigrationFreezeWriter `json:"writers"`
}
type MigrationFreezeWriter struct {
	Kind                string `json:"kind"`
	ID                  string `json:"id"`
	Role                string `json:"role"`
	ConfigFile          string `json:"config_file"`
	ConfigSHA256        string `json:"config_sha256"`
	DefinitionFile      string `json:"definition_file,omitempty"`
	DefinitionSHA256    string `json:"definition_sha256,omitempty"`
	Executable          string `json:"executable,omitempty"`
	ExecutableSHA256    string `json:"executable_sha256,omitempty"`
	StateDirectory      string `json:"state_directory,omitempty"`
	ContainerConfigFile string `json:"container_config_file,omitempty"`
	ComposeProject      string `json:"compose_project,omitempty"`
}
type migrationFreezeObserver func(context.Context, MigrationFreezeSource) (string, error)

func readMigrationFreezeManifest(path, id string) (MigrationFreezeManifest, string, error) {
	var m MigrationFreezeManifest
	raw, e := readTrustData(path, true, 1<<20)
	if e != nil || singleDecode(raw, &m) != nil || m.Format != 1 || m.Session != id || len(m.Sources) == 0 || len(m.Sources) > 3 {
		return m, "", ErrMigrationSession
	}
	sort.Slice(m.Sources, func(i, j int) bool { return m.Sources[i].Role < m.Sources[j].Role })
	for i, v := range m.Sources {
		if !validArchiveSource(v.SourceID) || len(v.Writers) == 0 || len(v.Writers) > 8 || !filepath.IsAbs(v.SQLite) || filepath.Clean(v.SQLite) != v.SQLite || i > 0 && v.Role == m.Sources[i-1].Role {
			return m, "", ErrMigrationSession
		}
		if _, e = migrationRoles([]string{v.Role}); e != nil {
			return m, "", e
		}
	}
	canonical, _ := json.Marshal(m)
	return m, digest(canonical), nil
}
func (s *Store) FreezeMigrationSession(ctx context.Context, id string, expected int64, manifestPath, directory string) (MigrationSession, error) {
	r, e := s.freezeMigrationSession(ctx, id, expected, manifestPath, directory, observeMigrationFrozenSource)
	if e != nil {
		return MigrationSession{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) freezeMigrationSession(ctx context.Context, id string, expected int64, manifestPath, directory string, observe migrationFreezeObserver) (MigrationSession, error) {
	manifest, manifestSHA, e := readMigrationFreezeManifest(manifestPath, id)
	if e != nil {
		return MigrationSession{}, e
	}
	state, e := s.MigrationSession(ctx, id)
	if e != nil || state.RecoveryHold || state.Phase != "collecting" && state.Phase != "indexed" && state.Phase != "frozen" && state.Phase != "reconciled" {
		return MigrationSession{}, ErrMigrationSession
	}
	if len(state.Roles) != len(manifest.Sources) {
		return MigrationSession{}, ErrMigrationSession
	}
	for i, source := range manifest.Sources {
		if source.Role != state.Roles[i] {
			return MigrationSession{}, ErrMigrationSession
		}
	}
	if state.Phase == "frozen" || state.Phase == "reconciled" {
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			return MigrationSession{}, e
		}
		defer tx.Rollback()
		if migrationSessionLock(ctx, tx, id) != nil {
			return MigrationSession{}, ErrMigrationSession
		}
		current, e := migrationSessionTx(ctx, tx, id)
		if e != nil || current.RecoveryHold || current.Version != state.Version {
			return MigrationSession{}, ErrConflict
		}
		for _, source := range manifest.Sources {
			var revision, storedManifest, storedEvidence string
			var request int64
			if tx.QueryRowContext(ctx, `SELECT revision,manifest_digest,evidence_digest,request_version FROM v3_migration_freezes WHERE session=$1 AND role=$2`, id, source.Role).Scan(&revision, &storedManifest, &storedEvidence, &request) != nil || storedManifest != manifestSHA || expected != request && expected != state.Version {
				return MigrationSession{}, ErrConflict
			}
			evidence, e := observe(ctx, source)
			if e != nil || evidence != storedEvidence || verifyMigrationRevisionIndex(ctx, tx, revision) != nil {
				return MigrationSession{}, ErrMigrationSession
			}
		}
		if e = tx.Commit(); e != nil {
			return MigrationSession{}, e
		}
		return s.MigrationSession(ctx, id)
	}
	if state.Version != expected {
		return MigrationSession{}, ErrConflict
	}
	before := map[string]string{}
	for _, source := range manifest.Sources {
		proof, e := observe(ctx, source)
		if e != nil || !releaseDigest(proof) {
			return MigrationSession{}, ErrMigrationSession
		}
		before[source.Role] = proof
	}
	version := expected
	final := map[string]MigrationRevisionReport{}
	for _, source := range manifest.Sources {
		// The snapshot is generated here after observing stopped, disabled writers.
		// Supplying a previously prepared hash cannot stand in for a final backup.
		archived, e := s.ArchiveSQLite(ctx, source.SQLite, directory)
		if e != nil {
			return MigrationSession{}, ErrMigrationSession
		}
		revision, e := s.BindMigrationRevision(ctx, id, version, MigrationRevisionInput{source.Role, source.SourceID, archived.Snapshot})
		if e != nil {
			return MigrationSession{}, e
		}
		final[source.Role] = revision
		version = revision.SessionVersion
	}
	evidence := map[string]string{}
	for _, source := range manifest.Sources {
		proof, e := observe(ctx, source)
		if e != nil || proof != before[source.Role] {
			return MigrationSession{}, ErrMigrationSession
		}
		evidence[source.Role] = proof
	}
	// Re-read the manifest so a replacement during snapshot creation cannot
	// authorize a different list of stopped writers at the commit boundary.
	_, again, e := readMigrationFreezeManifest(manifestPath, id)
	if e != nil || again != manifestSHA {
		return MigrationSession{}, ErrMigrationSession
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return MigrationSession{}, e
	}
	defer tx.Rollback()
	if e = migrationSessionLock(ctx, tx, id); e != nil {
		return MigrationSession{}, e
	}
	state, e = migrationSessionTx(ctx, tx, id)
	if e != nil || state.RecoveryHold {
		return MigrationSession{}, ErrMigrationSession
	}
	if state.Version != version || state.Phase != "indexed" {
		return MigrationSession{}, ErrConflict
	}
	for _, source := range manifest.Sources {
		revision := final[source.Role]
		var latest string
		if tx.QueryRowContext(ctx, `SELECT id FROM v3_migration_revisions WHERE session=$1 AND role=$2 ORDER BY sequence DESC LIMIT 1`, id, source.Role).Scan(&latest) != nil || latest != revision.ID || verifyMigrationRevisionIndex(ctx, tx, latest) != nil {
			return MigrationSession{}, ErrMigrationSession
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_freezes(session,role,revision,manifest_digest,evidence_digest,request_version) VALUES($1,$2,$3,$4,$5,$6)`, id, source.Role, latest, manifestSHA, evidence[source.Role], expected); e != nil {
			return MigrationSession{}, e
		}
	}
	summary, _ := json.Marshal(struct {
		Manifest  string
		Evidence  map[string]string
		Revisions map[string]MigrationRevisionReport
	}{manifestSHA, evidence, final})
	if _, e = tx.ExecContext(ctx, `UPDATE v3_migration_sessions SET version=version+1,phase='frozen',freeze_digest=$2,freeze_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1`, id, digest(summary)); e != nil {
		return MigrationSession{}, e
	}
	if e = tx.Commit(); e != nil {
		return MigrationSession{}, e
	}
	return s.MigrationSession(ctx, id)
}
