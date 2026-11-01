package controlplane

import (
	"context"
	"errors"
)

// Private CLI operations deliberately project all database, path and decoder
// failures to controlled errors. A failed batch never reports uncommitted
// progress; callers fetch the durable session/checkpoint before retrying.
func safeMigrationSessionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrConflict) {
		return ErrConflict
	}
	if errors.Is(err, ErrMigrationCutoverProtected) {
		return ErrMigrationCutoverProtected
	}
	return ErrMigrationSession
}
func (s *Store) BeginMigrationSession(ctx context.Context, id string, expected int64, roles []string) (MigrationSession, error) {
	r, e := s.beginMigrationSession(ctx, id, expected, roles)
	if e != nil {
		return MigrationSession{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) MigrationSession(ctx context.Context, id string) (MigrationSession, error) {
	r, e := s.migrationSession(ctx, id)
	if e != nil {
		return MigrationSession{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) BindMigrationRevision(ctx context.Context, id string, expected int64, in MigrationRevisionInput) (MigrationRevisionReport, error) {
	r, e := s.bindMigrationRevision(ctx, id, expected, in)
	if e != nil {
		return MigrationRevisionReport{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) ResumeMigrationRevision(ctx context.Context, id string, expected int64, revision string) (MigrationRevisionReport, error) {
	r, e := s.resumeMigrationRevision(ctx, id, expected, revision)
	if e != nil {
		return MigrationRevisionReport{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) CompareMigrationRevisions(ctx context.Context, id string, expected int64, base, target string) (MigrationDeltaReport, error) {
	r, e := s.compareMigrationRevisions(ctx, id, expected, base, target)
	if e != nil {
		return MigrationDeltaReport{}, safeMigrationSessionError(e)
	}
	return r, nil
}
func (s *Store) ResumeMigrationDelta(ctx context.Context, id string, expected int64, delta string) (MigrationDeltaReport, error) {
	r, e := s.resumeMigrationDelta(ctx, id, expected, delta)
	if e != nil {
		return MigrationDeltaReport{}, safeMigrationSessionError(e)
	}
	return r, nil
}
