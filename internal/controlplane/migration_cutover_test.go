package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"webscan/internal/common"
	"webscan/internal/persist"
)

func migrationCutoverFixture(t *testing.T) (*Store, string, MigrationCutoverInput, migrationFreezeObserver, int64) {
	t.Helper()
	ctx := context.Background()
	s, id, source, db, snapshot, v := migrationFinalFixture(t)
	r, err := s.BindMigrationRevision(ctx, id, 1, MigrationRevisionInput{"central", source, snapshot()})
	if err != nil {
		t.Fatal(err)
	}
	var file string
	if err = db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&file); err != nil {
		t.Fatal(err)
	}
	version := migrationBindLegacyYAMLFixture(t, s, id, source, r.SessionVersion, v)
	manifest := migrationFreezeTestManifest(t, id, source, file)
	migrationBindFrozenYAMLFixture(t, s, id, manifest, v)
	observer := func(context.Context, MigrationFreezeSource) (string, error) {
		return digest([]byte("private-stopped-source")), nil
	}
	frozen, err := s.freezeMigrationSession(ctx, id, version, manifest, privateTestDir(t), observer)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := s.MapMigrationFinalDomains(ctx, id, frozen.Version, MigrationFinalMappingInput{}, v)
	if err != nil || !mapped.Complete {
		t.Fatal(mapped, err)
	}
	state, err := s.MigrationSession(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	if err = s.DB.QueryRow(`SELECT snapshot FROM v3_migration_revisions WHERE session=$1 ORDER BY sequence DESC LIMIT 1`, id).Scan(&path); err != nil {
		t.Fatal(err)
	}
	sink, err := s.PrepareMigrationLegacySink(ctx, id, state.Version, map[string]string{"central": path}, filepath.Join(privateTestDir(t), "legacy"), v)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	j, err := s.ArmMigrationTargetJournal(ctx, id, state.Version)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := s.ProjectMigrationLegacyBaseline(ctx, id, j.SessionVersion, "verified_legacy", sink, v)
	if err != nil || !evidence.Verified {
		t.Fatal(evidence, err)
	}
	return s, id, MigrationCutoverInput{FreezeManifest: manifest, Consumer: "verified_legacy", LegacySink: sink, LegacyEvidence: evidence, Vault: v}, observer, j.SessionVersion
}

func TestMigrationCutoverActualBusinessReplayKeepsPostSwitchChangesAndRequiresMetrics(t *testing.T) {
	ctx := context.Background()
	s, id, in, observer, version := migrationCutoverFixture(t)
	if err := s.migrationCutover(ctx, id, version, in, "activate", observer); err != nil {
		t.Fatal("activate", err)
	}
	if err := s.migrationCutover(ctx, id, version, in, "activate", observer); err != nil {
		t.Fatal("lost activate response", err)
	}
	state, err := s.MigrationSession(ctx, id)
	if err != nil || state.Protected || state.Phase != "active" {
		t.Fatal(state, err)
	}
	var rows int
	if err = s.DB.QueryRow(`SELECT count(*) FROM v3_websites`).Scan(&rows); err != nil || rows == 0 {
		t.Fatal(rows, err)
	}
	// Use a real row identity: older fixtures keep their original site IDs.
	var site string
	if err = s.DB.QueryRow(`SELECT id FROM v3_websites ORDER BY id LIMIT 1`).Scan(&site); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE v3_websites SET name='after-switch' WHERE id=$1`, site); err != nil {
		t.Fatal(err)
	}
	sealed, err := s.SealMigrationTargetJournal(ctx, id, state.Version)
	if err != nil {
		t.Fatal("seal", err)
	}
	if _, err = s.DB.Exec(`UPDATE v3_websites SET name='forbidden-after-seal' WHERE id=$1`, site); err == nil {
		t.Fatal("sealed target accepted writes")
	}
	replayed, err := s.ReplayMigrationTargetJournal(ctx, id, sealed.SessionVersion, in.Consumer, in.LegacySink)
	if err != nil {
		t.Fatal("replay", err)
	}
	evidence, err := s.VerifyMigrationLegacyRollback(ctx, id, replayed.SessionVersion, in.Consumer, in.LegacySink, in.Vault)
	if err != nil || !evidence.Verified {
		t.Fatal(evidence, err)
	}
	in.LegacyEvidence = evidence
	// A correct business projection cannot prove that VM-only history has been
	// preserved. Final rollback must retain the fence until its independent
	// actual-store archive is present, authenticated and rechecked.
	if err = s.migrationCutover(ctx, id, replayed.SessionVersion, in, "rollback", observer); err == nil {
		t.Fatal("business-only receipt authorized rollback without metrics")
	}
	var name string
	if err = in.LegacySink.db.QueryRow(`SELECT name FROM central.websites WHERE id=?`, site).Scan(&name); err != nil || name != "after-switch" {
		t.Fatal("new data missing from real legacy business table", name, err)
	}
	state, err = s.MigrationSession(ctx, id)
	if err != nil || !state.Protected || state.Phase != "active" {
		t.Fatal(state, err)
	}
}

func TestMigrationCutoverRejectsStaleEvidenceAndForeignDomains(t *testing.T) {
	for _, mode := range []string{"wrong-vault", "output-tamper", "foreign-domain", "writer-restarted", "missing-evidence", "source-changed", "version"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, id, in, observer, version := migrationCutoverFixture(t)
			switch mode {
			case "wrong-vault":
				in.Vault, _ = testVault(t)
			case "output-tamper":
				_, err := in.LegacySink.db.Exec(`UPDATE central.websites SET name='tamper'`)
				if err != nil {
					t.Fatal(err)
				}
			case "foreign-domain":
				mustHistoryExec(t, s.DB, `INSERT INTO v3_migration_domains(domain,source,pending)VALUES('unrelated',$1,true)`, digest([]byte("other")))
			case "writer-restarted":
				observer = func(context.Context, MigrationFreezeSource) (string, error) { return "", ErrMigrationSession }
			case "missing-evidence":
				in.LegacyEvidence = MigrationLegacyProjectionEvidence{}
			case "source-changed":
				m, _, e := readMigrationFreezeManifest(in.FreezeManifest, id)
				if e != nil {
					t.Fatal(e)
				}
				db, e := persist.OpenDB(m.Sources[0].SQLite)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = db.Exec(`UPDATE websites SET name='changed-after-freeze'`); e != nil {
					db.Close()
					t.Fatal(e)
				}
				db.Close()
			case "version":
				version--
			}
			if err := s.migrationCutover(ctx, id, version, in, "activate", observer); err == nil {
				t.Fatal("unsafe activation accepted")
			}
			state, err := s.MigrationSession(ctx, id)
			if err != nil || !state.Protected || state.Phase == "active" {
				t.Fatal(state, err)
			}
		})
	}
}

func TestMigrationReconcileUsesActualFinalAndReverseEvidence(t *testing.T) {
	s, id, in, observer, version := migrationCutoverFixture(t)
	out, err := s.reconcileMigrationSessionWithEvidence(context.Background(), id, version, in, observer)
	if err != nil || !out.ReadyForCutover || !out.Protected || len(out.Conflicts) != 0 {
		t.Fatal(out, err)
	}
	if err = s.migrationCutover(context.Background(), id, out.SessionVersion, in, "activate", observer); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateMigrationSession(context.Background(), id, out.SessionVersion); !errors.Is(err, ErrMigrationCutoverProtected) {
		t.Fatal(err)
	}
	encoded := string(common.JSON(in.LegacyEvidence))
	if len(encoded) == 0 {
		t.Fatal("empty evidence")
	}
}
