package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"webscan/internal/common"
	"webscan/internal/persist"
)

// The reverse sink writes real legacy SQLite business tables in private copies.
// Unsupported semantics are explicit durable blockers, never an opaque mirror
// masquerading as a usable v2 rollback database.
type MigrationLegacySink struct {
	mu      sync.Mutex
	db      *sql.DB
	session string
	roles   map[string]bool
	output  string
}
type MigrationLegacySinkReport struct {
	Session          string                            `json:"session"`
	Batches          int64                             `json:"batches"`
	Rows             int64                             `json:"rows"`
	Pending          []MigrationReconciliationConflict `json:"pending"`
	Complete         bool                              `json:"complete"`
	ReadyForRollback bool                              `json:"ready_for_rollback"`
}
type migrationLegacySinkManifest struct {
	Session   string
	Snapshots map[string]string
}

// Preparation accepts only the session's currently verified role snapshots.
// No production source file is opened writable, and no pre-existing output
// directory or database may be adopted.
func (s *Store) PrepareMigrationLegacySink(ctx context.Context, session string, expected int64, sources map[string]string, output string, vaults ...*Vault) (sink *MigrationLegacySink, err error) {
	defer func() {
		if err != nil {
			err = safeMigrationSessionError(err)
		}
	}()
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = migrationSessionLock(ctx, tx, session); e != nil {
		return nil, e
	}
	state, e := migrationSessionTx(ctx, tx, session)
	if e != nil || state.RecoveryHold {
		return nil, ErrMigrationSession
	}
	if state.Version != expected {
		return nil, ErrConflict
	}
	if state.Phase != "indexed" && state.Phase != "frozen" && state.Phase != "reconciled" {
		return nil, ErrMigrationSession
	}
	revisions, e := migrationFinalRevisionsTx(ctx, tx, state)
	if e != nil || len(sources) != len(revisions) {
		return nil, ErrMigrationSession
	}
	manifest := migrationLegacySinkManifest{Session: session, Snapshots: map[string]string{}}
	baseline := map[string]string{}
	var sourceYAML []byte
	historyArtifacts := map[string]migrationLegacyHistoryArtifactImage{}
	defer func() { clear(sourceYAML) }()
	if len(vaults) > 1 {
		return nil, ErrMigrationSession
	}
	if len(vaults) == 1 && vaults[0] != nil {
		var yamlBaselines map[string]string
		sourceYAML, yamlBaselines, e = migrationLegacySourceYAMLTx(ctx, tx, session, vaults[0])
		if e != nil {
			return nil, e
		}
		for k, h := range yamlBaselines {
			baseline[k] = h
		}
		historyBaselines, e := migrationLegacyHistoryBaselinesTx(ctx, tx, session, vaults[0])
		if e != nil {
			return nil, e
		}
		for key, hash := range historyBaselines {
			baseline[key] = hash
		}
		historyArtifacts, e = migrationLegacyHistoryArtifactsTx(ctx, tx, session, vaults[0])
		if e != nil {
			return nil, e
		}
		var live string
		if e = tx.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&live); e != nil {
			return nil, e
		}
		metadata, e := migrationFinalMetadataTx(ctx, tx, live)
		if e != nil {
			return nil, e
		}
		owned, e := migrationFinalLoadOwnedTx(ctx, tx, vaults[0], session, metadata)
		if e != nil {
			return nil, e
		}
		var raw []byte
		revisionDigest := digest(common.JSON(revisions))
		if e = tx.QueryRowContext(ctx, `SELECT report FROM v3_migration_final_batches WHERE session=$1 AND revision_digest=$2 ORDER BY finished_version DESC LIMIT 1`, session, revisionDigest).Scan(&raw); e != nil {
			return nil, e
		}
		var report MigrationFinalMappingReport
		if singleDecode(raw, &report) != nil {
			return nil, ErrMigrationSession
		}
		if e = migrationFinalVerifyReceiptTx(ctx, tx, vaults[0], report, revisionDigest, owned); e != nil {
			return nil, e
		}
		for _, row := range owned {
			current, e := migrationFinalCurrentTx(ctx, tx, live, row)
			if e != nil || !reflect.DeepEqual(current, row.Data) {
				return nil, ErrConflict
			}
			baseline[migrationLegacySourceKey(row.Table, row.Key)] = digest(common.JSON(row.Data))
		}
	}
	opened := map[string]*migrationSnapshot{}
	defer func() {
		for _, v := range opened {
			v.close()
		}
	}()
	for _, r := range revisions {
		snapshot, e := openMigrationSnapshot(ctx, sources[r.Role])
		if e != nil {
			return nil, e
		}
		opened[r.Role] = snapshot
		if snapshot.sha != r.Source {
			return nil, ErrMigrationSession
		}
		manifest.Snapshots[r.Role] = r.Source
	}
	parent, e := privateDirectory(filepath.Dir(output))
	if e != nil {
		return nil, e
	}
	parent.Close()
	if e = os.Mkdir(output, 0700); e != nil {
		return nil, ErrMigrationSession
	}
	// On failure leave the private partial output for inspection; never remove an
	// administrator path while attempting to recover another error.
	for role, snapshot := range opened {
		if e = persist.BackupDB(snapshot.db, filepath.Join(output, migrationLegacyFilename(role))); e != nil {
			return nil, e
		}
		if !snapshot.unchanged() {
			return nil, ErrMigrationSession
		}
	}
	if e = os.WriteFile(filepath.Join(output, "manifest.json"), common.JSON(manifest), 0600); e != nil {
		return nil, e
	}
	sink, e = openMigrationLegacySink(ctx, output, manifest)
	if e != nil {
		return nil, e
	}
	for key, hash := range baseline {
		if _, e = sink.db.ExecContext(ctx, `INSERT INTO migration_source_baselines VALUES(?,?)`, key, hash); e != nil {
			sink.Close()
			return nil, e
		}
	}
	if len(sourceYAML) > 0 {
		if _, e = sink.db.ExecContext(ctx, `INSERT INTO migration_yaml VALUES(1,?,?)`, sourceYAML, digest(sourceYAML)); e != nil {
			sink.Close()
			return nil, e
		}
		if e = sink.migrationLegacyExportYAML(ctx); e != nil {
			sink.Close()
			return nil, e
		}
	}
	if e = sink.migrationLegacyStageArtifacts(ctx, historyArtifacts); e != nil {
		sink.Close()
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		sink.Close()
		return nil, e
	}
	return sink, nil
}
func migrationLegacyFilename(role string) string {
	switch role {
	case "central":
		return "events-v1.sqlite3"
	case "health":
		return "metrics-v1.sqlite3"
	case "host-manager":
		return "management.sqlite3"
	}
	return "invalid"
}
func migrationLegacyAlias(role string) string {
	if role == "host-manager" {
		return "manager"
	}
	return role
}

func OpenMigrationLegacySink(ctx context.Context, session, output string) (*MigrationLegacySink, error) {
	f, e := openTrustFile(filepath.Join(output, "manifest.json"), true, 65536)
	if e != nil {
		return nil, ErrMigrationSession
	}
	defer f.Close()
	var manifest migrationLegacySinkManifest
	if json.NewDecoder(f).Decode(&manifest) != nil || manifest.Session != session || !validArchiveSource(session) {
		return nil, ErrMigrationSession
	}
	sink, e := openMigrationLegacySink(ctx, output, manifest)
	if e != nil {
		return nil, ErrMigrationSession
	}
	return sink, nil
}
func openMigrationLegacySink(ctx context.Context, output string, manifest migrationLegacySinkManifest) (*MigrationLegacySink, error) {
	dir, e := privateDirectory(output)
	if e != nil {
		return nil, e
	}
	dir.Close()
	if len(manifest.Snapshots) == 0 || len(manifest.Snapshots) > 3 {
		return nil, ErrMigrationSession
	}
	path := filepath.Join(output, "reverse-checkpoint.sqlite3")
	checkpoint, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e == nil {
		e = checkpoint.Close()
	} else if os.IsExist(e) {
		var checked *os.File
		checked, e = openTrustFile(path, true, 1<<40)
		if e == nil {
			e = checked.Close()
		}
	}
	if e != nil {
		return nil, e
	}
	dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "_pragma=busy_timeout(30000)&_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)"}).String()
	db, e := sql.Open("sqlite", dsn)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(e error) (*MigrationLegacySink, error) { db.Close(); return nil, e }
	if e = db.PingContext(ctx); e != nil {
		return fail(e)
	}
	if e = os.Chmod(path, 0600); e != nil {
		return fail(e)
	}
	roles := map[string]bool{}
	for role, hash := range manifest.Snapshots {
		if migrationLegacyFilename(role) == "invalid" || !releaseDigest(hash) {
			return fail(ErrMigrationSession)
		}
		file, e := openTrustFile(filepath.Join(output, migrationLegacyFilename(role)), true, 1<<40)
		if e != nil {
			return fail(e)
		}
		file.Close()
		if _, e = db.ExecContext(ctx, `ATTACH DATABASE ? AS `+quotePG(migrationLegacyAlias(role)), filepath.Join(output, migrationLegacyFilename(role))); e != nil {
			return fail(e)
		}
		var mode string
		if e = db.QueryRowContext(ctx, `PRAGMA `+quotePG(migrationLegacyAlias(role))+`.journal_mode=DELETE`).Scan(&mode); e != nil || mode != "delete" {
			return fail(ErrMigrationSession)
		}
		roles[role] = true
	}
	if _, e = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS migration_node_activation_targets(node TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE IF NOT EXISTS migration_node_activation_images(identity TEXT PRIMARY KEY,table_name TEXT NOT NULL);CREATE TABLE IF NOT EXISTS migration_receipts(id TEXT PRIMARY KEY,digest TEXT NOT NULL,rows INTEGER NOT NULL,payload_digest TEXT NOT NULL,consumer TEXT NOT NULL,phase TEXT NOT NULL);CREATE TABLE IF NOT EXISTS migration_pending(table_name TEXT NOT NULL,identity TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(table_name,identity));CREATE TABLE IF NOT EXISTS migration_source_baselines(identity TEXT PRIMARY KEY,digest TEXT NOT NULL);CREATE TABLE IF NOT EXISTS migration_yaml(id INTEGER PRIMARY KEY CHECK(id=1),payload BLOB NOT NULL,digest TEXT NOT NULL);CREATE TABLE IF NOT EXISTS migration_notice_tasks(notification TEXT PRIMARY KEY,task INTEGER NOT NULL,channel TEXT NOT NULL,recipient TEXT NOT NULL);CREATE TABLE IF NOT EXISTS migration_event_keys(node TEXT NOT NULL,id TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(node,id));CREATE TABLE IF NOT EXISTS migration_configuration_artifacts(id TEXT PRIMARY KEY,name TEXT NOT NULL,payload BLOB NOT NULL,digest TEXT NOT NULL);`); e != nil {
		return fail(e)
	}
	return &MigrationLegacySink{db: db, session: manifest.Session, roles: roles, output: output}, nil
}
func (s *MigrationLegacySink) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
func (s *MigrationLegacySink) ApplyMigrationJournal(ctx context.Context, b MigrationTargetReplayBatch) (receipt MigrationTargetReplayReceipt, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil {
			err = safeMigrationSessionError(err)
		}
	}()
	if b.Session != s.session || !releaseDigest(b.ID) || !releaseDigest(b.SHA256) || len(b.Rows) > 250 {
		return receipt, ErrMigrationSession
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return receipt, e
	}
	defer tx.Rollback()
	var previous string
	var savedPayload string
	var count int64
	payload := migrationLegacyBatchDigest(b)
	e = tx.QueryRowContext(ctx, `SELECT digest,rows,payload_digest FROM migration_receipts WHERE id=?`, b.ID).Scan(&previous, &count, &savedPayload)
	if e == nil {
		if previous != b.SHA256 || count != int64(len(b.Rows)) || savedPayload != payload {
			return receipt, ErrConflict
		}
		return MigrationTargetReplayReceipt{b.ID, b.SHA256, count}, tx.Commit()
	}
	if e != sql.ErrNoRows {
		return receipt, e
	}
	for _, row := range b.Rows {
		if e = s.migrationLegacyApplyTx(ctx, tx, row); e != nil {
			return receipt, e
		}
	}
	count = int64(len(b.Rows))
	if _, e = tx.ExecContext(ctx, `INSERT INTO migration_receipts VALUES(?,?,?,?,?,?)`, b.ID, b.SHA256, count, payload, b.Consumer, b.Phase); e != nil {
		return receipt, e
	}
	if e = tx.Commit(); e != nil {
		return receipt, e
	}
	return MigrationTargetReplayReceipt{b.ID, b.SHA256, count}, nil
}
func (s *MigrationLegacySink) Report(ctx context.Context) (r MigrationLegacySinkReport, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r = MigrationLegacySinkReport{Session: s.session, Pending: []MigrationReconciliationConflict{}}
	if e := s.migrationLegacyExportYAML(ctx); e != nil {
		return r, ErrMigrationSession
	}
	if e := s.migrationLegacyExportArtifacts(ctx); e != nil {
		return r, ErrMigrationSession
	}
	if e := s.db.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(rows),0) FROM migration_receipts`).Scan(&r.Batches, &r.Rows); e != nil {
		return r, ErrMigrationSession
	}
	rows, e := s.db.QueryContext(ctx, `SELECT reason,count(*) FROM migration_pending GROUP BY reason ORDER BY reason`)
	if e != nil {
		return r, ErrMigrationSession
	}
	for rows.Next() {
		var issue MigrationReconciliationConflict
		if e = rows.Scan(&issue.Category, &issue.Count); e != nil {
			rows.Close()
			return r, ErrMigrationSession
		}
		r.Pending = append(r.Pending, issue)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return r, ErrMigrationSession
	}
	// Verify derived event keys against actual replayed receiver records.
	var keys int64
	if e = s.db.QueryRowContext(ctx, `SELECT count(*) FROM migration_event_keys`).Scan(&keys); e != nil {
		return r, ErrMigrationSession
	}
	if s.roles["central"] && keys > 0 {
		var missing int64
		if e = s.db.QueryRowContext(ctx, `SELECT count(*) FROM migration_event_keys k LEFT JOIN central.events e ON e.node=k.node AND e.id=k.id WHERE e.digest IS NULL OR e.digest<>k.digest`).Scan(&missing); e != nil {
			return r, ErrMigrationSession
		}
		if missing > 0 {
			r.Pending = append(r.Pending, MigrationReconciliationConflict{"reverse_event_key_missing", missing})
		}
	}
	r.Complete = len(r.Pending) == 0 && r.Batches > 0
	// This receipt alone does not prove PG's journal was sealed and fully read.
	// The orchestrator must match its durable replay upper bound separately.
	return r, nil
}

func migrationLegacyBatchDigest(b MigrationTargetReplayBatch) string {
	rows := []any{}
	for _, row := range b.Rows {
		rows = append(rows, []any{row.Table, row.Operation, row.Sequence, string(row.BeforeKey), string(row.AfterKey), string(row.Before), string(row.After), row.SHA256})
	}
	return digest(common.JSON([]any{b.Session, b.Consumer, b.ID, b.SHA256, b.Phase, rows}))
}
