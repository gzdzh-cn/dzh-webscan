package controlplane

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"webscan/internal/common"
)

// Authenticated actual-VM rollback artifacts are separate from the v2 sample
// projection: v2 cannot represent every label or millisecond timestamp.
const migrationReverseMetricsSchema = `
CREATE TABLE v3_migration_reverse_metric_receipts(
 session text PRIMARY KEY REFERENCES v3_migration_sessions(id),
 session_version bigint NOT NULL,seal_digest text NOT NULL,target_digest text NOT NULL,
 manifest_digest text NOT NULL,manifest jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
`

type MigrationReverseMetricsReport struct {
	Session        string `json:"session"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Nodes          int    `json:"nodes"`
	Fragments      int    `json:"series_fragments"`
	Points         int64  `json:"points"`
	Complete       bool   `json:"complete"`
	LegacyUI       string `json:"legacy_ui"`
}

type migrationReverseMetricsManifest struct {
	Format          int                            `json:"format"`
	Session         string                         `json:"session"`
	Version         int64                          `json:"session_version"`
	Seal            string                         `json:"journal_sha256"`
	Target          string                         `json:"target_sha256"`
	Plan            string                         `json:"original_binding_sha256"`
	Source          string                         `json:"postgres_binding_sha256"`
	Original        singleBackupSpec               `json:"original"`
	Began           time.Time                      `json:"began_at"`
	Sealed          time.Time                      `json:"sealed_at"`
	End             int64                          `json:"end_unix_millis"`
	Nodes           []string                       `json:"nodes"`
	Layers          []migrationReverseMetricsLayer `json:"layers"`
	IsolationBefore string                         `json:"isolation_before_sha256"`
	IsolationAfter  string                         `json:"isolation_after_sha256"`
	KeyID           string                         `json:"key_id"`
	MAC             string                         `json:"hmac_sha256"`
}
type migrationReverseMetricsLayer struct {
	Name   string                         `json:"name"`
	Nodes  []string                       `json:"nodes"`
	Chunks []migrationReverseMetricsChunk `json:"chunks"`
}
type migrationReverseMetricsChunk struct {
	Node      string `json:"node"`
	Start     int64  `json:"start_unix_millis"`
	End       int64  `json:"end_unix_millis"`
	File      string `json:"file"`
	SHA256    string `json:"sha256"`
	Bytes     int    `json:"bytes"`
	Fragments int    `json:"series_fragments"`
	Points    int64  `json:"points"`
}
type migrationReverseMetricsRuntime struct {
	plan func(context.Context, singleBackupSpec, string) (singleBackupPlan, error)
	host migrationRecoveryHostRuntime
}

func newMigrationReverseMetricsRuntime() migrationReverseMetricsRuntime {
	return migrationReverseMetricsRuntime{plan: planSingleBackup, host: newMigrationRecoveryHostRuntime()}
}
func migrationReverseMetricsMAC(v *Vault, m migrationReverseMetricsManifest) string {
	m.MAC = ""
	return migrationNodesMAC(v, m.KeyID, common.JSON([]any{"webscan-v3/actual-reverse-metrics/v1", m}))
}
func migrationReverseMetricsReport(m migrationReverseMetricsManifest, hash string) MigrationReverseMetricsReport {
	r := MigrationReverseMetricsReport{Session: m.Session, ManifestSHA256: hash, Nodes: len(m.Nodes), Complete: true, LegacyUI: "完整原始时序保存在受认证归档中；旧版页面仅显示已投影到 v2 样本的数据。"}
	for _, l := range m.Layers {
		for _, p := range l.Chunks {
			r.Fragments += p.Fragments
			r.Points += p.Points
		}
	}
	return r
}
func (s *Store) ArchiveMigrationReverseMetrics(ctx context.Context, c Config, session string, expected int64, sink *MigrationLegacySink, v *Vault, original singleBackupSpec) (MigrationReverseMetricsReport, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return MigrationReverseMetricsReport{}, ErrMigrationSession
	}
	return s.archiveMigrationReverseMetrics(ctx, c, session, expected, sink, v, original, newMigrationReverseMetricsRuntime())
}

func VerifyMigrationReverseMetricsTx(ctx context.Context, tx *sql.Tx, c Config, session string, sink *MigrationLegacySink, v *Vault) (string, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return "", ErrMigrationSession
	}
	return verifyMigrationReverseMetricsTx(ctx, tx, c, session, sink, v, newMigrationReverseMetricsRuntime())
}

func migrationReverseMetricsStateTx(ctx context.Context, tx *sql.Tx, session string, sink *MigrationLegacySink) (migrationReverseMetricsManifest, error) {
	m := migrationReverseMetricsManifest{Format: 1, Session: session, Nodes: []string{}}
	if sink == nil || sink.session != session {
		return m, ErrMigrationSession
	}
	state, e := migrationSessionTx(ctx, tx, session)
	if e != nil || state.RecoveryHold {
		return m, ErrMigrationSession
	}
	m.Version = state.Version
	var began, sealed sql.NullTime
	e = tx.QueryRowContext(ctx, `SELECT seal_digest,began_at,sealed_at FROM v3_migration_target_journals WHERE session=$1 AND state='sealed'`, session).Scan(&m.Seal, &began, &sealed)
	if e != nil || !began.Valid || !sealed.Valid || began.Time.IsZero() || sealed.Time.Before(began.Time) || sealed.Time.After(time.Now().Add(time.Minute)) || !releaseDigest(m.Seal) || verifyMigrationTargetJournal(ctx, tx, session) != nil {
		return m, ErrMigrationSession
	}
	m.Began, m.Sealed = began.Time.UTC(), sealed.Time.UTC()
	m.End = m.Sealed.Add(5 * time.Minute).UnixMilli()
	rows, e := tx.QueryContext(ctx, `SELECT node FROM (
 SELECT id AS node FROM v3_nodes
 UNION SELECT row_data->>'id' FROM v3_migration_target_baselines WHERE session=$1 AND table_name='v3_nodes'
 UNION SELECT before_data->>'id' FROM v3_migration_target_changes WHERE session=$1 AND table_name='v3_nodes'
 UNION SELECT after_data->>'id' FROM v3_migration_target_changes WHERE session=$1 AND table_name='v3_nodes'
 UNION SELECT r.node FROM v3_migration_node_rows r JOIN v3_migration_node_sources s ON r.source=s.id WHERE s.session=$1
 UNION SELECT r.node FROM v3_migration_metric_rows r JOIN v3_migration_metric_runs s ON r.run=s.id WHERE s.session=$1
 ) n WHERE node IS NOT NULL ORDER BY node COLLATE "C" LIMIT 20001`, session)
	if e != nil {
		return m, ErrMigrationSession
	}
	defer rows.Close()
	for rows.Next() {
		var node string
		if rows.Scan(&node) != nil || !identifier.MatchString(node) {
			return m, ErrMigrationSession
		}
		m.Nodes = append(m.Nodes, node)
	}
	if rows.Err() != nil || len(m.Nodes) > 20000 {
		return m, ErrMigrationSession
	}
	return m, nil
}
func migrationReverseMetricsPlan(ctx context.Context, tx *sql.Tx, c Config, sink *MigrationLegacySink, original singleBackupSpec, r migrationReverseMetricsRuntime) (singleBackupPlan, string, string, error) {
	var p singleBackupPlan
	if r.plan == nil || r.host.localSource == nil {
		return p, "", "", ErrMigrationSession
	}
	p, e := r.plan(ctx, original, filepath.Join(sink.output, "metrics-proof-not-output"))
	if e != nil || c.Central.Topology != "single" || c.Central.Instance != p.config.Central.Instance || c.Database.DSNFile != p.config.Database.DSNFile {
		return p, "", "", ErrMigrationSession
	}
	target, e := migrationRecoveryMetricsTarget(migrationRecoveryHostMetrics(c))
	actual, err := migrationRecoveryMetricsTarget(migrationRecoveryHostMetrics(p.config))
	if e != nil || err != nil || actual != target {
		return p, "", "", ErrMigrationSession
	}
	source, e := r.host.localSource(ctx, p, tx)
	if e != nil || !releaseDigest(source) {
		return p, "", "", ErrMigrationSession
	}
	return p, target, source, nil
}
func migrationReverseMetricsBinding(p singleBackupPlan) string {
	return digest(common.JSON([]any{p.installation, p.bindings, p.request}))
}
func (s *Store) archiveMigrationReverseMetrics(ctx context.Context, c Config, session string, expected int64, sink *MigrationLegacySink, v *Vault, original singleBackupSpec, r migrationReverseMetricsRuntime) (out MigrationReverseMetricsReport, err error) {
	defer func() {
		if err != nil {
			err = safeMigrationSessionError(err)
		}
	}()
	if sink == nil || v == nil {
		return out, ErrMigrationSession
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if migrationSessionLock(ctx, tx, session) != nil {
		return out, ErrMigrationSession
	}
	want, e := migrationReverseMetricsStateTx(ctx, tx, session, sink)
	if e != nil {
		return out, e
	}
	if want.Version != expected {
		return out, ErrConflict
	}
	p, target, source, e := migrationReverseMetricsPlan(ctx, tx, c, sink, original, r)
	if e != nil {
		return out, e
	}
	want.Original, want.Target, want.Source, want.Plan, want.KeyID = original, target, source, migrationReverseMetricsBinding(p), v.active
	before, e := r.host.isolation(ctx, p)
	if e != nil {
		return out, ErrMigrationSession
	}
	want.IsolationBefore = before
	directory, e := migrationReverseMetricsDirectory(sink, true)
	if e != nil {
		return out, e
	}
	defer directory.Close()
	old, exists, e := migrationReverseMetricsReadManifest(sink)
	if e != nil {
		return out, e
	}
	if exists {
		if migrationReverseMetricsSameState(want, old) != nil || migrationReverseMetricsVerifyManifest(ctx, sink, v, old) != nil || migrationReverseMetricsVerifyActual(ctx, c, old) != nil {
			return out, ErrMigrationSession
		}
		want = old
	} else {
		want.Layers, e = migrationReverseMetricsCapture(ctx, c, sink, want.Nodes, want.End)
		if e != nil {
			return out, e
		}
		if migrationReverseMetricsVerifyActual(ctx, c, want) != nil {
			return out, ErrMigrationSession
		}
		after, e := r.host.isolation(ctx, p)
		if e != nil {
			return out, ErrMigrationSession
		}
		want.IsolationAfter = after
		want.MAC = migrationReverseMetricsMAC(v, want)
		if want.MAC == "" {
			return out, ErrCredentialUnavailable
		}
		if e = migrationReverseMetricsWriteFile(sink, "manifest.json", common.JSON(want)); e != nil {
			return out, e
		}
	}
	if _, e = r.host.isolation(ctx, p); e != nil {
		return out, ErrMigrationSession
	}
	after, afterTarget, afterSource, e := migrationReverseMetricsPlan(ctx, tx, c, sink, original, r)
	if e != nil || migrationReverseMetricsBinding(after) != want.Plan || afterTarget != want.Target || afterSource != want.Source {
		return out, ErrMigrationSession
	}
	if _, e = r.host.isolation(ctx, after); e != nil {
		return out, ErrMigrationSession
	}
	raw := common.JSON(want)
	hash := digest(raw)
	var existing string
	e = tx.QueryRowContext(ctx, `SELECT manifest_digest FROM v3_migration_reverse_metric_receipts WHERE session=$1`, session).Scan(&existing)
	if e == nil && existing != hash || e != nil && e != sql.ErrNoRows {
		return out, ErrMigrationSession
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO v3_migration_reverse_metric_receipts(session,session_version,seal_digest,target_digest,manifest_digest,manifest) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(session) DO NOTHING`, session, want.Version, want.Seal, want.Target, hash, raw); e != nil {
		return out, e
	}
	if e = tx.Commit(); e != nil {
		return out, e
	}
	return migrationReverseMetricsReport(want, hash), nil
}
