package controlplane

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"
)

var ErrMigrationShadow = errors.New("影子采集目标、迁移保护或配置版本不匹配；未读取事件、确认事件或修改运行采集状态")

// The shared schema owner assigns the migration version. No shadow row is an
// active metric cursor, event receipt, readiness record or cutover permission.
const migrationShadowSchema = `
CREATE TABLE v3_migration_shadow_runs(id text PRIMARY KEY,session text NOT NULL REFERENCES v3_migration_sessions(id),session_version bigint NOT NULL CHECK(session_version>0),targets jsonb NOT NULL,targets_sha256 text NOT NULL,state text NOT NULL DEFAULT 'bound' CHECK(state IN ('bound','running','complete','partial')),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE v3_migration_shadow_evidence(run text NOT NULL REFERENCES v3_migration_shadow_runs(id),node text NOT NULL,status text NOT NULL CHECK(status IN ('observed','failed')),reason text NOT NULL DEFAULT '',evidence jsonb NOT NULL,observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(run,node));
`

type migrationShadowTarget struct {
	Node       string `json:"node"`
	Version    int64  `json:"version"`
	ConfigSHA  string `json:"config_sha256"`
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"server_name"`
	Mode       string `json:"mode"`
}

type MigrationShadowEvidence struct {
	Node               string    `json:"node"`
	SavedVersion       int64     `json:"saved_version"`
	SavedConfigSHA256  string    `json:"saved_config_sha256"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	Samples            int       `json:"samples"`
	FirstSample        int64     `json:"first_sample_unix_ms,omitempty"`
	LastSample         int64     `json:"last_sample_unix_ms,omitempty"`
	SampleSHA256       string    `json:"sample_sha256,omitempty"`
	PeerCertificate    string    `json:"peer_certificate_sha256,omitempty"`
	Protocol           uint32    `json:"protocol,omitempty"`
	AgentConfigVersion int64     `json:"agent_config_version,omitempty"`
	AgentConfigSHA256  string    `json:"agent_config_sha256,omitempty"`
	MatchesSaved       bool      `json:"configuration_matches_saved"`
	ObservedAt         time.Time `json:"observed_at"`
}

type MigrationShadowReport struct {
	ID              string                    `json:"id"`
	Session         string                    `json:"session"`
	SessionVersion  int64                     `json:"session_version"`
	State           string                    `json:"state"`
	TargetsSHA256   string                    `json:"targets_sha256"`
	Targets         int                       `json:"targets"`
	Observed        int                       `json:"observed"`
	Failed          int                       `json:"failed"`
	ReadOnly        bool                      `json:"read_only"`
	ReadyForCutover bool                      `json:"ready_for_cutover"`
	Evidence        []MigrationShadowEvidence `json:"evidence"`
}

func migrationShadowSessionTx(ctx context.Context, tx *sql.Tx, session string, expected int64) error {
	if !validArchiveSource(session) || expected < 1 {
		return ErrMigrationShadow
	}
	if err := migrationSessionLock(ctx, tx, session); err != nil {
		return err
	}
	state, err := migrationSessionTx(ctx, tx, session)
	if err != nil || state.Version != expected || state.RecoveryHold || state.Phase != "collecting" && state.Phase != "indexed" {
		return ErrMigrationShadow
	}
	// Merely creating a migration session is not a business-write fence.
	// Require the same durable domain protection used by ingestion/notifiers.
	held, err := migrationHeld(ctx, tx)
	if err != nil || !held {
		return ErrMigrationShadow
	}
	return nil
}

func migrationShadowTargetTx(ctx context.Context, tx *sql.Tx, id string) (migrationShadowTarget, error) {
	var target migrationShadowTarget
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR SHARE`, id))
	if err != nil || n.Validate() != nil || n.Enabled || n.Version < 1 {
		return target, ErrMigrationShadow
	}
	var running bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_active_nodes WHERE id=$1 AND enabled)`, id).Scan(&running); err != nil || running {
		return target, ErrMigrationShadow
	}
	return migrationShadowTarget{Node: n.ID, Version: n.Version, ConfigSHA: digest(n.Config), Endpoint: n.Endpoint, ServerName: n.ServerName, Mode: n.Mode}, nil
}

func (s *Store) BindMigrationShadow(ctx context.Context, session string, expected int64, nodes []string) (MigrationShadowReport, error) {
	if len(nodes) < 1 || len(nodes) > 100 {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	nodes = append([]string{}, nodes...)
	sort.Strings(nodes)
	for i, node := range nodes {
		if !identifier.MatchString(node) || i > 0 && nodes[i-1] == node {
			return MigrationShadowReport{}, ErrMigrationShadow
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	defer tx.Rollback()
	if err := migrationShadowSessionTx(ctx, tx, session, expected); err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	targets := make([]migrationShadowTarget, 0, len(nodes))
	for _, node := range nodes {
		target, err := migrationShadowTargetTx(ctx, tx, node)
		if err != nil {
			return MigrationShadowReport{}, ErrMigrationShadow
		}
		targets = append(targets, target)
	}
	raw, _ := json.Marshal(targets)
	id := token()
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_migration_shadow_runs(id,session,session_version,targets,targets_sha256) VALUES($1,$2,$3,$4,$5)`, id, session, expected, raw, digest(raw)); err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	if err := tx.Commit(); err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	return s.MigrationShadow(ctx, session, expected, id)
}

func migrationShadowRunTx(ctx context.Context, tx *sql.Tx, session string, expected int64, id string) (MigrationShadowReport, []migrationShadowTarget, time.Time, error) {
	out := MigrationShadowReport{ID: id, Session: session, SessionVersion: expected, ReadOnly: true, ReadyForCutover: false, Evidence: []MigrationShadowEvidence{}}
	var raw []byte
	var created time.Time
	if !validArchiveSource(id) {
		return out, nil, created, ErrMigrationShadow
	}
	err := tx.QueryRowContext(ctx, `SELECT targets,targets_sha256,state,created_at FROM v3_migration_shadow_runs WHERE id=$1 AND session=$2 AND session_version=$3 FOR UPDATE`, id, session, expected).Scan(&raw, &out.TargetsSHA256, &out.State, &created)
	var targets []migrationShadowTarget
	if err != nil || json.Unmarshal(raw, &targets) != nil || len(targets) < 1 || len(targets) > 100 {
		return out, nil, created, ErrMigrationShadow
	}
	canonical, _ := json.Marshal(targets)
	if digest(canonical) != out.TargetsSHA256 {
		return out, nil, created, ErrMigrationShadow
	}
	for index, target := range targets {
		if !identifier.MatchString(target.Node) || target.Version < 1 || !releaseDigest(target.ConfigSHA) || index > 0 && targets[index-1].Node >= target.Node {
			return out, nil, created, ErrMigrationShadow
		}
	}
	out.Targets = len(targets)
	return out, targets, created, nil
}

func migrationShadowEvidenceTx(ctx context.Context, tx *sql.Tx, out *MigrationShadowReport) error {
	rows, err := tx.QueryContext(ctx, `SELECT evidence FROM v3_migration_shadow_evidence WHERE run=$1 ORDER BY node`, out.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var evidence MigrationShadowEvidence
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		if json.Unmarshal(raw, &evidence) != nil {
			return ErrMigrationShadow
		}
		if evidence.Status == "observed" {
			out.Observed++
		} else if evidence.Status == "failed" {
			out.Failed++
		} else {
			return ErrMigrationShadow
		}
		out.Evidence = append(out.Evidence, evidence)
	}
	return rows.Err()
}

// Reading an existing report does not authorize another RPC or clear fences.
func (s *Store) MigrationShadow(ctx context.Context, session string, expected int64, id string) (MigrationShadowReport, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	defer tx.Rollback()
	out, _, _, err := migrationShadowRunTx(ctx, tx, session, expected, id)
	if err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	if err := migrationShadowEvidenceTx(ctx, tx, &out); err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	return out, tx.Commit()
}

// Run only uses the immutable database target binding. Config supplies local
// collector trust/identity files, never a request-controlled network address.
func (s *Store) RunMigrationShadow(ctx context.Context, c Config, session string, expected int64, id string) (MigrationShadowReport, error) {
	if !validArchiveSource(id) {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	defer conn.Close()
	var locked bool
	resource := "migration-shadow:" + id
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, resource).Scan(&locked); err != nil || !locked {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	defer func() {
		op, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		if _, err := conn.ExecContext(op, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, resource); err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	var targets []migrationShadowTarget
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	if err := migrationShadowSessionTx(ctx, tx, session, expected); err != nil {
		tx.Rollback()
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	out, targets, created, err := migrationShadowRunTx(ctx, tx, session, expected, id)
	if err != nil || time.Since(created) > 10*time.Minute || time.Until(created) > 5*time.Second {
		tx.Rollback()
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	// Validate the whole frozen target set before the first network request.
	for _, target := range targets {
		current, err := migrationShadowTargetTx(ctx, tx, target.Node)
		if err != nil || current != target {
			tx.Rollback()
			return MigrationShadowReport{}, ErrMigrationShadow
		}
	}
	if out.State == "complete" {
		tx.Rollback()
		return s.MigrationShadow(ctx, session, expected, id)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_migration_shadow_runs SET state='running',updated_at=clock_timestamp() WHERE id=$1`, id); err != nil {
		tx.Rollback()
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	if err := tx.Commit(); err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	// Every path after entering running must durably leave it, including trust
	// errors, cancellation and configuration changes between target reads.
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		_ = s.finishMigrationShadow(cleanup, id)
	}()
	tlsConfig, err := migrationShadowTLS(c)
	if err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			break
		}
		if err := migrationShadowSessionTx(ctx, tx, session, expected); err != nil {
			tx.Rollback()
			return MigrationShadowReport{}, ErrMigrationShadow
		}
		current, err := migrationShadowTargetTx(ctx, tx, target.Node)
		if err != nil || !reflect.DeepEqual(current, target) {
			tx.Rollback()
			return MigrationShadowReport{}, ErrMigrationShadow
		}
		var done bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_migration_shadow_evidence WHERE run=$1 AND node=$2 AND status='observed')`, id, target.Node).Scan(&done); err != nil {
			tx.Rollback()
			break
		}
		if done {
			tx.Rollback()
			continue
		}
		op, stop := context.WithTimeout(ctx, 10*time.Second)
		evidence := migrationShadowObserve(op, c, tlsConfig, target)
		stop()
		raw, _ := json.Marshal(evidence)
		_, err = tx.ExecContext(ctx, `INSERT INTO v3_migration_shadow_evidence(run,node,status,reason,evidence,observed_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(run,node) DO UPDATE SET status=excluded.status,reason=excluded.reason,evidence=excluded.evidence,observed_at=excluded.observed_at`, id, target.Node, evidence.Status, evidence.Reason, raw, evidence.ObservedAt)
		if err != nil {
			tx.Rollback()
			break
		}
		if err := tx.Commit(); err != nil {
			break
		}
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer stop()
	if err := s.finishMigrationShadow(cleanup, id); err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	report, err := s.MigrationShadow(cleanup, session, expected, id)
	if err != nil {
		return MigrationShadowReport{}, ErrMigrationShadow
	}
	return report, nil
}

func (s *Store) finishMigrationShadow(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE v3_migration_shadow_runs r SET state=CASE WHEN (SELECT count(*) FROM v3_migration_shadow_evidence e WHERE e.run=r.id AND e.status='observed')=jsonb_array_length(r.targets) THEN 'complete' ELSE 'partial' END,updated_at=clock_timestamp() WHERE id=$1`, id)
	return err
}
