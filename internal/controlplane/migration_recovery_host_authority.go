package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"webscan/internal/persist"
)

func migrationRecoveryHostDatabaseID(ctx context.Context, tx *sql.Tx) (string, error) {
	var database, schema, server, system string
	var port int
	if tx.QueryRowContext(ctx, `SELECT current_database(),current_schema(),COALESCE(inet_server_addr()::text,'local'),COALESCE(inet_server_port(),0),(SELECT system_identifier::text FROM pg_control_system())`).Scan(&database, &schema, &server, &port, &system) != nil || database == "" || schema == "" || system == "" {
		return "", ErrMigrationRecovery
	}
	raw, _ := json.Marshal([]any{system, server, port, database, schema})
	return digest(raw), nil
}

func migrationRecoveryHostFence(ctx context.Context, tx *sql.Tx, global bool) ([]string, error) {
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout='5s'`); err != nil {
		return nil, ErrMigrationRecovery
	}
	if global {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(773376002)`); err != nil {
			return nil, ErrMigrationRecovery
		}
	}
	if err := lockConfigurationOperationTx(ctx, tx, true); err != nil {
		return nil, ErrMigrationRecovery
	}
	tables, err := postgresTables(ctx, tx)
	if err != nil || len(tables) == 0 {
		return nil, ErrMigrationRecovery
	}
	quoted := []string{}
	for _, name := range tables {
		if name != "v3_bootstrap_processes" {
			quoted = append(quoted, quotePG(name))
		}
	}
	if _, err = tx.ExecContext(ctx, "LOCK TABLE "+strings.Join(quoted, ",")+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return nil, ErrMigrationRecovery
	}
	version, err := currentSchema(ctx, tx)
	if err != nil || version != SchemaVersion {
		return nil, ErrMigrationRecovery
	}
	return tables, nil
}

// No archived task authorization is reused. This first implementation requires
// lifecycle/configuration tasks to have independently reached a terminal state
// on both databases. Ongoing or unknown tasks retain the DR hold.
func migrationRecoveryHostTasksTerminal(ctx context.Context, tx *sql.Tx) error {
	var blocked bool
	query := `SELECT
EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE status NOT IN ('succeeded','rolled_back')) OR
EXISTS(SELECT 1 FROM v3_deployment_preparations WHERE status IN ('queued','running')) OR
EXISTS(SELECT 1 FROM v3_node_name_changes WHERE status NOT IN ('completed','canceled')) OR
EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE status NOT IN ('completed','canceled')) OR
EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE status NOT IN ('completed','canceled')) OR
EXISTS(SELECT 1 FROM v3_node_renewal_jobs WHERE activated_at IS NULL) OR
EXISTS(SELECT 1 FROM v3_root_rotations WHERE status NOT IN ('completed','canceled')) OR
EXISTS(SELECT 1 FROM v3_configuration_applications WHERE status NOT IN ('succeeded','rolled_back','cancelled')) OR
EXISTS(SELECT 1 FROM v3_monitoring_applications WHERE status IN ('queued','running','paused')) OR
EXISTS(SELECT 1 FROM v3_configuration_restore_stages WHERE status IN ('pending_validation','pending_application')) OR
EXISTS(SELECT 1 FROM v3_configuration_revisions WHERE status='pending_application')`
	if tx.QueryRowContext(ctx, query).Scan(&blocked) != nil || blocked {
		return ErrMigrationRecovery
	}
	return nil
}

func migrationRecoveryHostAuthorityTable(name string) bool {
	if strings.HasPrefix(name, "v3_node_") {
		return name != "v3_node_status" && name != "v3_node_readiness"
	}
	if strings.HasPrefix(name, "v3_root_") || strings.HasPrefix(name, "v3_pki_") {
		return true
	}
	switch name {
	case "v3_nodes", "v3_credentials", "v3_web_node_credentials", "v3_deployment_jobs", "v3_deployment_installations", "v3_deployment_recoveries", "v3_deployment_uninstalls", "v3_deployment_lifecycle_receipts", "v3_deployment_lifecycle_authorizations":
		return true
	}
	return false
}

func migrationRecoveryHostRows(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	if !identifier.MatchString(table) {
		return nil, ErrMigrationRecovery
	}
	// Only volatile retry/lease observations are omitted. Configuration,
	// credential, retirement, status and immutable task ancestry remain exact.
	query := `SELECT row_value FROM (SELECT (to_jsonb(t)-'updated_at'-'lease_owner'-'lease_epoch'-'lease_until'-'last_error'-'attempts'-'next_attempt_at')::text AS row_value FROM ` + quotePG(table) + ` t) v ORDER BY row_value COLLATE "C"`
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, ErrMigrationRecovery
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil || len(raw) > 32<<20 || len(out) >= 200000 {
			return nil, ErrMigrationRecovery
		}
		out = append(out, raw)
	}
	if rows.Err() != nil {
		return nil, ErrMigrationRecovery
	}
	return out, nil
}

func migrationRecoveryHostAuthorityTx(ctx context.Context, old, next *sql.Tx, oldTables, nextTables []string, source, target Config) (string, error) {
	// Re-enumerate after slow host/metrics checks. Existing table locks do not
	// cover a newly created authority table, so a changed inventory retains hold.
	currentOld, err := postgresTables(ctx, old)
	if err != nil || !reflect.DeepEqual(currentOld, oldTables) {
		return "", ErrMigrationRecovery
	}
	currentNext, err := postgresTables(ctx, next)
	if err != nil || !reflect.DeepEqual(currentNext, nextTables) {
		return "", ErrMigrationRecovery
	}
	if migrationRecoveryHostTasksTerminal(ctx, old) != nil || migrationRecoveryHostTasksTerminal(ctx, next) != nil || verifySingleBackupVaultTx(ctx, old, source.DeploymentTrust) != nil || verifySingleBackupVaultTx(ctx, next, target.DeploymentTrust) != nil {
		return "", ErrMigrationRecovery
	}
	oldSelected, nextSelected := []string{}, []string{}
	for _, name := range oldTables {
		if migrationRecoveryHostAuthorityTable(name) {
			oldSelected = append(oldSelected, name)
		}
	}
	for _, name := range nextTables {
		if migrationRecoveryHostAuthorityTable(name) {
			nextSelected = append(nextSelected, name)
		}
	}
	sort.Strings(oldSelected)
	sort.Strings(nextSelected)
	if !reflect.DeepEqual(oldSelected, nextSelected) {
		return "", ErrMigrationRecovery
	}
	proofs := []string{}
	for _, name := range oldSelected {
		a, err := migrationRecoveryHostRows(ctx, old, name)
		if err != nil {
			return "", err
		}
		b, err := migrationRecoveryHostRows(ctx, next, name)
		if err != nil || !reflect.DeepEqual(a, b) {
			return "", ErrMigrationRecovery
		}
		raw, _ := json.Marshal([]any{name, a})
		proofs = append(proofs, digest(raw))
	}
	files, err := migrationRecoveryHostLatestFiles(ctx, source, target)
	if err != nil {
		return "", err
	}
	proofs = append(proofs, files)
	raw, _ := json.Marshal(proofs)
	return digest(raw), nil
}

func migrationRecoveryHostLatestFiles(ctx context.Context, a, b Config) (string, error) {
	if !a.NodePKI.Enabled || !b.NodePKI.Enabled || a.NodePKI.AuthorityDirectory == "" || b.NodePKI.AuthorityDirectory == "" || len(a.DeploymentTrust.PreviousKeyFiles) != len(b.DeploymentTrust.PreviousKeyFiles) {
		return "", ErrMigrationRecovery
	}
	pairs := [][2]string{{a.DeploymentTrust.VaultKeyFile, b.DeploymentTrust.VaultKeyFile}, {a.Collector.CAFile, b.Collector.CAFile}, {a.Collector.IdentityFile, b.Collector.IdentityFile}, {a.Collector.CertFile, b.Collector.CertFile}, {a.Collector.KeyFile, b.Collector.KeyFile}, {a.Collector.RevocationFile, b.Collector.RevocationFile}}
	for i, path := range a.DeploymentTrust.PreviousKeyFiles {
		pairs = append(pairs, [2]string{path, b.DeploymentTrust.PreviousKeyFiles[i]})
	}
	proofs := []string{}
	for _, pair := range pairs {
		if pair[0] == "" && pair[1] == "" {
			continue
		}
		if pair[0] == "" || pair[1] == "" {
			return "", ErrMigrationRecovery
		}
		x, err := hashTrustArtifact(ctx, pair[0], 32<<20)
		if err != nil {
			return "", ErrMigrationRecovery
		}
		y, err := hashTrustArtifact(ctx, pair[1], 32<<20)
		if err != nil || x != y {
			return "", ErrMigrationRecovery
		}
		proofs = append(proofs, x.SHA256)
	}
	for _, directory := range []string{a.NodePKI.AuthorityDirectory, b.NodePKI.AuthorityDirectory} {
		d, err := trustDirectory(directory, true)
		if err != nil {
			return "", ErrMigrationRecovery
		}
		var tree metricsSnapshotManifest
		var total int64
		err = walkMetricsSnapshot(ctx, d, nil, "authority", true, &tree, &total)
		d.Close()
		if err != nil {
			return "", ErrMigrationRecovery
		}
		sort.Strings(tree.Directories)
		sort.Slice(tree.Files, func(i, j int) bool { return tree.Files[i].Path < tree.Files[j].Path })
		raw, _ := json.Marshal(tree)
		proofs = append(proofs, digest(raw))
	}
	if proofs[len(proofs)-1] != proofs[len(proofs)-2] {
		return "", ErrMigrationRecovery
	}
	if a.HostWatchdog.Enabled != b.HostWatchdog.Enabled {
		return "", ErrMigrationRecovery
	}
	if a.HostWatchdog.Enabled {
		x, err := migrationRecoveryHostWatchdog(ctx, filepath.Join(a.HostWatchdog.StateDirectory, "watchdog.sqlite3"), false)
		if err != nil {
			return "", err
		}
		y, err := migrationRecoveryHostWatchdog(ctx, filepath.Join(b.HostWatchdog.StateDirectory, "watchdog.sqlite3"), true)
		if err != nil || x != y {
			return "", ErrMigrationRecovery
		}
		proofs = append(proofs, x)
	}
	raw, _ := json.Marshal(proofs)
	return digest(raw), nil
}

func migrationRecoveryHostWatchdog(ctx context.Context, path string, requireFrozen bool) (string, error) {
	f, err := openTrustFile(path, true, 1<<30)
	if err != nil {
		return "", ErrMigrationRecovery
	}
	f.Close()
	db, err := persist.OpenReadOnly(path)
	if err != nil {
		return "", ErrMigrationRecovery
	}
	defer db.Close()
	var integrity string
	var frozen, ambiguous int
	if db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity) != nil || integrity != "ok" || db.QueryRowContext(ctx, `SELECT frozen FROM host_state WHERE id=1`).Scan(&frozen) != nil || requireFrozen && frozen != 1 || db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM outbox WHERE state IN ('unknown','sending'))+(SELECT count(*) FROM attempts WHERE state IN ('unknown','sending'))`).Scan(&ambiguous) != nil || ambiguous > 0 {
		return "", ErrMigrationRecovery
	}
	proofs := []string{}
	for _, table := range []string{"outbox", "attempts", "quota"} {
		rows, err := db.QueryContext(ctx, `SELECT * FROM `+table+` ORDER BY id`)
		if err != nil {
			return "", ErrMigrationRecovery
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			return "", ErrMigrationRecovery
		}
		count := 0
		for rows.Next() {
			count++
			if count > 200000 {
				rows.Close()
				return "", ErrMigrationRecovery
			}
			values := make([]any, len(cols))
			dest := make([]any, len(cols))
			for i := range values {
				dest[i] = &values[i]
			}
			if rows.Scan(dest...) != nil {
				rows.Close()
				return "", ErrMigrationRecovery
			}
			raw, _ := json.Marshal([]any{table, values})
			proofs = append(proofs, digest(raw))
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return "", ErrMigrationRecovery
		}
	}
	raw, _ := json.Marshal(proofs)
	return digest(raw), nil
}
