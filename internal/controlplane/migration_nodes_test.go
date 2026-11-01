package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
)

func migrationNodesYAMLFixture(t *testing.T) common.Map {
	t.Helper()
	m := legacySettingsFixture(t)
	first := common.M(common.A(m["nodes"])[0])
	first["ssh"] = common.Map{"port": 2222, "auth_method": "password", "password": "synthetic-migration-node-password", "host_key_sha256": credentialFixture().Fingerprint}
	first["monitor"] = common.Map{"roots": []string{"/srv/owned-site"}, "extensions": []string{".php", ".phtml"}, "exclude_paths": []string{"/srv/owned-site/**/cache/**"}, "reconciliation": common.Map{"interval_hours": 19, "start_jitter_minutes": 17, "max_read_mib_per_second": 11, "nice": 12, "ionice_class": 2}}
	common.M(m["node_defaults"])["deployment"] = common.Map{"mode": "native"}
	return m
}
func migrationNodesStoreFixture(t *testing.T) (*Store, string, string, *Vault, int64) {
	t.Helper()
	s, id, source, _, snapshot := migrationSessionFixture(t)
	if _, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS migration_nodes_test_marker(id integer)`); e != nil {
		t.Fatal(e)
	}
	var exists bool
	if e := s.DB.QueryRow(`SELECT to_regclass('v3_migration_node_sources') IS NOT NULL`).Scan(&exists); e != nil {
		t.Fatal(e)
	}
	if !exists {
		if _, e := s.DB.Exec(migrationNodesSchema); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.DB.Exec(`INSERT INTO v3_cluster VALUES(1,'{"topology":"single","shards":17}')`); e != nil {
		t.Fatal(e)
	}
	r, e := s.BindMigrationRevision(context.Background(), id, 1, MigrationRevisionInput{"central", source, snapshot()})
	if e != nil {
		t.Fatal(e)
	}
	v, _ := testVault(t)
	return s, id, source, v, r.SessionVersion
}

func TestMigrationNodesParsesLegacyRulesModesAndCredentialBoundaries(t *testing.T) {
	m := migrationNodesYAMLFixture(t)
	raw, _ := yaml.Marshal(m)
	nodes, e := parseMigrationLegacyNodes(raw)
	if e != nil || len(nodes) != 2 {
		t.Fatal("legacy fixture rejected", e)
	}
	var imported migrationLegacyNode
	for _, n := range nodes {
		if n.Node.ID == "node-202" {
			imported = n
		}
		if n.Node.Enabled || n.Node.AppliedVersion != 0 || n.Node.ServerName != n.Node.ID {
			t.Fatal("invented active TLS identity")
		}
	}
	s, e := nodeRuntimeSettings(imported.Node.Config)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(s.Monitor.Roots, []string{"/srv/owned-site"}) || s.Monitor.Reconciliation.IntervalHours != 19 || s.Monitor.Reconciliation.StartJitterMinutes != 17 || s.Monitor.Reconciliation.MaxReadMiBPerSecond != 11 || s.ProbeDirectory != "/srv/owned-site/.webscan-probe" || imported.Node.Mode != "native" || !imported.OriginalEnabled {
		t.Fatal("saved rules or native mode changed")
	}
	if imported.Credential == nil || imported.Credential.Port != 2222 || imported.CredentialState != "stored" {
		t.Fatal("fixed credential not recognized")
	}
	for _, n := range nodes {
		if strings.Contains(string(n.Node.Config), "password") || strings.Contains(string(n.Node.Config), "private_key") || strings.Contains(string(n.Node.Config), "public_url") {
			t.Fatal("legacy push/SSH secret entered node configuration")
		}
	}
	delete(common.M(m["node_defaults"]), "deployment")
	raw, _ = yaml.Marshal(m)
	nodes, e = parseMigrationLegacyNodes(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range nodes {
		if n.Node.Mode != "native" {
			t.Fatal("current Docker default reinterpreted v2 YAML")
		}
	}
	first := common.M(common.A(m["nodes"])[0])
	first["deployment"] = common.Map{"mode": "docker"}
	delete(common.M(first["ssh"]), "host_key_sha256")
	raw, _ = yaml.Marshal(m)
	nodes, e = parseMigrationLegacyNodes(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range nodes {
		if n.Node.ID == "node-202" && (n.Credential != nil || n.Node.Mode != "docker" || n.CredentialState != "fingerprint_confirmation_required") {
			t.Fatal("missing fingerprint silently authorized")
		}
	}
	// References are retained inside the encrypted YAML, never opened. A
	// deliberately missing host path remains a pending key import.
	first["ssh"] = common.Map{"port": 2222, "auth_method": "key", "private_key_path": "/does/not/exist/private-synthetic-key"}
	raw, _ = yaml.Marshal(m)
	nodes, e = parseMigrationLegacyNodes(raw)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range nodes {
		if n.Node.ID == "node-202" && (n.Credential != nil || n.CredentialState != "private_key_import_required") {
			t.Fatal("host key path became a usable credential")
		}
	}
}

func TestMigrationNodesPostgresResumeDeltaAndPrivateRecoveryEvidence(t *testing.T) {
	s, id, source, v, version := migrationNodesStoreFixture(t)
	ctx := context.Background()
	m := migrationNodesYAMLFixture(t)
	path := writeLegacySettings(t, m)
	r, e := s.MapLegacyNodes(ctx, id, version, path, source, v)
	if e != nil || !r.Complete || !r.Protected || r.ReadyForCutover || r.Nodes != 2 || r.Credentials != 1 || r.PendingCredentials != 1 || r.SessionVersion != version+1 {
		t.Fatal(r, e)
	}
	again, e := s.MapLegacyNodes(ctx, id, version, path, source, v)
	if e != nil || again.Source != r.Source || tableCount(t, s, "v3_credentials") != 1 {
		t.Fatal("lost-response retry duplicated nodes/credentials", again, e)
	}
	var count int
	if e = s.DB.QueryRow(`SELECT count(*) FROM v3_nodes WHERE enabled OR applied_version<>0`).Scan(&count); e != nil || count != 0 {
		t.Fatal("import activated nodes", e)
	}
	if e = s.DB.QueryRow(`SELECT count(*) FROM v3_active_nodes`).Scan(&count); e != nil || count != 0 {
		t.Fatal("import published pull identities", e)
	}
	var shard int
	if e = s.DB.QueryRow(`SELECT shard FROM v3_nodes WHERE id='node-202'`).Scan(&shard); e != nil || shard != Shard("node-202", 17) {
		t.Fatal("cluster shard identity lost", e)
	}
	var credentialID string
	if e = s.DB.QueryRow(`SELECT credential FROM v3_web_node_credentials WHERE node='node-202'`).Scan(&credentialID); e != nil {
		t.Fatal(e)
	}
	c, e := s.ReadCredential(ctx, v, credentialID, "node-202")
	if e != nil || c.Password != "synthetic-migration-node-password" || c.Port != 2222 {
		t.Fatal("Vault credential roundtrip failed", e)
	}
	wrong, _ := testVault(t)
	if _, e = s.MapLegacyNodes(ctx, id, r.SessionVersion, path, source, wrong); e == nil {
		t.Fatal("wrong Vault accepted fixed source")
	}
	var privateDump string
	if e = s.DB.QueryRow(`SELECT to_jsonb(s)::text FROM v3_migration_node_sources s WHERE id=$1`, r.Source).Scan(&privateDump); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"synthetic-migration-node-password", "private-settings", "/root/.ssh", "/srv/owned-site"} {
		if strings.Contains(privateDump, secret) {
			t.Fatal("private YAML exposed in migration row")
		}
	}
	if strings.Contains(string(common.JSON(r)), "node-202") || strings.Contains(string(common.JSON(r)), "198.51") {
		t.Fatal("public report exposed target")
	}
	first := common.M(common.A(m["nodes"])[0])
	first["name"] = "revised synthetic node"
	common.M(first["ssh"])["password"] = "replacement-synthetic-password"
	secondPath := writeLegacySettings(t, m)
	second, e := s.MapLegacyNodes(ctx, id, r.SessionVersion, secondPath, source, v)
	if e != nil || !second.Complete || second.Source == r.Source || tableCount(t, s, "v3_credentials") != 2 {
		t.Fatal("final YAML delta failed", second, e)
	}
	if _, e = s.MapLegacyNodes(ctx, id, second.SessionVersion, path, source, v); !errors.Is(e, ErrConflict) {
		t.Fatal("earlier YAML silently rolled target back", e)
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	changes, e := migrationNodeChangesTx(ctx, tx, v, second.Source)
	tx.Rollback()
	if e != nil {
		t.Fatal(e)
	}
	change := changes["node-202"]
	if change.Before == nil || change.Before.Version != 1 || change.After.Version != 2 || change.Before.CredentialID != credentialID || change.After.CredentialID == credentialID || !change.OriginalEnabled {
		t.Fatal("before/after recovery evidence incomplete")
	}
	nodes := common.A(m["nodes"])
	m["nodes"] = nodes[:1]
	common.M(m["deployment"])["node_order"] = []string{"node-202"}
	third, e := s.MapLegacyNodes(ctx, id, second.SessionVersion, writeLegacySettings(t, m), source, v)
	if e != nil || third.Retirements != 1 || tableCount(t, s, "v3_nodes") != 2 {
		t.Fatal("source deletion destroyed history", third, e)
	}
	if _, e = s.DB.Exec(`UPDATE v3_nodes SET name='independent-admin-change',version=version+1 WHERE id='node-202'`); e != nil {
		t.Fatal(e)
	}
	first["name"] = "newest source change"
	conflict, e := s.MapLegacyNodes(ctx, id, third.SessionVersion, writeLegacySettings(t, m), source, v)
	if e != nil || conflict.Complete || len(conflict.Conflicts) == 0 || tableCount(t, s, "v3_migration_node_sources") != 3 {
		t.Fatal("concurrent target overwritten", conflict, e)
	}
	state, e := s.MigrationSession(ctx, id)
	if e != nil || state.Version != third.SessionVersion {
		t.Fatal("conflict changed checkpoint", e)
	}
}

func TestMigrationNodesRejectsForeignTargetsSourceAndAtomicSecretFailures(t *testing.T) {
	t.Run("foreign-target", func(t *testing.T) {
		s, id, source, v, version := migrationNodesStoreFixture(t)
		n := nodeFixture("node-202")
		if e := s.PutNode(context.Background(), n, 0, 17); e != nil {
			t.Fatal(e)
		}
		r, e := s.MapLegacyNodes(context.Background(), id, version, writeLegacySettings(t, migrationNodesYAMLFixture(t)), source, v)
		if e != nil || r.Complete || len(r.Conflicts) == 0 || tableCount(t, s, "v3_nodes") != 1 || tableCount(t, s, "v3_migration_node_sources") != 0 {
			t.Fatal(r, e)
		}
	})
	t.Run("source-and-files", func(t *testing.T) {
		s, id, source, v, version := migrationNodesStoreFixture(t)
		path := writeLegacySettings(t, migrationNodesYAMLFixture(t))
		if _, e := s.MapLegacyNodes(context.Background(), id, version, path, digest([]byte("foreign-source")), v); e == nil {
			t.Fatal("unbound source accepted")
		}
		link := filepath.Join(t.TempDir(), "link")
		if e := os.Symlink(path, link); e != nil {
			t.Fatal(e)
		}
		if _, e := s.MapLegacyNodes(context.Background(), id, version, link, source, v); e == nil {
			t.Fatal("symlink accepted")
		}
		if _, e := s.MapLegacyNodes(context.Background(), id, version-1, path, source, v); !errors.Is(e, ErrConflict) {
			t.Fatal("stale session accepted", e)
		}
		if tableCount(t, s, "v3_nodes") != 0 {
			t.Fatal("invalid source mutated target")
		}
	})
	t.Run("transaction", func(t *testing.T) {
		s, id, source, v, version := migrationNodesStoreFixture(t)
		if _, e := s.DB.Exec(`CREATE FUNCTION fail_migration_credential() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE_DATABASE_PASSWORD'; END$$; CREATE TRIGGER fail_migration_credential BEFORE INSERT ON v3_credentials FOR EACH ROW EXECUTE FUNCTION fail_migration_credential()`); e != nil {
			t.Fatal(e)
		}
		r, e := s.MapLegacyNodes(context.Background(), id, version, writeLegacySettings(t, migrationNodesYAMLFixture(t)), source, v)
		if e == nil || !errors.Is(e, ErrMigrationSession) || strings.Contains(e.Error(), "SYNTHETIC_PRIVATE") || r.Complete {
			t.Fatal("unsafe database failure", e)
		}
		if tableCount(t, s, "v3_nodes") != 0 || tableCount(t, s, "v3_migration_node_sources") != 0 || tableCount(t, s, "v3_credentials") != 0 {
			t.Fatal("partial mapping committed")
		}
		var saved int64
		if e = s.DB.QueryRow(`SELECT version FROM v3_migration_sessions WHERE id=$1`, id).Scan(&saved); e != nil || saved != version {
			t.Fatal("failed transaction advanced session", e)
		}
	})
}

func TestMigrationNodesRejectsMalformedYAMLWithoutSensitiveDiagnostics(t *testing.T) {
	for _, raw := range []string{"config_version: 2\nconfig_version: synthetic-password", "config_version: 2\n---\nprivate_key: synthetic-password", "config_version: [synthetic-password"} {
		if _, e := parseMigrationLegacyNodes([]byte(raw)); !errors.Is(e, ErrMigrationSession) || strings.Contains(e.Error(), "synthetic-password") {
			t.Fatal("unsafe YAML diagnostic", e)
		}
	}
}

func TestMigrationNodesConcurrentRetryFreezeAndRecoveryHold(t *testing.T) {
	s, id, source, v, version := migrationNodesStoreFixture(t)
	ctx := context.Background()
	m := migrationNodesYAMLFixture(t)
	path := writeLegacySettings(t, m)
	var wg sync.WaitGroup
	reports := make(chan LegacyNodesImportReport, 2)
	errors := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.MapLegacyNodes(ctx, id, version, path, source, v)
			reports <- r
			errors <- e
		}()
	}
	wg.Wait()
	close(reports)
	close(errors)
	for e := range errors {
		if e != nil {
			t.Fatal("concurrent idempotent import failed", e)
		}
	}
	for r := range reports {
		if !r.Complete || r.SessionVersion != version+1 {
			t.Fatal("concurrent import reported another checkpoint", r)
		}
	}
	if tableCount(t, s, "v3_migration_node_sources") != 1 || tableCount(t, s, "v3_credentials") != 1 {
		t.Fatal("concurrent import duplicated immutable evidence")
	}
	if _, e := s.DB.Exec(`UPDATE v3_migration_sessions SET phase='frozen',version=version+1 WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if r, e := s.MapLegacyNodes(ctx, id, version+2, path, source, v); e != nil || !r.Complete {
		t.Fatal("exact frozen-source recheck unavailable", e)
	}
	common.M(common.A(m["nodes"])[0])["name"] = "after-freeze-source-change"
	if _, e := s.MapLegacyNodes(ctx, id, version+2, writeLegacySettings(t, m), source, v); e == nil {
		t.Fatal("new YAML slipped past frozen source binding")
	}
	if _, e := s.DB.Exec(`UPDATE v3_migration_sessions SET recovery_hold=true WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if _, e := s.MapLegacyNodes(ctx, id, version+2, path, source, v); e == nil {
		t.Fatal("recovery-held session accepted replay")
	}
}
