package controlplane

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"os"
	"webscan/internal/common"
	configuration "webscan/internal/config"
	"webscan/internal/persist"
	"webscan/internal/pull"
)

func migrationCutoverNodesFixture(t *testing.T) (*shadowFixture, MigrationSession, *Vault, string) {
	t.Helper()
	ctx := context.Background()
	f := newShadowFixture(t)
	for _, q := range []string{`DELETE FROM v3_node_runtime WHERE node=$1`, `DELETE FROM v3_node_configurations WHERE node=$1`, `DELETE FROM v3_nodes WHERE id=$1`} {
		if _, e := f.store.DB.Exec(q, f.node.ID); e != nil {
			t.Fatal(e)
		}
	}
	session, e := f.store.BeginMigrationSession(ctx, digest([]byte(t.Name())), 0, []string{"central"})
	if e != nil {
		t.Fatal(e)
	}
	db, e := persist.OpenDB(filepath.Join(privateTestDir(t), "old.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Exec(`CREATE TABLE synthetic(id INTEGER PRIMARY KEY);INSERT INTO synthetic VALUES(1)`); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(privateTestDir(t), "old-snapshot.sqlite3")
	if e = persist.BackupDB(db, path); e != nil {
		t.Fatal(e)
	}
	origin := digest([]byte("cutover-node-source"))
	revision, e := f.store.BindMigrationRevision(ctx, session.ID, session.Version, MigrationRevisionInput{"central", origin, path})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.DB.Exec(`INSERT INTO v3_cluster VALUES(1,'{"topology":"single","shards":17}')`); e != nil {
		t.Fatal(e)
	}
	settings := migrationNodesYAMLFixture(t)
	old := common.M(common.A(settings["nodes"])[0])
	old["id"] = f.node.ID
	old["name"] = "cutover-node"
	host, port, e := net.SplitHostPort(f.server.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	p, _ := strconv.Atoi(port)
	old["host"] = host
	old["metrics"] = common.Map{"port": p}
	old["enabled"] = true
	disabled := common.M(common.A(settings["nodes"])[1])
	disabled["enabled"] = false
	settings["nodes"] = []any{old, disabled}
	common.M(settings["deployment"])["node_order"] = []string{f.node.ID, common.S(disabled["id"])}
	v, _ := testVault(t)
	legacyPath := filepath.Join(privateTestDir(t), "legacy.yaml")
	raw, _ := os.ReadFile(writeLegacySettings(t, settings))
	localWrite(t, legacyPath, raw)
	if _, e = configuration.Parse(raw, ""); e != nil {
		t.Fatal("config parse", e)
	}
	if _, e = parseMigrationLegacyNodes(raw); e != nil {
		t.Fatal("node parse", e)
	}
	report, e := f.store.MapLegacyNodes(ctx, session.ID, revision.SessionVersion, legacyPath, origin, v)
	if e != nil || !report.Complete {
		t.Fatal(report, e)
	}
	manifestPath := filepath.Join(privateTestDir(t), "freeze.json")
	manifest := MigrationFreezeManifest{Format: 1, Session: session.ID, Sources: []MigrationFreezeSource{{Role: "central", SourceID: origin, SQLite: path, Writers: []MigrationFreezeWriter{{Kind: "systemd", ID: "synthetic-central.service", Role: "central", ConfigFile: legacyPath, ConfigSHA256: digest(raw)}}}}}
	localWrite(t, manifestPath, common.JSON(manifest))
	_, manifestSHA, e := readMigrationFreezeManifest(manifestPath, session.ID)
	if e != nil {
		t.Fatal(e)
	}
	// This focused test starts at the authenticated frozen-revision checkpoint;
	// full freeze/source-writer coverage lives in migration_cutover_test.go.
	if _, e = f.store.DB.Exec(`INSERT INTO v3_migration_freezes(session,role,revision,manifest_digest,evidence_digest,request_version) VALUES($1,'central',$2,$3,$3,$4)`, session.ID, revision.ID, manifestSHA, report.SessionVersion); e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.DB.Exec(`UPDATE v3_migration_sessions SET phase='frozen',freeze_digest=$2 WHERE id=$1`, session.ID, digest([]byte("synthetic-frozen-summary"))); e != nil {
		t.Fatal(e)
	}
	session, e = f.store.MigrationSession(ctx, session.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.store.DB.QueryRow(`SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1`, f.node.ID).Scan(&f.node.ID, &f.node.Name, &f.node.Endpoint, &f.node.ServerName, &f.node.Enabled, &f.node.Mode, &f.node.Version, &f.node.AppliedVersion, &f.node.Shard, &f.node.Config); e != nil {
		t.Fatal(e)
	}
	fixed, e := pull.New(f.source.DB, f.node.ID, "v3-cutover-isolated", new(sync.Mutex), pull.Configuration{Version: f.node.Version, SHA256: digest(f.node.Config)})
	if e != nil {
		t.Fatal(e)
	}
	*f.source = *fixed
	return f, session, v, manifestPath
}
func migrationCutoverNodesCall(ctx context.Context, s *Store, state MigrationSession, v *Vault, c Config, activate bool, manifests ...string) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = migrationSessionLock(ctx, tx, state.ID); e != nil {
		return e
	}
	if e = verifyMigrationNodesCutoverTx(ctx, tx, state, v, c, activate, manifests...); e != nil {
		return e
	}
	return tx.Commit()
}
func TestMigrationCutoverNodesActualMTLSPublishesOriginalIntent(t *testing.T) {
	f, state, v, manifest := migrationCutoverNodesFixture(t)
	ctx := context.Background()
	if _, e := nodeRuntimeSettings(f.node.Config); e != nil {
		t.Fatal("runtime settings", e)
	}
	if e := migrationCutoverNodesCall(ctx, f.store, state, v, f.config, false, manifest); e != nil {
		t.Fatal("ready", e)
	}
	var count int
	if e := f.store.DB.QueryRow(`SELECT count(*) FROM v3_node_runtime`).Scan(&count); e != nil || count != 0 {
		t.Fatal("readiness published runtime", count, e)
	}
	if e := migrationCutoverNodesCall(ctx, f.store, state, v, f.config, true, manifest); e != nil {
		t.Fatal("activate", e)
	}
	var enabled bool
	var delivered, version int64
	if e := f.store.DB.QueryRow(`SELECT enabled,version FROM v3_active_nodes WHERE id=$1`, f.node.ID).Scan(&enabled, &version); e != nil || !enabled {
		t.Fatal("no active node", e)
	}
	if e := f.store.DB.QueryRow(`SELECT delivered_version FROM v3_node_runtime WHERE node=$1`, f.node.ID).Scan(&delivered); e != nil || delivered != version {
		t.Fatal("false delivered version", e)
	}
	if e := f.store.DB.QueryRow(`SELECT count(*) FROM v3_nodes WHERE enabled`).Scan(&count); e != nil || count != 1 {
		t.Fatal("original disabled node enabled", count, e)
	}
	tx, e := f.store.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	images, e := migrationNodeActivationImagesTx(ctx, tx, state.ID, v)
	if e != nil || len(images) != 4 {
		t.Fatal("authenticated reverse images", len(images), e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, method := range f.methods {
		if method != "/webscan.agent.v1.AgentService/Capabilities" && method != "/webscan.agent.v1.AgentService/ReadMetrics" {
			t.Fatal("remote write", method)
		}
	}
}
func TestMigrationCutoverNodesActualRejectsMismatchMissingAndStale(t *testing.T) {
	for _, kind := range []string{"agent-config", "saved-config", "stale-metrics", "network", "source-auth", "missing-manifest", "changed-yaml"} {
		t.Run(kind, func(t *testing.T) {
			f, state, v, manifest := migrationCutoverNodesFixture(t)
			ctx := context.Background()
			switch kind {
			case "agent-config":
				fixed, e := pull.New(f.source.DB, f.node.ID, "isolated", new(sync.Mutex), pull.Configuration{Version: f.node.Version + 1, SHA256: digest(f.node.Config)})
				if e != nil {
					t.Fatal(e)
				}
				*f.source = *fixed
			case "saved-config":
				if _, e := f.store.DB.Exec(`UPDATE v3_nodes SET config=config||'{"tampered":true}'::jsonb WHERE id=$1`, f.node.ID); e != nil {
					t.Fatal(e)
				}
			case "stale-metrics":
				if _, e := f.source.DB.Exec(`DELETE FROM pull_metrics`); e != nil {
					t.Fatal(e)
				}
				if e := f.source.RecordMetrics(ctx, time.Now().Add(-5*time.Minute), []byte("node_memory_MemTotal_bytes 123456\n")); e != nil {
					t.Fatal(e)
				}
			case "network":
				f.mu.Lock()
				f.rejectMetrics = true
				f.mu.Unlock()
			case "missing-manifest":
				manifest = ""
			case "changed-yaml":
				m, _, e := readMigrationFreezeManifest(manifest, state.ID)
				if e != nil {
					t.Fatal(e)
				}
				config, e := os.ReadFile(m.Sources[0].Writers[0].ConfigFile)
				if e != nil {
					t.Fatal(e)
				}
				config = append(config, []byte("\n# changed after mapping\n")...)
				if e = os.WriteFile(m.Sources[0].Writers[0].ConfigFile, config, 0600); e != nil {
					t.Fatal(e)
				}
				m.Sources[0].Writers[0].ConfigSHA256 = digest(config)
				localWrite(t, manifest, common.JSON(m))
				_, sha, e := readMigrationFreezeManifest(manifest, state.ID)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.store.DB.Exec(`UPDATE v3_migration_freezes SET manifest_digest=$1 WHERE session=$2`, sha, state.ID); e != nil {
					t.Fatal(e)
				}
			case "source-auth":
				if _, e := f.store.DB.Exec(`UPDATE v3_migration_node_sources SET content_hmac=$1 WHERE session=$2`, digest([]byte("forged")), state.ID); e != nil {
					t.Fatal(e)
				}
			}
			if e := migrationCutoverNodesCall(ctx, f.store, state, v, f.config, true, manifest); e == nil {
				t.Fatal("unsafe activation passed")
			}
			var count int
			if e := f.store.DB.QueryRow(`SELECT count(*) FROM v3_node_runtime`).Scan(&count); e != nil || count != 0 {
				t.Fatal("partial activation", count, e)
			}
		})
	}
}

func TestMigrationCutoverNodesReverseAcceptsOnlyAuthenticatedMechanicalImages(t *testing.T) {
	f, state, v, manifest := migrationCutoverNodesFixture(t)
	ctx := context.Background()
	if e := migrationCutoverNodesCall(ctx, f.store, state, v, f.config, true, manifest); e != nil {
		t.Fatal(e)
	}
	db, e := persist.OpenDB(filepath.Join(privateTestDir(t), "reverse.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if _, e = db.Exec(`CREATE TABLE migration_node_activation_targets(node TEXT PRIMARY KEY,payload TEXT NOT NULL);CREATE TABLE migration_node_activation_images(identity TEXT PRIMARY KEY,table_name TEXT NOT NULL);CREATE TABLE migration_pending(table_name TEXT,identity TEXT,reason TEXT,PRIMARY KEY(table_name,identity))`); e != nil {
		t.Fatal(e)
	}
	sink := &MigrationLegacySink{db: db, session: state.ID}
	if e = f.store.AuthorizeMigrationLegacyNodeActivations(ctx, state.ID, sink, v); e != nil {
		t.Fatal(e)
	}
	var raw []byte
	if e = f.store.DB.QueryRow(`SELECT to_jsonb(n) FROM v3_nodes n WHERE id=$1`, f.node.ID).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	row := MigrationTargetReplayRow{Table: "v3_nodes", Operation: "UPDATE", AfterKey: common.JSON(common.Map{"id": f.node.ID}), After: raw}
	local, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = sink.migrationLegacyApplyTx(ctx, local, row); e != nil {
		t.Fatal(e)
	}
	if e = local.Commit(); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = db.QueryRow(`SELECT count(*) FROM migration_pending`).Scan(&count); e != nil || count != 0 {
		t.Fatal("valid mechanical change blocked", e)
	}
	decoded, e := common.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	common.M(decoded)["endpoint"] = "different.example:19100"
	row.After = common.JSON(decoded)
	local, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = sink.migrationLegacyApplyTx(ctx, local, row); e != nil {
		t.Fatal(e)
	}
	if e = local.Commit(); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow(`SELECT count(*) FROM migration_pending`).Scan(&count); e != nil || count != 1 {
		t.Fatal("arbitrary node edit silently discarded", e)
	}
	tx, e := f.store.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyMigrationLegacyNodeActivationsTx(ctx, tx, state.ID, sink, v); e != nil {
		t.Fatal(e)
	}
	tx.Rollback()
	if _, e = db.Exec(`DELETE FROM migration_node_activation_images WHERE rowid=(SELECT min(rowid) FROM migration_node_activation_images)`); e != nil {
		t.Fatal(e)
	}
	tx, e = f.store.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if e = VerifyMigrationLegacyNodeActivationsTx(ctx, tx, state.ID, sink, v); e == nil {
		t.Fatal("forged local authorization accepted")
	}
}

func TestMigrationCutoverNodesCredentialBaselineIsAuthenticated(t *testing.T) {
	f, state, v, _ := migrationCutoverNodesFixture(t)
	ctx := context.Background()
	tx, e := f.store.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	raw, baseline, e := migrationLegacySourceYAMLTx(ctx, tx, state.ID, v)
	clear(raw)
	if e != nil {
		t.Fatal(e)
	}
	var credential string
	if e = tx.QueryRowContext(ctx, `SELECT credential FROM v3_web_node_credentials WHERE node=$1`, f.node.ID).Scan(&credential); e != nil {
		t.Fatal(e)
	}
	if !releaseDigest(baseline[migrationLegacySourceKey("v3_credentials", common.Map{"id": credential})]) || !releaseDigest(baseline[migrationLegacySourceKey("v3_web_node_credentials", common.Map{"node": f.node.ID})]) {
		t.Fatal("unchanged encrypted credentials cannot establish reverse baseline")
	}
	tx.Rollback()
	if _, e = f.store.DB.Exec(`UPDATE v3_credentials SET ciphertext=ciphertext||'\x00'::bytea WHERE id=$1`, credential); e != nil {
		t.Fatal(e)
	}
	tx, e = f.store.DB.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	raw, _, e = migrationLegacySourceYAMLTx(ctx, tx, state.ID, v)
	clear(raw)
	if e == nil {
		t.Fatal("edited credential treated as original YAML")
	}
}

// Align the synthetic stopped-writer fixture with the same authenticated YAML
// that the production mapper imported. The host/kernel observer remains tested
// separately; this helper never relaxes the runtime source proof.
func migrationBindFrozenYAMLFixture(t *testing.T, s *Store, session, manifestPath string, v *Vault) {
	t.Helper()
	m, _, e := readMigrationFreezeManifest(manifestPath, session)
	if e != nil {
		t.Fatal(e)
	}
	for i, source := range m.Sources {
		var id, key string
		var nonce, sealed []byte
		e = s.DB.QueryRow(`SELECT id,key_id,nonce,ciphertext FROM v3_migration_node_sources WHERE session=$1 AND source_id=$2 ORDER BY sequence DESC LIMIT 1`, session, source.SourceID).Scan(&id, &key, &nonce, &sealed)
		if e == sql.ErrNoRows {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		raw, e := migrationNodesOpen(v, key, id, nonce, sealed)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(privateTestDir(t), "frozen-"+source.Role+".yaml")
		localWrite(t, path, raw)
		hash := digest(raw)
		clear(raw)
		for j := range m.Sources[i].Writers {
			m.Sources[i].Writers[j].ConfigFile = path
			m.Sources[i].Writers[j].ConfigSHA256 = hash
		}
	}
	localWrite(t, manifestPath, common.JSON(m))
}
