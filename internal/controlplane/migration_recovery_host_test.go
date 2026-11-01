package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrationRecoveryHostLoopbackAndMetricCanonicalization(t *testing.T) {
	for _, bad := range []string{"https://127.0.0.1:8428", "http://example.test:8428", "http://127.0.0.1:0", "http://127.0.0.1:8428/path", "http://u:p@127.0.0.1:8428", "http://127.0.0.1:8428?q=1"} {
		if migrationRecoveryHostLoopback(bad) {
			t.Fatal("unbound destination accepted")
		}
	}
	if !migrationRecoveryHostLoopback("http://127.0.0.1:8428") {
		t.Fatal("configured loopback destination rejected")
	}
	a := []migrationMetricLine{{Metric: map[string]string{"__name__": "isolated_probe"}, Values: []float64{0, 3}, Timestamps: []int64{10, 11}}}
	want, e := migrationRecoveryHostMetricMap(a)
	if e != nil || len(want) != 2 {
		t.Fatal(e)
	}
	a = append(a, migrationMetricLine{Metric: map[string]string{"__name__": "isolated_probe"}, Values: []float64{4}, Timestamps: []int64{11}})
	if _, e = migrationRecoveryHostMetricMap(a); !errors.Is(e, ErrMigrationRecovery) {
		t.Fatal("conflicting sample accepted")
	}
}

func migrationRecoveryHostFixture(t *testing.T) (*Store, *Store, migrationRecoveryHostPlan) {
	t.Helper()
	ctx := context.Background()
	source := testStore(t)
	p, _ := newSingleBackupFixture(t)
	p = singleBackupUpgradeBindTestDatabase(t, source, p)
	if e := source.Provision(ctx, "recovery-admin", "isolated-recovery-host-123"); e != nil {
		t.Fatal(e)
	}
	p.output = p.spec.Root + "-dr-archive"
	receipt, e := source.backupSingle(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	staged := p.spec.Root + "-dr-staged"
	if e = restoreSingleBackupOffline(ctx, receipt.Directory, receipt.ManifestSHA256, staged); e != nil {
		t.Fatal(e)
	}
	manifest, e := verifySingleBackup(ctx, receipt.Directory, receipt.ManifestSHA256)
	if e != nil {
		t.Fatal(e)
	}
	target := emptyTestStore(t)
	if e = target.RestorePostgres(ctx, filepath.Join(staged, manifest.Postgres)); e != nil {
		t.Fatal(e)
	}
	var generation string
	if e = target.DB.QueryRow(`SELECT generation FROM v3_migration_recovery_state WHERE id=1`).Scan(&generation); e != nil {
		t.Fatal(e)
	}
	if _, e = target.BeginMigrationRecovery(ctx, generation); e != nil {
		t.Fatal(e)
	}
	c := p.config
	var schema string
	if e = target.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); e != nil {
		t.Fatal(e)
	}
	dsn, e := readTrustData(p.config.Database.DSNFile, true, 64<<10)
	if e != nil {
		t.Fatal(e)
	}
	// The base test DSN is fixed by the isolated test environment. A distinct
	// PG schema is used, and the actual restored namespace identity is checked.
	c.Database.DSNFile = p.spec.Root + "-target-dsn"
	targetDSN, e := url.Parse(string(dsn))
	if e != nil {
		t.Fatal(e)
	}
	query := targetDSN.Query()
	query.Set("search_path", schema)
	targetDSN.RawQuery = query.Encode()
	localWrite(t, c.Database.DSNFile, []byte(targetDSN.String()))
	c.Metrics.QueryURL, c.Metrics.WriteURL = "http://127.0.0.1:59871", "http://127.0.0.1:59871"
	r := MigrationRecoveryHostRequest{Format: 1, Generation: generation, Backup: receipt.Directory, ManifestSHA256: receipt.ManifestSHA256, Staged: staged, Original: p.request, WorkDirectory: p.spec.Root + "-dr-work"}
	plan, e := planMigrationRecoveryHost(ctx, r, c)
	if e != nil {
		t.Fatal("verified full/staged archive rejected", e)
	}
	return source, target, plan
}

func migrationRecoveryHostObservedFixture(t *testing.T, p singleBackupPlan) migrationRecoveryHostRuntime {
	t.Helper()
	unitDir := privateTestDir(t)
	project := singleProject(p.spec.Root)
	defs := map[string]string{".service": filepath.Join(p.spec.Root, "stack.service")}
	if p.spec.Format >= 2 {
		defs["-pki.service"] = filepath.Join(p.spec.Root, "pki-maintenance.service")
		defs["-pki.timer"] = filepath.Join(p.spec.Root, "pki-maintenance.timer")
	}
	for suffix, file := range defs {
		raw, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		localWrite(t, filepath.Join(unitDir, project+suffix), raw)
	}
	r := migrationRecoveryHostRuntime{unitDirectory: unitDir, localSource: func(context.Context, singleBackupPlan, *sql.Tx) (string, error) {
		return digest([]byte("mock-original-owned-postgres-host-binding")), nil
	}, processes: func(context.Context, singleBackupPlan) (string, error) {
		return digest([]byte("observed-no-process-in-unit-test")), nil
	}, metrics: func(context.Context, migrationRecoveryHostPlan) (string, int64, error) {
		return digest([]byte("mocked-engine-separate-from-real-kernel-acceptance")), 0, nil
	}}
	r.command = func(_ context.Context, tool string, args ...string) ([]byte, error) {
		if tool == "docker" {
			if len(args) > 0 && (args[0] == "compose" || args[0] == "ps") {
				return nil, nil
			}
			t.Fatalf("unexpected docker command %q", args)
			return nil, ErrMigrationRecovery
		}
		if tool != "systemctl" || len(args) == 0 {
			t.Fatal("unexpected tool")
		}
		name := args[len(args)-1]
		suffix := strings.TrimPrefix(name, project)
		if _, ok := defs[suffix]; !ok {
			return []byte("LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nMainPID=0\nFragmentPath=\nDropInPaths=\n"), nil
		}
		return []byte("LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled\nMainPID=0\nFragmentPath=" + filepath.Join(unitDir, name) + "\nDropInPaths=\n"), nil
	}
	return r
}

func TestMigrationRecoveryHostArchiveStageTamperAndCurrentIsolation(t *testing.T) {
	_, _, p := migrationRecoveryHostFixture(t)
	ctx := context.Background()
	r := migrationRecoveryHostObservedFixture(t, p.original)
	if _, e := r.isolation(ctx, p.original); e != nil {
		t.Fatal("known stopped writer observation failed", e)
	}
	base := r.command
	r.command = func(ctx context.Context, tool string, args ...string) ([]byte, error) {
		raw, e := base(ctx, tool, args...)
		if tool == "systemctl" && args[len(args)-1] == singleProject(p.original.spec.Root)+".service" {
			raw = []byte(strings.ReplaceAll(string(raw), "UnitFileState=disabled", "UnitFileState=enabled"))
		}
		return raw, e
	}
	if _, e := r.isolation(ctx, p.original); !errors.Is(e, ErrMigrationRecovery) {
		t.Fatal("enabled startup considered isolated")
	}
	path := filepath.Join(p.request.Staged, p.manifest.Postgres)
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	localWrite(t, path, append(raw, '\n'))
	if e = migrationRecoveryHostVerifyStage(ctx, p); !errors.Is(e, ErrMigrationRecovery) {
		t.Fatal("modified staged archive accepted")
	}
}

func TestMigrationRecoveryHostActualPGTransactionAndLateIsolationChange(t *testing.T) {
	for _, late := range []bool{true, false} {
		t.Run(map[bool]string{true: "late-process-change", false: "activation"}[late], func(t *testing.T) {
			_, target, p := migrationRecoveryHostFixture(t)
			r := migrationRecoveryHostObservedFixture(t, p.original)
			calls := 0
			r.processes = func(context.Context, singleBackupPlan) (string, error) {
				calls++
				if late && calls > 1 {
					return digest([]byte("new-original-writer-observed")), nil
				}
				return digest([]byte("same-stopped-process-facts")), nil
			}
			check, e := target.migrationRecoveryHost(context.Background(), p, false, r)
			if late {
				if !errors.Is(e, ErrMigrationRecovery) {
					t.Fatal("late writer passed", check, e)
				}
				return
			}
			if e != nil || check.State != "verified" || check.CutoverAuthorized {
				t.Fatal("check incorrectly authorized handoff", check, e)
			}
			var phase, proof string
			if e = target.DB.QueryRow(`SELECT phase,metrics_sha256 FROM v3_migration_recovery_state WHERE id=1`).Scan(&phase, &proof); e != nil || phase != "reconciling" || proof != "" {
				t.Fatal("check persisted authority", phase, e)
			}
			final, e := target.migrationRecoveryHost(context.Background(), p, true, r)
			if e != nil || final.State != "complete" || !final.CutoverAuthorized {
				t.Fatal("actual PG handoff failed", final, e)
			}
			var pending bool
			if e = target.DB.QueryRow(`SELECT pending FROM v3_migration_domains WHERE domain='disaster-recovery'`).Scan(&pending); e != nil || pending {
				t.Fatal("recovery domain stayed pending", e)
			}
		})
	}
}

func TestMigrationRecoveryHostLatestAuthorityMismatchAndTaskHold(t *testing.T) {
	for _, kind := range []string{"node-inventory", "unknown-authority-table", "late-authority-table", "unfinished-task"} {
		t.Run(kind, func(t *testing.T) {
			source, target, p := migrationRecoveryHostFixture(t)
			switch kind {
			case "node-inventory":
				if _, e := source.DB.Exec(`INSERT INTO v3_nodes(id,name,endpoint,server_name,mode,shard) VALUES('new-node','new-node','192.0.2.1:19100','192.0.2.1','docker',1)`); e != nil {
					t.Fatal(e)
				}
			case "unknown-authority-table":
				for _, store := range []*Store{source, target} {
					if _, e := store.DB.Exec(`CREATE TABLE v3_node_new_authority(id text PRIMARY KEY,value text)`); e != nil {
						t.Fatal(e)
					}
				}
				if _, e := source.DB.Exec(`INSERT INTO v3_node_new_authority VALUES('current','post-backup-authority')`); e != nil {
					t.Fatal(e)
				}
			case "unfinished-task":
				if _, e := source.DB.Exec(`INSERT INTO v3_configuration_applications(id,stage,member,username,account_revision,generation,source_proof,plan_proof,controller,controller_revision,status,direction,state_proof) VALUES('unfinished','recovery-stage','single','recovery-admin',1,1,'source','plan','controller',1,'queued','forward','state')`); e != nil {
					t.Fatal(e)
				}
			}
			a, e := source.DB.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer a.Rollback()
			b, e := target.DB.Begin()
			if e != nil {
				t.Fatal(e)
			}
			defer b.Rollback()
			at, e := postgresTables(context.Background(), a)
			if e != nil {
				t.Fatal(e)
			}
			bt, e := postgresTables(context.Background(), b)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "late-authority-table" {
				if _, e = source.DB.Exec(`CREATE TABLE v3_node_late_authority(id text PRIMARY KEY)`); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := migrationRecoveryHostAuthorityTx(context.Background(), a, b, at, bt, p.original.config, p.target); !errors.Is(e, ErrMigrationRecovery) {
				t.Fatal("latest source mismatch accepted", e)
			}
		})
	}
}

// Real VM endpoints are the isolated services selected by the test launcher;
// this is exporter/comparison evidence, not a substitute for the signed CLI,
// archived-TSDB Docker and actual systemd kernel acceptance.
func TestMigrationRecoveryHostActualVMReadComparison(t *testing.T) {
	address := os.Getenv("WEBSCAN_V3_TEST_VM")
	if address == "" {
		t.Skip("isolated real VM required")
	}
	c := Config{}
	c.Metrics.QueryURL, c.Metrics.WriteURL = address, address
	m := migrationRecoveryHostMetrics(c)
	before, e := migrationRecoveryHostExport(context.Background(), m, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	after, e := migrationRecoveryHostExport(context.Background(), m, time.Now())
	if e != nil || !migrationRecoveryMetricContains(after, before, true) {
		t.Fatal("real VM read comparison failed", e)
	}
}

func TestMigrationRecoveryHostContainerCleanupRequiresExactOwner(t *testing.T) {
	id, name, owner := strings.Repeat("a", 64), "webscan-dr-verify-owned", "known-owner"
	for _, kind := range []string{"owned", "wrong-owner", "unknown-inspection", "absent"} {
		t.Run(kind, func(t *testing.T) {
			removed := false
			command := func(ctx context.Context, tool string, args ...string) ([]byte, error) {
				if _, ok := ctx.Deadline(); !ok || tool != "docker" {
					t.Fatal("cleanup lacks bounded fixed tool")
				}
				switch args[0] {
				case "ps":
					if kind == "absent" {
						return nil, nil
					}
					return []byte(id + "\n"), nil
				case "inspect":
					if kind == "unknown-inspection" {
						return nil, errors.New("lost response")
					}
					label := owner
					if kind == "wrong-owner" {
						label = "another-task"
					}
					return []byte(`[{"Id":"` + id + `","Name":"/` + name + `","Config":{"Labels":{"io.webscan.dr-verification":"` + label + `"}}}]`), nil
				case "rm":
					removed = true
					return nil, nil
				default:
					t.Fatal("unexpected cleanup verb")
					return nil, ErrMigrationRecovery
				}
			}
			c, cancel := context.WithCancel(context.Background())
			cancel()
			err := migrationRecoveryHostCleanupContainer(c, command, name, owner)
			want := kind == "owned" || kind == "absent"
			if (err == nil) != want || removed != (kind == "owned") {
				t.Fatal("cleanup ownership result incorrect", err, removed)
			}
		})
	}
}

func TestMigrationRecoveryHostLateMetricOrSourceObservationKeepsHold(t *testing.T) {
	for _, kind := range []string{"metrics-changed", "local-source-unproven"} {
		t.Run(kind, func(t *testing.T) {
			_, target, p := migrationRecoveryHostFixture(t)
			r := migrationRecoveryHostObservedFixture(t, p.original)
			calls := 0
			if kind == "metrics-changed" {
				r.metrics = func(context.Context, migrationRecoveryHostPlan) (string, int64, error) {
					calls++
					return digest([]byte(strings.Repeat("changed", calls))), 0, nil
				}
			} else {
				r.localSource = func(context.Context, singleBackupPlan, *sql.Tx) (string, error) { return "", ErrMigrationRecovery }
			}
			if _, err := target.migrationRecoveryHost(context.Background(), p, true, r); !errors.Is(err, ErrMigrationRecovery) {
				t.Fatal("unproved late evidence activated", err)
			}
			var phase, proof string
			if err := target.DB.QueryRow(`SELECT phase,metrics_sha256 FROM v3_migration_recovery_state WHERE id=1`).Scan(&phase, &proof); err != nil || phase != "reconciling" || proof != "" {
				t.Fatal("failure persisted cutover authority", phase, err)
			}
		})
	}
}

// This exercises the host's node/cache/epoch transaction using actual Agent
// mTLS and SQLite plus real dual VM. Host process/container isolation is
// covered separately; this does not replace the full archive kernel test.
func TestMigrationRecoveryHostActualNodeCacheAndDurableEpochFloor(t *testing.T) {
	if os.Getenv("WEBSCAN_V3_TEST_VM") == "" || os.Getenv("WEBSCAN_V3_TEST_RAW_VM") == "" {
		t.Skip("isolated dual VM required")
	}
	f, generation, backupAt := recoveryCoordinatorFixture(t)
	ctx := context.Background()
	f.config.Metrics.QueryURL = os.Getenv("WEBSCAN_V3_TEST_VM")
	f.config.Metrics.WriteURL = f.config.Metrics.QueryURL
	f.config.Metrics.RawURL = os.Getenv("WEBSCAN_V3_TEST_RAW_VM")
	if _, err := f.store.DB.Exec(`INSERT INTO v3_accounts VALUES('recovery-admin','synthetic-not-login-hash',1,'admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.BeginMigrationRecovery(ctx, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RunMigrationRecovery(ctx, f.config, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ReplayMigrationRecoveryMetrics(ctx, f.config, generation); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SuppressMigrationRecoveryNotifications(ctx, generation, "recovery-admin"); err != nil {
		t.Fatal(err)
	}
	p := migrationRecoveryHostPlan{request: MigrationRecoveryHostRequest{Generation: generation}, target: f.config, header: pgBackupLine{SnapshotAt: backupAt, SHA256: digest([]byte("synthetic-verified-backup"))}}
	tx, err := f.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	nodes, restored, err := migrationRecoveryHostStateTx(ctx, tx, p)
	if err != nil || len(nodes) != 1 {
		t.Fatal("actual recovered target state", len(nodes), err)
	}
	if _, err = migrationRecoveryHostVerifyCacheTx(ctx, tx, p, nodes[0], restored); err != nil {
		t.Fatal("actual retained-cache derived sample validation", err)
	}
	epoch, proof, err := migrationRecoveryHostObserveNode(ctx, f.config, nodes[0], backupAt)
	if err != nil || epoch != 7 || !releaseDigest(proof) {
		t.Fatal("actual mTLS host node observation", epoch, err)
	}
	source := testStore(t)
	if _, err = source.DB.Exec(`INSERT INTO v3_leases(resource,owner,epoch,expires_at) VALUES($1,'source-before-restore',11,clock_timestamp())`, shardResource(f.node.Shard)); err != nil {
		t.Fatal(err)
	}
	old, err := source.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer old.Rollback()
	if err = migrationRecoveryHostAdvanceTx(ctx, tx, old, generation, nodes, map[int]int64{f.node.Shard: epoch}); err != nil {
		t.Fatal(err)
	}
	var got int64
	if err = tx.QueryRow(`SELECT epoch FROM v3_leases WHERE resource=$1`, shardResource(f.node.Shard)).Scan(&got); err != nil || got != 12 {
		t.Fatal("durable source floor ignored", got, err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var phase string
	if err = f.store.DB.QueryRow(`SELECT phase FROM v3_migration_recovery_state WHERE id=1`).Scan(&phase); err != nil || phase != "reconciling" {
		t.Fatal("sub-observations unlocked recovery", phase, err)
	}
}
