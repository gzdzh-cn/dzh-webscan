package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

func environmentDSN(t *testing.T, s *Store) []byte {
	t.Helper()
	var schema string
	if e := s.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); e != nil {
		t.Fatal(e)
	}
	c, e := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if e != nil || (c.Scheme != "postgres" && c.Scheme != "postgresql") {
		t.Fatal(e)
	}
	q := c.Query()
	q.Set("search_path", schema)
	c.RawQuery = q.Encode()
	return []byte(c.String())
}

func environmentMetrics(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/query", "/select/0/prometheus/api/v1/query":
		if r.Method != "GET" || r.URL.Query().Get("query") != "vector(1)" {
			http.Error(w, "bad query", 400)
			return
		}
		at, e := strconv.ParseInt(r.URL.Query().Get("time"), 10, 64)
		if e != nil {
			http.Error(w, "bad time", 400)
			return
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"value":[%d,"1"]}]}}`, at)
	case "/api/v1/import", "/insert/0/prometheus/api/v1/import":
		raw, e := io.ReadAll(io.LimitReader(r.Body, 1024))
		if r.Method != "POST" || e != nil || len(raw) != 0 || r.Header.Get("Content-Type") != "application/stream+json" {
			http.Error(w, "sample writes prohibited in this diagnostic", 400)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func environmentFixture(t *testing.T, handler http.Handler) (*Store, configurationLocalFixture, string) {
	t.Helper()
	s, f := newSavedConfigurationStore(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	f.c.Metrics.WriteURL, f.c.Metrics.QueryURL = server.URL, server.URL
	localWrite(t, f.c.Database.DSNFile, environmentDSN(t, s))
	stage, r := savedRestoreFromDocument(t, s, f, f.document(t))
	raw, e := s.commitConfigurationRestoreSaved(context.Background(), f.v, f.c, "admin", "environment-save", stage.ID, r.Generation)
	_ = savedReceipt(t, raw, e)
	return s, f, stage.ID
}

func TestConfigurationEnvironmentReadOnlySavedAndPrivate(t *testing.T) {
	var queries, imports atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			queries.Add(1)
		} else {
			imports.Add(1)
		}
		environmentMetrics(w, r)
	})
	s, f, stage := environmentFixture(t, h)
	before := localTree(t, f.f.root)
	tables := []string{"v3_settings", "v3_nodes", "v3_deployment_jobs", "v3_configuration_restore_commits", "v3_audit"}
	counts := map[string]int{}
	for _, name := range tables {
		counts[name] = tableCount(t, s, name)
	}
	settings := settingsStateForTest(t, s)
	bootstrap, e := bootstrapStateForTest(s, f.v, f.c)
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.inspectSavedConfigurationEnvironment(context.Background(), f.v, f.c, "admin", stage)
	if e != nil || !r.PreflightPassed || !r.RequiresRuntimeReceipts || len(r.Checks) != 3 || queries.Load() != 1 || imports.Load() != 1 {
		t.Fatal("environment diagnostic failed", r, e, queries.Load(), imports.Load())
	}
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{f.f.root, string(environmentDSN(t, s)), f.c.Metrics.QueryURL, "private-dsn-password"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("diagnostic leaked private destination")
		}
	}
	var encoded map[string]any
	if json.Unmarshal(raw, &encoded) != nil {
		t.Fatal("report encoding")
	}
	if _, ok := encoded["generation"].(string); !ok {
		t.Fatal("generation lost string representation")
	}
	if !reflect.DeepEqual(before, localTree(t, f.f.root)) {
		t.Fatal("diagnostic wrote local files")
	}
	for _, name := range tables {
		if counts[name] != tableCount(t, s, name) {
			t.Fatal("diagnostic changed", name)
		}
	}
	afterBootstrap, e := bootstrapStateForTest(s, f.v, f.c)
	if e != nil || !reflect.DeepEqual(settings, settingsStateForTest(t, s)) || !reflect.DeepEqual(bootstrap, afterBootstrap) {
		t.Fatal("diagnostic applied saved state", e)
	}
	if s.DB.Stats().InUse != 0 {
		t.Fatal("diagnostic retained transactions")
	}
}

func TestConfigurationEnvironmentDatabaseIdentityAndPermissions(t *testing.T) {
	s := testStore(t)
	raw := environmentDSN(t, s)
	check := func(t *testing.T, dsn []byte, reason string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r := s.checkConfigurationDatabase(ctx, dsn)
		if r.Reason != reason || (r.Status == "passed") != (reason == "same_writable_database_verified") {
			t.Fatal("database identity check", r)
		}
		if s.DB.Stats().InUse != 0 {
			t.Fatal("source transaction leaked")
		}
	}
	check(t, raw, "same_writable_database_verified")
	t.Run("other-schema", func(t *testing.T) {
		other := testStore(t)
		check(t, environmentDSN(t, other), "database_schema_mismatch")
	})
	t.Run("other-database", func(t *testing.T) {
		c, e := url.Parse(string(raw))
		if e != nil {
			t.Fatal(e)
		}
		c.Path = "/template1"
		check(t, []byte(c.String()), "database_identity_mismatch")
	})
	t.Run("different-creation-schema", func(t *testing.T) {
		other := emptyTestStore(t)
		var schema string
		if e := other.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); e != nil {
			t.Fatal(e)
		}
		c, e := url.Parse(string(raw))
		if e != nil {
			t.Fatal(e)
		}
		q := c.Query()
		q.Set("search_path", schema+","+q.Get("search_path"))
		c.RawQuery = q.Encode()
		// An empty prefix still resolves the source tables but changes the
		// default schema used by future migrations. It must not pass.
		check(t, []byte(c.String()), "database_schema_mismatch")
	})
	t.Run("readonly", func(t *testing.T) {
		c, e := url.Parse(string(raw))
		if e != nil {
			t.Fatal(e)
		}
		q := c.Query()
		q.Set("default_transaction_read_only", "on")
		c.RawQuery = q.Encode()
		check(t, []byte(c.String()), "database_read_only")
	})
	t.Run("rls", func(t *testing.T) {
		mustHistoryExec(t, s.DB, `ALTER TABLE v3_settings ENABLE ROW LEVEL SECURITY`)
		defer mustHistoryExec(t, s.DB, `ALTER TABLE v3_settings DISABLE ROW LEVEL SECURITY`)
		check(t, raw, "database_permissions_insufficient")
	})
	t.Run("schema-version", func(t *testing.T) {
		mustHistoryExec(t, s.DB, `INSERT INTO v3_schema(version) VALUES(999)`)
		defer mustHistoryExec(t, s.DB, `DELETE FROM v3_schema WHERE version=999`)
		check(t, raw, "database_schema_mismatch")
	})
	t.Run("invalid", func(t *testing.T) { check(t, []byte("postgres://%invalid"), "database_credentials_invalid") })
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if r := s.checkConfigurationDatabase(ctx, raw); r.Status == "passed" {
			t.Fatal("cancelled check passed")
		}
	})
}

func TestConfigurationEnvironmentDatabaseIndividualPrivileges(t *testing.T) {
	s := testStore(t)
	role := "webscan_env_" + token()[:16]
	var schema string
	if e := s.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); e != nil {
		t.Fatal(e)
	}
	quote := func(x string) string { return pgx.Identifier{x}.Sanitize() }
	mustHistoryExec(t, s.DB, `CREATE ROLE `+quote(role)+` LOGIN`)
	t.Cleanup(func() {
		mustHistoryExec(t, s.DB, `DROP OWNED BY `+quote(role))
		mustHistoryExec(t, s.DB, `DROP ROLE `+quote(role))
	})
	mustHistoryExec(t, s.DB, `GRANT USAGE,CREATE ON SCHEMA `+quote(schema)+` TO `+quote(role))
	mustHistoryExec(t, s.DB, `GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA `+quote(schema)+` TO `+quote(role))
	mustHistoryExec(t, s.DB, `GRANT USAGE,SELECT,UPDATE ON ALL SEQUENCES IN SCHEMA `+quote(schema)+` TO `+quote(role))
	c, e := url.Parse(string(environmentDSN(t, s)))
	if e != nil {
		t.Fatal(e)
	}
	c.User = url.User(role)
	check := func(ok bool) {
		t.Helper()
		r := s.checkConfigurationDatabase(context.Background(), []byte(c.String()))
		if (r.Status == "passed") != ok {
			t.Fatal("individual permission check", r)
		}
	}
	check(true)
	// SELECT remains granted: a comma-list ANY check would incorrectly pass.
	mustHistoryExec(t, s.DB, `REVOKE DELETE ON v3_settings FROM `+quote(role))
	check(false)
	mustHistoryExec(t, s.DB, `GRANT DELETE ON v3_settings TO `+quote(role))
	check(true)
	var sequence string
	if e := s.DB.QueryRow(`SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind='S' ORDER BY relname LIMIT 1`).Scan(&sequence); e != nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, s.DB, `REVOKE UPDATE ON SEQUENCE `+quote(sequence)+` FROM `+quote(role))
	check(false)
	mustHistoryExec(t, s.DB, `GRANT UPDATE ON SEQUENCE `+quote(sequence)+` TO `+quote(role))
	check(true)
	mustHistoryExec(t, s.DB, `REVOKE CREATE ON SCHEMA `+quote(schema)+` FROM `+quote(role))
	check(false)
}

func TestConfigurationEnvironmentChangedDuringNetworkAndNoRelationLocks(t *testing.T) {
	for _, kind := range []string{"settings", "account", "dsn", "local-key", "archive-pin"} {
		t.Run(kind, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					close(started)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				environmentMetrics(w, r)
			})
			s, f, stage := environmentFixture(t, h)
			type result struct {
				r configurationEnvironmentReport
				e error
			}
			done := make(chan result, 1)
			go func() {
				r, e := s.inspectSavedConfigurationEnvironment(context.Background(), f.v, f.c, "admin", stage)
				done <- result{r, e}
			}()
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("network not reached")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			tx, e := s.DB.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if e = lockConfigurationRestoreStateTx(ctx, tx); e != nil {
				t.Fatal("network held configuration gate", e)
			}
			switch kind {
			case "settings":
				_, e = tx.ExecContext(ctx, `UPDATE v3_settings SET payload='{"diagnostic_drift":true}',version=version+1`)
			case "account":
				_, e = tx.ExecContext(ctx, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`)
			case "archive-pin":
				_, e = tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins`)
			case "dsn":
				localWrite(t, f.c.Database.DSNFile, append(environmentDSN(t, s), '\n'))
			case "local-key":
				localWrite(t, f.c.Collector.KeyFile, []byte("damaged"))
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			close(release)
			select {
			case got := <-done:
				if got.e == nil && got.r.PreflightPassed {
					t.Fatal("stale configuration was accepted", kind)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("diagnostic failed to finish")
			}
		})
	}
}

func TestConfigurationEnvironmentMissingMaterialOrOwnerNeverDials(t *testing.T) {
	var calls atomic.Int32
	s, f, stage := environmentFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); environmentMetrics(w, r) }))
	mustHistoryExec(t, s.DB, `INSERT INTO v3_accounts(username,password_hash,role) VALUES('other','not-a-login','admin')`)
	if _, e := s.inspectSavedConfigurationEnvironment(context.Background(), f.v, f.c, "other", stage); e == nil {
		t.Fatal("other owner accepted")
	}
	localWrite(t, f.c.Collector.KeyFile, []byte("damaged"))
	r, e := s.inspectSavedConfigurationEnvironment(context.Background(), f.v, f.c, "admin", stage)
	if e == nil && r.PreflightPassed || calls.Load() != 0 {
		t.Fatal("missing material connected", r, e)
	}
}

func TestConfigurationEnvironmentMetricsFailureBoundaries(t *testing.T) {
	for _, kind := range []string{"rejected", "invalid", "too-large", "stale", "wrong-value", "wrong-type", "extra-result", "nonfinite"} {
		t.Run("query-"+kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				at, _ := strconv.ParseInt(r.URL.Query().Get("time"), 10, 64)
				value := "1"
				switch kind {
				case "rejected":
					w.WriteHeader(503)
					return
				case "invalid":
					fmt.Fprint(w, "{damaged")
					return
				case "too-large":
					fmt.Fprint(w, strings.Repeat(" ", 65537))
					return
				case "stale":
					at -= 60
				case "wrong-value":
					value = "0"
				case "nonfinite":
					value = "NaN"
				case "wrong-type":
					fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[{"value":[%d,"1"]}]}}`, at)
					return
				case "extra-result":
					fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"value":[%d,"1"]},{"value":[%d,"1"]}]}}`, at, at)
					return
				}
				fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"value":[%d,%q]}]}}`, at, value)
			}))
			defer server.Close()
			if r := checkConfigurationMetricsQuery(context.Background(), server.Client(), server.URL); r.Status == "passed" {
				t.Fatal("invalid query accepted", kind)
			}
		})
	}
	for _, kind := range []string{"rejected", "oversized"} {
		t.Run("import-"+kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "rejected" {
					w.WriteHeader(503)
				} else {
					fmt.Fprint(w, strings.Repeat("x", 4097))
				}
			}))
			defer server.Close()
			if r := checkConfigurationMetricsImport(context.Background(), server.Client(), server.URL); r.Status == "passed" {
				t.Fatal("invalid import accepted")
			}
		})
	}
	t.Run("cluster-prefix", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(environmentMetrics))
		defer server.Close()
		if r := checkConfigurationMetricsQuery(context.Background(), server.Client(), server.URL+"/select/0/prometheus/"); r.Status != "passed" {
			t.Fatal(r)
		}
		if r := checkConfigurationMetricsImport(context.Background(), server.Client(), server.URL+"/insert/0/prometheus/"); r.Status != "passed" {
			t.Fatal(r)
		}
	})
	t.Run("tls", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(environmentMetrics))
		defer server.Close()
		client := &http.Client{Timeout: time.Second}
		if r := checkConfigurationMetricsQuery(context.Background(), client, server.URL); r.Status == "passed" {
			t.Fatal("untrusted TLS accepted")
		}
		if r := checkConfigurationMetricsImport(context.Background(), client, server.URL); r.Status == "passed" {
			t.Fatal("untrusted import TLS accepted")
		}
	})
	t.Run("deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if r := checkConfigurationMetricsQuery(ctx, server.Client(), server.URL); r.Status == "passed" {
			t.Fatal("deadline ignored")
		}
	})
}

func TestConfigurationEnvironmentRedirectsNotFollowed(t *testing.T) {
	var followed atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1); environmentMetrics(w, r) }))
	defer destination.Close()
	s, f, stage := environmentFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	r, e := s.inspectSavedConfigurationEnvironment(context.Background(), f.v, f.c, "admin", stage)
	if e != nil || r.PreflightPassed || followed.Load() != 0 {
		t.Fatal("redirect escaped configured destination", r, e)
	}
}

func TestConfigurationEnvironmentInputStrictAndPrivate(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "input.json")
	stage := strings.Repeat("a", 64)
	valid := `{"stage":"` + stage + `"}`
	for _, raw := range []string{`null`, `[]`, `{}`, `{"Stage":"` + stage + `"}`, `{"stage":null}`, `{"stage":42}`, `{"stage":"a"}`, `{"stage":"` + stage + `","stage":"` + stage + `"}`, valid + ` {}`, `{"stage":"` + stage + `","url":"http://127.0.0.1"}`, strings.Repeat(" ", 4097) + valid} {
		localWrite(t, path, []byte(raw))
		if _, e := configurationEnvironmentInput(path); e == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	localWrite(t, path, []byte(valid))
	if got, e := configurationEnvironmentInput(path); e != nil || got != stage {
		t.Fatal("valid local input rejected", e)
	}
	link := path + ".link"
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := configurationEnvironmentInput(link); e == nil {
		t.Fatal("symlink accepted")
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := configurationEnvironmentInput(path); e == nil {
		t.Fatal("public source accepted")
	}
}

func TestConfigurationEnvironmentCommandRealConfig(t *testing.T) {
	s, f, stage := environmentFixture(t, http.HandlerFunc(environmentMetrics))
	raw, e := yaml.Marshal(f.c)
	if e != nil {
		t.Fatal(e)
	}
	config, source := filepath.Join(f.f.root, "control.yaml"), filepath.Join(f.f.root, "request.json")
	localWrite(t, config, raw)
	localWrite(t, source, []byte(`{"stage":"`+stage+`"}`))
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if binary := os.Getenv("WEBSCAN_V3_TEST_CLI"); binary != "" {
		cmd := exec.CommandContext(ctx, binary, "control-v3", "--config", config, "--action", "check-configuration-apply", "--username", "admin", "--source", source)
		result, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatal("actual diagnostic CLI failed", e)
		}
		out.Write(result)
	} else if e := Command(ctx, Options{Config: config, Source: source, Username: "admin", Action: "check-configuration-apply"}, strings.NewReader(""), &out); e != nil {
		t.Fatal(e)
	}
	var report configurationEnvironmentReport
	if json.Unmarshal(out.Bytes(), &report) != nil || !report.PreflightPassed || !report.RequiresRuntimeReceipts {
		t.Fatal("CLI report unavailable")
	}
	localWrite(t, f.c.Database.DSNFile, []byte("postgres://%invalid"))
	out.Reset()
	if e := s.localConfigurationEnvironmentCommand(ctx, f.c, Options{Source: source, Username: "admin"}, &out); e == nil {
		t.Fatal("CLI passed failed dependency")
	}
	if json.Unmarshal(out.Bytes(), &report) != nil || report.PreflightPassed {
		t.Fatal("CLI missing failed diagnostic")
	}
	out.Reset()
	if e := s.localConfigurationEnvironmentCommand(ctx, f.c, Options{Source: source, Username: "absent"}, &out); e == nil || out.Len() != 0 {
		t.Fatal("unknown account inspected stage")
	}
}

func TestConfigurationEnvironmentVictoriaMetrics(t *testing.T) {
	endpoint := os.Getenv("WEBSCAN_V3_TEST_VM")
	if endpoint == "" {
		t.Skip("set WEBSCAN_V3_TEST_VM to an isolated VictoriaMetrics instance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Second}
	if r := checkConfigurationMetricsQuery(ctx, client, endpoint); r.Status != "passed" {
		t.Fatal("actual instant query failed", r)
	}
	if r := checkConfigurationMetricsImport(ctx, client, endpoint); r.Status != "passed" {
		t.Fatal("actual empty import failed", r)
	}
}
