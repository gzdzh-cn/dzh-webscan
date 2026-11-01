package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"gopkg.in/yaml.v3"
)

var errConfigurationEnvironment = errors.New("应用前环境检查未通过或保存配置已变化；运行配置未修改")

// This report is diagnostic, never an apply capability. Empty import checks an
// API route without writing samples; real collection receipts must still prove
// persistence. No target address, DSN, local path, key ID or raw error escapes.
type configurationEnvironmentReport struct {
	Stage                   string                    `json:"stage"`
	Generation              int64                     `json:"generation,string"`
	CheckedAt               time.Time                 `json:"checked_at"`
	Local                   configurationLocalReport  `json:"local"`
	Checks                  []configurationLocalCheck `json:"checks"`
	PreflightPassed         bool                      `json:"preflight_passed"`
	RequiresRuntimeReceipts bool                      `json:"requires_runtime_receipts"`
	RequiresCenterRestart   bool                      `json:"requires_center_restart"`
	NodesChanged            int                       `json:"nodes_changed"`
}

func configurationEnvironmentConfig(doc configurationDocument) (Config, error) {
	var c Config
	raw, e := json.Marshal(doc.Bootstrap)
	if e != nil {
		return c, errConfigurationEnvironment
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if d.Decode(&c) != nil || c.Validate() != nil {
		return Config{}, errConfigurationEnvironment
	}
	return c, nil
}

// Trusted local diagnostic only. A source file identifies an already saved
// intent; it cannot supply probe destinations, paths, credentials or commands.
func (s *Store) localConfigurationEnvironmentCommand(ctx context.Context, c Config, o Options, out io.Writer) error {
	stage, e := configurationEnvironmentInput(o.Source)
	if e != nil {
		return errConfigurationEnvironment
	}
	v, e := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
	if e != nil {
		return errConfigurationEnvironment
	}
	r, e := s.inspectSavedConfigurationEnvironment(ctx, v, c, o.Username, stage)
	if e != nil {
		return errConfigurationEnvironment
	}
	if e = json.NewEncoder(out).Encode(r); e != nil {
		return e
	}
	if !r.PreflightPassed {
		return errConfigurationEnvironment
	}
	return nil
}

func configurationEnvironmentInput(path string) (string, error) {
	raw, e := readTrustData(path, true, 4096)
	defer clear(raw)
	if e != nil || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return "", errConfigurationEnvironment
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if !uniqueProvisioningJSON(d, 0) || d.Decode(new(any)) != io.EOF {
		return "", errConfigurationEnvironment
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 1 {
		return "", errConfigurationEnvironment
	}
	stage, e := configurationRestoreString(fields, "stage")
	if e != nil {
		return "", errConfigurationEnvironment
	}
	return stage, nil
}

// Network work deliberately runs outside the configuration relation gate.
// After probes, re-open the saved proof and local files before returning. A
// changed account, archive, deployment, desired state or DSN invalidates the
// entire diagnostic; an old report cannot authorize later application.
func (s *Store) inspectSavedConfigurationEnvironment(ctx context.Context, v *Vault, c Config, user, stage string) (configurationEnvironmentReport, error) {
	return s.inspectApplicationEnvironment(ctx, v, c, user, stage, nil)
}

func (s *Store) inspectApplicationEnvironment(ctx context.Context, v *Vault, c Config, user, stage string, application *privateConfigurationApplication) (configurationEnvironmentReport, error) {
	out := configurationEnvironmentReport{Stage: stage, CheckedAt: time.Now().UTC(), Checks: []configurationLocalCheck{}, RequiresRuntimeReceipts: true}
	if !validArchiveSource(stage) {
		return out, errConfigurationEnvironment
	}
	op, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	load := func() (configurationSavedReceipt, configurationDocument, error) {
		tx, e := s.DB.BeginTx(op, nil)
		if e != nil {
			return configurationSavedReceipt{}, configurationDocument{}, e
		}
		defer tx.Rollback()
		receipt, doc, e := loadSavedConfigurationForApplicationTx(op, tx, v, c, user, stage, true, application)
		if e != nil {
			return receipt, doc, e
		}
		return receipt, doc, tx.Commit()
	}
	receipt, doc, e := load()
	if e != nil {
		return out, e
	}
	out.Generation, out.RequiresCenterRestart, out.NodesChanged = receipt.Generation, receipt.RequiresCenterRestart, receipt.NodesChanged
	out.Local, e = checkConfigurationLocalMaterial(op, doc, v, time.Now().UTC())
	if e != nil {
		return out, errConfigurationEnvironment
	}
	// No network call if the immutable candidate cannot be reconstructed or any
	// required local material is missing. The caller must not disable checks.
	if !out.Local.LocalChecksPassed {
		return out, nil
	}
	target, e := configurationEnvironmentConfig(doc)
	if e != nil {
		return out, e
	}
	rawDSN, e := readTrustData(target.Database.DSNFile, true, 64<<10)
	defer clear(rawDSN)
	if e != nil {
		return out, errConfigurationEnvironment
	}
	network, stop := context.WithTimeout(op, 10*time.Second)
	defer stop()
	var wg sync.WaitGroup
	checks := make([]configurationLocalCheck, 3)
	if target.Metrics.RawURL != "" {
		checks = append(checks, configurationLocalCheck{}, configurationLocalCheck{})
	}
	wg.Add(3)
	go func() { defer wg.Done(); checks[0] = s.checkConfigurationDatabase(network, rawDSN) }()
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxIdleConns: 2, MaxIdleConnsPerHost: 1, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	go func() {
		defer wg.Done()
		checks[1] = checkConfigurationMetricsQuery(network, client, target.Metrics.QueryURL)
	}()
	go func() {
		defer wg.Done()
		checks[2] = checkConfigurationMetricsImport(network, client, target.Metrics.WriteURL)
	}()
	if target.Metrics.RawURL != "" {
		wg.Add(2)
		go func() {
			defer wg.Done()
			checks[3] = checkConfigurationMetricsQuery(network, client, target.Metrics.RawURL)
			checks[3].Component = "raw_metrics_query_api"
		}()
		go func() {
			defer wg.Done()
			checks[4] = checkConfigurationMetricsImport(network, client, target.Metrics.RawURL)
			checks[4].Component = "raw_metrics_write_api"
		}()
	}
	wg.Wait()
	out.Checks = checks
	if e = op.Err(); e != nil {
		return out, e
	}
	// Authenticate again after releasing all probe connections. Never carry a
	// long table lock across DNS, TLS, proxy, database or HTTP operations.
	final, current, e := load()
	if e != nil {
		return out, e
	}
	if final.Generation != receipt.Generation || !configurationRestoreEqual(doc.Bootstrap, current.Bootstrap) {
		return out, errConfigurationEnvironment
	}
	out.Local, e = checkConfigurationLocalMaterial(op, current, v, time.Now().UTC())
	if e != nil {
		return out, errConfigurationEnvironment
	}
	latest, e := readTrustData(target.Database.DSNFile, true, 64<<10)
	defer clear(latest)
	if e != nil || !bytes.Equal(rawDSN, latest) {
		return out, errConfigurationEnvironment
	}
	out.PreflightPassed = out.Local.LocalChecksPassed
	for _, check := range checks {
		out.PreflightPassed = out.PreflightPassed && check.Status == "passed"
	}
	return out, nil
}

func environmentCheck(component, reason string, ok bool) configurationLocalCheck {
	status := "failed"
	if ok {
		status = "passed"
	}
	return configurationLocalCheck{component, status, reason}
}

// Check actual source identity, not equal-looking configuration, table counts,
// a copied cluster row or a server hostname. PostgreSQL advisory locks are local
// to one database on one server; a fresh private challenge held by the current
// store must be visible to the independently opened target transaction. A
// replica/different database/copy cannot pass. Relation OIDs also bind search_path.
// No SQL writes, schema migration, credential persistence or BindCluster occurs.
func (s *Store) checkConfigurationDatabase(ctx context.Context, raw []byte) configurationLocalCheck {
	fail := func(reason string) configurationLocalCheck { return environmentCheck("database", reason, false) }
	cfg, e := pgx.ParseConfig(strings.TrimSpace(string(raw)))
	if e != nil {
		return fail("database_credentials_invalid")
	}
	cfg.ConnectTimeout = 3 * time.Second
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = make(map[string]string)
	}
	cfg.RuntimeParams["statement_timeout"] = "3000"
	cfg.RuntimeParams["lock_timeout"] = "1000"
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "5000"
	target := stdlib.OpenDB(*cfg)
	defer target.Close()
	target.SetMaxOpenConns(1)
	target.SetMaxIdleConns(0)
	source, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return fail("database_source_unavailable")
	}
	defer source.Rollback()
	var stamp [8]byte
	held := false
	var challenge int64
	for tries := 0; tries < 3; tries++ {
		if _, e = rand.Read(stamp[:]); e != nil {
			return fail("database_identity_unavailable")
		}
		challenge = int64(binary.BigEndian.Uint64(stamp[:]))
		if e = source.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1::bigint)`, challenge).Scan(&held); e != nil {
			return fail("database_identity_unavailable")
		}
		if held {
			break
		}
	}
	if !held {
		return fail("database_identity_unavailable")
	}
	var sourceRelations string
	const relations = `SELECT json_build_array(current_schema(),to_regclass('v3_schema')::oid,to_regclass('v3_settings')::oid,to_regclass('v3_nodes')::oid,to_regclass('v3_configuration_restore_commits')::oid)::text`
	if e = source.QueryRowContext(ctx, relations).Scan(&sourceRelations); e != nil {
		return fail("database_source_unavailable")
	}
	tx, e := target.BeginTx(ctx, nil)
	if e != nil {
		return fail("database_connection_failed")
	}
	defer tx.Rollback()
	var acquired, readOnly bool
	var targetRelations string
	if e = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1::bigint),pg_is_in_recovery() OR current_setting('transaction_read_only')='on'`, challenge).Scan(&acquired, &readOnly); e != nil {
		return fail("database_identity_unavailable")
	}
	if acquired {
		return fail("database_identity_mismatch")
	}
	if readOnly {
		return fail("database_read_only")
	}
	if e = tx.QueryRowContext(ctx, relations).Scan(&targetRelations); e != nil || sourceRelations != targetRelations || strings.Contains(targetRelations, "null") {
		return fail("database_schema_mismatch")
	}
	var version int
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE(max(version),0) FROM v3_schema`).Scan(&version); e != nil || version != SchemaVersion {
		return fail("database_schema_mismatch")
	}
	var allowed bool
	// has_table_privilege's comma list means ANY privilege, not ALL. Check each
	// required privilege individually, including partitions, sequences and RLS.
	e = tx.QueryRowContext(ctx, `SELECT
 has_schema_privilege(current_user,(SELECT relnamespace FROM pg_class WHERE oid=to_regclass('v3_schema')),'USAGE') AND
 has_schema_privilege(current_user,(SELECT relnamespace FROM pg_class WHERE oid=to_regclass('v3_schema')),'CREATE') AND
 NOT EXISTS(SELECT 1 FROM pg_class WHERE relnamespace=(SELECT relnamespace FROM pg_class WHERE oid=to_regclass('v3_schema')) AND left(relname,3)='v3_' AND (
 (relkind IN ('r','p') AND (relrowsecurity OR NOT has_table_privilege(current_user,oid,'SELECT') OR NOT has_table_privilege(current_user,oid,'INSERT') OR NOT has_table_privilege(current_user,oid,'UPDATE') OR NOT has_table_privilege(current_user,oid,'DELETE'))) OR
 (relkind='S' AND (NOT has_sequence_privilege(current_user,oid,'USAGE') OR NOT has_sequence_privilege(current_user,oid,'SELECT') OR NOT has_sequence_privilege(current_user,oid,'UPDATE')))))`).Scan(&allowed)
	if e != nil || !allowed {
		return fail("database_permissions_insufficient")
	}
	return environmentCheck("database", "same_writable_database_verified", true)
}

// Empty import is explicitly not a disk or end-to-end sample persistence test.
func checkConfigurationMetricsImport(ctx context.Context, client *http.Client, endpoint string) configurationLocalCheck {
	fail := func(reason string) configurationLocalCheck {
		return environmentCheck("metrics_write_api", reason, false)
	}
	request, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(endpoint, "/")+"/api/v1/import", http.NoBody)
	if e != nil {
		return fail("metrics_write_unavailable")
	}
	request.Header.Set("Content-Type", "application/stream+json")
	response, e := client.Do(request)
	if e != nil {
		return fail("metrics_write_unavailable")
	}
	defer response.Body.Close()
	n, e := io.Copy(io.Discard, io.LimitReader(response.Body, 4097))
	if e != nil || n > 4096 || response.StatusCode/100 != 2 {
		return fail("metrics_write_rejected")
	}
	return environmentCheck("metrics_write_api", "empty_import_accepted_requires_sample_receipt", true)
}
func checkConfigurationMetricsQuery(ctx context.Context, client *http.Client, endpoint string) configurationLocalCheck {
	fail := func(reason string) configurationLocalCheck {
		return environmentCheck("metrics_query_api", reason, false)
	}
	now := time.Now().UTC()
	q := url.Values{"query": {"vector(1)"}, "time": {strconv.FormatInt(now.Unix(), 10)}}
	request, e := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(endpoint, "/")+"/api/v1/query?"+q.Encode(), nil)
	if e != nil {
		return fail("metrics_query_unavailable")
	}
	response, e := client.Do(request)
	if e != nil {
		return fail("metrics_query_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fail("metrics_query_rejected")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if e != nil || len(raw) > 64<<10 {
		return fail("metrics_query_response_invalid")
	}
	var out struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Value []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Status != "success" || out.Data.ResultType != "vector" || len(out.Data.Result) != 1 || len(out.Data.Result[0].Value) != 2 {
		return fail("metrics_query_response_invalid")
	}
	var at float64
	var value string
	if json.Unmarshal(out.Data.Result[0].Value[0], &at) != nil || json.Unmarshal(out.Data.Result[0].Value[1], &value) != nil {
		return fail("metrics_query_response_invalid")
	}
	number, e := strconv.ParseFloat(value, 64)
	if e != nil || number != 1 || math.IsNaN(at) || math.IsInf(at, 0) || math.Abs(at-float64(now.Unix())) > 1 {
		return fail("metrics_query_response_invalid")
	}
	return environmentCheck("metrics_query_api", "instant_query_verified", true)
}
