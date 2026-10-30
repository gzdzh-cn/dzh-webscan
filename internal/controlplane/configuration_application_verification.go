package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"webscan/internal/common"
)

// Verification reads the real workers' state. It neither applies missing
// phases nor repairs missing receipts. Launch is the independently retained
// startup anchor; bootstrap is this process's trusted effective configuration.
type configurationVerificationRuntime struct {
	store             *Store
	vault             *Vault
	launch, bootstrap Config
	roles             []string
}

func (r configurationVerificationRuntime) SupportsConfigurationPhase(phase string) bool {
	return phase == "verify" || phase == "finalize" || phase == "verify-rollback"
}
func (r configurationVerificationRuntime) valid() bool {
	if r.store == nil || r.vault == nil || r.launch.Validate() != nil || r.bootstrap.Validate() != nil || r.launch.Central.Instance != r.bootstrap.Central.Instance || len(r.roles) == 0 || len(r.roles) > 6 {
		return false
	}
	seen := map[string]bool{}
	for _, role := range r.roles {
		if !validServiceRole(role) || seen[role] {
			return false
		}
		seen[role] = true
	}
	return true
}
func (r configurationVerificationRuntime) InspectConfigurationPhase(ctx context.Context, p privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	return r.verifyPhase(ctx, p, false)
}
func (r configurationVerificationRuntime) ApplyConfigurationPhase(ctx context.Context, p privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	return r.verifyPhase(ctx, p, false)
}
func (r configurationVerificationRuntime) checkpointConfigurationPhase(ctx context.Context, p privateConfigurationApplication, proof configurationApplicationCheckpoint) error {
	if !proof.matches(p) {
		return errConfigurationApplication
	}
	_, err := r.verifyPhase(ctx, p, true)
	return err
}

func (r configurationVerificationRuntime) verifyPhase(ctx context.Context, expected privateConfigurationApplication, commit bool) (configurationApplicationCheckpoint, error) {
	var empty configurationApplicationCheckpoint
	if !r.valid() || !r.SupportsConfigurationPhase(expected.phase()) || expected.member != r.bootstrap.Central.Instance {
		return empty, errConfigurationApplication
	}
	op, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	// Authenticate before network probes. Repeat every SQL/runtime check after
	// probes, with no relation or lease lock held over networking.
	tx, err := r.store.DB.BeginTx(op, nil)
	if err != nil {
		return empty, err
	}
	if _, err = lockedApplication(op, tx, r.vault, expected); err == nil {
		err = applicationSourceTx(op, tx, r.vault, expected)
	}
	tx.Rollback()
	if err != nil {
		return empty, err
	}
	if err = r.verifyDependencies(op); err != nil {
		return empty, err
	}
	tx, err = r.store.DB.BeginTx(op, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if held, e := migrationHeld(op, tx); e != nil {
		return empty, e
	} else if held {
		return empty, ErrMigrationPending
	}
	p, err := lockedApplication(op, tx, r.vault, expected)
	if err != nil {
		return empty, err
	}
	if !p.RecoveryRequired {
		return empty, errConfigurationApplication
	}
	saved, doc, err := applicationSavedEvidenceTx(op, tx, r.vault, p)
	if err != nil {
		return empty, err
	}
	if err = r.verifySettingsTx(op, tx, p, saved, doc); err != nil {
		return empty, err
	}
	if err = r.verifyBootstrapTx(op, tx, p, saved, doc); err != nil {
		return empty, err
	}
	if err = r.verifyNodesTx(op, tx, p, doc); err != nil {
		return empty, err
	}
	if _, err = lockedApplication(op, tx, r.vault, p); err != nil {
		return empty, err
	}
	proof := configurationApplicationCheckpoint{p.ID, p.planProof, p.phase(), "complete", p.epoch}
	if commit {
		if _, err = tx.ExecContext(op, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-application-verified',$2,$3)`, p.Controller, p.ID, common.JSON(map[string]any{"phase": p.phase(), "nodes": len(doc.Nodes), "roles": len(r.roles)})); err != nil {
			return empty, err
		}
		if _, err = lockedApplication(op, tx, r.vault, p); err != nil {
			return empty, err
		}
		next, e := r.store.checkpointConfigurationApplicationTx(op, tx, r.vault, p)
		if e != nil {
			return empty, e
		}
		if next.Status == "succeeded" || next.Status == "rolled_back" {
			if err = releaseVerifiedApplicationArchivesTx(op, tx, p); err != nil {
				return empty, err
			}
		}
		var alive bool
		if err = tx.QueryRowContext(op, `SELECT $1::timestamptz>clock_timestamp()`, p.leaseUntil).Scan(&alive); err != nil {
			return empty, err
		}
		if !alive {
			return empty, ErrLeaseLost
		}
	}
	return proof, tx.Commit()
}

func (r configurationVerificationRuntime) verifyDependencies(ctx context.Context) error {
	raw, err := readTrustData(r.bootstrap.Database.DSNFile, true, 64<<10)
	if err != nil {
		return errConfigurationApplication
	}
	defer clear(raw)
	probe, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	checks := make([]configurationLocalCheck, 3)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); checks[0] = r.store.checkConfigurationDatabase(probe, raw) }()
	go func() {
		defer wg.Done()
		checks[1] = checkConfigurationMetricsQuery(probe, client, r.bootstrap.Metrics.QueryURL)
	}()
	go func() {
		defer wg.Done()
		checks[2] = checkConfigurationMetricsImport(probe, client, r.bootstrap.Metrics.WriteURL)
	}()
	wg.Wait()
	for _, check := range checks {
		if check.Status != "passed" {
			return errConfigurationApplication
		}
	}
	current, err := readTrustData(r.bootstrap.Database.DSNFile, true, 64<<10)
	defer clear(current)
	if err != nil || digest(raw) != digest(current) {
		return errConfigurationApplication
	}
	return nil
}

func (r configurationVerificationRuntime) verifySettingsTx(ctx context.Context, tx *sql.Tx, p privateConfigurationApplication, saved configurationSavedReceipt, doc configurationDocument) error {
	phase := "settings"
	if p.Direction == "rollback" {
		phase = "restore-settings"
	}
	receipt, err := readApplicationSettingsTx(ctx, tx, r.vault, p, phase)
	if err != nil {
		return errConfigurationApplication
	}
	d, err := readSettingsDraftTx(ctx, tx, true)
	if err != nil {
		return err
	}
	if err = checkSettingsDraftProof(r.vault, d); err != nil {
		return err
	}
	if !sameApplicationSettings(d, privateSettingsDraft(receipt.After)) || d.Generation != saved.Settings.Generation || !configurationJSONEqual(d.Desired, common.JSON(doc.Settings)) {
		return ErrConflict
	}
	if p.Direction == "forward" {
		if d.Pending || d.AppliedGeneration != d.Generation || !configurationJSONEqual(d.Runtime, d.Desired) {
			return ErrConflict
		}
	} else {
		forward, e := readApplicationSettingsTx(ctx, tx, r.vault, p, "settings")
		if e == nil {
			if !sameApplicationSettings(privateSettingsDraft(receipt.Before), privateSettingsDraft(forward.After)) || !configurationJSONEqual(d.Runtime, forward.Before.Runtime) || d.AppliedGeneration != forward.Before.AppliedGeneration {
				return ErrConflict
			}
		} else if !errors.Is(e, sql.ErrNoRows) || p.step > 3 {
			return errConfigurationApplication
		}
	}
	return nil
}

func (r configurationVerificationRuntime) verifyBootstrapTx(ctx context.Context, tx *sql.Tx, p privateConfigurationApplication, saved configurationSavedReceipt, doc configurationDocument) error {
	d, err := readBootstrapDraftTx(ctx, tx, r.vault, r.bootstrap)
	if err != nil {
		return err
	}
	if d.Generation != saved.Bootstrap.Generation || !configurationRestoreEqual(d.Desired, doc.Bootstrap) {
		return ErrConflict
	}
	if p.Direction == "forward" && (d.Pending || !configurationRestoreEqual(d.Runtime, doc.Bootstrap)) {
		return ErrConflict
	}
	anchor, err := bootstrapVaults(r.launch)
	if err != nil || anchor == nil {
		return errBootstrapRuntime
	}
	phase := "bootstrap"
	if p.Direction == "rollback" {
		phase = "restore-bootstrap"
	}
	var own int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM v3_bootstrap_handoffs WHERE job=$1 AND phase=$2`, p.ID, phase).Scan(&own)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if own == 0 {
		if p.Direction == "forward" && saved.RequiresCenterRestart {
			return errBootstrapRuntime
		}
		if p.Direction == "rollback" {
			var forward bool
			if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_bootstrap_handoffs WHERE job=$1 AND phase='bootstrap')`, p.ID).Scan(&forward); err != nil {
				return err
			}
			if forward || p.step > 2 && saved.RequiresCenterRestart {
				return errBootstrapRuntime
			}
		}
	}
	latest, err := readBootstrapHandoffTx(ctx, tx, anchor, p.member, 0)
	activation := int64(0)
	var required []string
	if err == nil {
		if latest.Confirmation == "" || own > 0 && latest.Revision != own || !configurationRestoreEqual(latest.Payload.Target, d.Runtime) {
			return errBootstrapRuntime
		}
		activation = latest.Revision
		required = latest.Payload.RequiredRoles
	} else if !errors.Is(err, sql.ErrNoRows) || own > 0 {
		return errBootstrapRuntime
	}
	launch, err := configurationBootstrapValues(r.launch)
	if err != nil {
		return err
	}
	processes, err := liveBootstrapProcessesTx(ctx, tx, r.vault, p.member)
	if err != nil {
		return err
	}
	roles := map[string]bool{}
	for _, process := range processes {
		if process.Activation != activation || process.LaunchDigest != digest(common.JSON(launch)) || process.RuntimeDigest != digest(common.JSON(d.Runtime)) || activation > 0 && process.Started.Before(latest.Created) {
			return errBootstrapRuntime
		}
		roles[process.Role] = true
	}
	for _, role := range append(append([]string{}, r.roles...), required...) {
		if !roles[role] {
			return errBootstrapRuntime
		}
	}
	return nil
}

func (r configurationVerificationRuntime) verifyNodesTx(ctx context.Context, tx *sql.Tx, p privateConfigurationApplication, doc configurationDocument) error {
	// Take every current collector fence first, in deterministic order, before
	// any runtime/node row. Collectors always lock lease -> node -> evidence.
	rows, err := tx.QueryContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE enabled ORDER BY id`)
	if err != nil {
		return err
	}
	var active []Node
	shards := map[int]bool{}
	for rows.Next() {
		n, e := scanActiveNode(rows)
		if e != nil {
			rows.Close()
			return e
		}
		active = append(active, n)
		shards[n.Shard] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	keys := make([]int, 0, len(shards))
	for shard := range shards {
		keys = append(keys, shard)
	}
	sort.Ints(keys)
	for _, shard := range keys {
		var epoch int64
		if err = tx.QueryRowContext(ctx, `SELECT epoch FROM v3_leases WHERE resource=$1 AND expires_at>clock_timestamp() FOR SHARE`, shardResource(shard)).Scan(&epoch); err == sql.ErrNoRows {
			return ErrDeploymentNotReady
		} else if err != nil {
			return err
		}
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM v3_nodes WHERE removed_at IS NULL`).Scan(&count); err != nil {
		return err
	}
	if count != len(doc.Nodes) {
		return ErrConflict
	}
	for id := range doc.Nodes {
		n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR SHARE`, id))
		if e != nil || !applicationNodeMatches(doc, n) || n.Shard != Shard(id, r.bootstrap.Collector.Shards) {
			return ErrConflict
		}
		if p.Direction == "forward" && n.Enabled {
			current, e := scanActiveNode(tx.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, id))
			if e != nil || !applicationNodeMatches(doc, current) || n.AppliedVersion != n.Version {
				return ErrConflict
			}
			baseline, e := runtimeBaselineTx(ctx, tx, id)
			if e != nil || baseline.Delivered != n.Version {
				return ErrConflict
			}
		}
	}
	if err = r.store.verifyApplicationNodeOutcomesTx(ctx, tx, r.vault, p); err != nil {
		return err
	}
	for _, n := range active {
		baseline, e := runtimeBaselineTx(ctx, tx, n.ID)
		if e != nil || baseline.Epoch != n.RuntimeEpoch || baseline.Version != n.Version {
			return ErrConflict
		}
		if err = r.currentNodeReadyTx(ctx, tx, n); err != nil {
			return err
		}
	}
	return nil
}

func (r configurationVerificationRuntime) currentNodeReadyTx(ctx context.Context, tx *sql.Tx, n Node) error {
	if err := r.store.deploymentHealth(ctx, tx, n, 0, time.Time{}); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.kind,r.release FROM v3_node_readiness r JOIN v3_leases l ON l.resource=r.resource AND l.owner=r.owner AND l.epoch=r.epoch
 WHERE r.node=$1 AND r.node_version=$2 AND r.config_digest=$3 AND r.endpoint=$4 AND r.server_name=$5 AND r.resource=$6
 AND l.expires_at>clock_timestamp() AND r.checked_at>clock_timestamp()-interval '60 seconds'
 AND EXISTS(SELECT 1 FROM v3_node_status s WHERE s.node=r.node AND s.metrics_error='' AND s.events_error='' AND s.protocol_error='')
 AND (r.kind='events' OR (r.reported_version=$2 AND r.reported_digest=$3 AND r.sampled_at=(SELECT sampled_at FROM v3_node_status WHERE node=$1)
 AND r.sampled_at>=extract(epoch FROM clock_timestamp()-interval '60 seconds')*1000 AND r.sampled_at<=extract(epoch FROM clock_timestamp()+interval '5 seconds')*1000))
 ORDER BY r.kind FOR SHARE OF r,l`, n.ID, n.Version, digest(n.Config), n.Endpoint, n.ServerName, shardResource(n.Shard))
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var kind, release string
		if err = rows.Scan(&kind, &release); err != nil {
			return err
		}
		if kind == "metrics" && !releaseVersion.MatchString(release) {
			return ErrDeploymentNotReady
		}
		seen[kind] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if !seen["metrics"] || !seen["events"] {
		return ErrDeploymentNotReady
	}
	return nil
}

// Only a verified terminal transition releases the parent's two original
// rollback pins. Child archives, parent archives and the final journal commit
// together; failure cannot leave a partially unprotected recovery operation.
func releaseVerifiedApplicationArchivesTx(ctx context.Context, tx *sql.Tx, p privateConfigurationApplication) error {
	result, err := tx.ExecContext(ctx, `DELETE FROM v3_configuration_backup_pins WHERE kind='rollback' AND reference IN($1,$2) AND expires_at IS NULL`, "restore:"+p.Stage+":source", "restore:"+p.Stage+":before")
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 2 {
		return errConfigurationApplication
	}
	return nil
}
