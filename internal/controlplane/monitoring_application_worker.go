package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
	"webscan/internal/nodepki"
)

type monitoringApplicationWorker struct {
	store    *Store
	config   Config
	trust    *deploymentTrust
	runtime  DeploymentRuntime
	instance string
}

func NewMonitoringApplicationWorker(s *Store, c Config, t *deploymentTrust, r DeploymentRuntime, instance string) *monitoringApplicationWorker {
	return &monitoringApplicationWorker{s, c, t, r, instance}
}
func (w *monitoringApplicationWorker) Run(ctx context.Context) error {
	heartbeatDone := make(chan struct{})
	heartbeatContext, stopHeartbeat := context.WithCancel(ctx)
	defer func() { stopHeartbeat(); <-heartbeatDone }()
	go func() {
		defer close(heartbeatDone)
		heartbeat := time.NewTicker(5 * time.Second)
		defer heartbeat.Stop()
		for {
			w.heartbeat(heartbeatContext)
			select {
			case <-heartbeatContext.Done():
				return
			case <-heartbeat.C:
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		p, e := w.claim(ctx)
		if e == nil {
			w.execute(ctx, p)
			continue
		}
		if e != sql.ErrNoRows && ctx.Err() == nil {
			_, _ = w.store.DB.ExecContext(ctx, `INSERT INTO v3_role_status(role,instance,heartbeat,error) VALUES('monitoring-applications',$1,clock_timestamp(),'规则应用执行器暂不可用') ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error`, w.instance)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	return ctx.Err()
}
func (w *monitoringApplicationWorker) claim(ctx context.Context) (monitoringApplication, error) {
	var empty monitoringApplication
	if w.trust == nil || w.trust.vault == nil || w.trust.release == nil || w.runtime == nil || !identifier.MatchString(w.instance) {
		return empty, errMonitoringApplication
	}
	tx, e := w.store.DB.BeginTx(ctx, nil)
	if e != nil {
		return empty, e
	}
	defer tx.Rollback()
	if e = lockMonitoringWriteTx(ctx, tx); e != nil {
		return empty, e
	}
	p, e := scanMonitoringApplication(tx.QueryRowContext(ctx, `SELECT `+monitoringApplicationColumns+` FROM v3_monitoring_applications WHERE NOT recovery_hold AND (status='queued' OR status='running' AND lease_until<=clock_timestamp()) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`))
	if e != nil {
		return p, e
	}
	if e = openMonitoringApplication(w.trust.vault, &p); e != nil {
		return p, e
	}
	if p.Manifest != w.trust.release.SHA256() || p.Release != w.trust.release.manifest.Release {
		return p, ErrRequestConflict
	}
	rev, e := deploymentPreviewAccount(ctx, tx, p.Controller)
	if e != nil || rev != p.ControllerRevision {
		if e != nil && !errors.Is(e, ErrDeploymentPreview) && !errors.Is(e, sql.ErrNoRows) {
			return p, e
		}
		p.Status = "paused"
		p.Error = "account_reauthorization_required"
		p.Owner = sql.NullString{}
		p.Lease = sql.NullTime{}
		if e = updateMonitoringApplicationTx(ctx, tx, w.trust.vault, &p); e != nil {
			return p, e
		}
		if e = tx.Commit(); e != nil {
			return p, e
		}
		return p, sql.ErrNoRows
	}
	p.Status = "running"
	p.Epoch++
	p.Owner = sql.NullString{String: w.instance, Valid: true}
	p.Lease = sql.NullTime{Time: time.Now().Add(30 * time.Second), Valid: true}
	if e = updateMonitoringApplicationTx(ctx, tx, w.trust.vault, &p); e != nil {
		return p, e
	}
	return p, tx.Commit()
}
func (w *monitoringApplicationWorker) execute(parent context.Context, p monitoringApplication) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(8 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				res, e := w.store.DB.ExecContext(ctx, `UPDATE v3_monitoring_applications SET lease_until=clock_timestamp()+interval '30 seconds' WHERE id=$1 AND status='running' AND lease_owner=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() AND NOT recovery_hold`, p.ID, p.Owner.String, p.Epoch)
				if deploymentAffected(res, e) != nil {
					cancel()
					return
				}
			}
		}
	}()
	workErr := w.process(ctx, p)
	if ctx.Err() != nil {
		cancel()
		<-done
		return
	}
	// Keep renewing until the last checkpoint is committed; a renewal error
	// fences the entire parent, including every child journal operation.
	finish, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	tx, e := w.store.DB.BeginTx(finish, nil)
	if e == nil {
		defer tx.Rollback()
		current, e := lockMonitoringParentTx(finish, tx, w.trust.vault, p)
		if e == nil {
			if workErr != nil {
				current.Status = "paused"
				current.Error = "monitoring-application-failed"
			} else if current.Selected != "" {
				current.Status = "paused"
				current.Error = ""
				current.Selected = ""
				if current.Direction == "rollback" {
					current.Direction = "forward"
				}
			} else {
				current.Status = "succeeded"
				if current.Direction == "rollback" {
					current.Status = "rolled_back"
				}
				if e = releaseMonitoringApplicationTx(finish, tx, w.trust.vault, current); e != nil {
					current.Status = "paused"
					current.Error = "monitoring-application-recovery-required"
				}
			}
			current.Owner = sql.NullString{}
			current.Lease = sql.NullTime{}
			if updateMonitoringApplicationTx(finish, tx, w.trust.vault, &current) == nil {
				_ = tx.Commit()
			}
		}
	}
	cancel()
	<-done
}

type monitoringNodeWork struct {
	id, state, child string
	batch            int
}

func (w *monitoringApplicationWorker) work(ctx context.Context, p monitoringApplication) ([]monitoringNodeWork, error) {
	tx, e := w.store.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	p, e = lockMonitoringParentTx(ctx, tx, w.trust.vault, p)
	if e != nil {
		return nil, e
	}
	out, e := monitoringApplicationWorkTx(ctx, tx, w.trust.vault, p, false)
	if e != nil {
		return nil, e
	}
	return out, tx.Commit()
}
func (w *monitoringApplicationWorker) process(ctx context.Context, p monitoringApplication) error {
	items, e := w.work(ctx, p)
	if e != nil {
		return e
	}
	for len(items) > 0 {
		batch := items[0].batch
		end := 0
		for end < len(items) && items[end].batch == batch && end < 20 {
			end++
		}
		group := items[:end]
		items = items[end:]
		type result struct{ err error }
		done := make(chan result, 5)
		active, next := 0, 0
		var first error
		start := func(item monitoringNodeWork) { active++; go func() { done <- result{w.processNode(ctx, p, item)} }() }
		for active < 5 && next < len(group) {
			start(group[next])
			next++
		}
		for active > 0 {
			r := <-done
			active--
			if r.err != nil && first == nil {
				first = r.err
			}
			if first == nil && ctx.Err() == nil && next < len(group) {
				start(group[next])
				next++
			}
		}
		if first != nil {
			return first
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}
func (w *monitoringApplicationWorker) processNode(ctx context.Context, p monitoringApplication, item monitoringNodeWork) (result error) {
	phase := "inputs"
	defer func() {
		if result != nil {
			result = fmt.Errorf("monitoring %s: %w", phase, result)
		}
	}()
	scoped := monitoringNodeContext(ctx, w.trust.vault, p, item.id, "")
	defer func() {
		if ctx.Err() != nil {
			return
		}
		tx, e := w.store.DB.BeginTx(ctx, nil)
		if e != nil {
			if result == nil {
				result = e
			}
			return
		}
		defer tx.Rollback()
		if e = finishMonitoringNodeTx(ctx, tx, w.trust.vault, p, item.id, result); e == nil {
			e = tx.Commit()
		}
		if result == nil {
			result = e
		}
	}()
	if p.Direction == "rollback" && item.child == "" {
		return nil
	}
	if item.child != "" && p.Direction == "forward" {
		if _, e := w.store.prepareMonitoringNode(scoped, w.config, w.trust, p, item.id); e != nil {
			return e
		}
	}
	if item.child == "" {
		if p.Direction != "forward" {
			return ErrDeploymentState
		}
		phase = "save-target"
		n, e := w.store.prepareMonitoringNode(scoped, w.config, w.trust, p, item.id)
		if e != nil {
			return e
		}
		original, _ := p.node(item.id)
		if configurationJSONEqual(original.Before, original.Target) {
			return nil
		}
		phase = "credential"
		credential, c, e := w.store.latestWebCredential(ctx, w.trust.vault, n.ID)
		if e != nil {
			return e
		}
		if credential != original.Credential {
			return ErrCredentialUnavailable
		}
		host, _, e := net.SplitHostPort(n.Endpoint)
		if e != nil || host != c.Host {
			return ErrCredentialUnavailable
		}
		phase = "fingerprint"
		fingerprint, e := readSSHHostFingerprint(ctx, host, c.Port)
		if e != nil {
			return e
		}
		if fingerprint != c.Fingerprint {
			return errFingerprintChanged
		}
		phase = "identity"
		collector, e := collectorIdentityMaterial(w.config, time.Now())
		if e != nil {
			return e
		}
		defer clear(collector.Key)
		cert, e := provisioningCertificate(collector.Certificate)
		if e != nil {
			return e
		}
		collectorID, e := nodepki.PeerID(cert, nodepki.Collector)
		if e != nil {
			return e
		}
		input := deploymentPreparationInput{Node: n.ID, Expected: n.Version, Kind: "upgrade", Credential: credential, Collectors: []string{collectorID}, RulesFile: w.config.Executor.RulesFile}
		_, managed, e := managedNodeAuthority(scoped, w.store.DB, w.config, n)
		if e != nil {
			return e
		}
		if !managed {
			receipt, e := w.store.IssueNodeCertificate(scoped, w.config, w.trust.vault, p.Controller, "monitoring-identity-"+p.ID+"-"+n.ID, NodeCertificateInput{Node: n.ID, Expected: n.Version})
			if e != nil {
				return e
			}
			var identity NodeCertificateRecord
			if json.Unmarshal(receipt, &identity) != nil {
				return errNodeIdentity
			}
			input.IdentityID = identity.ID
		}
		phase = "signed-material"
		request, e := w.store.prepareLocalDeployment(scoped, w.config, w.trust, input)
		if e != nil {
			return e
		}
		phase = "queue"
		j, e := w.store.queueMonitoringNode(scoped, w.config, w.trust, p, request)
		if e != nil {
			return e
		}
		item.child = j.ID
	}
	phase = "claim-child"
	j, childContext, e := w.store.claimMonitoringNode(ctx, w.trust.vault, p, item.id)
	if e != nil {
		return e
	}
	if j.Status == "running" {
		if !w.trust.release.matches(j) {
			return ErrRequestConflict
		}
		phase = "execute-child"
		return (&DeploymentRunner{Store: w.store, Vault: w.trust.vault, Runtime: w.runtime}).Execute(childContext, j)
	}
	if j.Status != "succeeded" && j.Status != "rolled_back" {
		return errors.New("monitoring child did not complete")
	}
	return nil
}

func (w *monitoringApplicationWorker) heartbeat(ctx context.Context) {
	if w.trust == nil || w.trust.release == nil || w.trust.vault == nil {
		return
	}
	issuer, rules := (&webDeploymentWorker{config: w.config}).readiness()
	reason := ""
	if w.runtime == nil || !w.config.Executor.Enabled || !issuer || !rules {
		reason = "规则下发执行资料暂不可用"
	}
	_, _ = w.store.DB.ExecContext(ctx, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('monitoring-applications',$1,clock_timestamp(),$2,jsonb_build_object('manifest',$3::text,'vault',$4::text,'issuer',$5::boolean,'rules',$6::boolean)) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details=excluded.details`, w.instance, reason, w.trust.release.SHA256(), w.trust.vault.active, issuer, rules)
}
