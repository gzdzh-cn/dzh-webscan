package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"time"

	"webscan/internal/common"
)

type configurationBootstrapRuntime struct {
	store             *Store
	vault             *Vault
	launch, bootstrap Config
}

func (r configurationBootstrapRuntime) SupportsConfigurationPhase(phase string) bool {
	return phase == "bootstrap" || phase == "restore-bootstrap"
}
func (r configurationBootstrapRuntime) InspectConfigurationPhase(ctx context.Context, j privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	return r.bootstrapPhase(ctx, j, false)
}
func (r configurationBootstrapRuntime) ApplyConfigurationPhase(ctx context.Context, j privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	return r.bootstrapPhase(ctx, j, true)
}

// Build the exact plan inside the application relation gate. This performs no
// networking; callers probe the bound DSN outside the transaction then rebuild
// and compare the plan before approving any restart.
func (r configurationBootstrapRuntime) bootstrapPlanTx(ctx context.Context, tx *sql.Tx, j privateConfigurationApplication, anchor *Vault) (bootstrapHandoffPayload, configurationDocument, error) {
	var p bootstrapHandoffPayload
	saved, doc, err := applicationSavedEvidenceTx(ctx, tx, r.vault, j)
	if err != nil {
		return p, doc, err
	}
	p.Epoch = j.epoch
	p.Launch, err = configurationBootstrapValues(r.launch)
	if err != nil {
		return p, doc, err
	}
	if j.Direction == "forward" {
		d, err := readBootstrapDraftTx(ctx, tx, r.vault, r.bootstrap)
		if err != nil {
			return p, doc, err
		}
		if d.Generation != saved.Bootstrap.Generation || d.AppliedGeneration != saved.Bootstrap.AppliedGeneration || !configurationRestoreEqual(d.Desired, doc.Bootstrap) {
			return p, doc, errBootstrapRuntime
		}
		p.Before, p.Target, p.DraftGeneration, p.BeforeApplied = d.Runtime, d.Desired, d.Generation, d.AppliedGeneration
	} else {
		var revision int64
		err = tx.QueryRowContext(ctx, `SELECT revision FROM v3_bootstrap_handoffs WHERE job=$1 AND phase='bootstrap'`, j.ID).Scan(&revision)
		if errors.Is(err, sql.ErrNoRows) {
			if j.step > 2 && saved.RequiresCenterRestart {
				return p, doc, errBootstrapRuntime
			}
			d, e := readBootstrapDraftTx(ctx, tx, r.vault, r.bootstrap)
			if e != nil || d.Generation != saved.Bootstrap.Generation || !configurationRestoreEqual(d.Desired, doc.Bootstrap) {
				return p, doc, errBootstrapRuntime
			}
			p.Before, p.Target, p.DraftGeneration, p.BeforeApplied = d.Runtime, d.Runtime, d.Generation, d.AppliedGeneration
			return p, doc, nil
		}
		if err != nil {
			return p, doc, err
		}
		forward, err := readBootstrapHandoffTx(ctx, tx, anchor, j.member, revision)
		if err != nil {
			return p, doc, err
		}
		p.Target = forward.Payload.Before
		p.RequiredRoles = forward.Payload.RequiredRoles
		base := forward.Payload.Before
		if forward.Confirmation != "" {
			base = forward.Payload.Target
		}
		c, err := bootstrapConfig(base)
		if err != nil {
			return p, doc, err
		}
		d, err := readBootstrapDraftTx(ctx, tx, r.vault, c)
		if err != nil || d.Generation != forward.Payload.DraftGeneration {
			return p, doc, errBootstrapRuntime
		}
		p.Before, p.DraftGeneration, p.BeforeApplied = d.Runtime, d.Generation, forward.Payload.BeforeApplied
	}
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(max(revision),0) FROM v3_bootstrap_handoffs WHERE member=$1`, j.member).Scan(&p.Previous); err != nil {
		return p, doc, err
	}
	if j.Direction == "forward" && !configurationRestoreEqual(p.Before, p.Target) {
		processes, err := liveBootstrapProcessesTx(ctx, tx, r.vault, j.member)
		if err != nil || len(processes) == 0 {
			return p, doc, errBootstrapRuntime
		}
		for _, process := range processes {
			if process.Activation != p.Previous || process.RuntimeDigest != digest(common.JSON(p.Before)) || process.LaunchDigest != digest(common.JSON(p.Launch)) {
				return p, doc, errBootstrapRuntime
			}
		}
		p.RequiredRoles = bootstrapRoles(processes)
	}
	return p, doc, nil
}

func (r configurationBootstrapRuntime) bootstrapPhase(ctx context.Context, expected privateConfigurationApplication, apply bool) (configurationApplicationCheckpoint, error) {
	var empty configurationApplicationCheckpoint
	if r.store == nil || r.vault == nil || r.launch.Validate() != nil || r.bootstrap.Validate() != nil || r.launch.Central.Instance != expected.member || r.bootstrap.Central.Instance != expected.member || !r.SupportsConfigurationPhase(expected.phase()) {
		return empty, errBootstrapRuntime
	}
	anchor, err := bootstrapVaults(r.launch)
	if err != nil || anchor == nil {
		return empty, errBootstrapRuntime
	}
	// Two short, fenced transactions surround the real database identity probe.
	var planned bootstrapHandoffPayload
	var dsn []byte
	defer func() { clear(dsn) }()
	for round := 0; round < 2; round++ {
		op, cancel := context.WithTimeout(ctx, 10*time.Second)
		tx, err := r.store.DB.BeginTx(op, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
		if err != nil {
			cancel()
			return empty, err
		}
		finish := func() { _ = tx.Rollback(); cancel() }
		if held, e := migrationHeld(op, tx); e != nil || held {
			finish()
			if e != nil {
				return empty, e
			}
			return empty, ErrMigrationPending
		}
		j, err := lockedApplication(op, tx, r.vault, expected)
		if err != nil {
			finish()
			return empty, err
		}
		if !j.RecoveryRequired || j.member != r.launch.Central.Instance || j.Direction == "forward" && j.phase() != "bootstrap" || j.Direction == "rollback" && j.phase() != "restore-bootstrap" {
			finish()
			return empty, errBootstrapRuntime
		}
		if _, _, err = applicationSavedEvidenceTx(op, tx, r.vault, j); err != nil {
			finish()
			return empty, err
		}
		var revision int64
		err = tx.QueryRowContext(op, `SELECT revision FROM v3_bootstrap_handoffs WHERE job=$1 AND phase=$2`, j.ID, j.phase()).Scan(&revision)
		if err == nil {
			h, e := readBootstrapHandoffTx(op, tx, anchor, j.member, revision)
			if e != nil {
				finish()
				return empty, e
			}
			p, e := r.inspectBootstrapHandoffTx(op, tx, j, h)
			if e != nil {
				finish()
				return empty, e
			}
			e = tx.Commit()
			cancel()
			return p, e
		}
		if !errors.Is(err, sql.ErrNoRows) {
			finish()
			return empty, err
		}
		p, doc, err := r.bootstrapPlanTx(op, tx, j, anchor)
		if err != nil {
			finish()
			return empty, err
		}
		// No startup change means no approved override and no process restart.
		// Rollback with an existing forward override must supersede that override
		// even if it never started and its original runtime is still running.
		if configurationRestoreEqual(p.Before, p.Target) && len(p.RequiredRoles) == 0 {
			e := tx.Commit()
			cancel()
			return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "complete", j.epoch}, e
		}
		if !apply {
			e := tx.Commit()
			cancel()
			return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "absent", j.epoch}, e
		}
		target, e := bootstrapConfig(p.Target)
		if e != nil || target.Central.Topology != r.launch.Central.Topology || target.Central.Instance != r.launch.Central.Instance || target.Collector.Shards != r.launch.Collector.Shards {
			finish()
			return empty, errBootstrapRuntime
		}
		doc.Bootstrap = p.Target
		local, e := checkConfigurationLocalMaterial(op, doc, r.vault, time.Now().UTC())
		if e != nil || !local.LocalChecksPassed {
			finish()
			return empty, errBootstrapRuntime
		}
		raw, e := readTrustData(target.Database.DSNFile, true, 64<<10)
		if e != nil {
			finish()
			return empty, errBootstrapRuntime
		}
		if round == 0 {
			planned, dsn = p, raw
			if e = tx.Commit(); e != nil {
				cancel()
				return empty, e
			}
			cancel()
			probe, stop := context.WithTimeout(ctx, 10*time.Second)
			check := r.store.checkConfigurationDatabase(probe, dsn)
			stop()
			if check.Status != "passed" {
				return empty, errBootstrapRuntime
			}
			if err := checkBootstrapListener(p); err != nil {
				return empty, err
			}
			continue
		}
		if digest(raw) != digest(dsn) || !configurationRestoreEqual(configurationValues{"plan": p}, configurationValues{"plan": planned}) {
			clear(raw)
			finish()
			return empty, errBootstrapRuntime
		}
		clear(raw)
		h := privateBootstrapHandoff{Job: j.ID, Phase: j.phase(), Member: j.member, Key: anchor.active, Payload: p}
		if err = tx.QueryRowContext(op, `SELECT nextval(pg_get_serial_sequence('v3_bootstrap_handoffs','revision')),clock_timestamp()`).Scan(&h.Revision, &h.Created); err != nil {
			finish()
			return empty, err
		}
		body, e := json.Marshal(p)
		if e != nil || len(body) > 6<<20 {
			clear(body)
			finish()
			return empty, errBootstrapRuntime
		}
		aead := anchor.keys[anchor.active]
		nonce := make([]byte, aead.NonceSize())
		if _, e = rand.Read(nonce); e != nil {
			clear(body)
			finish()
			return empty, e
		}
		sealed := aead.Seal(nil, nonce, body, handoffAAD(h))
		clear(body)
		_, err = tx.ExecContext(op, `INSERT INTO v3_bootstrap_handoffs(revision,job,phase,member,key_id,nonce,ciphertext,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, h.Revision, h.Job, h.Phase, h.Member, h.Key, nonce, sealed, h.Created)
		clear(sealed)
		if err != nil {
			finish()
			return empty, err
		}
		if _, err = lockedApplication(op, tx, r.vault, j); err != nil {
			finish()
			return empty, err
		}
		_, err = tx.ExecContext(op, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-bootstrap-approved',$2,$3)`, j.Controller, j.ID, common.JSON(map[string]any{"phase": j.phase(), "waiting_for_restart": true}))
		if err != nil {
			finish()
			return empty, err
		}
		err = tx.Commit()
		cancel()
		return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "pending", j.epoch}, err
	}
	return empty, errBootstrapRuntime
}

// Probe a changed API listener before authorizing the restart, outside the
// relation gate. Never disturb a process already using the target address.
// Serve still binds it again synchronously because availability may change.
func checkBootstrapListener(p bootstrapHandoffPayload) error {
	before, err := bootstrapConfig(p.Before)
	if err != nil {
		return errBootstrapRuntime
	}
	target, err := bootstrapConfig(p.Target)
	if err != nil {
		return errBootstrapRuntime
	}
	if before.Central.Listen == target.Central.Listen {
		return nil
	}
	for _, role := range p.RequiredRoles {
		if role == "api" || role == "all" {
			listener, err := net.Listen("tcp", target.Central.Listen)
			if err != nil {
				return errors.New("目标后台监听地址不可用，请检查地址及端口占用；尚未批准重启")
			}
			return listener.Close()
		}
	}
	return nil
}

func (r configurationBootstrapRuntime) inspectBootstrapHandoffTx(ctx context.Context, tx *sql.Tx, j privateConfigurationApplication, h privateBootstrapHandoff) (configurationApplicationCheckpoint, error) {
	empty := configurationApplicationCheckpoint{}
	pending := func() (configurationApplicationCheckpoint, error) {
		if time.Since(h.Created) > 10*time.Minute {
			return empty, errBootstrapRuntime
		}
		return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "pending", j.epoch}, nil
	}
	var latest int64
	if err := tx.QueryRowContext(ctx, `SELECT max(revision) FROM v3_bootstrap_handoffs WHERE member=$1`, j.member).Scan(&latest); err != nil {
		return empty, err
	}
	launch, err := configurationBootstrapValues(r.launch)
	if err != nil || latest != h.Revision || !configurationRestoreEqual(launch, h.Payload.Launch) {
		return empty, errBootstrapRuntime
	}
	target, err := bootstrapConfig(h.Payload.Target)
	if err != nil {
		return empty, err
	}
	base := h.Payload.Before
	if h.Confirmation != "" {
		base = h.Payload.Target
	}
	c, err := bootstrapConfig(base)
	if err != nil {
		return empty, err
	}
	d, err := readBootstrapDraftTx(ctx, tx, r.vault, c)
	if err != nil || d.Generation != h.Payload.DraftGeneration {
		return empty, errBootstrapRuntime
	}
	if h.Confirmation != "" {
		return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "complete", j.epoch}, nil
	}
	processes, err := liveBootstrapProcessesTx(ctx, tx, r.vault, j.member)
	if err != nil {
		return empty, err
	}
	roles := map[string]bool{}
	for _, p := range processes {
		if p.Activation != h.Revision || p.RuntimeDigest != digest(common.JSON(h.Payload.Target)) || p.LaunchDigest != digest(common.JSON(h.Payload.Launch)) || p.Started.Before(h.Created) {
			return pending()
		}
		roles[p.Role] = true
	}
	for _, role := range h.Payload.RequiredRoles {
		if !roles[role] {
			return pending()
		}
	}
	// Confirmation records actual fresh process evidence. A successful restart
	// request alone never advances this phase or its draft application marker.
	applied := h.Payload.BeforeApplied
	if configurationRestoreEqual(d.Desired, h.Payload.Target) {
		applied = d.Generation
	}
	baseDigest := digest(common.JSON(h.Payload.Target))
	proof, err := bootstrapDraftProof(r.vault, r.vault.active, j.member, d.Generation, applied, baseDigest, d.Desired)
	if err != nil {
		return empty, err
	}
	if d.Generation > 0 {
		if _, err = tx.ExecContext(ctx, `UPDATE v3_bootstrap_drafts SET runtime_digest=$2,applied_generation=$3,proof=$4,updated_at=clock_timestamp() WHERE instance=$1`, j.member, baseDigest, applied, proof); err != nil {
			return empty, err
		}
	}
	confirmation, err := bootstrapProof(r.vault, r.vault.active, "confirmed", h.Revision, j.planProof, baseDigest, h.Payload.DraftGeneration)
	if err != nil {
		return empty, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v3_bootstrap_handoffs SET confirmation=$2 WHERE revision=$1`, h.Revision, confirmation); err != nil {
		return empty, err
	}
	if _, err = readBootstrapDraftTx(ctx, tx, r.vault, target); err != nil {
		return empty, err
	}
	if _, err = lockedApplication(ctx, tx, r.vault, j); err != nil {
		return empty, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'configuration-bootstrap-confirmed',$2,$3)`, j.Controller, j.ID, common.JSON(map[string]any{"phase": j.phase(), "roles": h.Payload.RequiredRoles}))
	return configurationApplicationCheckpoint{j.ID, j.planProof, j.phase(), "complete", j.epoch}, err
}
