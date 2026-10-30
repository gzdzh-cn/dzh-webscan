package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"sort"
)

// This deliberately partial adapter is used only inside the explicit opt-in
// composite. It cannot arm executeConfigurationApplication until the composite
// runtime supplies every remaining forward and rollback phase. Preparation is
// trusted local provisioning, not a browser-supplied path or command.
type configurationNodesRuntime struct {
	store     *Store
	vault     *Vault
	bootstrap Config
	trust     *deploymentTrust
	runtime   DeploymentRuntime
	prepare   func(context.Context, privateConfigurationApplication, string) (DeploymentRequest, error)
}

type applicationNodeWork struct {
	node         string
	child        *DeploymentJob
	registration bool
}

func (configurationNodesRuntime) SupportsConfigurationPhase(phase string) bool {
	return phase == "nodes" || phase == "restore-nodes"
}

func (r configurationNodesRuntime) InspectConfigurationPhase(ctx context.Context, p privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	work, err := r.nodeWork(ctx, p)
	if err != nil {
		return configurationApplicationCheckpoint{}, err
	}
	state := "complete"
	if len(work) != 0 {
		state = "absent"
	}
	return configurationApplicationCheckpoint{p.ID, p.planProof, p.phase(), state, p.epoch}, nil
}

func (r configurationNodesRuntime) ApplyConfigurationPhase(ctx context.Context, p privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	work, err := r.nodeWork(ctx, p)
	if err != nil {
		return configurationApplicationCheckpoint{}, err
	}
	for _, item := range work {
		if err := ctx.Err(); err != nil {
			return configurationApplicationCheckpoint{}, err
		}
		if item.registration {
			if err = r.store.applyApplicationRegistration(ctx, r.vault, p, item.node); err != nil {
				return configurationApplicationCheckpoint{}, err
			}
			continue
		}
		if r.runtime == nil {
			return configurationApplicationCheckpoint{}, errConfigurationApplication
		}
		if item.child == nil {
			if p.Direction != "forward" || r.prepare == nil || r.trust == nil {
				return configurationApplicationCheckpoint{}, errConfigurationApplication
			}
			in, err := r.prepare(ctx, p, item.node)
			if err != nil {
				return configurationApplicationCheckpoint{}, err
			}
			if in.Node != item.node {
				return configurationApplicationCheckpoint{}, ErrConflict
			}
			if _, err = r.store.queueApplicationNodeDeployment(ctx, r.bootstrap, r.trust, p, in); err != nil {
				return configurationApplicationCheckpoint{}, err
			}
		} else if r.trust == nil || !r.trust.release.matches(*item.child) {
			return configurationApplicationCheckpoint{}, ErrRequestConflict
		}
		j, scoped, err := r.store.claimApplicationNodeDeployment(ctx, r.vault, p, item.node, p.owner.String)
		if err != nil {
			return configurationApplicationCheckpoint{}, err
		}
		if j.Status == "running" {
			if r.trust == nil || !r.trust.release.matches(j) {
				return configurationApplicationCheckpoint{}, ErrRequestConflict
			}
			if err = (&DeploymentRunner{Store: r.store, Vault: r.vault, Runtime: r.runtime}).Execute(scoped, j); err != nil {
				return configurationApplicationCheckpoint{}, err
			}
		}
	}
	// Re-read actual saved/runtime state and collector evidence after the last
	// child. Loop completion and remote command success are not phase receipts.
	return r.InspectConfigurationPhase(ctx, p)
}

func (r configurationNodesRuntime) nodeWork(ctx context.Context, expected privateConfigurationApplication) ([]applicationNodeWork, error) {
	if r.store == nil || r.vault == nil || expected.member != r.bootstrap.Central.Instance || !r.SupportsConfigurationPhase(expected.phase()) {
		return nil, errConfigurationApplication
	}
	tx, err := r.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return nil, err
	} else if held {
		return nil, ErrMigrationPending
	}
	p, err := lockedApplication(ctx, tx, r.vault, expected)
	if err != nil {
		return nil, err
	}
	if !p.RecoveryRequired {
		return nil, errConfigurationApplication
	}
	_, doc, err := applicationSavedEvidenceTx(ctx, tx, r.vault, p)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(doc.Nodes))
	for id := range doc.Nodes {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	if p.Direction == "rollback" {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	}
	var work []applicationNodeWork
	for _, id := range keys {
		n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR SHARE`, id))
		if err != nil || !applicationNodeMatches(doc, n) {
			return nil, ErrConflict
		}
		if !n.Enabled {
			complete, err := applicationRegistrationTx(ctx, tx, r.vault, p, doc, id, false)
			if err != nil {
				return nil, err
			}
			if !complete {
				work = append(work, applicationNodeWork{node: id, registration: true})
			}
			continue
		}
		l, err := readApplicationNodeTx(ctx, tx, r.vault, p, id)
		if err == nil {
			j, err := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR SHARE`, l.Child))
			if err != nil || j.Node != id || j.PlanDigest != l.Plan {
				return nil, errConfigurationApplication
			}
			if err = checkApplicationNodeTargetTx(ctx, tx, r.vault, p, j.Plan.Request, false); err != nil {
				return nil, err
			}
			terminal := p.Direction == "forward" && j.Status == "succeeded" || p.Direction == "rollback" && j.Status == "rolled_back"
			if !terminal {
				copy := j
				work = append(work, applicationNodeWork{node: id, child: &copy})
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if p.Direction == "rollback" {
			continue // No child was created, so this adapter changed no service.
		}
		active, err := scanActiveNode(tx.QueryRowContext(ctx, `SELECT `+activeNodeColumns+` FROM v3_active_nodes WHERE id=$1`, id))
		unchanged := err == nil && applicationNodeMatches(doc, active) && n.AppliedVersion == n.Version && active.AppliedVersion == n.Version
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if unchanged {
			continue
		}
		work = append(work, applicationNodeWork{node: id})
	}
	if len(work) == 0 {
		if err = r.store.verifyApplicationNodeOutcomesTx(ctx, tx, r.vault, p); err != nil {
			return nil, err
		}
	}
	return work, tx.Commit()
}
