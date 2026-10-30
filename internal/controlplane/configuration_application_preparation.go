package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"webscan/internal/nodeconfig"
)

// A concrete local provider. All inputs come from saved, authenticated SQL
// material and the current fenced parent, never from a browser path/callback.
// It only writes a private content-addressed configuration artifact; it does
// not create a child job, contact SSH or change node registration/services.
type configurationNodePreparer struct {
	store  *Store
	config Config
	trust  *deploymentTrust
}

type applicationPreparationSnapshot struct {
	binding          nodeProvisioningReceipt
	node             Node
	credential, kind string
	material         nodeconfig.Material
}

func (applicationPreparationSnapshot) String() string               { return "[private application preparation]" }
func (applicationPreparationSnapshot) GoString() string             { return "[private application preparation]" }
func (applicationPreparationSnapshot) MarshalJSON() ([]byte, error) { return nil, errNodeProvisioning }

func (r configurationNodePreparer) valid() bool {
	return r.store != nil && r.trust != nil && r.trust.vault != nil && r.trust.release != nil && r.config.Executor.Enabled && r.config.Central.Instance != ""
}

func (r configurationNodePreparer) read(ctx context.Context, expected privateConfigurationApplication, node string) (applicationPreparationSnapshot, error) {
	var out applicationPreparationSnapshot
	if !r.valid() || expected.member != r.config.Central.Instance || expected.Direction != "forward" || expected.phase() != "nodes" || !identifier.MatchString(node) {
		return out, errNodeProvisioning
	}
	op, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := r.store.DB.BeginTx(op, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(op, tx); err != nil {
		return out, err
	} else if held {
		return out, ErrMigrationPending
	}
	p, doc, err := lockedApplicationNodeParentTx(op, tx, r.trust.vault, expected, node)
	if err != nil {
		return out, err
	}
	// A previously linked child already has an immutable artifact/request and
	// must be resumed through that journal, never prepared from new material.
	var linked bool
	if err = tx.QueryRowContext(op, `SELECT EXISTS(SELECT 1 FROM v3_configuration_application_nodes WHERE application=$1 AND node=$2)`, p.ID, node).Scan(&linked); err != nil {
		return out, err
	}
	if linked {
		return out, errNodeProvisioning
	}
	n, err := scanNode(tx.QueryRowContext(op, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 FOR SHARE`, node))
	if err != nil || !applicationNodeMatches(doc, n) {
		return out, ErrConflict
	}
	snapshot, err := r.materialTx(op, tx, n)
	if err != nil {
		return out, err
	}
	keep := false
	defer func() {
		if !keep {
			clear(snapshot.material.Key)
			clear(snapshot.material.YARA)
		}
	}()
	if _, err = lockedApplication(op, tx, r.trust.vault, p); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	keep = true
	return snapshot, nil
}

// Caller supplies an authenticated saved node under the configuration gate.
func (r configurationNodePreparer) materialTx(ctx context.Context, tx *sql.Tx, n Node) (applicationPreparationSnapshot, error) {
	binding, m, err := readNodeProvisioningTx(ctx, tx, r.trust.vault, n.ID)
	if err != nil {
		return applicationPreparationSnapshot{}, err
	}
	defer clear(m.Rules)
	credential, err := provisioningCredentialTx(ctx, tx, r.trust.vault, m.Credential, n.ID)
	if err != nil || credential != m.CredentialProof {
		return applicationPreparationSnapshot{}, errNodeProvisioning
	}
	identity, managed, err := provisioningNodeIdentity(ctx, tx, r.config, r.trust.vault, m.Identity, n, true)
	if err != nil {
		return applicationPreparationSnapshot{}, errNodeProvisioning
	}
	rules := append([]byte{}, m.Rules...)
	keep := false
	defer func() {
		if !keep {
			clear(identity.Key)
			clear(rules)
		}
	}()
	if digest(identity.Certificate) != m.IdentityProof {
		return applicationPreparationSnapshot{}, errNodeProvisioning
	}
	crl, err := readTrustData(r.config.Collector.RevocationFile, false, 1<<20)
	if err != nil {
		return applicationPreparationSnapshot{}, errNodeProvisioning
	}
	material, err := nodeConfigurationMaterial(n, r.trust.release, NodeConfigurationInput{Node: n.ID, Expected: n.Version, Identity: identity, CRL: crl, Collectors: m.Collectors, Rules: rules, ManagedIdentity: managed})
	if err != nil || validateProvisioningTrust(r.config, material, time.Now()) != nil {
		clear(material.YARA)
		return applicationPreparationSnapshot{}, errNodeProvisioning
	}
	if err = checkIssuerFloor(ctx, tx, material); err != nil {
		clear(material.YARA)
		return applicationPreparationSnapshot{}, err
	}
	kind := "install"
	var applied int64
	err = tx.QueryRowContext(ctx, `SELECT delivered_version FROM v3_node_runtime WHERE node=$1`, n.ID).Scan(&applied)
	if err != nil && err != sql.ErrNoRows {
		clear(material.YARA)
		return applicationPreparationSnapshot{}, err
	}
	if n.AppliedVersion > 0 || applied > 0 {
		kind = "upgrade"
	}
	if managed {
		kind = "upgrade"
	}
	keep = true
	return applicationPreparationSnapshot{binding, n, m.Credential, kind, material}, nil
}

// Validate required bindings before recovery is armed. Authenticate the saved
// document once and read saved/active nodes in two batches, rather than reopen
// the whole configuration for each node. Secret material is cleared per node.
// This is bounded preflight, not a capacity guarantee or an artifact receipt;
// Prepare still rechecks the actual lease/material before and after disk I/O.
func (r configurationNodePreparer) checkEnvironment(ctx context.Context, expected privateConfigurationApplication) error {
	if !r.valid() || expected.member != r.config.Central.Instance || expected.Direction != "forward" || expected.phase() != "environment" {
		return errNodeProvisioning
	}
	op, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := r.store.DB.BeginTx(op, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(op, tx); err != nil {
		return err
	} else if held {
		return ErrMigrationPending
	}
	p, err := lockedApplication(op, tx, r.trust.vault, expected)
	if err != nil {
		return err
	}
	_, doc, err := applicationSavedEvidenceTx(op, tx, r.trust.vault, p)
	if err != nil {
		return err
	}
	// Do not restart into a configuration that removes the only coordinator
	// before this same application has finished. Disabling it needs a separate
	// administrative operation after completion.
	if r.config.Executor.ApplicationsEnabled {
		target, err := configurationEnvironmentConfig(doc)
		if err != nil || !target.Executor.Enabled || !target.Executor.ApplicationsEnabled {
			return errConfigurationApplication
		}
	}
	active := make(map[string]Node, len(doc.Nodes))
	rows, err := tx.QueryContext(op, `SELECT `+activeNodeColumns+` FROM v3_active_nodes`)
	if err != nil {
		return err
	}
	for rows.Next() {
		n, err := scanActiveNode(rows)
		if err != nil {
			rows.Close()
			return err
		}
		active[n.ID] = n
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(op, `SELECT `+nodeColumns+` FROM v3_nodes ORDER BY id FOR SHARE`)
	if err != nil {
		return err
	}
	var required []Node
	count := 0
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil || !applicationNodeMatches(doc, n) {
			rows.Close()
			return ErrConflict
		}
		count++
		current, registered := active[n.ID]
		if n.Enabled && !(registered && applicationNodeMatches(doc, current) && n.AppliedVersion == n.Version && current.AppliedVersion == n.Version) {
			required = append(required, n)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count != len(doc.Nodes) {
		return ErrConflict
	}
	for _, n := range required {
		snapshot, err := r.materialTx(op, tx, n)
		clear(snapshot.material.Key)
		clear(snapshot.material.YARA)
		if err != nil {
			return err
		}
	}
	if _, err = lockedApplication(op, tx, r.trust.vault, p); err != nil {
		return err
	}
	return tx.Commit()
}

// The concrete composition extends dependency checks with required node
// material. No artifact, SSH call or child job is created in this phase.
type configurationPreparationEnvironmentRuntime struct {
	environment configurationEnvironmentRuntime
	preparer    configurationNodePreparer
}

func (r configurationPreparationEnvironmentRuntime) SupportsConfigurationPhase(phase string) bool {
	return phase == "environment"
}
func (r configurationPreparationEnvironmentRuntime) InspectConfigurationPhase(ctx context.Context, p privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	return r.environment.InspectConfigurationPhase(ctx, p)
}
func (r configurationPreparationEnvironmentRuntime) ApplyConfigurationPhase(ctx context.Context, p privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	if err := r.preparer.checkEnvironment(ctx, p); err != nil {
		return configurationApplicationCheckpoint{}, err
	}
	proof, err := r.environment.ApplyConfigurationPhase(ctx, p)
	if err != nil {
		return configurationApplicationCheckpoint{}, err
	}
	if err := r.preparer.checkEnvironment(ctx, p); err != nil {
		return configurationApplicationCheckpoint{}, err
	}
	return proof, nil
}

func (r configurationNodePreparer) Prepare(ctx context.Context, p privateConfigurationApplication, node string) (DeploymentRequest, error) {
	var empty DeploymentRequest
	first, err := r.read(ctx, p, node)
	if err != nil {
		return empty, err
	}
	defer clear(first.material.Key)
	defer clear(first.material.YARA)
	return r.publish(ctx, p, node, first)
}

// Kept separate from the authenticated read so that the mandatory post-I/O
// recheck is an explicit boundary. The private snapshot is not API authority.
func (r configurationNodePreparer) publish(ctx context.Context, p privateConfigurationApplication, node string, first applicationPreparationSnapshot) (DeploymentRequest, error) {
	var empty DeploymentRequest
	raw, err := json.Marshal(first.material)
	defer clear(raw)
	if err != nil || len(raw) > nodeconfig.MaxBytes {
		return empty, errNodeProvisioning
	}
	artifact := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	if _, err = writeNodeConfiguration(r.config.Executor.ConfigurationDirectory, artifact, raw); err != nil {
		return empty, errNodeProvisioning
	}
	// Recheck the real lease, source, binding and current trust after disk I/O.
	// Failure may leave an unreferenced immutable artifact, which must not be
	// deleted here: an identical artifact may already be in another journal.
	last, err := r.read(ctx, p, node)
	if err != nil {
		return empty, err
	}
	defer clear(last.material.Key)
	defer clear(last.material.YARA)
	check, err := json.Marshal(last.material)
	defer clear(check)
	if err != nil || last.binding != first.binding || last.kind != first.kind || last.credential != first.credential || digest(check) != artifact.SHA256 {
		return empty, ErrConflict
	}
	if err = ctx.Err(); err != nil {
		return empty, err
	}
	target := r.trust.release.manifest.Native.SHA256
	if first.node.Mode == "docker" {
		target = r.trust.release.manifest.Image[len(r.trust.release.manifest.Image)-64:]
	}
	in := DeploymentRequest{Node: node, Expected: first.node.Version, Kind: first.kind, Credential: first.credential, Release: r.trust.release.manifest.Release, SHA256: target, ManifestSHA256: r.trust.release.SHA256(), RuntimeArtifact: &artifact}
	return in, in.validate()
}
