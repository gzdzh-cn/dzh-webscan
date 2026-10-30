package controlplane

import "context"

// Serve installs this concrete composition only when the local experimental
// executor.applications_enabled flag is explicit. HTTPS submissions use the
// same opt-in gate and independently reauthorize each request. Missing node preparation
// cannot masquerade as a runtime supporting every recovery phase.
type configurationCompositeRuntime struct {
	store             *Store
	vault             *Vault
	launch, bootstrap Config
	roles             []string
	nodes             configurationNodesRuntime
}

func newConfigurationCompositeRuntime(ctx context.Context, s *Store, v *Vault, launch, bootstrap Config, roles []string, remote DeploymentRuntime) (configurationCompositeRuntime, error) {
	t, err := loadDeploymentTrust(ctx, bootstrap.DeploymentTrust)
	if err != nil {
		return configurationCompositeRuntime{}, err
	}
	preparer := configurationNodePreparer{s, bootstrap, t}
	r := configurationCompositeRuntime{store: s, vault: v, launch: launch, bootstrap: bootstrap, roles: append([]string{}, roles...), nodes: configurationNodesRuntime{store: s, vault: v, bootstrap: bootstrap, trust: t, runtime: remote, prepare: preparer.Prepare}}
	if !preparer.valid() || !r.valid() {
		return configurationCompositeRuntime{}, errConfigurationApplication
	}
	return r, nil
}

func (r configurationCompositeRuntime) verifier() configurationVerificationRuntime {
	return configurationVerificationRuntime{r.store, r.vault, r.launch, r.bootstrap, r.roles}
}
func (r configurationCompositeRuntime) valid() bool {
	left, e1 := configurationBootstrapValues(r.nodes.bootstrap)
	right, e2 := configurationBootstrapValues(r.bootstrap)
	return e1 == nil && e2 == nil && configurationRestoreEqual(left, right) && r.verifier().valid() && r.nodes.store == r.store && r.nodes.vault == r.vault && r.nodes.bootstrap.Central.Instance == r.bootstrap.Central.Instance && r.nodes.runtime != nil && r.nodes.prepare != nil && r.nodes.trust != nil && r.nodes.trust.vault != nil && r.nodes.trust.vault.active == r.vault.active
}
func (r configurationCompositeRuntime) adapter(phase string) configurationApplicationRuntime {
	if !r.valid() {
		return nil
	}
	switch phase {
	case "environment":
		return configurationPreparationEnvironmentRuntime{
			environment: configurationEnvironmentRuntime{r.store, r.vault, r.bootstrap},
			preparer:    configurationNodePreparer{r.store, r.bootstrap, r.nodes.trust},
		}
	case "nodes", "restore-nodes":
		return r.nodes
	case "bootstrap", "restore-bootstrap":
		return configurationBootstrapRuntime{r.store, r.vault, r.launch, r.bootstrap}
	case "settings", "restore-settings":
		return configurationSettingsRuntime{r.store, r.vault, r.bootstrap}
	case "verify", "finalize", "verify-rollback":
		return r.verifier()
	}
	return nil
}
func (r configurationCompositeRuntime) SupportsConfigurationPhase(phase string) bool {
	return r.adapter(phase) != nil
}
func (r configurationCompositeRuntime) InspectConfigurationPhase(ctx context.Context, p privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	if a := r.adapter(p.phase()); a != nil {
		return a.InspectConfigurationPhase(ctx, p)
	}
	return configurationApplicationCheckpoint{}, errConfigurationApplication
}
func (r configurationCompositeRuntime) ApplyConfigurationPhase(ctx context.Context, p privateConfigurationApplication) (configurationApplicationCheckpoint, error) {
	if a := r.adapter(p.phase()); a != nil {
		return a.ApplyConfigurationPhase(ctx, p)
	}
	return configurationApplicationCheckpoint{}, errConfigurationApplication
}
func (r configurationCompositeRuntime) checkpointConfigurationPhase(ctx context.Context, p privateConfigurationApplication, proof configurationApplicationCheckpoint) error {
	if !r.valid() {
		return errConfigurationApplication
	}
	if r.verifier().SupportsConfigurationPhase(p.phase()) {
		return r.verifier().checkpointConfigurationPhase(ctx, p, proof)
	}
	_, err := r.store.checkpointConfigurationApplication(ctx, r.vault, p, proof)
	return err
}
