package nodeops

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

func (w *LocalRuntime) configurationDir(s Spec) string {
	return filepath.Join(w.root, "configurations", s.RuntimeSHA256)
}
func (w *LocalRuntime) configurationMaterial(ctx context.Context, r Request) (nodeconfig.Material, error) {
	if !r.Spec.configurationValid() {
		return nodeconfig.Material{}, errors.New("missing-node-configuration")
	}
	dir := filepath.Join(w.root, "configs", r.Spec.RuntimeSHA256)
	for _, path := range []string{w.root, filepath.Join(w.root, "configs"), dir} {
		if err := privateDirectoryTree(path); err != nil {
			return nodeconfig.Material{}, err
		}
	}
	raw, err := readPrivate(filepath.Join(dir, "node.json"), nodeconfig.MaxBytes)
	if err != nil || uint64(len(raw)) != r.Spec.RuntimeBytes || sha(raw) != r.Spec.RuntimeSHA256 {
		return nodeconfig.Material{}, errors.New("configuration-digest-mismatch")
	}
	if err := ctx.Err(); err != nil {
		return nodeconfig.Material{}, err
	}
	m, err := nodeconfig.Decode(raw, time.Now())
	rootState, rootErr := w.installedRootState(time.Now())
	if rootErr != nil {
		return nodeconfig.Material{}, rootErr
	}
	if rootState.Format != 0 {
		m, err = nodeconfig.DecodeManagedRootRuntime(raw, time.Now(), rootState)
	}
	if err != nil {
		// Only a node with an existing durable trust floor can inspect an
		// expired immutable managed seed. Its actual live identity is required
		// below; fresh installation and legacy split-key material stay strict.
		floor, floorErr := readPrivate(filepath.Join(w.managedDataDirectory(), "pki-trust", "ca.crl"), nodepki.MaxCRLBytes)
		if floorErr == nil && rootState.Format == 0 {
			m, err = nodeconfig.DecodeManagedRuntime(raw, time.Now(), floor)
		}
	}
	if err != nil || m.Node != r.Node || m.Version != r.Spec.ConfigVersion || m.SourceSHA256 != r.Spec.ConfigSourceSHA256 || m.Mode != r.Spec.Mode || m.Release != r.Spec.Release || m.BundleSHA256 != r.Spec.BundleSHA256 || m.MetricsPort != r.Spec.MetricsPort || m.ServerName != r.Spec.ServerName || !reflect.DeepEqual(m.Settings.Monitor.Roots, r.Spec.MonitorDirectories) || m.Settings.Scan.ClamAV.Enabled != r.Spec.ClamAV {
		return nodeconfig.Material{}, errors.New("configuration-task-mismatch")
	}
	_, managedErr := os.Lstat(filepath.Join(w.managedDataDirectory(), "pki-identity"))
	if m.Format == 3 || m.Format == 2 && !os.IsNotExist(managedErr) {
		if err := w.verifyManagedIdentity(m, time.Now()); err != nil {
			return nodeconfig.Material{}, err
		}
	}
	return m, nil
}

func (w *LocalRuntime) managedDataDirectory() string {
	if w.identityData != "" {
		return w.identityData
	}
	return agentDataDirectory
}

func (w *LocalRuntime) installedRootState(now time.Time) (nodepki.RootSetSnapshot, error) {
	data := w.managedDataDirectory()
	floor := filepath.Join(data, "pki-trust")
	if _, err := os.Lstat(filepath.Join(floor, "root-rotation")); os.IsNotExist(err) {
		return nodepki.RootSetSnapshot{}, nil
	}
	return nodepki.ReadRootState(filepath.Join(data, "pki-identity", "ca.crt"), floor, now)
}

// Read-only pre-stop validation. Renewal may replace a leaf between phases;
// pin the authority and node, not an obsolete transient certificate digest.
// Never initialize missing state or copy a key out of the Agent directory.
func (w *LocalRuntime) verifyManagedIdentity(m nodeconfig.Material, now time.Time) error {
	fail := errors.New("managed-node-identity-not-verified")
	data := w.managedDataDirectory()
	identity := filepath.Join(data, "pki-identity")
	floor := filepath.Join(data, "pki-trust")
	for _, dir := range []string{data, identity, floor} {
		if privateDirectoryTree(dir) != nil {
			return fail
		}
	}
	for _, path := range []string{filepath.Join(identity, "ca.crt"), filepath.Join(floor, "ca.crt")} {
		ca, err := readPrivate(path, 64<<10)
		if err != nil || !bytes.Equal(bytes.TrimSpace(ca), bytes.TrimSpace(m.CA)) {
			return fail
		}
	}
	rootState, err := w.installedRootState(now)
	if err != nil {
		return fail
	}
	if rootState.Format != 0 {
		// Read-only pre-stop proof under the current root authorization. Never
		// lower this floor to the immutable installation's original CRL.
		trust, err := nodepki.NewPersistentFileTrust(filepath.Join(identity, "ca.crt"), filepath.Join(floor, "ca.crl"), floor, now)
		if err != nil {
			return fail
		}
		b, _, err := nodepki.ReadIdentityWithRootState(filepath.Join(identity, "ca.crt"), filepath.Join(identity, "active.pem"), floor, nodepki.Node, m.Node, now)
		defer clear(b.Key)
		if err != nil {
			return fail
		}
		block, _ := pem.Decode(b.Certificate)
		if block == nil {
			return fail
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || leaf.VerifyHostname(m.ServerName) != nil || trust.Verify(leaf, nodepki.Node, m.Node, now) != nil {
			return fail
		}
		return nil
	}
	previous, err := readPrivate(filepath.Join(floor, "ca.crl"), nodepki.MaxCRLBytes)
	if err != nil {
		return fail
	}
	current := m.CRL
	if nodepki.ValidateCRLAdvance(m.CA, m.CRL, previous, now) == nil {
		// A newer accepted durable snapshot is never overwritten by an
		// immutable configuration, including during resume/rollback.
		current = previous
	} else if nodepki.ValidateCRLAdvance(m.CA, previous, m.CRL, now) != nil {
		return fail
	}
	b, _, err := nodepki.ReadIdentity(filepath.Join(identity, "ca.crt"), filepath.Join(identity, "active.pem"), nodepki.Node, m.Node, now)
	defer clear(b.Key)
	if err != nil {
		return fail
	}
	pair, err := tls.X509KeyPair(b.Certificate, b.Key)
	if err != nil || len(pair.Certificate) != 1 {
		return fail
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	trust, trustErr := nodepki.NewTrust(m.CA, current, now)
	if err != nil || trustErr != nil || cert.VerifyHostname(m.ServerName) != nil || trust.Verify(cert, nodepki.Node, m.Node, now) != nil {
		return fail
	}
	return nil
}
func (w *LocalRuntime) configurationFiles(m nodeconfig.Material, s Spec) (map[string][]byte, error) {
	runtime, err := m.Runtime(w.configurationDir(s), w.releaseDir(s))
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		return nil, err
	}
	name, definition, err := w.serviceDefinition(m, s)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{"runtime.json": raw, "rules.yar": m.YARA, "ca.crt": m.CA, "ca.crl": m.CRL, "clamd.conf": []byte("LocalSocket /run/clamav/clamd.ctl\n"), name: definition}
	if m.Format != 3 {
		files["identity.crt"], files["identity.key"] = m.Certificate, m.Key
	}
	return files, nil
}
func (w *LocalRuntime) prepareConfiguration(ctx context.Context, r Request) error {
	m, err := w.configurationMaterial(ctx, r)
	if err != nil {
		return err
	}
	parent := filepath.Join(w.root, "configurations")
	if err := ensurePrivateDirectory(parent); err != nil {
		return err
	}
	if _, err := os.Lstat(w.configurationDir(r.Spec)); !os.IsNotExist(err) {
		return w.verifyConfiguration(ctx, r)
	}
	files, err := w.configurationFiles(m, r.Spec)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".config-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for name, raw := range files {
		if err := writePrivate(filepath.Join(stage, name), bytes.NewReader(raw), int64(len(raw)), 0600); err != nil {
			return err
		}
	}
	// Validate the supplied rules, not only the prior installation's rules.
	if err := w.probeConfigurationRules(ctx, r.Spec, filepath.Join(stage, "rules.yar")); err != nil {
		return errors.New("configuration-yara-invalid")
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, w.configurationDir(r.Spec)); err != nil {
		return err
	}
	return syncDirectory(parent)
}
func (w *LocalRuntime) verifyConfiguration(ctx context.Context, r Request) error {
	m, err := w.configurationMaterial(ctx, r)
	if err != nil {
		return err
	}
	dir := w.configurationDir(r.Spec)
	for _, path := range []string{w.root, filepath.Join(w.root, "configurations"), dir} {
		if err := privateDirectoryTree(path); err != nil {
			return err
		}
	}
	files, err := w.configurationFiles(m, r.Spec)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(files) {
		return errors.New("prepared-configuration-changed")
	}
	for name, want := range files {
		got, err := readPrivate(filepath.Join(dir, name), nodeconfig.MaxBytes)
		if err != nil || !bytes.Equal(got, want) {
			return errors.New("prepared-configuration-changed")
		}
	}
	if err := w.probeConfigurationRules(ctx, r.Spec, filepath.Join(dir, "rules.yar")); err != nil {
		return errors.New("configuration-yara-invalid")
	}
	return nil
}

func (w *LocalRuntime) probeConfigurationRules(ctx context.Context, s Spec, rules string) error {
	program := filepath.Join(w.releaseDir(s), "tools/bin/yara")
	if w.rulesProbe != nil {
		return w.rulesProbe(ctx, program, rules)
	}
	_, err := bundleCommand(ctx, program, "-w", rules, "/dev/null")
	return err
}
