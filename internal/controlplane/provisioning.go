package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"path/filepath"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

var errProvisioning = errors.New("部署准备资料无效或与当前节点、采集身份不一致；请重新准备，私密内容不会回显")

// These inputs are exclusively local administrator files. They are never
// accepted by HTTP handlers. Public deployment submissions remain disabled.
type credentialFileInput struct {
	Node       string        `json:"node"`
	Expected   int64         `json:"expected_version"`
	Credential SSHCredential `json:"credential"`
}

type deploymentPreparationInput struct {
	Node              string   `json:"node"`
	Expected          int64    `json:"expected_version"`
	Kind              string   `json:"kind"`
	Credential        string   `json:"credential"`
	IdentityDirectory string   `json:"identity_directory"`
	IdentityID        string   `json:"identity_id,omitempty"`
	Collectors        []string `json:"collectors"`
	RulesFile         string   `json:"rules_file"`
}

func provisioningInput(path string, into any) error {
	raw, err := readTrustData(path, true, 128<<10)
	if err != nil {
		return errProvisioning
	}
	defer clear(raw)
	if !uniqueProvisioningJSON(json.NewDecoder(bytes.NewReader(raw)), 0) {
		return errProvisioning
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil || d.Decode(new(any)) != io.EOF {
		return errProvisioning
	}
	return nil
}

// Local requests permit ordinary whitespace but never duplicate object keys.
// Bound nesting independently of the byte limit before decoding secret fields.
func uniqueProvisioningJSON(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	tok, err := d.Token()
	if err != nil {
		return false
	}
	delim, compound := tok.(json.Delim)
	if !compound {
		return true
	}
	if delim != '{' && delim != '[' {
		return false
	}
	keys := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || keys[name] {
				return false
			}
			keys[name] = true
		}
		if !uniqueProvisioningJSON(d, depth+1) {
			return false
		}
	}
	end, err := d.Token()
	return err == nil && (delim == '{' && end == json.Delim('}') || delim == '[' && end == json.Delim(']'))
}

func provisioningAdmin(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, user string) error {
	if !identifier.MatchString(user) {
		return errProvisioning
	}
	var role string
	if err := q.QueryRowContext(ctx, "SELECT role FROM v3_accounts WHERE username=$1 FOR SHARE", user).Scan(&role); err != nil {
		if err == sql.ErrNoRows {
			return errProvisioning
		}
		return err
	}
	if role != "admin" {
		return errProvisioning
	}
	return nil
}

func provisioningCertificate(raw []byte) (*x509.Certificate, error) {
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errProvisioning
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, errProvisioning
	}
	return cert, nil
}

// Verify both ends against the collector's current trust, rather than trusting
// a self-consistent but unrelated CA in an uploaded node identity. No network
// connection, CA private key or remote side effect is needed to prepare a job.
func validateProvisioningTrust(c Config, m nodeconfig.Material, now time.Time) error {
	crl, roots, err := provisioningConfigurationTrust(c, m.CA, m.Format == 3, now)
	if err != nil {
		return errProvisioning
	}
	var verifier interface {
		Verify(*x509.Certificate, string, string, time.Time) error
	}
	if c.Collector.RevocationStateDirectory != "" {
		verifier, err = nodepki.NewPersistentFileTrust(c.Collector.CAFile, c.Collector.RevocationFile, c.Collector.RevocationStateDirectory, now)
	} else {
		verifier, err = nodepki.NewTrust(m.CA, crl, now)
	}
	if err != nil || roots != nil && m.Format != 3 {
		return errProvisioning
	}
	// Require exactly the current CRL at preparation and submission. An older,
	// still unexpired snapshot must not install a revoked collector identity.
	if !bytes.Equal(bytes.TrimSpace(crl), bytes.TrimSpace(m.CRL)) {
		return errProvisioning
	}
	if m.Format != 3 {
		cert, err := provisioningCertificate(m.Certificate)
		issuerTrust, issuerErr := nodepki.NewTrust(m.CA, crl, now)
		if err != nil || issuerErr != nil || issuerTrust.Verify(cert, nodepki.Node, m.Node, now) != nil || verifier.Verify(cert, nodepki.Node, m.Node, now) != nil || cert.VerifyHostname(m.ServerName) != nil {
			return errProvisioning
		}
	}
	identity, err := collectorIdentityMaterial(c, now)
	if err != nil {
		return errProvisioning
	}
	certRaw, keyRaw := identity.Certificate, identity.Key
	defer clear(keyRaw)
	if _, err = tls.X509KeyPair(certRaw, keyRaw); err != nil {
		return errProvisioning
	}
	collector, err := provisioningCertificate(certRaw)
	if err != nil {
		return errProvisioning
	}
	for _, id := range m.Collectors {
		if verifier.Verify(collector, nodepki.Collector, id, now) == nil {
			return nil
		}
	}
	return errProvisioning
}

func validateProvisioningNode(n Node, m nodeconfig.Material, r *TrustedRelease) error {
	port, err := endpointPort(n.Endpoint)
	if err != nil || !n.Enabled || n.ID != m.Node || n.Version != m.Version || digest(n.Config) != m.SourceSHA256 || n.Mode != m.Mode || n.ServerName != m.ServerName || port != m.MetricsPort || r == nil || r.manifest.Release != m.Release || r.manifest.Native.SHA256 != m.BundleSHA256 {
		return ErrConflict
	}
	settings, err := nodeRuntimeSettings(n.Config)
	if err != nil {
		return errProvisioning
	}
	want, _ := json.Marshal(settings)
	got, _ := json.Marshal(m.Settings)
	if !bytes.Equal(want, got) {
		return ErrConflict
	}
	return nil
}

func (s *Store) prepareLocalDeployment(ctx context.Context, c Config, t *deploymentTrust, in deploymentPreparationInput) (DeploymentRequest, error) {
	fail := func() (DeploymentRequest, error) { return DeploymentRequest{}, errProvisioning }
	if !identifier.MatchString(in.Node) || in.Expected < 1 || !identifier.MatchString(in.Credential) || (in.Kind != "install" && in.Kind != "upgrade") {
		return fail()
	}
	if _, err := s.ReadCredential(ctx, t.vault, in.Credential, in.Node); err != nil {
		return DeploymentRequest{}, err
	}
	n, err := scanNode(s.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL AND id=$1", in.Node))
	if err != nil {
		return DeploymentRequest{}, err
	}
	var identity nodepki.Bundle
	managed := false
	if in.Kind == "upgrade" && in.IdentityDirectory == "" {
		var ca []byte
		ca, managed, err = managedNodeAuthority(ctx, s.DB, c, n)
		if err != nil {
			return DeploymentRequest{}, err
		}
		identity.CA = ca
		if managed && in.IdentityID != "" {
			identity, managed, err = provisioningNodeIdentity(ctx, s.DB, c, t.vault, in.IdentityID, n, true)
			if err != nil {
				return DeploymentRequest{}, err
			}
		}
	}
	if !managed && in.IdentityID != "" {
		if in.IdentityDirectory != "" {
			return fail()
		}
		identity, err = s.readNodeIdentity(ctx, c, t.vault, in.IdentityID, in.Node)
		if err != nil {
			return DeploymentRequest{}, err
		}
	} else if !managed {
		dir, err := trustDirectory(in.IdentityDirectory, true)
		if err != nil {
			return fail()
		}
		dir.Close()
		for name, dest := range map[string]*[]byte{"ca.crt": &identity.CA, "identity.crt": &identity.Certificate, "identity.key": &identity.Key} {
			*dest, err = readTrustData(filepath.Join(in.IdentityDirectory, name), name == "identity.key", 64<<10)
			if err != nil {
				clear(identity.Key)
				return fail()
			}
		}
	}
	defer clear(identity.Key)
	crl, roots, err := provisioningConfigurationTrust(c, identity.CA, managed, time.Now())
	if err != nil {
		return fail()
	}
	format := 2
	if managed {
		format = 3
	}
	if err = checkConfigurationIssuerFloor(ctx, s.DB, c, nodeconfig.Material{Format: format, CA: identity.CA, CRL: crl}); err != nil {
		return DeploymentRequest{}, err
	}
	rules, err := readTrustData(in.RulesFile, false, 1<<20)
	if err != nil {
		return fail()
	}
	// Check trust before publishing even a private artifact.
	check := nodeconfig.Material{Node: in.Node, CA: identity.CA, Certificate: identity.Certificate, CRL: crl, Collectors: in.Collectors}
	if managed {
		check.Format = 3
		check.Certificate = nil
	}
	check.ServerName = n.ServerName
	if validateProvisioningTrust(c, check, time.Now()) != nil {
		return fail()
	}
	prepared, err := s.PrepareNodeConfiguration(ctx, t.release, NodeConfigurationInput{Node: in.Node, Expected: in.Expected, Identity: identity, CRL: crl, Collectors: in.Collectors, Rules: rules, Directory: c.Executor.ConfigurationDirectory, ManagedIdentity: managed, Roots: roots})
	if err != nil {
		return DeploymentRequest{}, err
	}
	target := t.release.manifest.Native.SHA256
	if n.Mode == "docker" {
		target = t.release.manifest.Image[len(t.release.manifest.Image)-64:]
	}
	request := DeploymentRequest{Node: in.Node, Expected: in.Expected, Kind: in.Kind, Credential: in.Credential, Release: t.release.manifest.Release, SHA256: target, ManifestSHA256: t.release.SHA256(), RuntimeArtifact: &prepared.Artifact}
	return request, request.validate()
}

func (s *Store) queueLocalDeployment(ctx context.Context, c Config, t *deploymentTrust, user, key string, in DeploymentRequest) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Check before looking up an idempotent response as well as under the
	// mutation transaction: a demoted account cannot replay an old receipt.
	if err := provisioningAdmin(ctx, s.DB, user); err != nil {
		return nil, err
	}
	m, err := s.localDeploymentMaterial(ctx, c, t, in)
	if err != nil {
		return nil, err
	}
	defer clear(m.Key)
	return retryDeploymentConfigurationMutation(ctx, func() (json.RawMessage, error) {
		return s.guardedMutationOptions(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, user, key, "create-deployment", in.Node, in, func(tx *sql.Tx) error {
			if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
				return err
			}
			return provisioningAdmin(ctx, tx, user)
		}, func(tx *sql.Tx) (any, error) {
			return insertDeploymentWithBackup(ctx, tx, user, in, func(tx *sql.Tx, n Node) error {
				return validateLocalDeploymentTx(ctx, tx, c, t, user, in, m, n)
			}, &deploymentConfigurationBackup{t.vault, c})
		})
	})
}

// Re-read immutable material and live collector trust before creating or
// confirming a preview. No SSH command or service operation occurs here.
func (s *Store) localDeploymentMaterial(ctx context.Context, c Config, t *deploymentTrust, in DeploymentRequest) (nodeconfig.Material, error) {
	if !c.Executor.Enabled {
		return nodeconfig.Material{}, errors.New("请先显式启用部署执行器，再提交本地部署任务")
	}
	if err := in.validate(); err != nil || in.RuntimeArtifact == nil {
		return nodeconfig.Material{}, errProvisioning
	}
	runtime := &SSHNodeRuntime{ConfigurationDirectory: c.Executor.ConfigurationDirectory, Lifecycle: true}
	j := DeploymentJob{Plan: DeploymentPlan{Request: in}}
	path, err := runtime.configurationFile(ctx, j)
	if err != nil {
		return nodeconfig.Material{}, err
	}
	raw, err := readTrustData(path, true, nodeconfig.MaxBytes)
	if err != nil {
		return nodeconfig.Material{}, errProvisioning
	}
	defer clear(raw)
	if digest(raw) != in.RuntimeArtifact.SHA256 || uint64(len(raw)) != in.RuntimeArtifact.Bytes {
		return nodeconfig.Material{}, errProvisioning
	}
	m, err := decodeProvisioningMaterial(c, raw, time.Now())
	if err != nil || validateProvisioningTrust(c, m, time.Now()) != nil {
		clear(m.Key)
		return nodeconfig.Material{}, errProvisioning
	}
	return m, nil
}

func validateLocalDeploymentTx(ctx context.Context, tx *sql.Tx, c Config, t *deploymentTrust, user string, in DeploymentRequest, m nodeconfig.Material, n Node) error {
	if err := provisioningAdmin(ctx, tx, user); err != nil {
		return err
	}
	if !t.release.matches(DeploymentJob{Plan: DeploymentPlan{Request: in, Node: n}}) {
		return errProvisioning
	}
	if err := checkConfigurationIssuerFloor(ctx, tx, c, m); err != nil {
		return err
	}
	if _, err := previewCredential(ctx, tx, t, in); err != nil {
		return err
	}
	if err := validateManagedDeployment(ctx, tx, c, n, in.Kind, m); err != nil {
		return err
	}
	return validateProvisioningNode(n, m, t.release)
}

func (s *Store) localProvisioningCommand(ctx context.Context, c Config, o Options, out io.Writer) error {
	if err := provisioningAdmin(ctx, s.DB, o.Username); err != nil {
		return err
	}
	if o.Action != "prepare-deployment" && o.Action != "preview-deployment" && !identifier.MatchString(o.RequestKey) {
		return errors.New("本地部署写操作必须提供有效的 --request-key；重试使用同一值")
	}
	t, err := loadDeploymentTrust(ctx, c.DeploymentTrust)
	if err != nil {
		return err
	}
	if o.Action == "prepare-deployment" || o.Action == "queue-deployment" || o.Action == "preview-deployment" || o.Action == "confirm-deployment" {
		dir, err := trustDirectory(c.Executor.ConfigurationDirectory, true)
		if err != nil {
			return errProvisioning
		}
		dir.Close()
	}
	var result any
	switch o.Action {
	case "bind-node-provisioning":
		var in nodeProvisioningInput
		if err = provisioningInput(o.Source, &in); err == nil {
			result, err = s.bindNodeProvisioning(ctx, c, t, o.Username, o.RequestKey, in)
		}
	case "issue-node-certificate":
		var in NodeCertificateInput
		if err = provisioningInput(o.Source, &in); err == nil {
			result, err = s.IssueNodeCertificate(ctx, c, t.vault, o.Username, o.RequestKey, in)
		}
	case "store-ssh-credential":
		var in credentialFileInput
		if err = provisioningInput(o.Source, &in); err == nil {
			result, err = s.AddCredential(ctx, t.vault, o.Username, o.RequestKey, in.Node, in.Expected, in.Credential)
		}
	case "prepare-deployment":
		var in deploymentPreparationInput
		if err = provisioningInput(o.Source, &in); err == nil {
			managed := false
			if in.Kind == "upgrade" && in.IdentityID == "" && in.IdentityDirectory == "" {
				var n Node
				n, err = scanNode(s.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL AND id=$1", in.Node))
				if err == nil {
					_, managed, err = managedNodeAuthority(ctx, s.DB, c, n)
				}
			}
			if err == nil && !managed && in.IdentityID == "" && in.IdentityDirectory == "" {
				if !identifier.MatchString(o.RequestKey) {
					return errors.New("自动签发节点证书需要 --request-key；重试使用同一值")
				}
				var receipt json.RawMessage
				receipt, err = s.IssueNodeCertificate(ctx, c, t.vault, o.Username, o.RequestKey, NodeCertificateInput{Node: in.Node, Expected: in.Expected})
				if err == nil {
					var record NodeCertificateRecord
					err = json.Unmarshal(receipt, &record)
					in.IdentityID = record.ID
				}
			}
			if err == nil {
				result, err = s.prepareLocalDeployment(ctx, c, t, in)
			}
		}
	case "queue-deployment":
		var in DeploymentRequest
		if err = provisioningInput(o.Source, &in); err == nil {
			result, err = s.queueLocalDeployment(ctx, c, t, o.Username, o.RequestKey, in)
		}
	case "queue-deployment-recovery":
		var in deploymentRecoveryInput
		if err = provisioningInput(o.Source, &in); err == nil {
			result, err = s.queueLocalDeploymentRecovery(ctx, c, t, o.Username, o.RequestKey, in)
		}
	case "preview-deployment":
		var in DeploymentRequest
		if err = provisioningInput(o.Source, &in); err == nil {
			result, err = s.previewLocalDeployment(ctx, c, t, o.Username, in)
		}
	case "confirm-deployment":
		var in deploymentConfirmationInput
		if err = provisioningInput(o.Source, &in); err == nil {
			result, err = s.confirmLocalDeployment(ctx, c, t, o.Username, o.RequestKey, in.Token)
		}
	default:
		return errProvisioning
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
