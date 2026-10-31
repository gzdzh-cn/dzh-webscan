package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"webscan/internal/nodepki"
)

var errNodeNamePruning = errors.New("证书名称收尾检查不满足要求：请核对已生效配置、身份登记、历史恢复依赖及未完成任务")

// This is a READ-ONLY eligibility calculation, not an authorization or a
// signing endpoint. Every snapshot remains a recovery dependency unless an
// explicit immutable retirement fences its reuse. A successful deployment
// alone does not retire its old TLS name.
type nodeNamePruningPlan struct {
	Node, Snapshot, ConfigurationSHA256, AuthoritySHA256, ParentSHA256 string
	ActiveName, DependenciesSHA256                                     string
	ActorRevision, NodeVersion, RuntimeEpoch                           int64
	Names, RemovableNames                                              []string
}

func (s *Store) planNodeNamePruning(ctx context.Context, c Config, user, node string, expected int64, certificate []byte) (nodeNamePruningPlan, error) {
	var empty nodeNamePruningPlan
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil || !identifier.MatchString(node) || !identifier.MatchString(user) || expected < 1 || len(certificate) == 0 || len(certificate) > 16<<10 {
		return empty, errNodeNamePruning
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	p, err := namePruningPolicyTx(ctx, tx, c, user, node, expected, certificate, "")
	if err != nil {
		return empty, err
	}
	return p, tx.Commit()
}

// Callers hold the configuration gate and use the same account -> node order
// as deployment. Only the exact persisted task may replay its own issuance.
func namePruningPolicyTx(ctx context.Context, tx *sql.Tx, c Config, user, node string, expected int64, certificate []byte, except string) (nodeNamePruningPlan, error) {
	var empty nodeNamePruningPlan
	if held, err := migrationHeld(ctx, tx); err != nil {
		return empty, err
	} else if held {
		return empty, ErrMigrationPending
	}
	if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
		return empty, err
	}
	actor, err := deploymentPreviewAccount(ctx, tx, user)
	if err != nil {
		return empty, err
	}
	n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE`, node))
	if err != nil || !n.Enabled || n.Version != expected || n.AppliedVersion != expected {
		return empty, errNodeNamePruning
	}
	var p nodeNamePruningPlan
	var generation, delivered, activeVersion int64
	var activeConfig []byte
	var enabled, matches bool
	err = tx.QueryRowContext(ctx, `SELECT r.snapshot,r.epoch,r.delivered_version,n.runtime_generation,c.version,c.enabled,c.server_name,c.config,ROW(n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config)=ROW(c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config) FROM v3_node_runtime r JOIN v3_nodes n ON n.id=r.node JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot WHERE r.node=$1`, node).Scan(&p.Snapshot, &p.RuntimeEpoch, &delivered, &generation, &activeVersion, &enabled, &p.ActiveName, &activeConfig, &matches)
	if err != nil || !enabled || !matches || p.RuntimeEpoch < 1 || p.RuntimeEpoch != generation || delivered != expected || activeVersion != expected {
		return empty, errNodeNamePruning
	}
	var busy bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required)) OR EXISTS(SELECT 1 FROM v3_node_renewal_jobs WHERE node=$1 AND activated_at IS NULL)`, node).Scan(&busy); err != nil {
		return empty, err
	}
	if busy {
		return empty, ErrDeploymentBusy
	}
	if busy, err := nodeIdentityRecoveryBusyTx(ctx, tx, node, except); err != nil {
		return empty, err
	} else if busy {
		return empty, ErrDeploymentBusy
	}
	parent, err := provisioningCertificate(certificate)
	if err != nil || len(parent.DNSNames)+len(parent.IPAddresses) < 1 || len(parent.DNSNames)+len(parent.IPAddresses) > 16 {
		return empty, errNodeNamePruning
	}
	ca, currentCRL, err := provisioningCertificateIssuer(c, parent, time.Now())
	if err != nil {
		return empty, errNodeNamePruning
	}
	root, err := provisioningCertificate(ca)
	if err != nil {
		return empty, errNodeNamePruning
	}
	p.AuthoritySHA256, p.ParentSHA256 = digest(root.Raw), digest(parent.Raw)
	var known, pinnedCA, crl []byte
	err = tx.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificates WHERE node=$1 AND authority=$2 AND serial=$3 UNION ALL SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND authority=$2 AND serial=$3 UNION ALL SELECT certificate FROM v3_root_identity_issuances WHERE role='node' AND subject=$1 AND authority=$2 AND serial=$3 LIMIT 1`, node, p.AuthoritySHA256, parent.SerialNumber.Text(16)).Scan(&known)
	if err != nil || !bytes.Equal(bytes.TrimSpace(known), bytes.TrimSpace(certificate)) {
		return empty, errNodeNamePruning
	}
	err = tx.QueryRowContext(ctx, `SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1`, p.AuthoritySHA256).Scan(&pinnedCA, &crl)
	if err != nil || !bytes.Equal(bytes.TrimSpace(pinnedCA), bytes.TrimSpace(ca)) {
		return empty, errNodeNamePruning
	}
	if nodepki.ValidateCRLAdvance(ca, crl, currentCRL, time.Now()) != nil {
		return empty, errNodeNamePruning
	}
	crl = currentCRL
	// Keep all recorded bytes in the proof, including retired snapshots. Only
	// exact, explicitly retired history stops protecting a name; historical
	// task/certificate records remain intact and cannot reactivate that ID.
	rows, err := tx.QueryContext(ctx, `SELECT to_jsonb(c),server_name,COALESCE(h.snapshot_sha256,'') FROM v3_node_configurations c LEFT JOIN v3_node_history_retirements h ON h.node=c.node AND h.snapshot=c.id WHERE c.node=$1 ORDER BY c.id`, node)
	if err != nil {
		return empty, err
	}
	dependencies := sha256.New()
	dependencies.Write([]byte("webscan-v3/node-name-pruning-dependencies/v1\x00"))
	var size [8]byte
	names := map[string]bool{}
	for rows.Next() {
		var raw []byte
		var name string
		var retired string
		if err := rows.Scan(&raw, &name, &retired); err != nil {
			rows.Close()
			return empty, err
		}
		if retired != "" && retired != digest(raw) || retired == "" && parent.VerifyHostname(name) != nil {
			rows.Close()
			return empty, errNodeNamePruning
		}
		binary.BigEndian.PutUint64(size[:], uint64(len(raw)))
		dependencies.Write(size[:])
		dependencies.Write(raw)
		dependencies.Write([]byte{0})
		dependencies.Write([]byte(retired))
		if retired == "" {
			names[name] = true
		}
	}
	err = rows.Err()
	closed := rows.Close()
	if err != nil {
		return empty, err
	}
	if closed != nil {
		return empty, closed
	}
	if !names[p.ActiveName] {
		return empty, errNodeNamePruning
	}
	for name := range names {
		p.Names = append(p.Names, name)
	}
	slices.Sort(p.Names)
	for _, name := range parent.DNSNames {
		if !names[name] {
			p.RemovableNames = append(p.RemovableNames, name)
		}
	}
	for _, ip := range parent.IPAddresses {
		if name := ip.String(); !names[name] {
			p.RemovableNames = append(p.RemovableNames, name)
		}
	}
	slices.Sort(p.RemovableNames)
	p.Node, p.ActorRevision, p.NodeVersion, p.ConfigurationSHA256 = node, actor, expected, digest(activeConfig)
	p.DependenciesSHA256 = hex.EncodeToString(dependencies.Sum(nil))
	// A previously issued leaf permits a fresh administrator authorization,
	// never a second issuance or a different configuration/epoch/SAN subset.
	original, issued, _, priorErr := namePruningPriorIssuance(ctx, tx, p)
	if priorErr == sql.ErrNoRows {
		trust, err := nodepki.NewTrust(ca, crl, time.Now())
		if err != nil || trust.Verify(parent, nodepki.Node, node, time.Now()) != nil {
			return empty, errNodeNamePruning
		}
	} else if priorErr != nil || !bytes.Equal(bytes.TrimSpace(original.Certificate), bytes.TrimSpace(certificate)) || nodepki.ValidateNodeNamePruningReceipt(ca, crl, original, issued, time.Now()) != nil {
		return empty, errNodeNamePruning
	}
	// Reuse the exact PKI subset/canonical-name rules, without generating any
	// authorization, challenge or local private key for a read-only plan.
	if len(p.RemovableNames) > 0 {
		if err := nodepki.ValidateNodeNamePruningScope(certificate, p.ActiveName, p.Names); err != nil {
			return empty, errNodeNamePruning
		}
	}
	return p, nil
}
