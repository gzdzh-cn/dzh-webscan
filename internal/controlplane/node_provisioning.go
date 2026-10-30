package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

var errNodeProvisioning = errors.New("节点部署资料未配置、已变化或校验失败；请核实已保存凭据、节点证书和扫描规则后重新绑定")

// Local administrator input only. Public requests must never provide paths,
// credential material, collector identities or preparation receipts.
type nodeProvisioningInput struct {
	Node       string   `json:"node"`
	Expected   int64    `json:"expected_version"`
	Generation int64    `json:"expected_generation"`
	Credential string   `json:"credential"`
	Identity   string   `json:"identity_id"`
	Collectors []string `json:"collectors"`
	RulesFile  string   `json:"rules_file"`
}

type nodeProvisioningReceipt struct {
	ID         string `json:"id"`
	Node       string `json:"node"`
	Generation int64  `json:"generation,string"`
	Configured bool   `json:"configured"`
}

type nodeProvisioningMaterial struct {
	Format                         int
	Node, Credential, Identity     string
	CredentialProof, IdentityProof string
	Collectors                     []string
	Rules                          []byte
}

func (nodeProvisioningMaterial) String() string               { return "[private node provisioning]" }
func (nodeProvisioningMaterial) GoString() string             { return "[private node provisioning]" }
func (nodeProvisioningMaterial) MarshalJSON() ([]byte, error) { return nil, errNodeProvisioning }

func provisioningAAD(id, node, key string, generation int64) []byte {
	return []byte(fmt.Sprintf("webscan-v3/node-provisioning/v1/%s/%s/%s/%d", id, node, key, generation))
}

func sealNodeProvisioning(v *Vault, r nodeProvisioningReceipt, m nodeProvisioningMaterial) (string, []byte, []byte, error) {
	if v == nil || v.keys[v.active] == nil {
		return "", nil, nil, errNodeProvisioning
	}
	type privateMaterial nodeProvisioningMaterial
	raw, err := json.Marshal(privateMaterial(m))
	defer clear(raw)
	if err != nil || len(raw) > 1<<20 {
		return "", nil, nil, errNodeProvisioning
	}
	aead := v.keys[v.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", nil, nil, errNodeProvisioning
	}
	return v.active, nonce, aead.Seal(nil, nonce, raw, provisioningAAD(r.ID, r.Node, v.active, r.Generation)), nil
}

func readNodeProvisioningTx(ctx context.Context, tx *sql.Tx, v *Vault, node string) (nodeProvisioningReceipt, nodeProvisioningMaterial, error) {
	var r nodeProvisioningReceipt
	var m nodeProvisioningMaterial
	var key string
	var nonce, sealed []byte
	err := tx.QueryRowContext(ctx, `SELECT id,node,generation,key_id,nonce,ciphertext FROM v3_node_provisioning WHERE node=$1 FOR SHARE`, node).Scan(&r.ID, &r.Node, &r.Generation, &key, &nonce, &sealed)
	if err != nil {
		if err == sql.ErrNoRows {
			err = errNodeProvisioning
		}
		return r, m, err
	}
	if !validArchiveSource(r.ID) || !identifier.MatchString(r.Node) || r.Generation < 1 || v == nil || v.keys[key] == nil || len(nonce) != v.keys[key].NonceSize() || len(sealed) < v.keys[key].Overhead() || len(sealed) > (1<<20)+v.keys[key].Overhead() {
		return r, m, errNodeProvisioning
	}
	raw, err := v.keys[key].Open(nil, nonce, sealed, provisioningAAD(r.ID, r.Node, key, r.Generation))
	defer clear(raw)
	if err != nil || json.Unmarshal(raw, &m) != nil || m.Format != 1 || m.Node != node || !identifier.MatchString(m.Credential) || !identifier.MatchString(m.Identity) || !releaseDigest(m.CredentialProof) || !releaseDigest(m.IdentityProof) || len(m.Rules) < 1 || len(m.Rules) > 512<<10 {
		clear(m.Rules)
		return r, nodeProvisioningMaterial{}, errNodeProvisioning
	}
	r.Configured = true
	return r, m, nil
}

func provisioningCredentialTx(ctx context.Context, tx *sql.Tx, v *Vault, id, node string) (string, error) {
	var key string
	var revision int64
	var nonce, sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT key_id,revision,nonce,ciphertext FROM v3_credentials WHERE id=$1 AND node=$2 FOR SHARE`, id, node).Scan(&key, &revision, &nonce, &sealed); err != nil {
		return "", errNodeProvisioning
	}
	c, err := v.open(id, node, key, revision, nonce, sealed)
	if err != nil {
		return "", errNodeProvisioning
	}
	raw, err := json.Marshal(c)
	defer clear(raw)
	if err != nil {
		return "", errNodeProvisioning
	}
	return digest(raw), nil
}

// Store a binding atomically with audit and replay receipt. SSH credentials and
// leaf keys remain in their existing encrypted registries; only immutable
// references, authenticated identity digests and the rule bytes are sealed here.
// A rewrap does not change the credential's semantic digest.
func (s *Store) bindNodeProvisioning(ctx context.Context, c Config, t *deploymentTrust, user, key string, in nodeProvisioningInput) (json.RawMessage, error) {
	if t == nil || t.vault == nil || t.release == nil || !identifier.MatchString(in.Node) || !identifier.MatchString(in.Credential) || !identifier.MatchString(in.Identity) || in.Expected < 1 || in.Generation < 0 {
		return nil, errNodeProvisioning
	}
	if err := provisioningAdmin(ctx, s.DB, user); err != nil {
		return nil, err
	}
	rules, err := readTrustData(in.RulesFile, false, 512<<10)
	defer clear(rules)
	if err != nil || len(rules) == 0 {
		return nil, errNodeProvisioning
	}
	collectors := append([]string{}, in.Collectors...)
	sort.Strings(collectors)
	// Persist only this digest, never a source path or rule content, in the
	// request index. Actual private material is protected by AEAD below.
	request := []any{in.Node, in.Expected, in.Generation, in.Credential, in.Identity, collectors, digest(rules)}
	op, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.guardedMutationOptions(op, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, user, key, "bind-node-provisioning", in.Node, request, func(tx *sql.Tx) error {
		if err := lockConfigurationRestoreStateTx(op, tx); err != nil {
			return err
		}
		return provisioningAdmin(op, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		n, err := scanNode(tx.QueryRowContext(op, `SELECT `+nodeColumns+` FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE`, in.Node))
		if err != nil || n.Version != in.Expected {
			return nil, ErrConflict
		}
		var busy bool
		if err = tx.QueryRowContext(op, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND (status IN ('queued','running') OR recovery_required)) OR EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())`, n.ID).Scan(&busy); err != nil {
			return nil, err
		}
		if busy {
			return nil, ErrDeploymentBusy
		}
		var current int64
		err = tx.QueryRowContext(op, `SELECT generation FROM v3_node_provisioning WHERE node=$1 FOR UPDATE`, n.ID).Scan(&current)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if current != in.Generation {
			return nil, ErrConflict
		}
		credential, err := provisioningCredentialTx(op, tx, t.vault, in.Credential, n.ID)
		if err != nil {
			return nil, err
		}
		identity, managed, err := provisioningNodeIdentity(op, tx, c, t.vault, in.Identity, n, true)
		if err != nil {
			return nil, errNodeProvisioning
		}
		defer clear(identity.Key)
		crl, err := readTrustData(c.Collector.RevocationFile, false, 1<<20)
		if err != nil {
			return nil, errNodeProvisioning
		}
		input := NodeConfigurationInput{Node: n.ID, Expected: n.Version, Identity: identity, CRL: crl, Collectors: collectors, Rules: rules, ManagedIdentity: managed}
		material, err := nodeConfigurationMaterial(n, t.release, input)
		if err != nil || validateProvisioningTrust(c, material, time.Now()) != nil {
			return nil, errNodeProvisioning
		}
		private := nodeProvisioningMaterial{Format: 1, Node: n.ID, Credential: in.Credential, Identity: in.Identity, CredentialProof: credential, IdentityProof: digest(identity.Certificate), Collectors: collectors, Rules: rules}
		r := nodeProvisioningReceipt{ID: token(), Node: n.ID, Generation: current + 1, Configured: true}
		keyID, nonce, sealed, err := sealNodeProvisioning(t.vault, r, private)
		if err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(op, `INSERT INTO v3_node_provisioning(node,id,generation,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(node) DO UPDATE SET id=EXCLUDED.id,generation=EXCLUDED.generation,key_id=EXCLUDED.key_id,nonce=EXCLUDED.nonce,ciphertext=EXCLUDED.ciphertext,updated_at=clock_timestamp()`, r.Node, r.ID, r.Generation, keyID, nonce, sealed)
		return r, err
	})
}
