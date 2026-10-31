package controlplane

// Root rotation is an explicit host administrator task. Public API roles have
// neither CA keys nor an endpoint that can start or finalize this operation.
import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"webscan/internal/nodepki"
)

var errRootRotationTask = errors.New("换根任务未获当前授权，或成员、配置、凭据、签名物料已变化；保留现有身份，请核对后继续原任务")

type rootTaskContextKey struct{}

func rootTaskContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, rootTaskContextKey{}, id)
}

func rootRotationAvailableTx(ctx context.Context, tx *sql.Tx) error {
	// The table is introduced after the legacy configuration gate. Migration
	// tools may inspect older schemas, but they may never fabricate task state.
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass(current_schema()||'.v3_root_rotations') IS NOT NULL`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	except, _ := ctx.Value(rootTaskContextKey{}).(string)
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_root_rotations WHERE status NOT IN ('completed','canceled') AND id<>$1)`, except).Scan(&active); err != nil {
		return err
	}
	if active {
		return errRootRotationTask
	}
	return nil
}

type rootRotationNodeInput struct {
	Node        string `json:"node"`
	Credential  string `json:"credential"`
	Certificate []byte `json:"certificate"`
}

type rootRotationMember struct {
	Role            string `json:"role"`
	ID              string `json:"id"`
	Credential      string `json:"credential,omitempty"`
	CredentialProof string `json:"credential_proof,omitempty"`
	Snapshot        string `json:"snapshot,omitempty"`
	RuntimeEpoch    int64  `json:"runtime_epoch,omitempty"`
	Configuration   string `json:"configuration_sha256"`
	NodeDigest      string `json:"node_sha256,omitempty"`
	Certificate     []byte `json:"certificate"`
}

type rootRotationMemberState struct {
	Trust       bool            `json:"trust"`
	Request     json.RawMessage `json:"request,omitempty"`
	Certificate []byte          `json:"certificate,omitempty"`
	Activated   bool            `json:"activated"`
	ObservedAt  time.Time       `json:"observed_at,omitempty"`
	Final       bool            `json:"final"`
}

type rootRotationTask struct {
	Format        int                       `json:"format"`
	ID            string                    `json:"id"`
	User          string                    `json:"user"`
	ActorRevision int64                     `json:"actor_revision"`
	Configuration string                    `json:"configuration_sha256"`
	Helper        string                    `json:"helper_sha256"`
	Release       string                    `json:"manifest_sha256"`
	Anchor        []byte                    `json:"anchor"`
	Members       []rootRotationMember      `json:"members"`
	MembersSHA256 string                    `json:"members_sha256"`
	State         []rootRotationMemberState `json:"state"`
	Roots         *nodepki.RootSetSnapshot  `json:"roots,omitempty"`
	Status        string                    `json:"status"`
	Revision      int64                     `json:"revision"`
	ExpiresAt     time.Time                 `json:"expires_at"`
}

func rootTaskMAC(v *Vault, key string, raw []byte) (string, error) {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return "", errRootRotationTask
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/root-administrator-task/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func rootConfigDigest(c Config) string {
	// Config is host-owned; only its digest is stored. Bind paths, instance,
	// role configuration and release trust, without persisting its credentials.
	raw, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return digest(raw)
}

func scanRootTask(row interface{ Scan(...any) error }, v *Vault) (j rootRotationTask, hold bool, err error) {
	var id, user, key, proof, status string
	var revision int64
	var raw []byte
	err = row.Scan(&id, &user, &revision, &raw, &key, &proof, &status, &hold)
	if err != nil {
		return j, hold, err
	}
	want, err := rootTaskMAC(v, key, raw)
	if err != nil || !hmac.Equal([]byte(want), []byte(proof)) || json.Unmarshal(raw, &j) != nil {
		return rootRotationTask{}, hold, errRootRotationTask
	}
	canonical, _ := json.Marshal(j)
	members, _ := json.Marshal(j.Members)
	if !bytes.Equal(raw, canonical) || j.Format != 1 || j.ID != id || j.User != user || j.Revision != revision || j.Status != status || !releaseDigest(id) || j.MembersSHA256 != digest(members) || len(j.Members) == 0 || len(j.State) != len(j.Members) {
		return rootRotationTask{}, hold, errRootRotationTask
	}
	return j, hold, nil
}

const rootTaskColumns = `id,username,revision,document,key_id,proof,status,restore_hold`

func (s *Store) readRootTask(ctx context.Context, v *Vault, id string) (rootRotationTask, bool, error) {
	if !releaseDigest(id) {
		return rootRotationTask{}, false, errRootRotationTask
	}
	return scanRootTask(s.DB.QueryRowContext(ctx, `SELECT `+rootTaskColumns+` FROM v3_root_rotations WHERE id=$1`, id), v)
}

// Must run under the configuration gate. Every installed/runtime member is
// included, even if disabled. Saving drafts or credentials cannot silently
// change an in-flight root task's target.
func rootMemberBindingsTx(ctx context.Context, tx *sql.Tx, c Config, v *Vault, inputs []rootRotationNodeInput) ([]rootRotationMember, error) {
	anchor, err := readTrustData(c.Collector.CAFile, false, 64<<10)
	if err != nil {
		return nil, errRootRotationTask
	}
	crl, err := readTrustData(c.Collector.RevocationFile, false, nodepki.MaxCRLBytes)
	if err != nil {
		return nil, errRootRotationTask
	}
	trust, err := nodepki.NewTrust(anchor, crl, time.Now())
	if err != nil {
		return nil, errRootRotationTask
	}
	root, err := provisioningCertificate(anchor)
	if err != nil {
		return nil, errRootRotationTask
	}
	byID := make(map[string]rootRotationNodeInput, len(inputs))
	for _, in := range inputs {
		if !identifier.MatchString(in.Node) || !identifier.MatchString(in.Credential) || len(in.Certificate) == 0 || len(in.Certificate) > 16<<10 {
			return nil, errRootRotationTask
		}
		if _, exists := byID[in.Node]; exists {
			return nil, errRootRotationTask
		}
		byID[in.Node] = in
	}
	rows, err := tx.QueryContext(ctx, `SELECT node FROM v3_node_runtime ORDER BY node`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(ids) != len(byID) {
		return nil, errRootRotationTask
	}
	var members []rootRotationMember
	for _, id := range ids {
		in, ok := byID[id]
		if !ok {
			return nil, errRootRotationTask
		}
		var snapshot string
		var epoch int64
		var config, node []byte
		var same bool
		var name string
		err := tx.QueryRowContext(ctx, `SELECT r.snapshot,r.epoch,c.config,to_jsonb(c),r.epoch=n.runtime_generation AND r.delivered_version=n.version AND n.applied_version=n.version AND ROW(n.version,n.name,n.endpoint,n.server_name,n.enabled,n.mode,n.shard,n.config)=ROW(c.version,c.name,c.endpoint,c.server_name,c.enabled,c.mode,c.shard,c.config),c.server_name FROM v3_node_runtime r JOIN v3_nodes n ON n.id=r.node JOIN v3_node_configurations c ON c.node=r.node AND c.id=r.snapshot WHERE r.node=$1 AND n.removed_at IS NULL FOR SHARE OF n,c`, id).Scan(&snapshot, &epoch, &config, &node, &same, &name)
		if err != nil || !same {
			return nil, errRootRotationTask
		}
		proof, err := provisioningCredentialTx(ctx, tx, v, in.Credential, id)
		if err != nil {
			return nil, err
		}
		leaf, err := provisioningCertificate(in.Certificate)
		if err != nil || trust.Verify(leaf, nodepki.Node, id, time.Now()) != nil || leaf.VerifyHostname(name) != nil {
			return nil, errRootRotationTask
		}
		var known []byte
		err = tx.QueryRowContext(ctx, `SELECT certificate FROM v3_node_certificates WHERE node=$1 AND authority=$2 AND serial=$3 UNION ALL SELECT certificate FROM v3_node_certificate_renewals WHERE node=$1 AND authority=$2 AND serial=$3 LIMIT 1`, id, digest(root.Raw), leaf.SerialNumber.Text(16)).Scan(&known)
		if err != nil || !bytes.Equal(known, in.Certificate) {
			return nil, errRootRotationTask
		}
		members = append(members, rootRotationMember{Role: nodepki.Node, ID: id, Credential: in.Credential, CredentialProof: proof, Snapshot: snapshot, RuntimeEpoch: epoch, Configuration: digest(config), NodeDigest: digest(node), Certificate: in.Certificate})
	}
	return members, nil
}

func (s *Store) prepareRootRotation(ctx context.Context, c Config, v *Vault, user, key string, release *TrustedRelease, inputs []rootRotationNodeInput) (rootRotationTask, error) {
	var empty rootRotationTask
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil || c.Collector.IdentityFile == "" || c.Collector.RevocationStateDirectory == "" || release == nil || !releaseDigest(release.SHA256()) || !releaseDigest(release.manifest.Helper.SHA256) || len(inputs) > 20000 {
		return empty, errRootRotationTask
	}
	identity, _ := json.Marshal([]string{"webscan-v3/root-task/v1", user, key, rootConfigDigest(c)})
	id := digest(identity)
	ctx = rootTaskContext(ctx, id)
	raw, err := s.guardedMutation(ctx, user, key, "prepare-root-rotation", "central", []any{inputs, release.SHA256()}, func(tx *sql.Tx) error {
		if err := lockConfigurationOperationTx(ctx, tx, true); err != nil {
			return err
		}
		return provisioningAdmin(ctx, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		state, err := nodepki.ReadRootState(c.Collector.CAFile, c.Collector.RevocationStateDirectory, time.Now())
		if err != nil || state.Format != 0 {
			return nil, errRootRotationTask
		}
		var busy bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE status IN ('queued','running') OR recovery_required) OR EXISTS(SELECT 1 FROM v3_node_renewal_jobs WHERE activated_at IS NULL) OR EXISTS(SELECT 1 FROM v3_configuration_applications WHERE status NOT IN ('succeeded','rolled_back','cancelled')) OR EXISTS(SELECT 1 FROM v3_leases WHERE resource LIKE 'node-renewal:%' AND expires_at>clock_timestamp())`).Scan(&busy); err != nil {
			return nil, err
		}
		if busy {
			return nil, ErrDeploymentBusy
		}
		if busy, err := nodeIdentityRecoveryBusyTx(ctx, tx, "", ""); err != nil {
			return nil, err
		} else if busy {
			return nil, ErrDeploymentBusy
		}
		if held, err := migrationHeld(ctx, tx); err != nil {
			return nil, err
		} else if held {
			return nil, ErrMigrationPending
		}
		actor, err := deploymentPreviewAccount(ctx, tx, user)
		if err != nil {
			return nil, err
		}
		members, err := rootMemberBindingsTx(ctx, tx, c, v, inputs)
		if err != nil {
			return nil, err
		}
		b, record, err := nodepki.ReadIdentityWithRootState(c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, "", time.Now())
		defer clear(b.Key)
		if err != nil {
			return nil, errRootRotationTask
		}
		anchor, err := readTrustData(c.Collector.CAFile, false, 64<<10)
		if err != nil || !bytes.Equal(b.CA, anchor) {
			return nil, errRootRotationTask
		}
		collector, parseErr := provisioningCertificate(b.Certificate)
		crl, readErr := readTrustData(c.Collector.RevocationFile, false, nodepki.MaxCRLBytes)
		policy, trustErr := nodepki.NewTrust(anchor, crl, time.Now())
		if parseErr != nil || readErr != nil || trustErr != nil || policy.Verify(collector, nodepki.Collector, record.ID, time.Now()) != nil {
			return nil, errRootRotationTask
		}
		members = append(members, rootRotationMember{Role: nodepki.Collector, ID: record.ID, Configuration: rootConfigDigest(c), Certificate: b.Certificate})
		sort.Slice(members, func(i, j int) bool { return members[i].Role+":"+members[i].ID < members[j].Role+":"+members[j].ID })
		membership, _ := json.Marshal(members)
		j := rootRotationTask{Format: 1, ID: id, User: user, ActorRevision: actor, Configuration: rootConfigDigest(c), Helper: release.manifest.Helper.SHA256, Release: release.SHA256(), Anchor: anchor, Members: members, MembersSHA256: digest(membership), State: make([]rootRotationMemberState, len(members)), Status: "prepared", Revision: 1, ExpiresAt: time.Now().UTC().Add(24 * time.Hour)}
		doc, _ := json.Marshal(j)
		proof, err := rootTaskMAC(v, v.active, doc)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_root_rotations(id,username,revision,document,key_id,proof,status) VALUES($1,$2,1,$3,$4,$5,'prepared')`, j.ID, user, doc, v.active, proof); err != nil {
			return nil, err
		}
		if err := advanceConfigurationOperationTx(ctx, tx); err != nil {
			return nil, err
		}
		return map[string]string{"id": j.ID, "status": j.Status}, nil
	})
	if err != nil {
		return empty, err
	}
	var ref struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &ref) != nil {
		return empty, errRootRotationTask
	}
	j, _, err := s.readRootTask(ctx, v, ref.ID)
	return j, err
}
