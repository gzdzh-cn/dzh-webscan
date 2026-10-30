package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var errWebDeployment = errors.New("部署准备已过期或账号、节点、凭据及发布资料已变化，请重新操作")
var errFingerprintChanged = errors.New("SSH 主机指纹与已固定指纹不同，已停止；请在主服务器核实后处理")

// No public request can select an executable, certificate directory or command.
// These inputs are sealed immediately and never enter job plans/audit receipts.
type webDeploymentInput struct {
	Expected               int64  `json:"expected_version"`
	Kind                   string `json:"kind,omitempty"`
	SSHPort                int    `json:"ssh_port,omitempty"`
	Password               string `json:"password,omitempty"`
	PrivateKey             string `json:"private_key_content,omitempty"`
	PrivateKeyPath         string `json:"private_key_path,omitempty"`
	FingerprintPreparation string `json:"fingerprint_preparation,omitempty"`
	FingerprintToken       string `json:"fingerprint_token,omitempty"`
	Preparation            string `json:"preparation,omitempty"`
	PreviewToken           string `json:"preview_token,omitempty"`
}

func (webDeploymentInput) String() string   { return "[受保护的部署输入]" }
func (webDeploymentInput) GoString() string { return "[受保护的部署输入]" }

type deploymentPreparation struct {
	ID              string               `json:"id"`
	Node            string               `json:"node"`
	Username        string               `json:"-"`
	AccountRevision int64                `json:"-"`
	Version         int64                `json:"version"`
	Manifest        string               `json:"-"`
	Kind            string               `json:"kind"`
	Status          string               `json:"status"`
	Phase           string               `json:"phase"`
	ErrorCode       string               `json:"error_code"`
	Created         time.Time            `json:"created_at"`
	Updated         time.Time            `json:"updated_at"`
	Expires         time.Time            `json:"expires_at"`
	Owner           sql.NullString       `json:"-"`
	Epoch           int64                `json:"-"`
	Result          *webDeploymentResult `json:"result,omitempty"`
}
type webDeploymentResult struct {
	CredentialState  string             `json:"credential_state,omitempty"`
	Host             string             `json:"host,omitempty"`
	Port             int                `json:"port,omitempty"`
	Fingerprint      string             `json:"fingerprint,omitempty"`
	FingerprintToken string             `json:"fingerprint_token,omitempty"`
	Configured       bool               `json:"configured,omitempty"`
	Preview          *DeploymentPreview `json:"preview,omitempty"`
	Job              string             `json:"job,omitempty"`
}

const preparationColumns = `id,node,username,account_revision,node_version,manifest_sha256,kind,status,phase,error_code,created_at,updated_at,expires_at,lease_owner,lease_epoch`

func scanPreparation(row interface{ Scan(...any) error }) (p deploymentPreparation, err error) {
	err = row.Scan(&p.ID, &p.Node, &p.Username, &p.AccountRevision, &p.Version, &p.Manifest, &p.Kind, &p.Status, &p.Phase, &p.ErrorCode, &p.Created, &p.Updated, &p.Expires, &p.Owner, &p.Epoch)
	return
}
func preparationAAD(id, purpose string) []byte {
	return []byte("webscan-v3/web-deployment/v1/" + id + "/" + purpose)
}
func sealPreparation(v *Vault, id, purpose string, raw []byte) (string, []byte, []byte, error) {
	if v == nil || v.keys[v.active] == nil || len(raw) > 128<<10 {
		return "", nil, nil, errWebDeployment
	}
	a := v.keys[v.active]
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, nil, err
	}
	return v.active, nonce, a.Seal(nil, nonce, raw, preparationAAD(id, purpose)), nil
}
func openPreparation(v *Vault, id, purpose, key string, nonce, sealed []byte) ([]byte, error) {
	if v == nil || v.keys[key] == nil || len(nonce) != v.keys[key].NonceSize() || len(sealed) > (128<<10)+16 {
		return nil, errWebDeployment
	}
	raw, err := v.keys[key].Open(nil, nonce, sealed, preparationAAD(id, purpose))
	if err != nil {
		return nil, errWebDeployment
	}
	return raw, nil
}
func (s *Store) submitPreparation(ctx context.Context, t *deploymentTrust, user, key, node, kind string, in webDeploymentInput) (json.RawMessage, error) {
	if t == nil || !identifier.MatchString(node) || in.Expected < 1 || (kind != "fingerprint" && kind != "credential" && kind != "prepare" && kind != "confirm") {
		return nil, errWebDeployment
	}
	raw, err := json.Marshal(in)
	defer clear(raw)
	if err != nil {
		return nil, errWebDeployment
	}
	id := token()
	keyID, nonce, sealed, err := sealPreparation(t.vault, id, "input", raw)
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, t.vault.receiptKeys[t.vault.active])
	h.Write(raw)
	request := []any{node, kind, t.release.SHA256(), t.vault.active, hex.EncodeToString(h.Sum(nil))}
	return s.guardedMutation(ctx, user, key, "web-deployment-"+kind, node, request, func(tx *sql.Tx) error {
		if err := lockConfigurationRestoreStateTx(ctx, tx); err != nil {
			return err
		}
		return provisioningAdmin(ctx, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		rev, err := deploymentPreviewAccount(ctx, tx, user)
		if err != nil {
			return nil, err
		}
		n, err := scanNode(tx.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE", node))
		if err != nil {
			return nil, err
		}
		if n.Version != in.Expected || !n.Enabled {
			return nil, ErrConflict
		}
		if _, _, _, err = deploymentPreviewState(ctx, tx, n, DeploymentRequest{}); err != nil {
			return nil, err
		}
		// Expired requests must not reserve a node forever after a host outage.
		if _, err = tx.ExecContext(ctx, "UPDATE v3_deployment_preparations SET status='expired',phase='expired',updated_at=clock_timestamp() WHERE node=$1 AND status IN ('queued','running') AND expires_at<=clock_timestamp()", node); err != nil {
			return nil, err
		}
		var busy bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_deployment_preparations WHERE node=$1 AND status IN ('queued','running'))", node).Scan(&busy); err != nil {
			return nil, err
		}
		if busy {
			return nil, ErrDeploymentBusy
		}
		var pending int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM v3_deployment_preparations WHERE username=$1 AND expires_at>clock_timestamp()", user).Scan(&pending); err != nil {
			return nil, err
		}
		if pending >= 100 {
			return nil, errWebDeployment
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO v3_deployment_preparations(id,node,username,account_revision,node_version,manifest_sha256,kind) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, node, user, rev, n.Version, t.release.SHA256(), kind); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO v3_deployment_private_inputs(id,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4)", id, keyID, nonce, sealed); err != nil {
			return nil, err
		}
		return map[string]any{"id": id, "node": node, "status": "queued", "phase": "queued", "kind": kind}, nil
	})
}
func (s *Store) preparation(ctx context.Context, v *Vault, user, id string) (deploymentPreparation, error) {
	p, err := scanPreparation(s.DB.QueryRowContext(ctx, "SELECT "+preparationColumns+" FROM v3_deployment_preparations WHERE id=$1 AND username=$2", id, user))
	if err != nil {
		return p, err
	}
	var rev int64
	if err = s.DB.QueryRowContext(ctx, "SELECT revision FROM v3_accounts WHERE username=$1 AND role='admin'", user).Scan(&rev); err != nil {
		return deploymentPreparation{}, errWebDeployment
	}
	if rev != p.AccountRevision {
		return deploymentPreparation{}, errWebDeployment
	}
	if !time.Now().Before(p.Expires) {
		p.Status = "expired"
		p.Phase = "expired"
		return p, nil
	}
	if p.Status == "succeeded" {
		var k string
		var nonce, sealed []byte
		if err = s.DB.QueryRowContext(ctx, "SELECT result_key_id,result_nonce,result_ciphertext FROM v3_deployment_private_inputs WHERE id=$1", id).Scan(&k, &nonce, &sealed); err != nil {
			return p, err
		}
		raw, e := openPreparation(v, id, "result", k, nonce, sealed)
		defer clear(raw)
		if e != nil {
			return p, e
		}
		p.Result = &webDeploymentResult{}
		if json.Unmarshal(raw, p.Result) != nil {
			return deploymentPreparation{}, errWebDeployment
		}
	}
	return p, nil
}

// Worker only: a bounded unauthenticated handshake obtains the saved host's
// public key. No password is sent, command run, or trust implicitly accepted.
func readSSHHostFingerprint(ctx context.Context, host string, port int) (string, error) {
	conn, err := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		return "", DeploymentFailure{"remote-unavailable"}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	var fingerprint string
	_, _, _, _ = ssh.NewClientConn(conn, net.JoinHostPort(host, itoa(port)), &ssh.ClientConfig{User: "root", HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(k)
		return errors.New("fingerprint captured")
	}, Timeout: 8 * time.Second})
	if fingerprint == "" {
		return "", DeploymentFailure{"remote-unavailable"}
	}
	return fingerprint, nil
}
func itoa(v int) string { return strconv.Itoa(v) }

func (s *Store) latestWebCredential(ctx context.Context, v *Vault, node string) (string, SSHCredential, error) {
	var id string
	err := s.DB.QueryRowContext(ctx, `SELECT id FROM v3_credentials WHERE node=$1 ORDER BY (id=COALESCE((SELECT credential FROM v3_web_node_credentials WHERE node=$1),'')) DESC,created_at DESC,id DESC LIMIT 1`, node).Scan(&id)
	if err != nil {
		return "", SSHCredential{}, ErrCredentialUnavailable
	}
	c, err := s.ReadCredential(ctx, v, id, node)
	return id, c, err
}

func controlledSSHKey(c ExecutorConfig, path string) (string, error) {
	dirs := c.SSHKeyDirectories
	if len(dirs) == 0 {
		dirs = []string{"/var/lib/webscan-deploy/ssh-keys", "/root/.ssh"}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrCredentialUnavailable
	}
	allowed := false
	for _, d := range dirs {
		rel, e := filepath.Rel(d, path)
		if e == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			allowed = true
		}
	}
	if !allowed {
		return "", ErrCredentialUnavailable
	}
	// readTrustData traverses every parent with no-follow and verifies owner,
	// mode, regular file and size. A symlink inside an allowed tree is rejected.
	raw, err := readTrustData(path, true, 64<<10)
	defer clear(raw)
	if err != nil {
		return "", ErrCredentialUnavailable
	}
	if _, err = ssh.ParsePrivateKey(raw); err != nil {
		return "", ErrCredentialUnavailable
	}
	return string(raw), nil
}

// Compare opaque confirmation capabilities without leaking mismatched values.
func sameCapability(a, b string) bool {
	return len(a) == 64 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func webDeploymentError(err error) string {
	switch {
	case errors.Is(err, errFingerprintChanged):
		return "fingerprint_changed"
	case errors.Is(err, ErrCredentialUnavailable):
		return "credential_unavailable"
	case errors.Is(err, ErrDeploymentUnnecessary):
		return "upgrade_unnecessary"
	case errors.Is(err, ErrDeploymentDowngrade):
		return "downgrade_rejected"
	case errors.Is(err, ErrDeploymentModeMigration):
		return "mode_migration_required"
	case errors.Is(err, ErrDeploymentBusy):
		return "deployment_busy"
	case errors.Is(err, ErrConflict), errors.Is(err, ErrDeploymentPreview), errors.Is(err, errWebDeployment):
		return "preparation_conflict"
	case errors.Is(err, errNodeIdentity):
		return "issuer_unavailable"
	default:
		return "preparation_failed"
	}
}

func (s *Store) webCredentialState(ctx context.Context, node string) (string, error) {
	var id string
	var rev int64
	err := s.DB.QueryRowContext(ctx, `SELECT id,revision FROM v3_credentials WHERE node=$1 ORDER BY (id=COALESCE((SELECT credential FROM v3_web_node_credentials WHERE node=$1),'')) DESC,created_at DESC,id DESC LIMIT 1`, node).Scan(&id, &rev)
	if err == sql.ErrNoRows {
		return "none", nil
	}
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal([]any{id, rev})
	return digest(raw), nil
}
