package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

var ErrDeploymentPreview = errors.New("部署预览已过期或账号、配置、凭据、部署状态已变化，请重新预览")
var ErrDeploymentUnnecessary = errors.New("已确认相同版本、摘要和配置，无需重复升级")
var ErrDeploymentDowngrade = errors.New("已确认目标版本低于当前版本，不能通过升级入口降级")
var ErrDeploymentModeMigration = errors.New("部署方式已变化，请使用专门迁移流程")

type DeploymentTarget struct {
	Release string `json:"release"`
	SHA256  string `json:"sha256"`
	Mode    string `json:"mode"`
}

// The only capability returned here is the short-lived token. No credential,
// private material, artifact path or editable draft belongs in this response.
type DeploymentPreview struct {
	Token          string            `json:"token"`
	Node           string            `json:"node"`
	Kind           string            `json:"kind"`
	Version        int64             `json:"version"`
	AppliedVersion int64             `json:"applied_version"`
	Target         DeploymentTarget  `json:"target"`
	Current        *DeploymentTarget `json:"current,omitempty"`
	Comparison     string            `json:"comparison"`
	ExpiresAt      time.Time         `json:"expires_at"`
}

func deploymentPreviewAccount(ctx context.Context, tx *sql.Tx, user string) (int64, error) {
	var role string
	var rev int64
	if err := tx.QueryRowContext(ctx, "SELECT role,revision FROM v3_accounts WHERE username=$1 FOR SHARE", user).Scan(&role, &rev); err != nil {
		if err == sql.ErrNoRows {
			return 0, ErrDeploymentPreview
		}
		return 0, err
	}
	if role != "admin" {
		return 0, ErrDeploymentPreview
	}
	return rev, nil
}

// Call only with the node row locked. Ordinary telemetry is deliberately not
// included; a new task or a changed saved configuration must expire a preview.
func deploymentPreviewState(ctx context.Context, tx *sql.Tx, n Node, in DeploymentRequest) (string, *DeploymentTarget, string, error) {
	var busy bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_deployment_jobs WHERE node=$1 AND status NOT IN ('succeeded','rolled_back') AND (status IN ('queued','running') OR recovery_required)) OR EXISTS(SELECT 1 FROM v3_node_identity_recoveries WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_changes WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp()) OR EXISTS(SELECT 1 FROM v3_node_name_prunings WHERE node=$1 AND status IN ('prepared','requested','signed') AND expires_at>clock_timestamp())", n.ID).Scan(&busy); err != nil {
		return "", nil, "", err
	}
	if busy {
		return "", nil, "", ErrDeploymentBusy
	}
	var last []byte
	err := tx.QueryRowContext(ctx, `SELECT jsonb_build_array(id,plan_digest,status,direction,step,rollback_step,lease_epoch,log_cursor,updated_at) FROM v3_deployment_jobs WHERE node=$1 ORDER BY created_at DESC,id DESC LIMIT 1 FOR SHARE`, n.ID).Scan(&last)
	if err != nil && err != sql.ErrNoRows {
		return "", nil, "", err
	}
	var current *DeploymentTarget
	comparison := "unknown"
	baseline, err := scanDeployment(tx.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM v3_deployment_jobs WHERE node=$1 AND status='succeeded' ORDER BY created_at DESC,id DESC LIMIT 1 FOR SHARE", n.ID))
	if err != nil && err != sql.ErrNoRows {
		return "", nil, "", err
	}
	if err == nil && n.AppliedVersion != 0 && n.AppliedVersion == baseline.NodeVersion {
		old := baseline.Plan.Request
		current = &DeploymentTarget{Release: old.Release, SHA256: old.SHA256, Mode: baseline.Plan.Node.Mode}
		if in.Kind == "upgrade" {
			if n.Mode != current.Mode {
				return "", nil, "", ErrDeploymentModeMigration
			}
			if order, known := compareDeploymentRelease(in.Release, old.Release); known {
				switch {
				case order < 0:
					return "", nil, "", ErrDeploymentDowngrade
				case order > 0:
					comparison = "newer"
				default:
					comparison = "same-version"
				}
			}
			if in.Release == old.Release && in.SHA256 == old.SHA256 && n.Version == n.AppliedVersion && digest(n.Config) == baseline.Plan.ConfigDigest {
				return "", nil, "", ErrDeploymentUnnecessary
			}
		}
	}
	raw, err := json.Marshal(struct {
		Node    Node
		Config  string
		Last    json.RawMessage
		Current *DeploymentTarget
	}{n, digest(n.Config), last, current})
	return digest(raw), current, comparison, err
}

func previewCredential(ctx context.Context, tx *sql.Tx, t *deploymentTrust, in DeploymentRequest) (int64, error) {
	var key string
	var rev int64
	var nonce, sealed []byte
	if err := tx.QueryRowContext(ctx, "SELECT key_id,revision,nonce,ciphertext FROM v3_credentials WHERE id=$1 AND node=$2 FOR SHARE", in.Credential, in.Node).Scan(&key, &rev, &nonce, &sealed); err != nil {
		if err == sql.ErrNoRows {
			return 0, ErrCredentialUnavailable
		}
		return 0, err
	}
	_, err := t.vault.open(in.Credential, in.Node, key, rev, nonce, sealed)
	return rev, err
}

// Local/internal only until full native and Docker service acceptance passes.
// This checks saved material and state, not network or remote environment.
func (s *Store) previewLocalDeployment(ctx context.Context, c Config, t *deploymentTrust, user string, in DeploymentRequest) (DeploymentPreview, error) {
	var out DeploymentPreview
	if err := provisioningAdmin(ctx, s.DB, user); err != nil {
		return out, err
	}
	m, err := s.localDeploymentMaterial(ctx, c, t, in)
	if err != nil {
		return out, err
	}
	defer clear(m.Key)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return out, err
	} else if held {
		return out, ErrMigrationPending
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM v3_deployment_previews WHERE job IS NULL AND expires_at<=clock_timestamp() AND token_hash IN (SELECT token_hash FROM v3_deployment_previews WHERE job IS NULL AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 200 FOR UPDATE SKIP LOCKED)"); err != nil {
		return out, err
	}
	// Bound outstanding capabilities even when multiple API processes preview
	// for the same account. This lock never serializes unrelated node operations.
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,773376013))", user); err != nil {
		return out, err
	}
	rev, err := deploymentPreviewAccount(ctx, tx, user)
	if err != nil {
		return out, err
	}
	n, err := scanNode(tx.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE", in.Node))
	if err != nil {
		return out, err
	}
	if n.Version != in.Expected || !n.Enabled || in.Kind == "upgrade" && n.AppliedVersion == 0 || in.Kind == "install" && n.AppliedVersion != 0 {
		return out, ErrConflict
	}
	if err = validateLocalDeploymentTx(ctx, tx, c, t, user, in, m, n); err != nil {
		return out, err
	}
	state, current, comparison, err := deploymentPreviewState(ctx, tx, n, in)
	if err != nil {
		return out, err
	}
	cred, err := previewCredential(ctx, tx, t, in)
	if err != nil {
		return out, err
	}

	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM v3_deployment_previews WHERE username=$1 AND job IS NULL AND expires_at>clock_timestamp()", user).Scan(&count); err != nil {
		return out, err
	}
	if count >= 100 {
		return out, errors.New("有效部署预览过多，请等待旧预览过期")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	var canonical []byte
	if err = tx.QueryRowContext(ctx, "SELECT $1::jsonb", raw).Scan(&canonical); err != nil {
		return out, err
	}
	out = DeploymentPreview{Token: token(), Node: n.ID, Kind: in.Kind, Version: n.Version, AppliedVersion: n.AppliedVersion, Target: DeploymentTarget{in.Release, in.SHA256, n.Mode}, Current: current, Comparison: comparison}
	if err = tx.QueryRowContext(ctx, "INSERT INTO v3_deployment_previews(token_hash,username,account_revision,node,request,request_digest,state_digest,credential_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING expires_at", digest([]byte(out.Token)), user, rev, in.Node, canonical, digest(canonical), state, cred).Scan(&out.ExpiresAt); err != nil {
		return DeploymentPreview{}, err
	}
	// Never pass out to the generic mutation/audit writer: it contains a token.
	audit, _ := json.Marshal(map[string]any{"node": n.ID, "kind": in.Kind, "version": n.Version, "target": out.Target, "expires_at": out.ExpiresAt})
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'preview-deployment',$2,$3)", user, n.ID, audit); err != nil {
		return DeploymentPreview{}, err
	}
	if err = tx.Commit(); err != nil {
		return DeploymentPreview{}, err
	}
	return out, nil
}

type deploymentConfirmationInput struct {
	Token string `json:"token"`
}

func (s *Store) confirmLocalDeployment(ctx context.Context, c Config, t *deploymentTrust, user, key, preview string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !validArchiveSource(preview) || !identifier.MatchString(user) {
		return nil, ErrDeploymentPreview
	}
	if !c.Executor.Enabled {
		return nil, errors.New("请先显式启用部署执行器，再确认部署任务")
	}
	hash := digest([]byte(preview))
	var in DeploymentRequest
	var storedState string
	var storedCredential int64
	var used sql.NullString
	var expired bool
	return retryDeploymentConfigurationMutation(ctx, func() (json.RawMessage, error) {
		return s.guardedMutationOptions(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead}, user, key, "confirm-deployment", hash, []string{hash}, func(tx *sql.Tx) error {
			if err := lockDeploymentWriteRelationsTx(ctx, tx); err != nil {
				return err
			}
			rev, err := deploymentPreviewAccount(ctx, tx, user)
			if err != nil {
				return err
			}
			var account int64
			var raw []byte
			var sum string
			err = tx.QueryRowContext(ctx, "SELECT account_revision,request,request_digest,state_digest,credential_revision,job,expires_at<=clock_timestamp() FROM v3_deployment_previews WHERE token_hash=$1 AND username=$2 FOR UPDATE", hash, user).Scan(&account, &raw, &sum, &storedState, &storedCredential, &used, &expired)
			if err == sql.ErrNoRows {
				return ErrDeploymentPreview
			}
			if err != nil {
				return err
			}
			if rev != account || digest(raw) != sum || json.Unmarshal(raw, &in) != nil || in.validate() != nil {
				return ErrDeploymentPreview
			}
			return nil
		}, func(tx *sql.Tx) (any, error) {
			// A receipt replay bypasses this callback but never authorization above.
			// Another idempotency key cannot turn a consumed token into a new job.
			if expired || used.Valid {
				return nil, ErrDeploymentPreview
			}
			m, err := s.localDeploymentMaterial(ctx, c, t, in)
			if err != nil {
				return nil, err
			}
			defer clear(m.Key)
			result, err := insertDeploymentWithBackup(ctx, tx, user, in, func(tx *sql.Tx, n Node) error {
				// A lock wait or slow filesystem check cannot extend the ten-minute
				// window. Recheck database time after acquiring the node reservation.
				var current bool
				if err := tx.QueryRowContext(ctx, "SELECT expires_at>clock_timestamp() FROM v3_deployment_previews WHERE token_hash=$1", hash).Scan(&current); err != nil {
					return err
				}
				if !current {
					return ErrDeploymentPreview
				}
				if err := validateLocalDeploymentTx(ctx, tx, c, t, user, in, m, n); err != nil {
					return err
				}
				state, _, _, err := deploymentPreviewState(ctx, tx, n, in)
				if err != nil {
					return err
				}
				if state != storedState {
					return ErrDeploymentPreview
				}
				cred, err := previewCredential(ctx, tx, t, in)
				if err != nil {
					return err
				}
				if cred != storedCredential {
					return ErrDeploymentPreview
				}
				return nil
			}, &deploymentConfigurationBackup{t.vault, c})
			if err != nil {
				return nil, err
			}
			response := result.(map[string]any)
			if _, err = tx.ExecContext(ctx, "UPDATE v3_deployment_previews SET job=$2 WHERE token_hash=$1", hash, response["id"]); err != nil {
				return nil, err
			}
			return response, nil
		})
	})
}

// Compare canonical SemVer releases without bounded integer conversions.
// Noncanonical legacy strings have unknown order, never a fabricated version.
func compareDeploymentRelease(a, b string) (int, bool) {
	parse := func(s string) ([]string, []string, bool) {
		if !releaseVersion.MatchString(s) || len(s) > 128 {
			return nil, nil, false
		}
		parts := strings.SplitN(s[1:], "-", 2)
		core := strings.Split(parts[0], ".")
		for _, p := range core {
			if len(p) > 1 && p[0] == '0' {
				return nil, nil, false
			}
		}
		var pre []string
		if len(parts) == 2 {
			pre = strings.Split(parts[1], ".")
			for _, p := range pre {
				if p == "" || numericVersionPart(p) && len(p) > 1 && p[0] == '0' {
					return nil, nil, false
				}
			}
		}
		return core, pre, true
	}
	x, xp, ok := parse(a)
	if !ok {
		return 0, false
	}
	y, yp, ok := parse(b)
	if !ok {
		return 0, false
	}
	integerCompare := func(a, b string) int {
		x, _ := new(big.Int).SetString(a, 10)
		y, _ := new(big.Int).SetString(b, 10)
		return x.Cmp(y)
	}
	for i := range x {
		if c := integerCompare(x[i], y[i]); c != 0 {
			return c, true
		}
	}
	if len(xp) == 0 && len(yp) > 0 {
		return 1, true
	}
	if len(yp) == 0 && len(xp) > 0 {
		return -1, true
	}
	for i := 0; i < len(xp) && i < len(yp); i++ {
		xn, yn := numericVersionPart(xp[i]), numericVersionPart(yp[i])
		var c int
		switch {
		case xn && yn:
			c = integerCompare(xp[i], yp[i])
		case xn:
			c = -1
		case yn:
			c = 1
		default:
			c = strings.Compare(xp[i], yp[i])
		}
		if c != 0 {
			return c, true
		}
	}
	if len(xp) < len(yp) {
		return -1, true
	}
	if len(xp) > len(yp) {
		return 1, true
	}
	return 0, true
}

func numericVersionPart(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
