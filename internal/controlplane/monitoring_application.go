package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
)

var errMonitoringApplication = errors.New("公共规则应用计划、账号或节点状态已变化，请重新预览；原服务未主动修改")

type monitoringApplicationRequest struct {
	Expected string                        `json:"expected_version"`
	Nodes    []monitoringApplicationTarget `json:"nodes"`
}
type monitoringApplicationTarget struct {
	ID       string `json:"id"`
	Expected int64  `json:"expected_version"`
}
type monitoringApplicationPlanNode struct {
	Node            Node            `json:"node"`
	Before          json.RawMessage `json:"before"`
	TargetDigest    string          `json:"target_digest"`
	Target          json.RawMessage `json:"target"`
	State           string          `json:"state"`
	Credential      string          `json:"credential"`
	CredentialState string          `json:"credential_state"`
}
type monitoringApplicationPlan struct {
	Username   string                          `json:"username"`
	Account    int64                           `json:"account"`
	Generation string                          `json:"generation"`
	Release    string                          `json:"release"`
	Manifest   string                          `json:"manifest"`
	Nodes      []monitoringApplicationPlanNode `json:"nodes"`
}
type monitoringApplication struct {
	ID                    string                      `json:"id"`
	Username              string                      `json:"-"`
	Account               int64                       `json:"-"`
	Generation            string                      `json:"rules_version"`
	Manifest              string                      `json:"manifest_sha256"`
	Release               string                      `json:"release"`
	Status                string                      `json:"status"`
	Direction             string                      `json:"direction"`
	Version               int64                       `json:"-"`
	Expected              string                      `json:"version"`
	Digest                string                      `json:"-"`
	Key                   string                      `json:"-"`
	Nonce                 []byte                      `json:"-"`
	Sealed                []byte                      `json:"-"`
	Proof                 string                      `json:"-"`
	TokenHash             string                      `json:"-"`
	Expires               time.Time                   `json:"expires_at"`
	Owner                 sql.NullString              `json:"-"`
	Epoch                 int64                       `json:"-"`
	Lease                 sql.NullTime                `json:"-"`
	Error                 string                      `json:"error_code,omitempty"`
	Created               time.Time                   `json:"created_at"`
	Updated               time.Time                   `json:"updated_at"`
	Controller            string                      `json:"controller"`
	ControllerRevision    int64                       `json:"-"`
	CanReauthorize        bool                        `json:"can_reauthorize"`
	ReauthorizationReason string                      `json:"reauthorization_reason,omitempty"`
	CanResume             bool                        `json:"can_resume"`
	CanRollback           bool                        `json:"can_rollback"`
	Selected              string                      `json:"selected_node,omitempty"`
	Nodes                 []monitoringApplicationItem `json:"nodes"`
	Plan                  monitoringApplicationPlan   `json:"-"`
}
type monitoringApplicationItem struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Batch       int             `json:"batch"`
	State       string          `json:"state"`
	Job         string          `json:"job,omitempty"`
	Error       string          `json:"error_code,omitempty"`
	BeforeRules *NodeMonitoring `json:"before,omitempty"`
	Rules       *NodeMonitoring `json:"effective,omitempty"`
	Changed     bool            `json:"changed"`
	CanResume   bool            `json:"can_resume"`
	CanRollback bool            `json:"can_rollback"`
}

const monitoringApplicationColumns = `id,username,account_revision,global_generation,manifest_sha256,release,status,direction,version,plan_digest,key_id,nonce,ciphertext,proof,token_hash,expires_at,lease_owner,lease_epoch,lease_until,error_code,created_at,updated_at,selected_node,controller,controller_revision`

func scanMonitoringApplication(row interface{ Scan(...any) error }) (monitoringApplication, error) {
	var p monitoringApplication
	e := row.Scan(&p.ID, &p.Username, &p.Account, &p.Generation, &p.Manifest, &p.Release, &p.Status, &p.Direction, &p.Version, &p.Digest, &p.Key, &p.Nonce, &p.Sealed, &p.Proof, &p.TokenHash, &p.Expires, &p.Owner, &p.Epoch, &p.Lease, &p.Error, &p.Created, &p.Updated, &p.Selected, &p.Controller, &p.ControllerRevision)
	p.Expected = strconv.FormatInt(p.Version, 10)
	return p, e
}
func monitoringApplicationMAC(v *Vault, key, domain string, value any) string {
	if v == nil || len(v.receiptKeys[key]) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, v.receiptKeys[key])
	h.Write([]byte("webscan-v3/monitoring-application/" + domain + "\x00"))
	h.Write(common.JSON(value))
	return key + ":" + hex.EncodeToString(h.Sum(nil))
}
func monitoringApplicationProof(v *Vault, key string, p monitoringApplication) string {
	return monitoringApplicationMAC(v, key, "state/v1", []any{p.ID, p.Username, p.Account, p.Generation, p.Manifest, p.Release, p.Digest, p.Status, p.Direction, p.Version, p.Epoch, p.TokenHash, p.Expires.Unix(), p.Selected, p.Controller, p.ControllerRevision})
}
func openMonitoringApplication(v *Vault, p *monitoringApplication) error {
	key, _, ok := strings.Cut(p.Proof, ":")
	want := monitoringApplicationProof(v, key, *p)
	if !ok || want == "" || !hmac.Equal([]byte(want), []byte(p.Proof)) {
		return errMonitoringApplication
	}
	raw, e := openMonitoringPlan(v, p.ID, p.Key, p.Nonce, p.Sealed)
	defer clear(raw)
	if e != nil || digest(raw) != p.Digest || json.Unmarshal(raw, &p.Plan) != nil {
		return errMonitoringApplication
	}
	if p.Plan.Username != p.Username || p.Plan.Account != p.Account || p.Plan.Generation != p.Generation || p.Plan.Manifest != p.Manifest || p.Plan.Release != p.Release || len(p.Plan.Nodes) == 0 {
		return errMonitoringApplication
	}
	return nil
}
func updateMonitoringApplicationTx(ctx context.Context, tx *sql.Tx, v *Vault, p *monitoringApplication) error {
	p.Version++
	p.Expected = strconv.FormatInt(p.Version, 10)
	p.Proof = monitoringApplicationProof(v, v.active, *p)
	if p.Proof == "" {
		return errMonitoringApplication
	}
	res, e := tx.ExecContext(ctx, `UPDATE v3_monitoring_applications SET status=$2,direction=$3,version=$4,proof=$5,lease_owner=$6,lease_epoch=$7,lease_until=$8,error_code=$9,selected_node=$11,controller=$12,controller_revision=$13,updated_at=clock_timestamp() WHERE id=$1 AND version=$10`, p.ID, p.Status, p.Direction, p.Version, p.Proof, p.Owner, p.Epoch, p.Lease, p.Error, p.Version-1, p.Selected, p.Controller, p.ControllerRevision)
	return deploymentAffected(res, e)
}
func monitoringApplicationCredentialTx(ctx context.Context, tx *sql.Tx, node string) (string, string, error) {
	var credential string
	var revision int64
	e := tx.QueryRowContext(ctx, `SELECT c.id,c.revision FROM v3_credentials c WHERE c.node=$1 ORDER BY (c.id=COALESCE((SELECT credential FROM v3_web_node_credentials WHERE node=$1),'')) DESC,c.created_at DESC,c.id DESC LIMIT 1 FOR SHARE OF c`, node).Scan(&credential, &revision)
	return credential, digest(common.JSON([]any{credential, revision})), e
}
func (s *Store) previewMonitoringApplication(ctx context.Context, t *deploymentTrust, user, key string, in monitoringApplicationRequest) (monitoringApplication, string, error) {
	var out monitoringApplication
	if t == nil || t.release == nil || !canonicalMonitoringVersion(in.Expected) || len(in.Nodes) < 1 || len(in.Nodes) > 1000 {
		return out, "", errMonitoringApplication
	}
	sort.Slice(in.Nodes, func(i, j int) bool { return in.Nodes[i].ID < in.Nodes[j].ID })
	for i, n := range in.Nodes {
		if !identifier.MatchString(n.ID) || n.ID == "central" || n.Expected < 1 || i > 0 && in.Nodes[i-1].ID == n.ID {
			return out, "", errMonitoringApplication
		}
	}
	raw, e := s.guardedMutation(ctx, user, key, "monitoring-application-preview", "monitoring", in, func(tx *sql.Tx) error { return lockMonitoringWriteTx(ctx, tx) }, func(tx *sql.Tx) (any, error) {
		account, e := deploymentPreviewAccount(ctx, tx, user)
		if e != nil {
			return nil, e
		}
		d, e := readSettingsDraftTx(ctx, tx, false)
		if e != nil {
			return nil, e
		}
		if checkSettingsDraftProof(t.vault, d) != nil {
			return nil, errMonitoringApplication
		}
		global, e := monitoringRulesFromDraft(d)
		if e != nil || global.Version != in.Expected {
			return nil, ErrConflict
		}
		plan := monitoringApplicationPlan{Username: user, Account: account, Generation: global.Version, Release: t.release.manifest.Release, Manifest: t.release.SHA256(), Nodes: []monitoringApplicationPlanNode{}}
		for _, target := range in.Nodes {
			n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR UPDATE`, target.ID))
			if e != nil {
				return nil, e
			}
			monitor := monitoringForNode(n)
			if n.Version != target.Expected || !n.Enabled || n.AppliedVersion == 0 || n.AppliedVersion != n.Version || monitor == nil || monitor.Source != "inherited" {
				return nil, ErrConflict
			}
			if e = checkMonitoringNodeReservationTx(ctx, tx, n.ID); e != nil {
				return nil, e
			}
			state, current, _, e := monitoringDeploymentState(ctx, tx, n)
			if e != nil {
				return nil, e
			}
			// Configuration-only application must not silently change a binary release.
			if current == nil || current.Release != plan.Release || current.Mode != n.Mode {
				return nil, ErrDeploymentModeMigration
			}
			credential, credentialState, e := monitoringApplicationCredentialTx(ctx, tx, n.ID)
			if e != nil {
				return nil, ErrCredentialUnavailable
			}
			wanted := n
			wanted.Monitoring = &NodeMonitoring{Source: "inherited", RulesVersion: global.Version}
			if e = prepareMonitoringNodeTx(ctx, tx, &wanted, n.Version, t.vault); e != nil {
				return nil, e
			}
			if e = tx.QueryRowContext(ctx, `SELECT $1::jsonb`, wanted.Config).Scan(&wanted.Config); e != nil {
				return nil, e
			}
			plan.Nodes = append(plan.Nodes, monitoringApplicationPlanNode{Node: n, Before: append(json.RawMessage{}, n.Config...), Target: append(json.RawMessage{}, wanted.Config...), TargetDigest: digest(wanted.Config), State: state, Credential: credential, CredentialState: credentialState})
		}
		p := monitoringApplication{ID: token(), Username: user, Account: account, Controller: user, ControllerRevision: account, Generation: global.Version, Manifest: plan.Manifest, Release: plan.Release, Status: "preview", Direction: "forward", Version: 1, Expires: time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)}
		body := common.JSON(plan)
		p.Digest = digest(body)
		p.Key, p.Nonce, p.Sealed, e = sealMonitoringPlan(t.vault, p.ID, body)
		if e != nil {
			return nil, e
		}
		capability := monitoringApplicationMAC(t.vault, p.Key, "capability/v1", []any{p.ID, p.Digest})
		p.TokenHash = digest([]byte(capability))
		p.Proof = monitoringApplicationProof(t.vault, t.vault.active, p)
		_, e = tx.ExecContext(ctx, `INSERT INTO v3_monitoring_applications(id,username,account_revision,global_generation,manifest_sha256,release,status,direction,version,plan_digest,key_id,nonce,ciphertext,proof,token_hash,expires_at,controller,controller_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, p.ID, user, account, p.Generation, p.Manifest, p.Release, p.Status, p.Direction, p.Version, p.Digest, p.Key, p.Nonce, p.Sealed, p.Proof, p.TokenHash, p.Expires, p.Controller, p.ControllerRevision)
		if e != nil {
			return nil, e
		}
		for i, n := range plan.Nodes {
			if _, e = tx.ExecContext(ctx, `INSERT INTO v3_monitoring_application_nodes(application,node,ordinal,batch_index) VALUES($1,$2,$3,$4)`, p.ID, n.Node.ID, i, i/20); e != nil {
				return nil, e
			}
		}
		return map[string]string{"id": p.ID}, nil
	})
	if e != nil {
		return out, "", e
	}
	var receipt struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &receipt) != nil {
		return out, "", errMonitoringApplication
	}
	out, e = s.monitoringApplication(ctx, t.vault, user, receipt.ID)
	if e != nil {
		return out, "", e
	}
	if out.Status != "preview" || !time.Now().Before(out.Expires) {
		return out, "", ErrDeploymentPreview
	}
	capability := monitoringApplicationMAC(t.vault, out.Key, "capability/v1", []any{out.ID, out.Digest})
	return out, capability, nil
}
func (s *Store) monitoringApplication(ctx context.Context, v *Vault, user, id string) (monitoringApplication, error) {
	p, e := scanMonitoringApplication(s.DB.QueryRowContext(ctx, `SELECT `+monitoringApplicationColumns+` FROM v3_monitoring_applications WHERE id=$1`, id))
	if e != nil {
		return p, e
	}
	if e = openMonitoringApplication(v, &p); e != nil {
		return p, e
	}
	if e = provisioningAdmin(ctx, s.DB, user); e != nil {
		return p, e
	}
	var rev int64
	if e = s.DB.QueryRowContext(ctx, `SELECT revision FROM v3_accounts WHERE username=$1 AND role='admin'`, user).Scan(&rev); e != nil {
		return p, e
	}
	var hold bool
	if e = s.DB.QueryRowContext(ctx, `SELECT recovery_hold FROM v3_monitoring_applications WHERE id=$1`, id).Scan(&hold); e != nil {
		return p, e
	}
	authorized := p.Controller == user && p.ControllerRevision == rev && !hold
	p.CanReauthorize = p.Status == "paused" && !hold && !authorized
	if p.CanReauthorize {
		p.ReauthorizationReason = "执行账号权限或版本已变化，需要管理员重新核对并授权"
	}
	p.Nodes = []monitoringApplicationItem{}
	rows, e := s.DB.QueryContext(ctx, `SELECT node,batch_index,state,coalesce(child,''),error_code FROM v3_monitoring_application_nodes WHERE application=$1 ORDER BY ordinal`, id)
	if e != nil {
		return p, e
	}
	defer rows.Close()
	for rows.Next() {
		var item monitoringApplicationItem
		if e = rows.Scan(&item.ID, &item.Batch, &item.State, &item.Job, &item.Error); e != nil {
			return p, e
		}
		for _, n := range p.Plan.Nodes {
			if n.Node.ID == item.ID {
				item.Name = n.Node.Name
				before := n.Node
				before.Config = n.Before
				after := n.Node
				after.Config = n.Target
				item.BeforeRules = monitoringForNode(before)
				item.Rules = monitoringForNode(after)
				item.Changed = !configurationJSONEqual(n.Before, n.Target)
				break
			}
		}
		item.CanResume = authorized && p.Status == "paused" && (item.State == "failed" || item.State == "pending") && p.Direction == "forward"
		item.CanRollback = authorized && p.Status == "paused" && item.State != "rolled_back"
		p.CanResume = p.CanResume || item.CanResume
		p.CanRollback = p.CanRollback || item.CanRollback
		p.Nodes = append(p.Nodes, item)
	}
	if e = rows.Err(); e != nil {
		return p, e
	}
	if e = rows.Close(); e != nil {
		return p, e
	}
	if p.Status == "paused" {
		if e = s.monitoringApplicationPermissions(ctx, v, user, &p); e != nil {
			return p, e
		}
	}
	return p, nil
}
func (s *Store) confirmMonitoringApplication(ctx context.Context, t *deploymentTrust, user, key, id, capability string) (json.RawMessage, error) {
	if !identifier.MatchString(id) || len(capability) > 256 {
		return nil, errMonitoringApplication
	}
	return s.guardedMutation(ctx, user, key, "monitoring-application-confirm", id, struct{ ID, Hash string }{id, digest([]byte(capability))}, func(tx *sql.Tx) error { return lockMonitoringWriteTx(ctx, tx) }, func(tx *sql.Tx) (any, error) {
		p, e := scanMonitoringApplication(tx.QueryRowContext(ctx, `SELECT `+monitoringApplicationColumns+` FROM v3_monitoring_applications WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return nil, e
		}
		if e = openMonitoringApplication(t.vault, &p); e != nil {
			return nil, e
		}
		rev, e := deploymentPreviewAccount(ctx, tx, user)
		if e != nil {
			return nil, e
		}
		if p.Username != user || p.Account != rev || p.Status != "preview" || !time.Now().Before(p.Expires) || !sameCapability(p.TokenHash, digest([]byte(capability))) || p.Manifest != t.release.SHA256() {
			return nil, ErrDeploymentPreview
		}
		d, e := readSettingsDraftTx(ctx, tx, false)
		if e != nil {
			return nil, e
		}
		if checkSettingsDraftProof(t.vault, d) != nil || strconv.FormatInt(d.Generation, 10) != p.Generation {
			return nil, ErrConflict
		}
		for _, item := range p.Plan.Nodes {
			n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR UPDATE`, item.Node.ID))
			if e != nil {
				return nil, e
			}
			if n.Version != item.Node.Version || !n.Enabled || !configurationJSONEqual(n.Config, item.Before) {
				return nil, ErrConflict
			}
			if e = checkMonitoringNodeReservationTx(ctx, tx, n.ID); e != nil {
				return nil, e
			}
			state, _, _, e := monitoringDeploymentState(ctx, tx, n)
			if e != nil || state != item.State {
				return nil, ErrConflict
			}
			_, credentialState, e := monitoringApplicationCredentialTx(ctx, tx, n.ID)
			if e != nil || credentialState != item.CredentialState {
				return nil, ErrConflict
			}
		}
		if _, e = tx.ExecContext(ctx, `UPDATE v3_monitoring_application_nodes SET reserved=true WHERE application=$1`, p.ID); e != nil {
			return nil, e
		}
		p.Status = "queued"
		if e = updateMonitoringApplicationTx(ctx, tx, t.vault, &p); e != nil {
			return nil, e
		}
		return map[string]any{"id": p.ID, "status": p.Status, "version": p.Expected}, nil
	})
}
func (s *Store) recoverMonitoringApplication(ctx context.Context, v *Vault, user, key, id, version, direction string, selected ...string) (json.RawMessage, error) {
	if !identifier.MatchString(id) || !canonicalMonitoringVersion(version) || direction != "forward" && direction != "rollback" {
		return nil, errMonitoringApplication
	}
	node := ""
	if len(selected) > 0 {
		node = selected[0]
		if !identifier.MatchString(node) {
			return nil, errMonitoringApplication
		}
	}
	return s.guardedMutation(ctx, user, key, "monitoring-application-"+direction, id, []string{id, version, node}, func(tx *sql.Tx) error { return lockMonitoringWriteTx(ctx, tx) }, func(tx *sql.Tx) (any, error) {
		p, e := scanMonitoringApplication(tx.QueryRowContext(ctx, `SELECT `+monitoringApplicationColumns+` FROM v3_monitoring_applications WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return nil, e
		}
		if e = openMonitoringApplication(v, &p); e != nil {
			return nil, e
		}
		rev, e := deploymentPreviewAccount(ctx, tx, user)
		if e != nil {
			return nil, e
		}
		if p.Expected != version || p.Status != "paused" || p.Controller != user || p.ControllerRevision != rev || p.Direction == "rollback" && direction != "rollback" {
			return nil, ErrConflict
		}
		var held bool
		if e = tx.QueryRowContext(ctx, `SELECT recovery_hold FROM v3_monitoring_applications WHERE id=$1`, p.ID).Scan(&held); e != nil {
			return nil, e
		}
		if held {
			return nil, ErrConflict
		}
		if node != "" {
			if _, ok := p.node(node); !ok {
				return nil, ErrConflict
			}
			var state string
			if e = tx.QueryRowContext(ctx, `SELECT state FROM v3_monitoring_application_nodes WHERE application=$1 AND node=$2`, p.ID, node).Scan(&state); e != nil {
				return nil, e
			}
			if direction == "forward" && state != "failed" && state != "pending" && state != "preparing" {
				return nil, ErrConflict
			}
			if direction == "rollback" && state == "rolled_back" {
				return nil, ErrConflict
			}
		}
		p.Status = "queued"
		p.Direction = direction
		p.Selected = node
		p.Error = ""
		if e = updateMonitoringApplicationTx(ctx, tx, v, &p); e != nil {
			return nil, e
		}
		return map[string]any{"id": p.ID, "status": p.Status, "version": p.Expected}, nil
	})
}
func (a *API) monitoringApplicationRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const base = "/api/v3/monitoring/applications"
	if r.URL.Path != base && !strings.HasPrefix(r.URL.Path, base+"/") {
		return false
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "需要管理员权限")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	t, e := loadDeploymentMetadata(ctx, a.Config.DeploymentTrust)
	if e != nil {
		monitoringFailure(w, e)
		return true
	}
	path := strings.TrimPrefix(r.URL.Path, base)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if r.Method == "GET" && len(parts) == 1 && identifier.MatchString(parts[0]) && parts[0] != "preview" {
		p, e := a.Store.monitoringApplication(ctx, t.vault, id.Username, parts[0])
		if e != nil {
			monitoringFailure(w, e)
		} else {
			reply(w, 200, p)
		}
		return true
	}
	if r.Method != "POST" {
		failure(w, 405, "method_not_allowed", "请使用规则应用预览、确认或恢复方法")
		return true
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "规则下发需要可信 HTTPS 连接")
		return true
	}
	key := r.Header.Get("Idempotency-Key")
	if !identifier.MatchString(key) {
		failure(w, 400, "invalid_idempotency_key", "请提供有效幂等键")
		return true
	}
	var raw json.RawMessage
	switch {
	case len(parts) == 2 && parts[1] == "reauthorization-preview":
		var in struct {
			Expected string `json:"expected_version"`
		}
		if decodeStrictDeployment(w, r, &in, 4096, "expected_version") != nil {
			failure(w, 400, "invalid_monitoring_application", "重新授权请求不正确")
			return true
		}
		ticket, expires, reauthErr := a.Store.previewMonitoringReauthorization(ctx, t.vault, id.Username, key, parts[0], in.Expected)
		if reauthErr != nil {
			monitoringFailure(w, reauthErr)
		} else {
			reply(w, 200, map[string]any{"token": ticket, "expires_at": expires})
		}
		return true
	case len(parts) == 2 && parts[1] == "reauthorize":
		var in struct {
			Expected string `json:"expected_version"`
			Token    string `json:"token"`
		}
		if decodeStrictDeployment(w, r, &in, 4096, "expected_version", "token") != nil {
			failure(w, 400, "invalid_monitoring_application", "重新授权请求不正确")
			return true
		}
		raw, e = a.Store.reauthorizeMonitoringApplication(ctx, t.vault, id.Username, key, parts[0], in.Expected, in.Token)
	case path == "/preview":
		var in monitoringApplicationRequest
		if decodeStrictDeployment(w, r, &in, 128<<10, "expected_version", "nodes") != nil {
			failure(w, 400, "invalid_monitoring_application", "规则应用请求不正确")
			return true
		}
		p, capability, e := a.Store.previewMonitoringApplication(ctx, t, id.Username, key, in)
		if e != nil {
			monitoringFailure(w, e)
		} else {
			reply(w, 200, map[string]any{"id": p.ID, "token": capability, "expires_at": p.Expires, "nodes": p.Nodes, "release": p.Release})
		}
		return true
	case path == "":
		var in struct {
			Preview string `json:"preview"`
			Token   string `json:"token"`
		}
		if decodeStrictDeployment(w, r, &in, 4096, "preview", "token") != nil {
			failure(w, 400, "invalid_monitoring_application", "规则应用请求不正确")
			return true
		}
		raw, e = a.Store.confirmMonitoringApplication(ctx, t, id.Username, key, in.Preview, in.Token)
	case (len(parts) == 2 && (parts[1] == "resume" || parts[1] == "rollback")) || (len(parts) == 4 && parts[1] == "nodes" && (parts[3] == "resume" || parts[3] == "rollback")):
		var in struct {
			Expected string `json:"expected_version"`
		}
		if decodeStrictDeployment(w, r, &in, 4096, "expected_version") != nil {
			failure(w, 400, "invalid_monitoring_application", "规则应用请求不正确")
			return true
		}
		direction := "forward"
		if parts[len(parts)-1] == "rollback" {
			direction = "rollback"
		}
		if len(parts) == 4 {
			raw, e = a.Store.recoverMonitoringApplication(ctx, t.vault, id.Username, key, parts[0], in.Expected, direction, parts[2])
		} else {
			raw, e = a.Store.recoverMonitoringApplication(ctx, t.vault, id.Username, key, parts[0], in.Expected, direction)
		}
	default:
		failure(w, 404, "not_found", "未找到规则应用操作")
		return true
	}
	if e != nil {
		monitoringFailure(w, e)
	} else {
		var receipt struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &receipt) != nil {
			monitoringFailure(w, errMonitoringApplication)
		} else if p, readErr := a.Store.monitoringApplication(ctx, t.vault, id.Username, receipt.ID); readErr != nil {
			monitoringFailure(w, readErr)
		} else {
			reply(w, 202, p)
		}
	}
	return true
}

// The plan has a separate bounded encryption envelope: batches can exceed the
// web preparation payload limit, while no public endpoint accepts plan bytes.
func sealMonitoringPlan(v *Vault, id string, raw []byte) (string, []byte, []byte, error) {
	if v == nil || v.keys[v.active] == nil || len(raw) > 16<<20 {
		return "", nil, nil, errMonitoringApplication
	}
	a := v.keys[v.active]
	nonce := make([]byte, a.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return "", nil, nil, e
	}
	return v.active, nonce, a.Seal(nil, nonce, raw, []byte("webscan-v3/monitoring-plan/v1/"+id)), nil
}
func openMonitoringPlan(v *Vault, id, key string, nonce, sealed []byte) ([]byte, error) {
	if v == nil || v.keys[key] == nil || len(sealed) > 16<<20+16 || len(nonce) != v.keys[key].NonceSize() {
		return nil, errMonitoringApplication
	}
	raw, e := v.keys[key].Open(nil, nonce, sealed, []byte("webscan-v3/monitoring-plan/v1/"+id))
	if e != nil {
		return nil, errMonitoringApplication
	}
	return raw, nil
}
func monitoringDeploymentState(ctx context.Context, tx *sql.Tx, n Node) (string, *DeploymentTarget, string, error) {
	// Permission projections change when this parent reserves a node. They are
	// not configuration authority and must not invalidate its own exact binding.
	n.Configuration = nil
	n.Monitoring = nil
	n.CanRemove = false
	n.RemoveReason = ""
	return deploymentPreviewState(ctx, tx, n, DeploymentRequest{})
}
func (n *monitoringApplicationTarget) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 || fields["id"] == nil || fields["expected_version"] == nil || string(fields["id"]) == "null" || string(fields["expected_version"]) == "null" {
		return errMonitoringApplication
	}
	type wire monitoringApplicationTarget
	var value wire
	if json.Unmarshal(raw, &value) != nil {
		return errMonitoringApplication
	}
	*n = monitoringApplicationTarget(value)
	return nil
}

// A new administrator explicitly assumes responsibility after a password reset
// or role change. Neither the immutable plan nor any child/backup is replaced.
func monitoringReauthorizationStateTx(ctx context.Context, tx *sql.Tx, p monitoringApplication) (string, error) {
	values := []any{p.ID, p.Digest, p.Version, p.Status, p.Direction, p.Selected}
	for _, item := range p.Plan.Nodes {
		n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR SHARE`, item.Node.ID))
		if e != nil {
			return "", e
		}
		if !n.Enabled || n.Endpoint != item.Node.Endpoint || n.Mode != item.Node.Mode || n.ServerName != item.Node.ServerName || !(n.Version == item.Node.Version && configurationJSONEqual(n.Config, item.Before) || n.Version == item.Node.Version+1 && configurationJSONEqual(n.Config, item.Target)) {
			return "", ErrConflict
		}
		credential, state, e := monitoringApplicationCredentialTx(ctx, tx, n.ID)
		if e != nil || credential != item.Credential || state != item.CredentialState {
			return "", ErrCredentialUnavailable
		}
		var stateJSON []byte
		e = tx.QueryRowContext(ctx, `SELECT jsonb_build_array(l.state,l.reserved,l.child,l.child_plan_digest,l.parent_epoch,l.proof,d.status,d.direction,d.step,d.rollback_step,d.lease_epoch,d.log_cursor,d.plan_digest,d.recovery_required) FROM v3_monitoring_application_nodes l LEFT JOIN v3_deployment_jobs d ON d.id=l.child WHERE l.application=$1 AND l.node=$2 FOR SHARE OF l`, p.ID, n.ID).Scan(&stateJSON)
		if e != nil {
			return "", e
		}
		values = append(values, []any{n.ID, n.Version, n.AppliedVersion, digest(n.Config), state, json.RawMessage(stateJSON)})
	}
	return digest(common.JSON(values)), nil
}
func monitoringReauthorizationToken(v *Vault, key, id, application string, account, parent int64, state string) string {
	proof := monitoringApplicationMAC(v, key, "reauthorization/v1", []any{id, application, account, parent, state})
	return base64.RawURLEncoding.EncodeToString(common.JSON([]string{id, proof}))
}
func (s *Store) previewMonitoringReauthorization(ctx context.Context, v *Vault, user, key, id, version string) (string, time.Time, error) {
	var expiry time.Time
	if !identifier.MatchString(id) || !canonicalMonitoringVersion(version) {
		return "", expiry, errMonitoringApplication
	}
	raw, e := s.guardedMutation(ctx, user, key, "monitoring-application-reauthorization-preview", id, []string{id, version}, func(tx *sql.Tx) error { return lockMonitoringWriteTx(ctx, tx) }, func(tx *sql.Tx) (any, error) {
		rev, e := deploymentPreviewAccount(ctx, tx, user)
		if e != nil {
			return nil, e
		}
		p, e := scanMonitoringApplication(tx.QueryRowContext(ctx, `SELECT `+monitoringApplicationColumns+` FROM v3_monitoring_applications WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return nil, e
		}
		if e = openMonitoringApplication(v, &p); e != nil {
			return nil, e
		}
		var hold bool
		if e = tx.QueryRowContext(ctx, `SELECT recovery_hold FROM v3_monitoring_applications WHERE id=$1`, id).Scan(&hold); e != nil {
			return nil, e
		}
		if p.Status != "paused" || p.Expected != version || hold {
			return nil, ErrConflict
		}
		state, e := monitoringReauthorizationStateTx(ctx, tx, p)
		if e != nil {
			return nil, e
		}
		auth := token()
		capability := monitoringReauthorizationToken(v, v.active, auth, id, rev, p.Version, state)
		expires := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
		if _, e = tx.ExecContext(ctx, `INSERT INTO v3_monitoring_application_authorizations(id,application,username,account_revision,parent_version,state_digest,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, auth, id, user, rev, p.Version, state, digest([]byte(capability)), expires); e != nil {
			return nil, e
		}
		return map[string]string{"id": auth}, nil
	})
	if e != nil {
		return "", expiry, e
	}
	var receipt struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &receipt) != nil {
		return "", expiry, errMonitoringApplication
	}
	var app, owner, state string
	var rev, parent int64
	var consumed bool
	e = s.DB.QueryRowContext(ctx, `SELECT application,username,account_revision,parent_version,state_digest,expires_at,consumed FROM v3_monitoring_application_authorizations WHERE id=$1`, receipt.ID).Scan(&app, &owner, &rev, &parent, &state, &expiry, &consumed)
	if e != nil {
		return "", expiry, e
	}
	if owner != user || app != id || consumed || !time.Now().Before(expiry) {
		return "", expiry, ErrDeploymentPreview
	}
	return monitoringReauthorizationToken(v, v.active, receipt.ID, app, rev, parent, state), expiry, nil
}
func (s *Store) reauthorizeMonitoringApplication(ctx context.Context, v *Vault, user, key, id, version, capability string) (json.RawMessage, error) {
	if !identifier.MatchString(id) || !canonicalMonitoringVersion(version) || len(capability) > 512 {
		return nil, errMonitoringApplication
	}
	body, e := base64.RawURLEncoding.DecodeString(capability)
	var parts []string
	if e != nil || json.Unmarshal(body, &parts) != nil || len(parts) != 2 || !identifier.MatchString(parts[0]) {
		return nil, ErrDeploymentPreview
	}
	return s.guardedMutation(ctx, user, key, "monitoring-application-reauthorize", id, []string{id, version, digest([]byte(capability))}, func(tx *sql.Tx) error { return lockMonitoringWriteTx(ctx, tx) }, func(tx *sql.Tx) (any, error) {
		rev, e := deploymentPreviewAccount(ctx, tx, user)
		if e != nil {
			return nil, e
		}
		p, e := scanMonitoringApplication(tx.QueryRowContext(ctx, `SELECT `+monitoringApplicationColumns+` FROM v3_monitoring_applications WHERE id=$1 FOR UPDATE`, id))
		if e != nil {
			return nil, e
		}
		if e = openMonitoringApplication(v, &p); e != nil {
			return nil, e
		}
		var held bool
		if e = tx.QueryRowContext(ctx, `SELECT recovery_hold FROM v3_monitoring_applications WHERE id=$1`, id).Scan(&held); e != nil {
			return nil, e
		}
		if p.Status != "paused" || p.Expected != version || held {
			return nil, ErrConflict
		}
		var app, owner, state, hash string
		var account, parent int64
		var expiry time.Time
		var consumed bool
		e = tx.QueryRowContext(ctx, `SELECT application,username,account_revision,parent_version,state_digest,token_hash,expires_at,consumed FROM v3_monitoring_application_authorizations WHERE id=$1 FOR UPDATE`, parts[0]).Scan(&app, &owner, &account, &parent, &state, &hash, &expiry, &consumed)
		if e != nil {
			return nil, e
		}
		if app != id || owner != user || account != rev || parent != p.Version || consumed || !time.Now().Before(expiry) || !sameCapability(hash, digest([]byte(capability))) {
			return nil, ErrDeploymentPreview
		}
		proofKey, _, ok := strings.Cut(parts[1], ":")
		want := monitoringReauthorizationToken(v, proofKey, parts[0], id, rev, p.Version, state)
		if !ok || !hmac.Equal([]byte(want), []byte(capability)) {
			return nil, ErrDeploymentPreview
		}
		current, e := monitoringReauthorizationStateTx(ctx, tx, p)
		if e != nil {
			return nil, e
		}
		if state != current {
			return nil, ErrConflict
		}
		p.Controller = user
		p.ControllerRevision = rev
		p.Error = ""
		p.Owner = sql.NullString{}
		p.Lease = sql.NullTime{}
		p.Epoch++
		if e = updateMonitoringApplicationTx(ctx, tx, v, &p); e != nil {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE v3_monitoring_application_authorizations SET consumed=true WHERE id=$1`, parts[0]); e != nil {
			return nil, e
		}
		return map[string]any{"id": p.ID, "status": p.Status, "version": p.Expected}, nil
	})
}

func (s *Store) monitoringApplicationPermissions(ctx context.Context, v *Vault, user string, p *monitoringApplication) error {
	for i := range p.Nodes {
		p.Nodes[i].CanResume = false
		p.Nodes[i].CanRollback = false
	}
	p.CanResume = false
	p.CanRollback = false
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = lockConfigurationOperationTx(ctx, tx, false); e != nil {
		return e
	}
	current, e := scanMonitoringApplication(tx.QueryRowContext(ctx, `SELECT `+monitoringApplicationColumns+` FROM v3_monitoring_applications WHERE id=$1`, p.ID))
	if e != nil {
		return e
	}
	if current.Version != p.Version || current.Status != "paused" {
		return nil
	}
	rev, e := deploymentPreviewAccount(ctx, tx, user)
	if e != nil {
		return e
	}
	var hold bool
	if e = tx.QueryRowContext(ctx, `SELECT recovery_hold FROM v3_monitoring_applications WHERE id=$1`, p.ID).Scan(&hold); e != nil {
		return e
	}
	if hold || p.Controller != user || p.ControllerRevision != rev {
		return nil
	}
	draft, e := readSettingsDraftTx(ctx, tx, false)
	if e != nil {
		return e
	}
	forward := checkSettingsDraftProof(v, draft) == nil && strconv.FormatInt(draft.Generation, 10) == p.Generation
	anyRolledBack := false
	for i := range p.Nodes {
		item := &p.Nodes[i]
		target, ok := p.node(item.ID)
		if !ok {
			return errMonitoringApplication
		}
		l, e := readMonitoringNodeCheckpointTx(ctx, tx, *p, item.ID)
		if e != nil {
			return e
		}
		if verifyMonitoringNodeCheckpoint(v, *p, l) != nil || l.state != item.State {
			continue
		}
		n, e := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM v3_nodes WHERE id=$1 AND removed_at IS NULL FOR SHARE`, item.ID))
		if e != nil {
			return e
		}
		if !n.Enabled || n.Endpoint != target.Node.Endpoint || n.ServerName != target.Node.ServerName || n.Mode != target.Node.Mode || !(n.Version == target.Node.Version && configurationJSONEqual(n.Config, target.Before) || n.Version == target.Node.Version+1 && configurationJSONEqual(n.Config, target.Target)) {
			continue
		}
		_, credentialState, e := monitoringApplicationCredentialTx(ctx, tx, item.ID)
		if e != nil || credentialState != target.CredentialState {
			continue
		}
		if l.child != "" {
			j, e := scanDeployment(tx.QueryRowContext(ctx, `SELECT `+deploymentColumns+` FROM v3_deployment_jobs WHERE id=$1 FOR SHARE`, l.child))
			if e != nil {
				return e
			}
			if j.Node != item.ID || j.PlanDigest != l.plan {
				continue
			}
			if j.Direction == "rollback" {
				item.CanRollback = j.Status != "rolled_back"
				p.CanRollback = p.CanRollback || item.CanRollback
				continue
			}
		}
		item.CanResume = forward && p.Direction == "forward" && (item.State == "pending" || item.State == "failed" || item.State == "preparing")
		item.CanRollback = item.State != "rolled_back"
		anyRolledBack = anyRolledBack || item.State == "rolled_back"
		p.CanResume = p.CanResume || item.CanResume
		p.CanRollback = p.CanRollback || item.CanRollback
	}
	if anyRolledBack {
		p.CanResume = false
	}
	return tx.Commit()
}
