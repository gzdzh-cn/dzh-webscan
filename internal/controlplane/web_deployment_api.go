package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"webscan/internal/deploy"
)

type featureAvailability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}
type deploymentAvailability struct {
	featureAvailability
	Trust *deploymentTrust `json:"-"`
}

func (s *Store) vaultAvailable(ctx context.Context, v *Vault) error {
	if v == nil {
		return ErrCredentialUnavailable
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT DISTINCT key_id FROM (SELECT key_id FROM v3_credentials UNION SELECT key_id FROM v3_configuration_backups UNION SELECT key_id FROM v3_node_certificates UNION SELECT key_id FROM v3_node_provisioning UNION SELECT key_id FROM v3_monitoring_applications) k`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			return err
		}
		if v.keys[key] == nil {
			return ErrCredentialUnavailable
		}
	}
	return rows.Err()
}
func (a *API) deploymentAvailability(ctx context.Context) deploymentAvailability {
	return a.deploymentOperationAvailability(ctx, false)
}

func (a *API) deploymentOperationAvailability(ctx context.Context, uninstall bool) deploymentAvailability {
	unavailable := func(reason string) deploymentAvailability {
		return deploymentAvailability{featureAvailability: featureAvailability{Reason: reason}}
	}
	if !a.Config.Executor.Enabled {
		return unavailable("部署执行器未启用")
	}
	t, err := loadDeploymentMetadata(ctx, a.Config.DeploymentTrust)
	if err != nil {
		return unavailable("部署信任资料或共享 Vault 密钥不可用")
	}
	if a.Store.vaultAvailable(ctx, t.vault) != nil {
		return unavailable("共享 Vault 密钥与已有加密资料不匹配")
	}
	var ready bool
	err = a.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_role_status e JOIN v3_role_status p ON e.instance=p.instance AND p.role='deployment-preparations' WHERE e.role='executor' AND e.heartbeat>clock_timestamp()-interval '15 seconds' AND p.heartbeat>clock_timestamp()-interval '15 seconds' AND e.error='' AND p.error='' AND e.details->>'manifest'=$1 AND e.details->>'vault'=$2 AND p.details->>'manifest'=$1 AND p.details->>'vault'=$2 AND ($3::boolean OR p.details->>'issuer'='true' AND p.details->>'rules'='true'))`, t.release.SHA256(), t.vault.active, uninstall).Scan(&ready)
	if err != nil || !ready {
		return unavailable("宿主执行器、签发器或部署准备工作器未就绪，请检查宿主服务")
	}
	return deploymentAvailability{featureAvailability: featureAvailability{Available: true}, Trust: t}
}
func (a *API) capabilities(ctx context.Context) map[string]any {
	settings := featureAvailability{}
	if b, err := a.configurationEditBackup(); err == nil && a.Store.vaultAvailable(ctx, b.vault) == nil {
		settings.Available = true
	} else {
		settings.Reason = "共享 Vault 密钥或配置备份不可用"
	}
	deployment := a.deploymentAvailability(ctx)
	monitoring := a.monitoringApplicationAvailability(ctx, deployment)
	return map[string]any{"api_version": 3, "version": deploy.Release, "topology": a.Config.Central.Topology, "features": []string{"server-pagination", "event-pull", "metrics-query", "persistent-sessions", "websites", "website-incidents", "website-config-backups", "configuration-backup-archives", "configuration-saved-restore", "configuration-application-history", "deployment-history", "server-alerts", "automatic-history-retention", "manual-history-cleanup", "history-export", "notification-history", "notification-details", "notification-tests", "operation-audit", "settings-editor", "web-deployment", "account-password", "monitoring-rules", "monitoring-applications"}, "configuration_application_writes": a.applicationWritesEnabled(), "settings": settings, "metrics_retention": a.metricsRetentionAvailability(ctx), "notification_tests": a.notificationTestAvailability(ctx), "monitoring_rules": settings, "monitoring_applications": monitoring, "deployments": deployment, "executor": deployment.featureAvailability, "operations": map[string]any{"uninstall": a.deploymentOperationAvailability(ctx, true)}, "deployment_defaults": map[string]any{"central": "docker", "node": "docker", "node_modes": []string{"docker", "native"}}, "implementation_stage": "v3"}
}

func (a *API) monitoringApplicationAvailability(ctx context.Context, deployment deploymentAvailability) featureAvailability {
	if !deployment.Available || deployment.Trust == nil {
		return deployment.featureAvailability
	}
	t := deployment.Trust
	var ready bool
	err := a.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_role_status m JOIN v3_role_status e ON e.instance=m.instance AND e.role='executor' JOIN v3_role_status p ON p.instance=m.instance AND p.role='deployment-preparations' WHERE m.role='monitoring-applications' AND m.heartbeat>clock_timestamp()-interval '15 seconds' AND e.heartbeat>clock_timestamp()-interval '15 seconds' AND p.heartbeat>clock_timestamp()-interval '15 seconds' AND m.error='' AND e.error='' AND p.error='' AND m.details->>'manifest'=$1 AND e.details->>'manifest'=$1 AND p.details->>'manifest'=$1 AND m.details->>'vault'=$2 AND e.details->>'vault'=$2 AND p.details->>'vault'=$2 AND m.details->>'issuer'='true' AND m.details->>'rules'='true' AND p.details->>'issuer'='true' AND p.details->>'rules'='true')`, t.release.SHA256(), t.vault.active).Scan(&ready)
	if err != nil || !ready {
		return featureAvailability{Reason: "公共规则应用工作器未就绪，请检查宿主服务"}
	}
	return featureAvailability{Available: true}
}

// Decode exact, route-specific JSON fields, rejecting duplicate keys (including
// nested ones), invalid UTF-8, aliases, trailing JSON and oversized secrets.
func decodeWebDeployment(w http.ResponseWriter, r *http.Request, allowed ...string) (webDeploymentInput, error) {
	var in webDeploymentInput
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	defer clear(raw)
	if err != nil || len(raw) == 0 || !utf8.Valid(raw) || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return in, errWebDeployment
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if !uniqueProvisioningJSON(d, 0) {
		return in, errWebDeployment
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return in, errWebDeployment
	}
	for k := range fields {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
			}
		}
		if !ok {
			return in, errWebDeployment
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		return webDeploymentInput{}, errWebDeployment
	}
	return in, nil
}
func webDeploymentFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "not_found", "记录不存在")
	case errors.Is(err, ErrDeploymentBusy):
		failure(w, 409, "deployment_busy", ErrDeploymentBusy.Error())
	case errors.Is(err, errNodeUninstall):
		failure(w, 409, "uninstall_protected", errNodeUninstall.Error())
	case errors.Is(err, ErrConflict), errors.Is(err, errWebDeployment), errors.Is(err, ErrDeploymentPreview), errors.Is(err, ErrDeploymentState):
		failure(w, 409, "preparation_conflict", errWebDeployment.Error())
	case errors.Is(err, ErrRequestConflict):
		failure(w, 409, "idempotency_conflict", "幂等键已用于不同请求，请重新确认")
	default:
		failure(w, 503, "deployment_unavailable", "部署操作暂时不可用，请保留输入并重试")
	}
}
func (a *API) webDeploymentRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	path := r.URL.Path
	var node, kind string
	switch {
	case strings.HasPrefix(path, "/api/v3/deployment-preparations/"):
		kind = "read"
		node = strings.TrimPrefix(path, "/api/v3/deployment-preparations/")
	case strings.HasPrefix(path, "/api/v3/servers/"):
		parts := strings.Split(strings.TrimPrefix(path, "/api/v3/servers/"), "/")
		if len(parts) != 2 {
			return false
		}
		node = parts[0]
		switch parts[1] {
		case "ssh-credential":
			kind = "credential"
		case "ssh-fingerprint":
			kind = "fingerprint"
		case "deployment-preview":
			kind = "prepare"
		default:
			return false
		}
	case path == "/api/v3/deployments" && r.Method == "POST":
		kind = "confirm"
	default:
		return false
	}
	if id.Role != "admin" {
		failure(w, 403, "permission_denied", "需要管理员权限")
		return true
	}
	if (kind == "read" || kind == "credential" && r.Method == "GET") && r.Method == "GET" {
	} else if kind != "read" && r.Method == "POST" {
	} else {
		failure(w, 405, "method_not_allowed", "请使用规定的接口方法")
		return true
	}
	if kind != "confirm" && !identifier.MatchString(node) {
		failure(w, 404, "not_found", "接口不存在")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if r.Method == "GET" {
		v, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile, a.Config.DeploymentTrust.PreviousKeyFiles...)
		if err != nil {
			webDeploymentFailure(w, err)
			return true
		}
		if kind == "read" {
			p, err := a.Store.preparation(ctx, v, id.Username, node)
			if err != nil {
				webDeploymentFailure(w, err)
			} else {
				if p.Result != nil {
					p.Result.CredentialState = ""
					p.Result.SourceState = ""
				}
				reply(w, 200, p)
			}
			return true
		}
		n, err := scanNode(a.Store.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL AND id=$1", node))
		if err != nil {
			webDeploymentFailure(w, err)
			return true
		}
		if operation := r.URL.Query().Get("kind"); operation != "" {
			if operation != "uninstall" {
				failure(w, 400, "invalid_kind", "操作类型不正确")
				return true
			}
			result, err := a.uninstallCredentialStatus(ctx, v, n)
			if err != nil {
				webDeploymentFailure(w, err)
			} else {
				reply(w, 200, result)
			}
			return true
		}
		_, c, err := a.Store.latestWebCredential(ctx, v, node)
		if err != nil {
			var count int
			if e := a.Store.DB.QueryRowContext(ctx, "SELECT count(*) FROM v3_credentials WHERE node=$1", node).Scan(&count); e != nil || count > 0 {
				webDeploymentFailure(w, ErrCredentialUnavailable)
				return true
			}
		}
		host, _, _ := net.SplitHostPort(n.Endpoint)
		reply(w, 200, map[string]any{"configured": err == nil && c.Host == host, "version": n.Version, "ssh_port": c.Port, "fingerprint": c.Fingerprint})
		return true
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "部署写操作需要可信 HTTPS 连接")
		return true
	}
	if !identifier.MatchString(r.Header.Get("Idempotency-Key")) {
		failure(w, 400, "invalid_idempotency_key", "请提供有效幂等键")
		return true
	}
	availability := a.deploymentOperationAvailability(ctx, true)
	if !availability.Available {
		failure(w, 503, "executor_unavailable", availability.Reason)
		return true
	}
	allowed := []string{"expected_version"}
	switch kind {
	case "fingerprint":
		allowed = append(allowed, "ssh_port", "kind")
	case "credential":
		allowed = append(allowed, "kind", "ssh_port", "password", "private_key_content", "private_key_path", "fingerprint_preparation", "fingerprint_token")
	case "prepare":
		allowed = append(allowed, "kind")
	case "confirm":
		allowed = append(allowed, "preparation", "preview_token")
	}
	in, err := decodeWebDeployment(w, r, allowed...)
	if err != nil || in.Expected < 1 {
		failure(w, 400, "invalid_request", "请求字段或配置版本不正确")
		return true
	}
	if (kind == "fingerprint" || kind == "credential") && in.Kind != "" && in.Kind != "uninstall" {
		failure(w, 400, "invalid_kind", "凭据操作类型不正确")
		return true
	}
	if kind == "fingerprint" && in.SSHPort == 0 {
		in.SSHPort = 22
	}
	if kind == "fingerprint" || kind == "credential" {
		if in.SSHPort < 1 || in.SSHPort > 65535 {
			failure(w, 400, "invalid_ssh_port", "SSH 端口不正确")
			return true
		}
	}
	if kind == "credential" {
		count := 0
		for _, s := range []string{in.Password, in.PrivateKey, in.PrivateKeyPath} {
			if s != "" {
				count++
			}
		}
		if count > 1 || len(in.Password) > 4096 || len(in.PrivateKey) > 64<<10 || len(in.PrivateKeyPath) > 4096 || !identifier.MatchString(in.FingerprintPreparation) || len(in.FingerprintToken) != 64 {
			failure(w, 400, "invalid_credential", "请选择一种认证方式并确认本次 SSH 指纹；私钥最大 64 KiB")
			return true
		}
		if in.PrivateKey != "" {
			if _, e := ssh.ParsePrivateKey([]byte(in.PrivateKey)); e != nil {
				failure(w, 400, "invalid_private_key", "私钥无效或需要口令；仅支持未加密私钥")
				return true
			}
		}
	}
	if kind == "prepare" && in.Kind != "install" && in.Kind != "upgrade" && in.Kind != "uninstall" {
		failure(w, 400, "invalid_kind", "部署类型只允许 install、upgrade 或 uninstall")
		return true
	}
	if kind == "confirm" {
		p, e := a.Store.preparation(ctx, availability.Trust.vault, id.Username, in.Preparation)
		if e != nil || p.Status != "succeeded" || p.Kind != "prepare" || p.Result == nil || p.Result.Preview == nil || p.Version != in.Expected || !sameCapability(in.PreviewToken, p.Result.Preview.Token) {
			webDeploymentFailure(w, errWebDeployment)
			return true
		}
		node = p.Node
		in.Kind = p.Result.Preview.Kind
	}
	if in.Kind != "uninstall" {
		availability = a.deploymentAvailability(ctx)
		if !availability.Available {
			failure(w, 503, "executor_unavailable", availability.Reason)
			return true
		}
	}
	response, err := a.Store.submitPreparation(ctx, availability.Trust, id.Username, r.Header.Get("Idempotency-Key"), node, kind, in)
	if err != nil {
		webDeploymentFailure(w, err)
	} else {
		reply(w, 202, response)
	}
	return true
}

func decodeStrictDeployment(w http.ResponseWriter, r *http.Request, into any, limit int64, allowed ...string) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	defer clear(raw)
	if err != nil || !utf8.Valid(raw) || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return errWebDeployment
	}
	if !uniqueProvisioningJSON(json.NewDecoder(bytes.NewReader(raw)), 0) {
		return errWebDeployment
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return errWebDeployment
	}
	for k := range fields {
		ok := false
		for _, name := range allowed {
			if k == name {
				ok = true
			}
		}
		if !ok {
			return errWebDeployment
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil || d.Decode(new(any)) != io.EOF {
		return errWebDeployment
	}
	return nil
}
