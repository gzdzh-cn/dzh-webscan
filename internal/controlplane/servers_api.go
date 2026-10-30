package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Detail is read from one database snapshot. Private configuration, credentials
// and deployment plans never enter the response, including for administrators.
func (a *API) serverDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v3/servers/")
	if !identifier.MatchString(id) {
		failure(w, 404, "not_found", "服务器不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, err := a.Store.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		failure(w, 503, "query_failed", "服务器详情暂时不可用")
		return
	}
	defer tx.Rollback()
	n, err := scanManagedNode(tx.QueryRowContext(ctx, "SELECT "+managedNodeColumns+" FROM "+managedNodeRelations+" WHERE n.id=$1", id))
	if err == sql.ErrNoRows {
		failure(w, 404, "not_found", "服务器不存在")
		return
	}
	if err != nil {
		failure(w, 503, "query_failed", "服务器详情暂时不可用")
		return
	}
	var status json.RawMessage
	err = tx.QueryRowContext(ctx, `SELECT jsonb_build_object('sampled_at',sampled_at,'updated_at',updated_at,'error',error,'metrics_error',metrics_error,'events_error',events_error,'protocol_error',protocol_error,'metrics',jsonb_build_object('cpu_percent',metrics->'cpu_percent','memory_percent',metrics->'memory_percent','disk_percent',metrics->'disk_percent','uptime',metrics->'uptime'),'info',jsonb_build_object('hostname',info->'nodename','kernel',info->'release','architecture',info->'machine','agent_version',info->'agent_version','agent_mode',info->'agent_mode')) FROM v3_node_status WHERE node=$1`, id).Scan(&status)
	if err != nil && err != sql.ErrNoRows {
		failure(w, 503, "query_failed", "服务器采集状态暂时不可用")
		return
	}
	if status == nil {
		status = json.RawMessage("null")
	}
	var latest *DeploymentJob
	j, err := scanDeployment(tx.QueryRowContext(ctx, "SELECT "+deploymentColumns+" FROM v3_deployment_jobs WHERE node=$1 ORDER BY created_at DESC,id DESC LIMIT 1", id))
	if err != nil && err != sql.ErrNoRows {
		failure(w, 503, "query_failed", "服务器部署状态暂时不可用")
		return
	}
	if err == nil {
		latest = &j
	}
	if err = tx.Commit(); err != nil {
		failure(w, 503, "query_failed", "服务器详情暂时不可用")
		return
	}
	reply(w, 200, map[string]any{"node": n, "status": status, "latest_deployment": latest})
}
