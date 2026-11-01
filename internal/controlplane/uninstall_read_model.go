package controlplane

import (
	"context"
	"crypto/hmac"
	"encoding/json"
)

type nodeLifecycleSummary struct {
	CanUninstall bool   `json:"can_uninstall"`
	Reason       string `json:"uninstall_reason"`
	State        string `json:"lifecycle"`
}

// One bounded query decorates a page. Cryptographic checks run locally; no SSH,
// per-node API query or editable target is used to infer an installation.
func (a *API) uninstallSummaries(ctx context.Context, ids []string) (map[string]nodeLifecycleSummary, error) {
	out := make(map[string]nodeLifecycleSummary, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	for _, id := range ids {
		out[id] = nodeLifecycleSummary{Reason: "安装证据未知，无法确认可卸载的程序", State: "unknown"}
	}
	v, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile, a.Config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return out, nil
	}
	rows, err := a.Store.DB.QueryContext(ctx, `SELECT n.id,n.runtime_generation,COALESCE(l.body,'null'::jsonb),COALESCE(l.key_id,''),COALESCE(l.proof,''),
 COALESCE(i.job,''),COALESCE(i.plan_digest,''),COALESCE(i.spec,'null'::jsonb),COALESCE(i.capture_sha256,''),COALESCE(i.active_sha256,''),COALESCE(i.recorded_epoch,0),COALESCE(i.key_id,''),COALESCE(i.proof,''),
 COALESCE(source.node,''),COALESCE(source.status,''),COALESCE(source.direction,''),COALESCE(source.kind,''),COALESCE(source.plan_digest,''),COALESCE(source.plan,'null'::jsonb),COALESCE(to_jsonb(c),'null'::jsonb),COALESCE(c.config,'null'::jsonb),
 COALESCE(r.snapshot,''),COALESCE(r.delivered_version,0),COALESCE(r.epoch,0),n.applied_version,
 EXISTS(SELECT 1 FROM v3_deployment_jobs d WHERE d.node=n.id AND (d.status IN ('queued','running') OR d.status NOT IN ('succeeded','rolled_back') AND d.recovery_required)) OR EXISTS(SELECT 1 FROM v3_monitoring_application_nodes m WHERE m.node=n.id AND m.reserved)
 FROM v3_nodes n LEFT JOIN v3_node_runtime r ON r.node=n.id LEFT JOIN v3_node_lifecycle l ON l.node=n.id
 LEFT JOIN LATERAL (SELECT j.id FROM v3_deployment_jobs j WHERE j.node=n.id AND j.status='succeeded' AND j.kind IN ('install','upgrade') AND j.plan->>'target_runtime'=r.snapshot ORDER BY j.created_at DESC,j.id DESC LIMIT 1) baseline ON true
 LEFT JOIN v3_deployment_installations i ON i.job=COALESCE(l.body->'source'->>'job',baseline.id)
 LEFT JOIN v3_deployment_jobs source ON source.id=i.job
 LEFT JOIN v3_node_configurations c ON c.node=n.id AND c.id=source.plan->>'target_runtime'
 WHERE n.id=ANY($1::text[]) AND n.removed_at IS NULL`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, key, proof string
		var generation int64
		var body, spec, sourcePlan, snapshot, configuration []byte
		var source DeploymentJob
		var currentSnapshot string
		var delivered, runtimeEpoch, applied int64
		var row deploymentInstallation
		var busy bool
		if err := rows.Scan(&id, &generation, &body, &key, &proof, &row.Job, &row.PlanDigest, &spec, &row.Evidence.CaptureSHA256, &row.Evidence.ActiveSHA256, &row.Epoch, &row.Key, &row.Proof, &source.Node, &source.Status, &source.Direction, &source.Kind, &source.PlanDigest, &sourcePlan, &snapshot, &configuration, &currentSnapshot, &delivered, &runtimeEpoch, &applied, &busy); err != nil {
			return nil, err
		}
		if busy {
			out[id] = nodeLifecycleSummary{Reason: "节点存在未完成任务，请先查看原任务", State: "pending"}
			continue
		}
		var state *deploymentLifecycleState
		if json.Unmarshal(body, &state) != nil {
			continue
		}
		if state != nil {
			want, err := lifecycleProof(v, key, "node-lifecycle", state)
			if err != nil || state.Node != id || state.RuntimeGeneration != generation || !hmac.Equal([]byte(want), []byte(proof)) {
				continue
			}
			if state.State == "uninstalled" {
				out[id] = nodeLifecycleSummary{Reason: "子控已卸载，数据和中心记录保留", State: "uninstalled"}
				continue
			}
			if state.State != "installed" || state.Source == nil || state.Source.Job != row.Job || state.Source.PlanDigest != row.PlanDigest {
				continue
			}
		}
		source.ID = row.Job
		if json.Unmarshal(sourcePlan, &source.Plan) != nil || digest(sourcePlan) != source.PlanDigest || source.PlanDigest != row.PlanDigest || source.Node != id || source.Status != "succeeded" || source.Direction != "forward" || source.Kind != "install" && source.Kind != "upgrade" || source.Plan.TargetRuntime != currentSnapshot || digest(snapshot) != source.Plan.TargetRuntimeDigest || delivered < 1 || applied < 1 || runtimeEpoch != generation {
			continue
		}
		source.NodeVersion = source.Plan.Request.Expected
		row.Node = id
		if json.Unmarshal(spec, &row.Spec) != nil || !row.Evidence.Valid() || row.Spec.Validate() != nil || row.Job == "" || !installationMatchesPlan(source, row.Spec, configuration) {
			continue
		}
		want, err := installationProof(v, row)
		if err != nil || !hmac.Equal([]byte(want), []byte(row.Proof)) {
			continue
		}
		out[id] = nodeLifecycleSummary{CanUninstall: true, State: "installed"}
	}
	return out, rows.Err()
}

func (a *API) decorateUninstallNodes(ctx context.Context, items []json.RawMessage) error {
	ids := make([]string, len(items))
	for i, raw := range items {
		var n Node
		if err := json.Unmarshal(raw, &n); err != nil {
			return err
		}
		ids[i] = n.ID
	}
	summaries, err := a.uninstallSummaries(ctx, ids)
	if err != nil {
		return err
	}
	for i, raw := range items {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		summary := summaries[ids[i]]
		object["can_uninstall"], _ = json.Marshal(summary.CanUninstall)
		object["uninstall_reason"], _ = json.Marshal(summary.Reason)
		object["lifecycle"], _ = json.Marshal(summary.State)
		items[i], _ = json.Marshal(object)
	}
	return nil
}
