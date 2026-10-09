package deploy

import (
	"strings"
	"webscan/internal/common"
)

// A full rollout with no accepted nodes may start a new release only after
// automatic rollback was confirmed. Keep the old journal and current main;
// an explicit resume always retains the original release and run.
func CanRetryRolledBackRollout(c *Config, state common.Map) bool {
	failure, rollout := common.M(state["last_failure"]), common.M(state["rollout"])
	if !strings.HasPrefix(common.S(state["run_id"]), "go-") || common.Contains([]string{"complete", "rolled-back"}, common.S(state["step"])) || common.S(failure["stage"]) != "rollout" || !common.B(failure["rollback_confirmed"]) || len(rollout) == 0 || len(common.M(rollout["accepted"])) != 0 || len(common.M(rollout["prepared"])) != 0 || common.B(rollout["main_started"]) || common.B(rollout["main_ready"]) || common.S(state["target_node"]) != "" || common.B(state["target_central_only"]) || common.B(state["target_add_node"]) || common.B(state["central_uninstall_pending"]) {
		return false
	}
	if u := common.M(state["single_uninstall"]); len(u) > 0 && !common.B(u["complete"]) {
		return false
	}
	if common.S(state["target_config_hash"]) != common.Hash(common.JSON(Redact(c.Raw))) || string(common.JSON(common.SS(state["active"]))) != string(common.JSON(common.SS(rollout["previous_active"]))) {
		return false
	}
	for _, value := range common.M(state["nodes"]) {
		n := common.M(value)
		if common.S(n["go_run_id"]) == common.S(state["run_id"]) && common.S(n["phase"]) != "go-rolled-back" {
			return false
		}
	}
	return true
}

func (d *Deploy) canRetryRollout() bool {
	return (d.O.Install || d.O.Upgrade) && !d.O.Resume && !d.O.Reinstall && !d.O.AddNode && d.O.Node == "" && !d.O.CentralOnly && CanRetryRolledBackRollout(d.C, d.State)
}
