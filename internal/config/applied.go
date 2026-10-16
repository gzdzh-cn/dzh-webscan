package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"webscan/internal/common"
)

// ApplicationInput keeps the loader's explicit-mode information without persisting credentials.
func ApplicationInput(raw common.Map, nodes []common.Map) common.Map {
	out := common.Clone(raw)
	items := []any{}
	for _, n := range nodes {
		items = append(items, common.Clone(n))
	}
	out["nodes"] = items
	return out
}

// ApplicationSnapshots removes derived fields and resolves legacy nodes against deployed mode.
func ApplicationSnapshots(raw common.Map, states ...common.Map) common.Map {
	state := common.Map{}
	if len(states) > 0 {
		state = states[0]
	}
	out := common.Map{}
	central := common.Clone(raw)
	for _, key := range []string{"nodes", "node_defaults", "images", "registry", "deployment"} {
		delete(central, key)
	}
	out["central"] = central
	for _, v := range common.A(raw["nodes"]) {
		original := common.M(v)
		n := common.Merge(common.M(raw["node_defaults"]), original)
		id := common.S(n["id"])
		explicit, tracked := original["_deployment_explicit"]
		if tracked && !common.B(explicit) || !tracked && common.S(common.M(original["deployment"])["mode"]) == "" {
			deployed := common.M(common.M(state["nodes"])[id])
			mode := common.S(deployed["deployment_mode"])
			if mode == "" && deployed["go_image"] != nil {
				mode = "docker"
			}
			if mode != "" {
				n["deployment"] = common.Map{"mode": mode}
			}
		}
		if metrics := common.M(n["metrics"]); len(metrics) > 0 {
			metrics["tls_enabled"] = common.B(common.M(raw["ssl"])["enabled"])
			n["metrics"] = metrics
		}
		for key := range n {
			if strings.HasPrefix(key, "_") {
				delete(n, key)
			}
		}
		out[id] = n
	}
	return out
}
func ApplicationFingerprints(raw common.Map, key string, states ...common.Map) common.Map {
	out := common.Map{}
	for id, snapshot := range ApplicationSnapshots(raw, states...) {
		h := hmac.New(sha256.New, []byte(key))
		h.Write(common.JSON(snapshot))
		out[id] = hex.EncodeToString(h.Sum(nil))
	}
	return out
}

// RecordApplied tracks only the scopes actually applied, retaining unrelated pending changes.
func RecordApplied(state, raw common.Map, node string, centralOnly bool) {
	key := common.S(state["fingerprint_key"])
	if key == "" {
		key = common.ID() + common.ID()
		state["fingerprint_key"] = key
	}
	current := ApplicationFingerprints(raw, key, state)
	saved := common.Clone(common.M(state["applied_fingerprints"]))
	for id, value := range current {
		if node != "" && id != node {
			continue
		}
		if centralOnly && id != "central" {
			continue
		}
		saved[id] = value
	}
	state["applied_fingerprints"] = saved
}
