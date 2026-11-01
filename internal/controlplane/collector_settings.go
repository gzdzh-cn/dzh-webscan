package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"webscan/internal/common"
)

var errCollectorSettings = errors.New("主控采集周期配置读取失败，请检查已应用设置；保持当前配置且不推测采集健康状态")

func collectorSettingsInterval(root configurationValues, fallback int) (int, error) {
	if fallback < 10 || fallback > 3600 {
		return 0, errCollectorSettings
	}
	if section, ok := root["collector"]; ok {
		if _, ok := section.(map[string]any); !ok {
			if _, ok := section.(common.Map); !ok {
				return 0, errCollectorSettings
			}
		}
	}
	value, ok := settingsPath(root, "collector.interval_seconds")
	if !ok {
		return fallback, nil
	}
	f := settingsField{Kind: "integer", Min: 10, Max: 3600}
	if !f.valid(value) {
		return 0, errCollectorSettings
	}
	interval, _ := strconv.Atoi(value.(json.Number).String())
	return interval, nil
}

// Read only the applied row. Saving a draft cannot change collection cadence.
// The caller captures the result for one node run instead of mutating Config
// concurrently with an existing gRPC/long-poll worker.
func (s *Store) effectiveCollectorInterval(ctx context.Context, fallback int) (int, error) {
	if s == nil || s.DB == nil {
		return 0, errCollectorSettings
	}
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT payload FROM v3_settings WHERE id=1`).Scan(&raw); err != nil {
		return 0, err
	}
	var root configurationValues
	if decodeConfigurationObject(raw, &root) != nil {
		return 0, errCollectorSettings
	}
	return collectorSettingsInterval(root, fallback)
}

func collectorRunWithInterval(c *Collector, seconds int) *Collector {
	copy := *c
	copy.Config.Collector.IntervalSeconds = seconds
	return &copy
}
