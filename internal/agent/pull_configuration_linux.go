//go:build linux

package agent

import (
	"encoding/json"
	"errors"
	"math"
	"webscan/internal/common"
	"webscan/internal/pull"
)

func pullConfigurations(c common.Map) ([]pull.Configuration, error) {
	if c["config_version"] == nil && c["config_sha256"] == nil {
		return nil, nil
	}
	var version int64
	switch value := c["config_version"].(type) {
	case json.Number:
		parsed, err := value.Int64()
		if err != nil {
			return nil, errors.New("invalid_effective_configuration_version")
		}
		version = parsed
	case int64:
		version = value
	case int:
		version = int64(value)
	case float64:
		// The real file decoder preserves json.Number. Do not silently round a
		// large or fractional version supplied by another in-process caller.
		if math.IsNaN(value) || math.IsInf(value, 0) || value != math.Trunc(value) || value > 9007199254740991 || value < 1 {
			return nil, errors.New("invalid_effective_configuration_version")
		}
		version = int64(value)
	default:
		return nil, errors.New("invalid_effective_configuration_version")
	}
	if version < 1 {
		return nil, errors.New("invalid_effective_configuration_version")
	}
	return []pull.Configuration{{Version: version, SHA256: common.S(c["config_sha256"])}}, nil
}
