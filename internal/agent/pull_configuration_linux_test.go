//go:build linux

package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestEffectiveConfigurationPreservesIntegerVersionAndRejectsRounding(t *testing.T) {
	sha := strings.Repeat("a", 64)
	raw := []byte(`{"config_version":9007199254740993,"config_sha256":"` + sha + `"}`)
	value, err := common.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	configs, err := pullConfigurations(common.M(value))
	if err != nil || len(configs) != 1 || configs[0].Version != 9007199254740993 {
		t.Fatal("effective version lost precision", err)
	}
	for _, value := range []any{json.Number("1.5"), json.Number("9223372036854775808"), float64(9007199254740992), 1.5, "1", 0, -1, true} {
		if _, err := pullConfigurations(common.Map{"config_version": value, "config_sha256": sha}); err == nil {
			t.Fatal("invalid effective version accepted", value)
		}
	}
	if configs, err := pullConfigurations(common.Map{}); err != nil || len(configs) != 0 {
		t.Fatal("legacy configuration changed", err)
	}
}
