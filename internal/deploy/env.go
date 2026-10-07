package deploy

import (
	"errors"
	"os"
	"strings"
	"webscan/internal/common"
	configuration "webscan/internal/config"
)

// resolvedFeishu treats the legacy env file as literal data and never executes it.
func resolvedFeishu(f common.Map) (common.Map, error) {
	out := common.Clone(f)
	if common.B(f["enabled"]) && common.Contains([]string{"existing", "existing_env"}, common.S(f["mode"])) {
		b, err := os.ReadFile(common.S(f["existing_env_file"]))
		if err != nil {
			return nil, errors.New("feishu_env_file_unreadable")
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			if len(value) >= 2 && (value[0] == '\'' || value[0] == '"') {
				if value[len(value)-1] != value[0] {
					return nil, errors.New("feishu_env_invalid_literal")
				}
				value = value[1 : len(value)-1]
			}
			values[key] = value
		}
		out["webhook_url"], out["signing_secret"] = values["FEISHU_WEBHOOK_URL"], values["FEISHU_SECRET"]
	}
	if common.B(out["enabled"]) {
		if !configuration.ValidFeishuWebhook(common.S(out["webhook_url"])) {
			return nil, errors.New("invalid_feishu_webhook")
		}
		if common.B(out["signing_enabled"]) && common.S(out["signing_secret"]) == "" {
			return nil, errors.New("missing_feishu_signing_secret")
		}
	}
	return out, nil
}
