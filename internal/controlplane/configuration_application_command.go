package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
)

func (s *Store) localConfigurationApplicationCommand(ctx context.Context, c Config, o Options, out io.Writer) error {
	if err := provisioningAdmin(ctx, s.DB, o.Username); err != nil {
		return err
	}
	if !identifier.MatchString(o.RequestKey) {
		return errors.New("配置应用写操作需要有效 --request-key；重试使用同一值")
	}
	v, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return errConfigurationApplication
	}
	var result json.RawMessage
	switch o.Action {
	case "queue-configuration-application":
		var in struct {
			Stage      string `json:"stage"`
			Generation int64  `json:"generation,string"`
			Confirm    bool   `json:"confirm"`
		}
		if provisioningInput(o.Source, &in) != nil || !in.Confirm || !c.Executor.ApplicationsEnabled {
			return errConfigurationApplication
		}
		result, err = s.queueConfigurationApplication(ctx, v, c, o.Username, o.RequestKey, in.Stage, in.Generation)
	case "control-configuration-application":
		var in struct {
			ID      string `json:"id"`
			Action  string `json:"action"`
			Confirm bool   `json:"confirm"`
		}
		if provisioningInput(o.Source, &in) != nil || !in.Confirm || in.Action != "cancel" && !c.Executor.ApplicationsEnabled {
			return errConfigurationApplication
		}
		result, err = s.controlConfigurationApplication(ctx, v, o.Username, o.RequestKey, in.ID, in.Action)
	default:
		return errConfigurationApplication
	}
	if err != nil {
		return err
	}
	_, err = out.Write(append(result, '\n'))
	return err
}
