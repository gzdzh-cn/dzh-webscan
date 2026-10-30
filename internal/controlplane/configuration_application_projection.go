package controlplane

import (
	"context"
	"database/sql"
)

type configurationApplicationVault func() (*Vault, error)

func (a *API) configurationApplicationVault() (*Vault, error) {
	v, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile, a.Config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return nil, errConfigurationBeforeEdit
	}
	return v, nil
}

// Read a page's application journals in one query and the same MVCC snapshot
// as its stages/revisions. This does not claim that a historical successful
// configuration is still the current desired or active configuration.
// A missing key or invalid proof fails the read instead of inventing pending
// or successful state. Keys are not needed for pages without applications.
func projectConfigurationApplicationsTx(ctx context.Context, tx *sql.Tx, stages []configurationRestoreStage, load configurationApplicationVault) error {
	if len(stages) == 0 {
		return nil
	}
	ids := make([]string, len(stages))
	indices := make(map[string]int, len(stages))
	for i, stage := range stages {
		ids[i], indices[stage.ID] = stage.ID, i
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+configurationApplicationColumns+` FROM v3_configuration_applications WHERE stage=ANY($1::text[])`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	var v *Vault
	for rows.Next() {
		j, err := scanApplication(rows)
		if err != nil {
			return err
		}
		if v == nil {
			if load == nil {
				return errConfigurationBeforeEdit
			}
			v, err = load()
			if err != nil || v == nil {
				return errConfigurationBeforeEdit
			}
		}
		if err = validateApplicationProof(v, j); err != nil {
			return err
		}
		i, ok := indices[j.Stage]
		if !ok || stages[i].Status != "saved" || stages[i].Username != j.Username {
			return errConfigurationApplication
		}
		message, err := configurationApplicationMessage(j)
		if err != nil {
			return err
		}
		public := j.public()
		stages[i].Application, stages[i].Message = &public, message
	}
	return rows.Err()
}

func configurationApplicationMessage(j privateConfigurationApplication) (string, error) {
	if j.RecoveryHold {
		return "应用任务已冻结，需管理员检查恢复资料后继续；不能视为已生效", nil
	}
	switch j.Status {
	case "queued", "running":
		if j.Direction == "rollback" {
			return "配置回退中，请查看任务阶段；尚未完成回退验收", nil
		}
		return "配置应用中，请查看任务阶段；尚未完成生效验收", nil
	case "failed":
		if j.RecoveryRequired {
			return "配置应用或回退未完成，需继续或回退原任务；请勿重复部署", nil
		}
		return "配置应用检查失败，未进入运行切换；请查看任务阶段", nil
	case "succeeded":
		return "本次配置应用已完成验收；此为历史任务结果，不代表当前配置版本", nil
	case "rolled_back":
		return "本次配置应用已回退并验收；保存配置仍保留，不能视为已应用", nil
	case "cancelled":
		return "本次配置应用已取消；保存配置仍保留，不能视为已应用", nil
	}
	return "", errConfigurationApplication
}
