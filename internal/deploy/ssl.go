package deploy

import (
	"webscan/internal/common"
	"webscan/internal/progress"
)

func (d *Deploy) validateSSLChange() error {
	previous := common.M(d.State["configuration"])
	if !common.B(d.State["central_installed"]) || len(previous) == 0 || d.O.Uninstall || d.O.Rollback {
		return nil
	}
	if (&Config{Raw: previous}).SSLEnabled() == d.C.SSLEnabled() {
		return nil
	}
	if d.O.CentralOnly || d.O.Node != "" || d.O.AddNode || d.O.ReloadRules || d.O.GrafanaOnly || d.O.SyncGrafana || d.O.Check {
		return &progress.Failure{Code: "ssl_mode_change_requires_full_upgrade", Message: "SSL 总开关已改变，必须执行 bash deploy-webscan.sh --upgrade 同时更新主服务器和全部启用节点；不能只更新主服务器、单节点或规则"}
	}
	return nil
}
