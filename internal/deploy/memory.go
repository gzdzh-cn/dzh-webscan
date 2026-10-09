package deploy

import (
	"fmt"
	"webscan/internal/common"
	"webscan/internal/progress"
)

type installMemoryBudget struct{ Components, Grafana, Loki, Website, Reserve int }

func (b installMemoryBudget) Total() int {
	return b.Components + b.Grafana + b.Loki + b.Website + b.Reserve
}

// Container limits remain unchanged; the reserve controls only the preflight
// admission check. Saved configurations predating the option retain 128 MiB.
func freshInstallMemory(c *Config) installMemoryBudget {
	center := common.M(c.Raw["central"])
	reserve := 128
	if value, exists := center["install_memory_reserve_mib"]; exists {
		reserve = common.I(value)
	}
	b := installMemoryBudget{Components: common.I(center["new_components_memory_budget_mib"]), Website: websiteMemory(c), Reserve: reserve}
	if !common.B(common.M(center["reuse_existing"])["grafana"]) {
		b.Grafana = 192
	}
	if !common.B(common.M(center["reuse_existing"])["loki"]) {
		b.Loki = 256
	}
	return b
}
func (b installMemoryBudget) Check(availableKiB int) error {
	if availableKiB >= b.Total()*1024 {
		return nil
	}
	missingKiB := b.Total()*1024 - availableKiB
	return &progress.Failure{Code: "insufficient_available_memory_for_fresh_install", Message: fmt.Sprintf("首次安装内存不足：可用 %d MiB，要求 %d MiB，还差约 %d MiB（新组件 %d、Grafana %d、Loki %d、网站后台 %d、预留 %d）。请释放内存或扩容；也可按实际余量调整 central.install_memory_reserve_mib（最低 64，默认 128 MiB）。此次尚未启动监控容器，调整后重新执行脚本；无需 --resume", availableKiB/1024, b.Total(), (missingKiB+1023)/1024, b.Components, b.Grafana, b.Loki, b.Website, b.Reserve)}
}
