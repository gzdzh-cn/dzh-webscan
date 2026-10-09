package deploy

import (
	"strings"
	"testing"
	"webscan/internal/common"
	"webscan/internal/progress"
)

func TestFreshInstallMemoryReserveAdmissionAndContainerLimits(t *testing.T) {
	c := fixture(t)
	center := common.M(c.Raw["central"])
	center["new_components_memory_budget_mib"] = 320
	center["website_monitor"] = common.Map{"enabled": true, "extra_memory_mib": 128, "host_port": 19444, "bind_address": "0.0.0.0"}
	before := ReceiverService(c, "fixture:v1")["mem_limit"]
	delete(center, "install_memory_reserve_mib")
	b := freshInstallMemory(c)
	if b.Total() != 1024 || b.Check(1008*1024) == nil {
		t.Fatal(b)
	}
	if b.Check(1024*1024) != nil {
		t.Fatal("exact boundary refused")
	}
	if text := progress.Explain(b.Check(1008 * 1024)); !strings.Contains(text, "16 MiB") || !strings.Contains(text, "central.install_memory_reserve_mib") {
		t.Fatal(text)
	}
	center["install_memory_reserve_mib"] = 64
	b = freshInstallMemory(c)
	if b.Total() != 960 || b.Check(996*1024) != nil || b.Check(959*1024+1023) == nil {
		t.Fatal(b)
	}
	if ReceiverService(c, "fixture:v1")["mem_limit"] != before {
		t.Fatal("reserve changed container limit")
	}
	center["reuse_existing"] = common.Map{"grafana": true, "loki": true}
	b = freshInstallMemory(c)
	if b.Total() != 512 {
		t.Fatal(b)
	}
	common.M(center["website_monitor"])["enabled"] = false
	b = freshInstallMemory(c)
	if b.Total() != 384 {
		t.Fatal(b)
	}
}
