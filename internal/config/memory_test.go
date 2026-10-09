package config

import (
	"strings"
	"testing"
	"webscan/internal/common"
)

func TestInstallMemoryReserveDefaultAndValidation(t *testing.T) {
	m := example(t)
	center := common.M(m["central"])
	delete(center, "install_memory_reserve_mib")
	c, e := loadMap(t, m)
	if e != nil || common.I(common.M(c.Raw["central"])["install_memory_reserve_mib"]) != 128 {
		t.Fatal(e)
	}
	for _, n := range []int{64, 128, 4096} {
		center["install_memory_reserve_mib"] = n
		if _, e = loadMap(t, m); e != nil {
			t.Fatal(e)
		}
	}
	for _, n := range []int{0, 63, 4097} {
		center["install_memory_reserve_mib"] = n
		_, e = loadMap(t, m)
		if e == nil {
			t.Fatal("invalid reserve accepted", n)
		}
		message, ok := Explain(e)
		if !ok || !strings.Contains(message, "central.install_memory_reserve_mib") || !strings.Contains(message, "64～4096") {
			t.Fatal(n, e)
		}
	}
}
