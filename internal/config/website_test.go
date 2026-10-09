package config

import (
	"testing"
	"webscan/internal/common"
)

func TestWebsiteOptionalAndValidation(t *testing.T) {
	m := example(t)
	center := common.M(m["central"])
	delete(center, "website_monitor")
	c, e := loadMap(t, m)
	if e != nil {
		t.Fatal(e)
	}
	if common.B(common.M(common.M(c.Raw["central"])["website_monitor"])["enabled"]) {
		t.Fatal("old YAML enabled console")
	}
	wm := common.Map{"enabled": true, "host_port": 19444}
	center["website_monitor"] = wm
	if _, e = loadMap(t, m); e != nil {
		t.Fatal(e)
	}
	for _, value := range []common.Map{{"host_port": 19443}, {"timeout_seconds": 60}, {"admin_password": "short"}, {"max_concurrent": 129}} {
		center["website_monitor"] = common.Merge(wm, value)
		_, e = loadMap(t, m)
		if e == nil {
			t.Fatal("accepted", value)
		}
		if message, ok := Explain(e); !ok || message == "" {
			t.Fatal("no clear diagnostic", e)
		}
	}
}
