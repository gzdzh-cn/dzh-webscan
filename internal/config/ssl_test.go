package config

import (
	"testing"
	"webscan/internal/common"
)

func TestSSLDefaultsAndGlobalProtocol(t *testing.T) {
	m := example(t)
	delete(m, "ssl")
	c, err := loadMap(t, m)
	if err != nil || !c.SSLEnabled() {
		t.Fatal("legacy HTTPS", err)
	}
	m["ssl"] = common.Map{"enabled": false}
	c, err = loadMap(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if common.S(common.M(c.Raw["central"])["public_url"]) != "http://192.0.2.10:19443" {
		t.Fatal("HTTP public URL not normalized")
	}
	for _, n := range c.Nodes {
		if common.B(common.M(n["metrics"])["tls_enabled"]) {
			t.Fatal("node override defeated global switch")
		}
	}
	common.M(m["ssl"])["enabled"] = true
	common.M(m["central"])["public_url"] = "http://192.0.2.10:19443"
	c, err = loadMap(t, m)
	if err != nil || common.S(common.M(c.Raw["central"])["public_url"]) != "https://192.0.2.10:19443" {
		t.Fatal("HTTPS normalization", err)
	}
	m["ssl"] = common.Map{"enabled": "false"}
	if _, err = loadMap(t, m); err == nil {
		t.Fatal("quoted switch accepted")
	}
}
