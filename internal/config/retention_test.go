package config

import (
	"testing"
	"webscan/internal/common"
)

func TestRetentionUpgradeDefaultsAndCustomPeriods(t *testing.T) {
	for _, custom := range []bool{false, true} {
		m := example(t)
		r := common.M(m["retention"])
		for _, key := range []string{"security_events_days", "website_incidents_days", "server_alerts_days"} {
			delete(r, key)
		}
		if custom {
			r["sqlite_events_days"] = 120
			common.M(common.M(m["central"])["monitoring"])["history_days"] = 45
		} else {
			delete(r, "sqlite_events_days")
			delete(common.M(common.M(m["central"])["monitoring"]), "history_days")
		}
		c, e := loadMap(t, m)
		if e != nil {
			t.Fatal(e)
		}
		got := common.M(c.Raw["retention"])
		security, server := 30, 15
		if custom {
			security, server = 120, 45
		}
		if common.I(got["security_events_days"]) != security || common.I(got["server_alerts_days"]) != server || common.I(got["website_incidents_days"]) != 30 {
			t.Fatalf("unexpected upgrade periods: %v", got)
		}
	}
}
func TestRetentionPeriodBounds(t *testing.T) {
	for _, key := range []string{"sqlite_events_days", "security_events_days", "website_incidents_days", "server_alerts_days", "delivery_records_days"} {
		for _, value := range []float64{0, 3651, 2.5} {
			m := example(t)
			common.M(m["retention"])[key] = value
			if _, e := loadMap(t, m); e == nil {
				t.Fatalf("accepted %s=%v", key, value)
			}
		}
	}
}
