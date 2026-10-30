package telemetry

import (
	"fmt"
	"strings"

	"webscan/internal/common"
)

// RulesFor shares the existing health policy across SQLite and PostgreSQL.
// Missing measurements remain unknown, rather than becoming healthy zeroes.
func RulesFor(n Node, snapshot Snapshot, config common.Map) []Rule {
	return rules(n, snapshot, config)
}

// AdvanceRule is the existing duration/hysteresis state machine without I/O.
// Callers serialize state, reject stale observations and commit history/outbox
// together. Reminder is advanced only after that event has been persisted.
func AdvanceRule(st RuleState, r Rule, at int64, interval, repeatHours int) (RuleState, string) {
	if !r.Known {
		return st, ""
	}
	if st.Phase == "disabled" {
		st.Phase = "normal"
		st.Since = 0
	}
	previous, last := st.Phase, st.Last
	st.Last, st.Message, st.Severity = at, r.Message, r.Severity
	if r.Bad {
		st.Recovery = 0
		if st.Phase == "pending" && last > 0 && at-last > int64(max(10, interval)*3) {
			st.Since = at
		}
		if st.Phase == "normal" {
			st.Since, st.Phase = at, "pending"
		}
		if at-st.Since >= r.For {
			st.Phase = "firing"
		}
	} else if st.Phase == "pending" {
		st.Phase, st.Since = "normal", 0
	} else if st.Phase == "firing" && r.Recover {
		if last > 0 && at-last > int64(max(10, interval)*3) {
			st.Recovery = 0
		}
		st.Recovery++
		if st.Recovery >= r.RecoverSamples {
			st.Phase = "normal"
		}
	} else {
		st.Recovery = 0
	}
	phase := ""
	if st.Phase == "firing" && previous != "firing" {
		phase = "firing"
	} else if st.Phase == "normal" && previous == "firing" {
		phase = "resolved"
	} else if st.Phase == "firing" && at-st.Reminder >= int64(max(1, repeatHours)*3600) {
		phase = "reminder"
	}
	return st, phase
}

func RuleMessage(n Node, r Rule, st RuleState, phase string, at int64) string {
	if phase == "resolved" {
		return fmt.Sprintf("监控已恢复\n服务器：%s（%s）\n已恢复项目：%s\n持续时间：%d 秒", n.Name, n.Host, r.Message, at-st.Since)
	}
	return fmt.Sprintf("监控异常提醒\n服务器：%s（%s）\n问题：%s", n.Name, n.Host, r.Message)
}

// A critical disk/inode alert keeps its warning history but inhibits duplicate
// warning delivery, preserving the existing policy.
func RuleInhibited(r Rule, snapshot Snapshot, config common.Map) bool {
	if !strings.HasSuffix(r.Kind, ":warning") {
		return false
	}
	base := strings.TrimSuffix(r.Kind, ":warning")
	metric, mount, _ := strings.Cut(base, ":")
	limit := common.I(common.M(config["alerts"])[metric+"_critical_percent"])
	if limit == 0 {
		limit = 90
	}
	return snapshot.Values[metric+"_percent:"+mount] > float64(limit)
}
