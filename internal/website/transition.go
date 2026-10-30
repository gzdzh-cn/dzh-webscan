package website

import (
	"fmt"
	"time"
)

// TransitionEffects are run by the caller inside its storage transaction.
// The same state machine is shared by SQLite and PostgreSQL.
type TransitionEffects struct {
	Open   func(kind string) (int64, error)
	Close  func(id int64) error
	Notice func(kind, message string) error
}

func Transition(s Site, r Result, interval int, effects TransitionEffects) (State, error) {
	st := s.State
	var e error
	incident, closeIncident, notice := effects.Open, effects.Close, effects.Notice
	// Network failures retain the last certificate without claiming it was
	// checked or renewed. A successful plain-HTTP check is explicitly N/A.
	if r.CertExpires == 0 && !r.OK && st.Last.CertExpires > 0 {
		r.CertExpires = st.Last.CertExpires
		r.CertHost = st.Last.CertHost
		r.CertChecked = st.Last.CertChecked
		r.CertApplicable = true
		if r.CertError == "" {
			r.CertError = "本次证书检查失败，保留最近证书信息"
		}
	}
	freshCertificate := r.CertExpires > 0 && (r.CertError == "" || r.CertObserved)
	st.Last = r
	st.Checks++
	now := r.Time
	st.Next = now + int64(max(1, interval))
	if r.OK {
		st.Passed++
		st.Successes++
		st.Failures = 0
		if st.Incident != 0 && st.Successes >= 2 {
			if e = closeIncident(st.Incident); e != nil {
				return State{}, e
			}
			if e = notice("recovery", fmt.Sprintf("网站已恢复访问；故障持续 %s", time.Duration(now-st.DownSince)*time.Second)); e != nil {
				return State{}, e
			}
			st.Incident = 0
			st.DownSince = 0
			st.Status = "normal"
		} else if st.Incident == 0 {
			st.Status = "normal"
		}
	} else {
		st.Failures++
		st.Successes = 0
		if st.Failures >= 3 && st.Incident == 0 {
			st.Status = "down"
			st.DownSince = now
			st.Reminder = now
			st.Incident, e = incident("outage")
			if e != nil {
				return State{}, e
			}
			if e = notice("outage", "网站连续 3 次检查失败，无法正常访问；原因："+r.Reason); e != nil {
				return State{}, e
			}
		}
		if st.Incident != 0 && now-st.Reminder >= 4*3600 {
			st.Reminder = now
			if e = notice("outage_reminder", "网站仍无法正常访问；原因："+r.Reason); e != nil {
				return State{}, e
			}
		}
	}
	if r.CertExpires > 0 {
		remaining := r.CertExpires - now
		expired := remaining <= 0
		days := int64(0)
		if remaining > 0 {
			days = (remaining + 86399) / 86400
		}
		if remaining <= 7*86400 && (!st.CertWarn || now-st.CertReminder >= 86400 || expired && !st.CertExpired) {
			if !st.CertWarn {
				st.CertIncident, e = incident("certificate")
				if e != nil {
					return State{}, e
				}
			}
			st.CertWarn = true
			st.CertReminder = now
			text := fmt.Sprintf("HTTPS 证书将在 %d 天内到期，请及时续签", days)
			if expired {
				text = "HTTPS 证书已过期，请立即续签"
			}
			if !freshCertificate {
				text += "；本次证书检查失败，以上为最近一次取得的证书信息"
			}
			if e = notice("certificate", text); e != nil {
				return State{}, e
			}
		}
		if remaining > 7*86400 && freshCertificate && r.CertError == "" && st.CertWarn {
			if st.CertIncident != 0 {
				if e = closeIncident(st.CertIncident); e != nil {
					return State{}, e
				}
				st.CertIncident = 0
			}
			st.CertWarn = false
			if e = notice("certificate_recovery", "HTTPS 证书已更新，有效期恢复正常"); e != nil {
				return State{}, e
			}
		}
		st.CertExpired = expired
	}
	if s.Slow && !r.OK {
		st.SlowSince = 0
		st.Fast = 0
	}
	if s.Slow && r.OK {
		if r.Latency > 3 {
			st.Fast = 0
			if st.SlowSince == 0 {
				st.SlowSince = now
			}
			if now-st.SlowSince >= 300 && st.SlowIncident == 0 {
				st.SlowIncident, e = incident("slow")
				if e != nil {
					return State{}, e
				}
				if e = notice("slow", "网站响应超过 3 秒并持续 5 分钟，请检查网站负载"); e != nil {
					return State{}, e
				}
			}
		} else {
			st.Fast++
			st.SlowSince = 0
			if st.SlowIncident != 0 && st.Fast >= 2 {
				if e = closeIncident(st.SlowIncident); e != nil {
					return State{}, e
				}
				if e = notice("slow_recovery", "网站响应速度已恢复正常"); e != nil {
					return State{}, e
				}
				st.SlowIncident = 0
			}
		}
	}
	return st, nil
}
