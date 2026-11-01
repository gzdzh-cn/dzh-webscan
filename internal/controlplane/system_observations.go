package controlplane

import (
	"context"
	"encoding/json"
	"time"
)

// A channel heartbeat describes the actual worker, including failed claims
// and sends. Queue length alone cannot prove that a notifier is running.
func (n *Notifier) notificationHeartbeat(ctx context.Context, channel string, failed bool) {
	op, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	reason := ""
	if failed {
		reason = "通知工作器领取、投递或结果持久化失败，请检查配置和服务状态"
	}
	_, _ = n.Store.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error) VALUES($1,$2,clock_timestamp(),$3)
ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details='{}'::jsonb`, "notify-"+channel, n.Instance, reason)
}

type systemHostObservation struct {
	Configured bool                `json:"configured"`
	Available  bool                `json:"available"`
	Fresh      bool                `json:"fresh"`
	Reason     string              `json:"reason"`
	Status     *HostWatchdogStatus `json:"status"`
}

// Only the summary worker calls the private host service. Dashboard readers
// use its persisted result and cannot supply probe addresses or commands.
func (s *Store) hostObservation(ctx context.Context) (json.RawMessage, error) {
	out := systemHostObservation{Configured: s.HostQuota != nil, Reason: "尚未配置独立宿主看门狗"}
	if s.HostQuota != nil {
		status, err := s.HostQuota.Snapshot(ctx)
		if err != nil {
			out.Reason = "宿主看门狗不可访问，运行状态未知"
		} else {
			out.Available = true
			age := time.Since(status.ObservedAt)
			out.Fresh = !status.ObservedAt.IsZero() && age >= -5*time.Second && age <= 45*time.Second
			out.Status = &status
			out.Reason = ""
			if !out.Fresh {
				out.Reason = "宿主观测已过期，运行状态未知"
			}
		}
	}
	return json.Marshal(out)
}
