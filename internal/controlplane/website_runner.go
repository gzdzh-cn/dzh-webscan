package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"webscan/internal/common"
	"webscan/internal/website"
)

type SiteChecker interface {
	Check(context.Context, website.Site, time.Duration) website.Result
}

type WebsiteRunner struct {
	Store       *Store
	Instance    string
	Concurrency int
	Checker     SiteChecker
}

func (w *WebsiteRunner) Run(ctx context.Context) error {
	if !identifier.MatchString(w.Instance) {
		return errors.New("网站工作器标识不正确")
	}
	if w.Concurrency == 0 {
		w.Concurrency = 128
	}
	if w.Concurrency < 1 || w.Concurrency > 256 {
		return errors.New("网站并发须为 1～256")
	}
	if w.Checker == nil {
		w.Checker = website.NewChecker()
	}
	active := make(chan struct{}, w.Concurrency)
	var wg sync.WaitGroup
	defer wg.Wait()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		free := w.Concurrency - len(active)
		var jobs []WebsiteJob
		var err error
		op, cancel := context.WithTimeout(ctx, 5*time.Second)
		if free > 0 {
			jobs, err = w.Store.ClaimSites(op, w.Instance, free)
		}
		reason := ""
		if err != nil {
			reason = "网站检测任务读取失败，请检查数据库"
		}
		_, heartbeatError := w.Store.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('websites',$1,clock_timestamp(),$2,$3) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details=excluded.details`, w.Instance, reason, common.JSON(common.Map{"active": len(active), "concurrency": w.Concurrency}))
		if err == nil && heartbeatError == nil {
			runtimeReady(ctx, "websites")
		}
		cancel()
		for _, job := range jobs {
			active <- struct{}{}
			wg.Add(1)
			go func(job WebsiteJob) {
				defer wg.Done()
				defer func() { <-active }()
				probe, stop := context.WithTimeout(ctx, job.Timeout)
				result := w.Checker.Check(probe, job.Site, job.Timeout)
				stop()
				// A cancelled runner leaves its lease to expire. A timed-out
				// HTTP probe is a real failed check, not a cancelled job.
				if ctx.Err() != nil {
					return
				}
				op, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				if err := w.Store.ApplySiteResult(op, job, result); err != nil && !errors.Is(err, ErrLeaseLost) {
					_, _ = w.Store.DB.ExecContext(op, "UPDATE v3_role_status SET error=$2 WHERE role='websites' AND instance=$1", w.Instance, "网站检测结果保存失败，将在租约到期后重试")
				}
			}(job)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	return ctx.Err()
}

func (s *Store) WebsiteSummary(ctx context.Context) (json.RawMessage, error) {
	var raw json.RawMessage
	err := s.DB.QueryRowContext(ctx, `SELECT jsonb_build_object(
 'total',count(*),'normal',count(*) FILTER(WHERE NOT paused AND NOT migration_pending AND state->>'status'='normal'),
 'down',count(*) FILTER(WHERE NOT paused AND NOT migration_pending AND state->>'status'='down'),
 'pending',count(*) FILTER(WHERE NOT paused AND NOT migration_pending AND COALESCE(state->>'status','pending')='pending'),
 'paused',count(*) FILTER(WHERE paused AND NOT migration_pending),
 'unknown',count(*) FILTER(WHERE NOT paused AND NOT migration_pending AND COALESCE(state->>'status','pending') NOT IN ('normal','down','pending')),
 'migration_pending',count(*) FILTER(WHERE migration_pending),
 'due',count(*) FILTER(WHERE NOT paused AND NOT migration_pending AND next_check<=clock_timestamp()),
 'notification_outbox',(SELECT jsonb_build_object('pending',count(*),'oldest_wait_seconds',CASE WHEN min(created) IS NULL THEN NULL ELSE GREATEST(0,floor(extract(epoch FROM clock_timestamp()))::bigint-min(created)) END) FROM v3_website_outbox WHERE done_at IS NULL),
 'notification_worker',(SELECT jsonb_build_object('heartbeat',max(heartbeat),'healthy',bool_or(heartbeat>clock_timestamp()-interval '15 seconds' AND error='')) FROM v3_role_status WHERE role='website-notifications'),
 'scheduler',COALESCE((SELECT jsonb_build_object('heartbeat',max(heartbeat),'healthy',bool_or(heartbeat>clock_timestamp()-interval '10 seconds' AND error='')) FROM v3_role_status WHERE role='websites'),'{"healthy":false}'::jsonb)
 ) FROM v3_websites WHERE NOT deleted`).Scan(&raw)
	return raw, err
}
