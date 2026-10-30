package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// One phase at a time per process. The durable global operation gate and the
// real journal lease also fence other processes; a channel is not authority.
// No public request can supply this concrete runtime or bypass its verifier.
type configurationApplicationWorker struct {
	store    *Store
	runtime  configurationCompositeRuntime
	instance string
}

func (w configurationApplicationWorker) valid() bool {
	return w.store != nil && w.store.DB != nil && w.runtime.store == w.store && w.runtime.valid() && identifier.MatchString(w.instance)
}

func (w configurationApplicationWorker) Run(ctx context.Context) error {
	if !w.valid() {
		return errConfigurationApplication
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	active := false
	defer func() {
		cancel()
		if active {
			<-done
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		reason := ""
		if !active {
			op, stop := context.WithTimeout(ctx, 5*time.Second)
			job, err := w.store.claimConfigurationApplication(op, w.runtime.vault, w.runtime.bootstrap.Central.Instance, w.instance)
			stop()
			switch {
			case err == nil:
				active = true
				go func() { done <- w.store.executeConfigurationApplication(ctx, w.runtime.vault, job, w.runtime) }()
			case errors.Is(err, sql.ErrNoRows):
			case errors.Is(err, ErrMigrationPending):
				reason = "数据迁移尚未完成，配置应用任务已暂停"
			default:
				reason = "配置应用任务读取或授权检查失败，请检查原任务与数据库"
			}
		}
		op, stop := context.WithTimeout(ctx, 3*time.Second)
		_, err := w.store.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error,details) VALUES('configuration-applications',$1,clock_timestamp(),$2,jsonb_build_object('active',$3::boolean)) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details=excluded.details`, w.instance, reason, active)
		stop()
		if reason == "" && err == nil {
			runtimeReady(ctx, "configuration-applications")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			// Execute owns phase failure journals. Never replay a failed phase here,
			// log a raw runtime error, or turn a pending restart into completion.
			active = false
		case <-tick.C:
		}
	}
	return ctx.Err()
}
