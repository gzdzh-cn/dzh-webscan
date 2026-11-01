package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

func (s *hostWatchdogStore) reserve(ctx context.Context, in hostQuotaInput) (HostQuotaReservation, error) {
	out := HostQuotaReservation{AttemptKey: in.AttemptKey, RuntimeVersion: in.RuntimeVersion}
	if (in.Channel != "email" && in.Channel != "feishu") || in.RuntimeVersion < 1 || !eventText(in.AttemptKey, 256) || strings.TrimSpace(in.AttemptKey) == "" {
		return out, ErrHostQuota
	}
	tx, err := persist.BeginWrite(ctx, s.db)
	if err != nil {
		return out, ErrHostQuota
	}
	defer tx.Rollback()
	version, raw, frozen, err := s.settings(ctx, tx)
	defer clear(raw)
	if err != nil || frozen || version != in.RuntimeVersion {
		return out, ErrHostSettingsFrozen
	}
	var root common.Map
	if json.Unmarshal(raw, &root) != nil {
		return out, ErrHostQuota
	}
	cfg := common.M(root[in.Channel])
	if !common.B(cfg["enabled"]) {
		return out, ErrHostQuota
	}
	var at float64
	err = tx.QueryRowContext(ctx, `SELECT id,at FROM quota WHERE channel=? AND attempt_key=?`, in.Channel, in.AttemptKey).Scan(&out.ID, &at)
	if err == nil {
		out.GrantedAt = time.UnixMilli(int64(at * 1000)).UTC()
		out.ExpiresAt = out.GrantedAt.Add(5 * time.Second)
		return out, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return out, ErrHostQuota
	}
	now := float64(time.Now().UnixNano()) / 1e9
	var last float64
	if err = tx.QueryRowContext(ctx, `SELECT last_clock FROM host_state WHERE id=1`).Scan(&last); err != nil {
		return out, ErrHostQuota
	}
	// Backward wall-clock movement must not release old quota early.
	if now+1 < last {
		return out, ErrHostQuota
	}
	now = math.Max(now, last)
	perMinute := min(600, max(1, common.I(cfg["max_per_minute"])))
	perSecond := 0.0
	if in.Channel == "feishu" {
		rate := common.M(cfg["rate_limit"])
		perMinute = min(600, max(1, common.I(rate["max_per_minute"])))
		perSecond = common.F(rate["max_per_second"])
	}
	var count int
	var newest sql.NullFloat64
	if err = tx.QueryRowContext(ctx, `SELECT count(*),max(at) FROM quota WHERE channel=? AND at>?`, in.Channel, now-60).Scan(&count, &newest); err != nil {
		return out, ErrHostQuota
	}
	if count >= perMinute || perSecond > 0 && newest.Valid && now-newest.Float64 < 1/perSecond {
		retry := time.UnixMilli(int64((now + 1) * 1000)).UTC()
		out.RetryAt = &retry
		return out, tx.Commit()
	}
	out.ID = token()
	out.New = true
	out.GrantedAt = time.UnixMilli(int64(now * 1000)).UTC()
	out.ExpiresAt = out.GrantedAt.Add(5 * time.Second)
	if _, err = tx.ExecContext(ctx, `INSERT INTO quota(id,channel,attempt_key,version,at) VALUES(?,?,?,?,?)`, out.ID, in.Channel, in.AttemptKey, version, now); err != nil {
		return out, ErrHostQuota
	}
	if _, err = tx.ExecContext(ctx, `UPDATE host_state SET last_clock=? WHERE id=1`, now); err != nil {
		return out, ErrHostQuota
	}
	return out, tx.Commit()
}
