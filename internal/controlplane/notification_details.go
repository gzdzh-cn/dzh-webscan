package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type NotificationOutcome struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type NotificationDetail struct {
	Notification NotificationRecord  `json:"notification"`
	Body         string              `json:"body"`
	Outcome      NotificationOutcome `json:"outcome"`
}
type NotificationAttempt struct {
	ID      string    `json:"id"`
	Epoch   string    `json:"epoch"`
	Success bool      `json:"success"`
	Outcome string    `json:"outcome"`
	Message string    `json:"message"`
	Created time.Time `json:"created_at"`
}

func notificationID(id string) (int64, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n < 1 || strconv.FormatInt(n, 10) != id {
		return 0, ErrHistoryInput
	}
	return n, nil
}

func notificationAttemptOutcome(success bool) NotificationOutcome {
	if success {
		return NotificationOutcome{"accepted", "通知服务已确认接收；不代表收件人已阅读。"}
	}
	return NotificationOutcome{"unknown", "发送返回错误，结果未知，通知可能已经投递。"}
}

func (s *Store) NotificationDetail(ctx context.Context, id string) (NotificationDetail, error) {
	var out NotificationDetail
	n, err := notificationID(id)
	if err != nil {
		return out, err
	}
	// One repeatable snapshot keeps metadata, digest proof and attempt evidence
	// consistent while a notification worker finishes concurrently.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	out.Notification, err = scanNotificationRecord(tx.QueryRowContext(ctx, `SELECT `+notificationRecordColumns+` FROM `+notificationHistoryReadSQL()+` t WHERE t.id=$1`, n))
	if err != nil {
		return out, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT public_body FROM `+notificationPublicReadSQL()+` t WHERE t.id=$1`, n).Scan(&out.Body); err != nil {
		return out, err
	}
	var success bool
	err = tx.QueryRowContext(ctx, `SELECT success FROM v3_notification_attempts WHERE notification=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, n).Scan(&success)
	if err == nil {
		out.Outcome = notificationAttemptOutcome(success)
	} else if err == sql.ErrNoRows {
		out.Outcome = NotificationOutcome{"pending", "尚无通知发送尝试。"}
		if out.Notification.Completed != nil {
			out.Outcome = NotificationOutcome{"unknown", "历史记录缺少可核验的发送结果。"}
		}
	} else {
		return out, err
	}
	return out, tx.Commit()
}

func (s *Store) NotificationAttempts(ctx context.Context, id string, before notificationCursor, limit int) ([]NotificationAttempt, error) {
	n, err := notificationID(id)
	if err != nil || limit < 1 || limit > 100 {
		return nil, ErrHistoryInput
	}
	if before.Time.IsZero() {
		before = notificationCursor{time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), "1"}
	}
	if _, err = decodeNotificationCursor(before.encode()); err != nil {
		return nil, ErrHistoryInput
	}
	var exists bool
	if err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_notifications WHERE id=$1)`, n).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, sql.ErrNoRows
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id::text,epoch::text,success,created_at FROM v3_notification_attempts WHERE notification=$1 AND (created_at,id)<($2,$3::bigint) ORDER BY created_at DESC,id DESC LIMIT $4`, n, before.Time, before.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationAttempt{}
	for rows.Next() {
		var v NotificationAttempt
		if err = rows.Scan(&v.ID, &v.Epoch, &v.Success, &v.Created); err != nil {
			return nil, err
		}
		o := notificationAttemptOutcome(v.Success)
		v.Outcome, v.Message = o.Code, o.Message
		out = append(out, v)
	}
	return out, rows.Err()
}

func (a *API) notificationDetailRoutes(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/api/v3/notifications/"
	if !strings.HasPrefix(r.URL.Path, prefix) || r.URL.Path == prefix+"stats" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) > 2 || len(parts) == 2 && parts[1] != "attempts" {
		failure(w, 404, "not_found", "接口不存在")
		return true
	}
	if r.Method != http.MethodGet {
		failure(w, 405, "method_not_allowed", "请使用 GET")
		return true
	}
	if _, err := notificationID(parts[0]); err != nil {
		failure(w, 400, "invalid_notification_id", "通知标识不正确")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if len(parts) == 1 {
		out, err := a.Store.NotificationDetail(ctx, parts[0])
		if err != nil {
			notificationReadFailure(w, err)
		} else {
			reply(w, 200, out)
		}
		return true
	}
	limit, err := pageSize(r, 20)
	if err != nil || limit > 100 {
		failure(w, 400, "invalid_limit", "每页数量须为 1～100")
		return true
	}
	before, err := decodeNotificationCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		failure(w, 400, "invalid_cursor", "通知尝试分页游标不正确")
		return true
	}
	items, err := a.Store.NotificationAttempts(ctx, parts[0], before, limit)
	if err != nil {
		notificationReadFailure(w, err)
		return true
	}
	next := ""
	if len(items) == limit {
		last := items[len(items)-1]
		next = (notificationCursor{last.Created, last.ID}).encode()
	}
	reply(w, 200, map[string]any{"items": items, "next_cursor": next, "limit": limit})
	return true
}

func notificationReadFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		failure(w, 404, "notification_not_found", "通知记录不存在")
		return
	}
	if errors.Is(err, ErrHistoryInput) {
		failure(w, 400, "invalid_notification_request", "通知查询参数不正确")
		return
	}
	failure(w, 503, "query_failed", "通知记录暂时不可用")
}
