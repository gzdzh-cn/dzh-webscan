package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"webscan/internal/central"
	"webscan/internal/common"
	"webscan/internal/notify"
)

type Notification struct {
	ID, Epoch                                int64
	Owner, Node, EventID, Channel, Recipient string
	Payload                                  json.RawMessage
	Attempts                                 int
	Settings                                 common.Map
	DeliveryKey                              string
	HostQuotaExpiresAt                       time.Time
}

// claimNotification reserves a persistent, channel-wide rate slot and one
// recipient. Disabled channels leave their queues untouched. Older pending
// notices for the same node/channel/recipient cannot be overtaken.
func (s *Store) claimNotification(ctx context.Context, channel, owner string) (*Notification, error) {
	if channel != "email" && channel != "feishu" || !identifier.MatchString(owner) {
		return nil, errors.New("通知通道或工作器标识不正确")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if held, e := migrationHeld(ctx, tx); e != nil {
		return nil, e
	} else if held {
		return nil, nil
	}
	var raw []byte
	var runtimeVersion int64
	if err = tx.QueryRowContext(ctx, "SELECT version,payload FROM v3_settings WHERE id=1 FOR SHARE").Scan(&runtimeVersion, &raw); err != nil {
		return nil, err
	}
	var settings common.Map
	if err = json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	c := common.M(settings[channel])
	if !common.B(c["enabled"]) {
		return nil, nil
	}
	reserved, err := channelRateSlotTx(ctx, tx, channel, settings)
	if err != nil || !reserved {
		return nil, err
	}
	n := &Notification{Owner: owner, Channel: channel, Settings: settings}
	err = tx.QueryRowContext(ctx, `SELECT id,node,event_id,recipient,payload,attempts,lease_epoch,delivery_key FROM v3_notifications n
	WHERE channel=$1 AND NOT migration_pending AND done_at IS NULL AND next_try<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp())
	AND NOT EXISTS(SELECT 1 FROM v3_migration_recovery_notices q WHERE q.notification=n.id AND q.identity_sha256=encode(sha256(convert_to(jsonb_build_array(n.node,n.event_id,n.channel,n.recipient,n.delivery_key,n.payload)::text,'UTF8')),'hex') AND q.resolution<>'verified_unsent')
	AND NOT EXISTS(SELECT 1 FROM v3_notifications older WHERE older.node=n.node AND older.channel=n.channel AND older.recipient=n.recipient AND older.id<n.id AND older.done_at IS NULL AND NOT EXISTS(SELECT 1 FROM v3_migration_recovery_notices q WHERE q.notification=older.id AND q.identity_sha256=encode(sha256(convert_to(jsonb_build_array(older.node,older.event_id,older.channel,older.recipient,older.delivery_key,older.payload)::text,'UTF8')),'hex') AND q.resolution<>'verified_unsent'))
	ORDER BY id FOR UPDATE OF n SKIP LOCKED LIMIT 1`, channel).Scan(&n.ID, &n.Node, &n.EventID, &n.Recipient, &n.Payload, &n.Attempts, &n.Epoch, &n.DeliveryKey)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.Epoch++
	if s.HostQuota != nil {
		grant, e := s.HostQuota.Reserve(ctx, channel, fmt.Sprintf("business:%d:%d:%s", n.ID, n.Epoch, token()), runtimeVersion)
		if e != nil {
			return nil, e
		}
		if !grant.New || !grant.ExpiresAt.After(time.Now()) {
			return nil, nil
		}
		n.HostQuotaExpiresAt = grant.ExpiresAt
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_notifications SET lease_owner=$2,lease_epoch=$3,lease_until=clock_timestamp()+interval '90 seconds' WHERE id=$1", n.ID, owner, n.Epoch); err != nil {
		return nil, err
	}
	return n, tx.Commit()
}

// channelRateSlotTx reserves the existing durable rate window. Callers commit
// the slot only together with a claimed business or test delivery.
func channelRateSlotTx(ctx context.Context, tx *sql.Tx, channel string, settings common.Map) (bool, error) {
	c := common.M(settings[channel])
	var raw []byte
	var err error
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_notification_rates VALUES($1,'[]') ON CONFLICT DO NOTHING", channel); err != nil {
		return false, err
	}
	var now float64
	if err = tx.QueryRowContext(ctx, "SELECT history,extract(epoch FROM clock_timestamp()) FROM v3_notification_rates WHERE channel=$1 FOR UPDATE", channel).Scan(&raw, &now); err != nil {
		return false, err
	}
	var previous []float64
	if err = json.Unmarshal(raw, &previous); err != nil {
		return false, err
	}
	history := []float64{}
	for _, v := range previous {
		if v > now-60 {
			history = append(history, v)
		}
	}
	perMinute := common.I(c["max_per_minute"])
	perSecond := 0.0
	if channel == "feishu" {
		rate := common.M(c["rate_limit"])
		perMinute, perSecond = common.I(rate["max_per_minute"]), common.F(rate["max_per_second"])
	}
	perMinute = min(600, max(1, perMinute))
	if len(history) >= perMinute || perSecond > 0 && len(history) > 0 && now-history[len(history)-1] < 1/perSecond {
		return false, nil
	}
	history = append(history, now)
	raw, err = json.Marshal(history)
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_notification_rates SET history=$2 WHERE channel=$1", channel, raw); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) finishNotification(ctx context.Context, n *Notification, failed bool) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result := "通知已提交"
	if failed {
		result = "通知投递失败，请检查通道配置或网络"
	}
	retry := common.M(common.M(n.Settings[n.Channel])["retry"])
	initial := max(1, min(86400, common.I(retry["initial_delay_seconds"])))
	maximum := max(initial, min(86400, common.I(retry["max_delay_seconds"])))
	delay := min(maximum, initial*(1<<min(n.Attempts, 16)))
	jitter := rand.Float64() * float64(delay) / 5
	res, err := tx.ExecContext(ctx, `UPDATE v3_notifications SET attempts=attempts+1,lease_until=NULL,lease_owner=NULL,result=$4,
	done_at=CASE WHEN $5 THEN NULL ELSE clock_timestamp() END,next_try=clock_timestamp()+($6::double precision*interval '1 second')
	WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() AND done_at IS NULL`, n.ID, n.Owner, n.Epoch, result, failed, float64(delay)+jitter)
	if err != nil {
		return err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrLeaseLost
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_notification_attempts(notification,epoch,success,result) VALUES($1,$2,$3,$4)", n.ID, n.Epoch, !failed, result); err != nil {
		return err
	}
	return tx.Commit()
}

type NotificationSender interface {
	Send(context.Context, *Notification) error
}

type ChannelSender struct{ HTTP *http.Client }

func (s ChannelSender) Send(ctx context.Context, n *Notification) error {
	if !n.HostQuotaExpiresAt.IsZero() && !n.HostQuotaExpiresAt.After(time.Now()) {
		return ErrHostQuota
	}
	var event common.Map
	if err := json.Unmarshal(n.Payload, &event); err != nil {
		return errors.New("通知内容无效")
	}
	message := common.S(event["message"])
	if message == "" {
		message = central.EventNotification(event)
	}
	c := common.M(n.Settings[n.Channel])
	if n.Channel == "email" {
		line, _, _ := strings.Cut(message, "\n")
		runes := []rune(line)
		if len(runes) > 80 {
			line = string(runes[:80])
		}
		key := n.DeliveryKey
		if key == "" {
			key = digest([]byte(fmt.Sprintf("%d:%s", n.ID, n.Recipient)))
		}
		return notify.Send(ctx, c, n.Recipient, key, "【网站监控】"+line, message)
	}
	if n.Channel != "feishu" {
		return errors.New("通知通道不支持")
	}
	client := s.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	status, response, err := common.Request(ctx, client, "POST", common.S(c["webhook_url"]), central.FeishuPayload(c, message, time.Now().Unix()), nil)
	if err != nil || status/100 != 2 {
		return errors.New("飞书通知传输失败")
	}
	m := common.M(response)
	code, ok := m["code"]
	if !ok {
		code, ok = m["StatusCode"]
	}
	if !ok || common.I(code) != 0 {
		return errors.New("飞书未确认接收通知")
	}
	return nil
}

type Notifier struct {
	Store    *Store
	Instance string
	Sender   NotificationSender
}

func (n *Notifier) Run(ctx context.Context) error {
	if n.Sender == nil {
		n.Sender = ChannelSender{}
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go func() { defer wg.Done(); n.runHealth(ctx) }()
	wg.Add(1)
	go func() { defer wg.Done(); n.runWebsites(ctx) }()
	for _, channel := range []string{"feishu", "email"} {
		wg.Add(1)
		go func(channel string) {
			defer wg.Done()
			var lastSendFailed bool
			for ctx.Err() == nil {
				op, cancel := context.WithTimeout(ctx, 5*time.Second)
				task, err := n.Store.claimNotification(op, channel, n.Instance)
				cancel()
				if err == nil {
					runtimeReady(ctx, "notify-"+channel)
				}
				n.notificationHeartbeat(ctx, channel, err != nil || lastSendFailed)
				if err != nil || task == nil {
					if !waitRetry(ctx, time.Second) {
						return
					}
					continue
				}
				op, cancel = context.WithTimeout(ctx, 60*time.Second)
				err = n.Sender.Send(op, task)
				cancel()
				if ctx.Err() != nil {
					return
				}
				op, cancel = context.WithTimeout(ctx, 5*time.Second)
				finished := n.Store.finishNotification(op, task, err != nil)
				cancel()
				lastSendFailed = err != nil || finished != nil
				n.notificationHeartbeat(ctx, channel, lastSendFailed)
				if finished != nil && !waitRetry(ctx, time.Second) {
					return
				}
			}
		}(channel)
	}
	<-ctx.Done()
	return ctx.Err()
}
