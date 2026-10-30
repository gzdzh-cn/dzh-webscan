package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func notificationSettings(t *testing.T, s *Store) {
	t.Helper()
	_, err := s.DB.Exec(`UPDATE v3_settings SET payload='{"feishu":{"enabled":true,"rate_limit":{"max_per_minute":600,"max_per_second":10000},"retry":{"initial_delay_seconds":2,"max_delay_seconds":60}},"email":{"enabled":true,"max_per_minute":600,"retry":{"initial_delay_seconds":2,"max_delay_seconds":60}}}'`)
	if err != nil {
		t.Fatal(err)
	}
}

func enqueueNotification(t *testing.T, s *Store, node, event, channel, recipient string) {
	t.Helper()
	_, err := s.DB.Exec("INSERT INTO v3_notifications(node,event_id,channel,recipient,payload) VALUES($1,$2,$3,$4,$5)", node, event, channel, recipient, `{"message":"隔离测试，不发送真实通知"}`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNotificationChannelsRetryAndOrderingAreIndependent(t *testing.T) {
	s := testStore(t)
	notificationSettings(t, s)
	ctx := context.Background()
	enqueueNotification(t, s, "a", "failure", "feishu", "")
	enqueueNotification(t, s, "a", "recovery", "feishu", "")
	enqueueNotification(t, s, "a", "failure", "email", "test@example.test")
	first, err := s.claimNotification(ctx, "feishu", "one")
	if err != nil || first == nil || first.EventID != "failure" {
		t.Fatal(first, err)
	}
	blocked, err := s.claimNotification(ctx, "feishu", "two")
	if err != nil || blocked != nil {
		t.Fatal("recovery overtook failure", blocked, err)
	}
	mail, err := s.claimNotification(ctx, "email", "two")
	if err != nil || mail == nil {
		t.Fatal(mail, err)
	}
	if err = s.finishNotification(ctx, mail, false); err != nil {
		t.Fatal(err)
	}
	if err = s.finishNotification(ctx, first, true); err != nil {
		t.Fatal(err)
	}
	blocked, err = s.claimNotification(ctx, "feishu", "two")
	if err != nil || blocked != nil {
		t.Fatal("retry delay ignored", blocked, err)
	}
	if _, err = s.DB.Exec("UPDATE v3_notifications SET next_try=clock_timestamp()-interval '1 second' WHERE id=$1", first.ID); err != nil {
		t.Fatal(err)
	}
	next, err := s.claimNotification(ctx, "feishu", "two")
	if err != nil || next == nil || next.ID != first.ID || next.Epoch <= first.Epoch {
		t.Fatal(next, err)
	}
	if err = s.finishNotification(ctx, first, false); !errors.Is(err, ErrLeaseLost) {
		t.Fatal("stale completion accepted", err)
	}
	if err = s.finishNotification(ctx, next, false); err != nil {
		t.Fatal(err)
	}
	recovery, err := s.claimNotification(ctx, "feishu", "three")
	if err != nil || recovery == nil || recovery.EventID != "recovery" {
		t.Fatal(recovery, err)
	}
	var attempts int
	if err = s.DB.QueryRow("SELECT count(*) FROM v3_notification_attempts WHERE notification=$1", first.ID).Scan(&attempts); err != nil || attempts != 2 {
		t.Fatal(attempts, err)
	}
}

func TestNotificationPauseRateAndLeaseSurviveWorkerReplacement(t *testing.T) {
	s := testStore(t)
	notificationSettings(t, s)
	ctx := context.Background()
	enqueueNotification(t, s, "a", "one", "email", "test@example.test")
	if _, err := s.DB.Exec(`UPDATE v3_settings SET payload=jsonb_set(payload,'{email,enabled}','false')`); err != nil {
		t.Fatal(err)
	}
	task, err := s.claimNotification(ctx, "email", "one")
	if err != nil || task != nil {
		t.Fatal("disabled channel sent", task, err)
	}
	if _, err = s.DB.Exec(`UPDATE v3_settings SET payload=jsonb_set(payload,'{email,enabled}','true')`); err != nil {
		t.Fatal(err)
	}
	task, err = s.claimNotification(ctx, "email", "one")
	if err != nil || task == nil {
		t.Fatal(task, err)
	}
	// A replacement must wait for the old task lease, then use a new epoch.
	blocked, err := s.claimNotification(ctx, "email", "replacement")
	if err != nil || blocked != nil {
		t.Fatal(blocked, err)
	}
	if _, err = s.DB.Exec("UPDATE v3_notifications SET lease_until=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	replacement, err := s.claimNotification(ctx, "email", "replacement")
	if err != nil || replacement == nil || replacement.Epoch <= task.Epoch {
		t.Fatal(replacement, err)
	}
	if err = s.finishNotification(ctx, task, false); !errors.Is(err, ErrLeaseLost) {
		t.Fatal(err)
	}
	if err = s.finishNotification(ctx, replacement, false); err != nil {
		t.Fatal(err)
	}
	enqueueNotification(t, s, "b", "two", "email", "test@example.test")
	if _, err = s.DB.Exec(`UPDATE v3_settings SET payload=jsonb_set(payload,'{email,max_per_minute}','1')`); err != nil {
		t.Fatal(err)
	}
	blocked, err = s.claimNotification(ctx, "email", "third")
	if err != nil || blocked != nil {
		t.Fatal("persisted rate slot lost on restart", blocked, err)
	}
	if _, err = s.DB.Exec("UPDATE v3_notification_rates SET history='[]'"); err != nil {
		t.Fatal(err)
	}
	if task, err = s.claimNotification(ctx, "email", "third"); err != nil || task == nil {
		t.Fatal(task, err)
	}
}

type fakeNotificationSender struct{}

func (fakeNotificationSender) Send(ctx context.Context, n *Notification) error {
	if n.Channel == "feishu" {
		return errors.New("simulated secret that must never appear in persistent results")
	}
	return nil
}

func TestNotifierWorkerDoesNotLetOneFailedChannelStopTheOther(t *testing.T) {
	s := testStore(t)
	notificationSettings(t, s)
	enqueueNotification(t, s, "a", "one", "feishu", "")
	enqueueNotification(t, s, "a", "one", "email", "test@example.test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n := &Notifier{Store: s, Instance: "test", Sender: fakeNotificationSender{}}
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	for {
		var completed, retried int
		err := s.DB.QueryRow("SELECT count(*) FILTER(WHERE channel='email' AND done_at IS NOT NULL),count(*) FILTER(WHERE channel='feishu' AND done_at IS NULL AND attempts>0) FROM v3_notifications").Scan(&completed, &retried)
		if err != nil {
			t.Fatal(err)
		}
		if completed == 1 && retried == 1 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("workers did not finish", ctx.Err())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	var leaked int
	if err := s.DB.QueryRow("SELECT count(*) FROM v3_notification_attempts WHERE result LIKE '%simulated secret%'").Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal(leaked, err)
	}
}
