package controlplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type notificationTestSender struct {
	mu      sync.Mutex
	calls   []*Notification
	err     error
	entered chan struct{}
	release chan struct{}
}

func (s *notificationTestSender) Send(ctx context.Context, n *Notification) error {
	s.mu.Lock()
	s.calls = append(s.calls, n)
	err := s.err
	s.mu.Unlock()
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}
func (s *notificationTestSender) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.calls) }
func TestNotificationTestSingleAttemptAcceptedAndUnknown(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "accepted"
		if failed {
			name = "response-loss"
		}
		t.Run(name, func(t *testing.T) {
			f := newNotificationTestFixture(t)
			j := f.submit(t, f.preview(t, "email"))
			sender := &notificationTestSender{}
			if failed {
				sender.err = errors.New("PRIVATE SMTP credential and server response")
			}
			f.worker.Sender = sender
			for i := 0; i < 4; i++ {
				if e := f.worker.RunRound(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			got := f.job(t, j.ID)
			want := "succeeded"
			state := "accepted"
			if failed {
				want, state = "unknown", "unknown"
			}
			if got.Status != want || sender.count() != 2 {
				t.Fatal("delivery duplicated or wrong outcome", got, sender.count())
			}
			for _, item := range got.Items {
				if item.State != state || strings.Contains(item.Message, "PRIVATE") {
					t.Fatal(item)
				}
			}
			sender.mu.Lock()
			defer sender.mu.Unlock()
			for i, n := range sender.calls {
				wantKey := digest([]byte("notification-test:" + j.ID + ":" + string(rune('1'+i))))
				if n.DeliveryKey != wantKey || !strings.Contains(string(n.Payload), "管理员主动发送") {
					t.Fatal("unstable sender content/key")
				}
			}
		})
	}
}
func TestNotificationTestLostSendingLeaseBecomesUnknownWithoutResend(t *testing.T) {
	f := newNotificationTestFixture(t)
	j := f.submit(t, f.preview(t, "feishu"))
	a, e := f.worker.claim(context.Background())
	if e != nil || a == nil {
		t.Fatal(e)
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_notification_test_deliveries SET lease_until=clock_timestamp()-interval '1 second' WHERE job=$1`, j.ID)
	sender := &notificationTestSender{}
	replacement := &NotificationTestWorker{Store: f.s, Vault: f.vault, Instance: "replacement", Sender: sender}
	if e = replacement.RunRound(context.Background()); e != nil {
		t.Fatal(e)
	}
	got := f.job(t, j.ID)
	if got.Status != "unknown" || sender.count() != 0 {
		t.Fatal("unknown delivery retried", got)
	}
	if e = f.worker.finish(context.Background(), a, true); !errors.Is(e, ErrLeaseLost) {
		t.Fatal("stale response accepted", e)
	}
}
func TestNotificationTestChangesCancelOnlyQueuedTargets(t *testing.T) {
	for _, change := range []string{`UPDATE v3_settings SET version=version+1`, `UPDATE v3_accounts SET revision=revision+1 WHERE username='admin'`, `UPDATE v3_accounts SET role='viewer' WHERE username='admin'`, `UPDATE v3_notification_test_jobs SET proof=repeat('0',64)`} {
		t.Run(change, func(t *testing.T) {
			f := newNotificationTestFixture(t)
			j := f.submit(t, f.preview(t, "email"))
			a, e := f.worker.claim(context.Background())
			if e != nil || a == nil {
				t.Fatal(e)
			}
			mustHistoryExec(t, f.s.DB, change)
			if e = f.worker.RunRound(context.Background()); e != nil {
				t.Fatal(e)
			}
			if e = f.worker.finish(context.Background(), a, true); e != nil {
				t.Fatal("known response discarded after authorization change", e)
			}
			// Direct owner query: an account demoted during sending cannot make API reads.
			tx, e := f.s.DB.Begin()
			if e != nil {
				t.Fatal(e)
			}
			got, e := notificationTestJobTx(context.Background(), tx, "admin", j.ID)
			tx.Rollback()
			if e != nil {
				t.Fatal(e)
			}
			if got.Status != "partial" || got.Items[0].State != "accepted" || got.Items[1].State != "cancelled" {
				t.Fatal("changed authorization sent queued target", got)
			}
		})
	}
}
func TestNotificationTestSharesBusinessRateAndDoesNotBlockOtherChannel(t *testing.T) {
	f := newNotificationTestFixture(t)
	ctx := context.Background()
	mustHistoryExec(t, f.s.DB, `UPDATE v3_settings SET payload=jsonb_set(payload,'{email,max_per_minute}','1')`)
	j := f.submit(t, f.preview(t, "email"))
	other := f.submit(t, f.preview(t, "feishu"))
	enqueueNotification(t, f.s, "synthetic", "business-rate", "email", "synthetic@example.test")
	b, e := f.s.claimNotification(ctx, "email", "business")
	if e != nil || b == nil {
		t.Fatal(e)
	}
	sender := &notificationTestSender{}
	f.worker.Sender = sender
	if e = f.worker.RunRound(ctx); e != nil {
		t.Fatal(e)
	}
	if f.job(t, j.ID).Status != "queued" || f.job(t, other.ID).Status != "succeeded" || sender.count() != 1 {
		t.Fatal("blocked channel starved independent channel")
	}
	mustHistoryExec(t, f.s.DB, `UPDATE v3_notification_rates SET history='[]' WHERE channel='email'`)
	if e = f.worker.RunRound(ctx); e != nil {
		t.Fatal(e)
	}
	enqueueNotification(t, f.s, "synthetic", "business-after-test", "email", "another@example.test")
	if n, e := f.s.claimNotification(ctx, "email", "business"); e != nil || n != nil {
		t.Fatal("business bypassed test rate slot", e)
	}
}
func TestNotificationTestRestoreRevokesUnsentWithoutLosingAccepted(t *testing.T) {
	f := newNotificationTestFixture(t)
	ctx := context.Background()
	j := f.submit(t, f.preview(t, "email"))
	a, e := f.worker.claim(ctx)
	if e != nil || a == nil {
		t.Fatal(e)
	}
	if e = f.worker.finish(ctx, a, true); e != nil {
		t.Fatal(e)
	}
	other := f.submit(t, f.preview(t, "feishu"))
	if a, e = f.worker.claimJob(ctx, other.ID); e != nil || a == nil {
		t.Fatal(e)
	}
	unused := f.preview(t, "email")
	tx, e := f.s.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	if e = quarantineNotificationTestsTx(ctx, tx); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	got := f.job(t, j.ID)
	if got.Items[0].State != "accepted" || got.Items[1].State != "cancelled" || got.Status != "partial" {
		t.Fatal("restore lost known response or retained authorization", got)
	}
	if f.job(t, other.ID).Status != "unknown" {
		t.Fatal("restore resurrected in-flight send")
	}
	if _, e = f.s.submitNotificationTest(ctx, f.vault, "admin", "restore-confirm", unused.Token, true); !errors.Is(e, errNotificationTestPreview) {
		t.Fatal("restore retained preview authorization", e)
	}
	sender := &notificationTestSender{}
	f.worker.Sender = sender
	if e = f.worker.RunRound(ctx); e != nil || sender.count() != 0 {
		t.Fatal("restore sent notification", e)
	}
}
func TestNotificationTestWorkerHeartbeatRemainsLiveDuringSlowSend(t *testing.T) {
	f := newNotificationTestFixture(t)
	f.submit(t, f.preview(t, "feishu"))
	sender := &notificationTestSender{entered: make(chan struct{}, 1), release: make(chan struct{})}
	f.worker.Sender = sender
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.worker.Run(ctx) }()
	defer func() {
		cancel()
		close(sender.release)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("worker did not stop")
		}
	}()
	select {
	case <-sender.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not start")
	}
	api := NewAPI(f.s, Config{})
	api.Config.DeploymentTrust.VaultKeyFile = f.vaultPath
	readyDeadline := time.Now().Add(5 * time.Second)
	for !api.notificationTestAvailability(context.Background()).Available {
		if time.Now().After(readyDeadline) {
			t.Fatal("initial heartbeat missing")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Replace the heartbeat timestamp to prove the ticker refreshes it while send is blocked.
	mustHistoryExec(t, f.s.DB, `UPDATE v3_role_status SET heartbeat=clock_timestamp()-interval '1 minute' WHERE role='notification-tests'`)
	if api.notificationTestAvailability(context.Background()).Available {
		t.Fatal("stale heartbeat still available")
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if api.notificationTestAvailability(context.Background()).Available {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("slow send made test worker appear unavailable")
}

func TestNotificationTestConcurrentWorkersNeverResendRecipients(t *testing.T) {
	f := newNotificationTestFixture(t)
	j := f.submit(t, f.preview(t, "email"))
	sender := &notificationTestSender{}
	var wg sync.WaitGroup
	for _, instance := range []string{"test-one", "test-two", "test-three", "test-four"} {
		wg.Add(1)
		go func(instance string) {
			defer wg.Done()
			w := &NotificationTestWorker{Store: f.s, Vault: f.vault, Instance: instance, Sender: sender}
			for i := 0; i < 3; i++ {
				if e := w.RunRound(context.Background()); e != nil {
					t.Error(e)
					return
				}
			}
		}(instance)
	}
	wg.Wait()
	if sender.count() != 2 || f.job(t, j.ID).Status != "succeeded" {
		t.Fatal("concurrent workers duplicated targets", sender.count())
	}
}

type notificationTestTransport struct {
	target    *url.URL
	transport http.RoundTripper
}

func (t notificationTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "open.feishu.cn" {
		return nil, errors.New("unexpected transport target")
	}
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.target.Scheme
	u.Host = t.target.Host
	clone.URL = &u
	clone.Host = t.target.Host
	return t.transport.RoundTrip(clone)
}
func TestNotificationTestActualChannelSenderUsesIsolatedVerifiedTLS(t *testing.T) {
	for _, response := range []string{`{"code":0}`, `{"code":1,"msg":"PRIVATE webhook provider failure"}`} {
		t.Run(response, func(t *testing.T) {
			f := newNotificationTestFixture(t)
			j := f.submit(t, f.preview(t, "feishu"))
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				raw, _ := io.ReadAll(r.Body)
				if r.Method != "POST" || !strings.Contains(string(raw), "管理员主动发送") {
					t.Error("incorrect fixed test body")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, response)
			}))
			defer server.Close()
			target, e := url.Parse(server.URL)
			if e != nil {
				t.Fatal(e)
			}
			client := server.Client()
			client.Transport = notificationTestTransport{target: target, transport: client.Transport}
			f.worker.Sender = ChannelSender{HTTP: client}
			for i := 0; i < 2; i++ {
				if e = f.worker.RunRound(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			got := f.job(t, j.ID)
			want := "succeeded"
			if strings.Contains(response, `"code":1`) {
				want = "unknown"
			}
			if got.Status != want || calls != 1 || strings.Contains(got.Message, "PRIVATE") {
				t.Fatal("unverified response or auto retry", got, calls)
			}
		})
	}
}

func TestNotificationTestWorkerFailureRemainsUnavailableAcrossHeartbeats(t *testing.T) {
	f := newNotificationTestFixture(t)
	f.submit(t, f.preview(t, "email"))
	mustHistoryExec(t, f.s.DB, `INSERT INTO v3_notification_rates(channel,history) VALUES('email','{"invalid":"rate window"}')`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.worker.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("worker did not stop")
		}
	}()
	api := NewAPI(f.s, Config{})
	api.Config.DeploymentTrust.VaultKeyFile = f.vaultPath
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var failed bool
		_ = f.s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM v3_role_status WHERE role='notification-tests' AND error<>'')`).Scan(&failed)
		if failed {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(5200 * time.Millisecond)
	if api.notificationTestAvailability(context.Background()).Available {
		t.Fatal("heartbeat concealed persistent worker error")
	}
}
