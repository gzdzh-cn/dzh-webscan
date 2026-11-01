package controlplane

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"webscan/internal/common"
	"webscan/internal/notify"
	"webscan/internal/persist"
)

type hostWatchdogService struct {
	store   *hostWatchdogStore
	pg      *sql.DB
	probe   hostWatchdogProbe
	sender  NotificationSender
	started time.Time
}

func runHostWatchdogCommand(ctx context.Context, o Options, out io.Writer) error {
	if hostWatchdogPlatform() != nil {
		return errHostWatchdog
	}
	raw, err := readTrustData(o.Source, true, 64<<10)
	var preliminary HostWatchdogSpec
	if err != nil || singleDecode(raw, &preliminary) != nil || validateHostSpec(preliminary) != nil {
		return errHostWatchdog
	}
	c, err := LoadConfig(preliminary.HostConfigFile)
	if err != nil {
		return errHostWatchdog
	}
	v, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return errHostWatchdog
	}
	spec, err := loadHostSpec(o.Source, v)
	if err != nil || spec.Instance != c.Central.Instance || spec.Socket != c.HostWatchdog.Socket || spec.StateDirectory != c.HostWatchdog.StateDirectory {
		return errHostWatchdog
	}
	for _, item := range []struct{ path, hash string }{{spec.InstallationFile, spec.InstallationSHA256}, {spec.HelperFile, spec.HelperSHA256}, {spec.HostConfigFile, spec.HostConfigSHA256}} {
		a, e := hashTrustArtifact(ctx, item.path, 256<<20)
		if e != nil || a.SHA256 != item.hash {
			return errHostWatchdog
		}
	}
	binary, e := os.Executable()
	if e != nil {
		return errHostWatchdog
	}
	actual, e := filepath.EvalSymlinks(binary)
	if e != nil || actual != spec.HelperFile {
		return errHostWatchdog
	}
	store, err := openHostWatchdogStore(spec, v)
	if err != nil {
		return err
	}
	defer store.db.Close()
	dsn, err := ReadSecret(c.Database.DSNFile)
	if err != nil {
		return errHostWatchdog
	}
	pg, err := sql.Open("pgx", dsn)
	if err != nil {
		return errHostWatchdog
	}
	defer pg.Close()
	pg.SetMaxOpenConns(2)
	service := &hostWatchdogService{store: store, pg: pg, probe: newHostWatchdogProbe(spec, pg), sender: ChannelSender{}, started: time.Now()}
	listener, cleanup, err := hostWatchdogListener(spec)
	if err != nil {
		return err
	}
	defer cleanup()
	local, cancel := context.WithCancel(ctx)
	defer cancel()
	srv := &http.Server{Handler: service, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 4 * time.Second, MaxHeaderBytes: 4096}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); service.run(local) }()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-done:
		cancel()
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	_ = srv.Shutdown(closeCtx)
	cancel()
	wg.Wait()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errHostWatchdog
	}
	return nil
}

func (s *hostWatchdogService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	var e hostRPCEnvelope
	if err != nil || len(raw) > 8192 || singleDecode(raw, &e) != nil || len(e.Nonce) != 64 || e.At < time.Now().Add(-30*time.Second).Unix() || e.At > time.Now().Add(30*time.Second).Unix() {
		w.WriteHeader(403)
		return
	}
	proof, err := hostRPCMAC(s.store.vault, r.URL.Path, e)
	if err != nil || !hmac.Equal([]byte(proof), []byte(e.MAC)) {
		w.WriteHeader(403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var value any
	switch r.URL.Path {
	case "/v1/quota":
		var in hostQuotaInput
		if singleDecode(e.Body, &in) != nil {
			err = ErrHostQuota
			break
		}
		value, err = s.store.reserve(ctx, in)
	case "/v1/settings/prepare":
		var in hostSettingsInput
		if singleDecode(e.Body, &in) != nil {
			err = ErrHostQuota
			break
		}
		value, err = s.store.prepare(ctx, s.pg, in)
	case "/v1/settings/resolve":
		var in struct {
			ID string `json:"id"`
		}
		if singleDecode(e.Body, &in) != nil {
			err = ErrHostQuota
			break
		}
		value, err = s.store.resolve(ctx, s.pg, in.ID)
	case "/v1/status":
		if singleDecode(e.Body, &struct{}{}) != nil {
			err = ErrHostQuota
			break
		}
		value, err = s.store.publicSnapshot(ctx)
	case "/v1/history":
		if singleDecode(e.Body, &struct{}{}) != nil {
			err = ErrHostQuota
			break
		}
		value, err = s.store.history(ctx)
	case "/v1/maintenance":
		var in hostWatchdogMaintenance
		if singleDecode(e.Body, &in) != nil {
			err = ErrHostQuota
			break
		}
		err = s.store.maintain(ctx, in)
		value = struct{}{}
	case "/v1/history/ack":
		var in struct {
			IDs []string `json:"ids"`
		}
		if singleDecode(e.Body, &in) != nil {
			err = ErrHostQuota
			break
		}
		err = s.store.ackHistory(ctx, in.IDs)
		value = struct{}{}
	default:
		w.WriteHeader(404)
		return
	}
	if err != nil {
		if err == ErrHostSettingsFrozen {
			w.WriteHeader(423)
		} else {
			w.WriteHeader(503)
		}
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}
func (s *hostWatchdogService) run(ctx context.Context) {
	for ctx.Err() == nil {
		op, cancel := context.WithTimeout(ctx, 2*time.Second)
		_ = s.store.initializeSettings(op, s.pg)
		cancel()
		op, cancel = context.WithTimeout(ctx, 2*time.Second)
		rows, err := s.store.db.QueryContext(op, `SELECT id FROM preparations WHERE state='frozen' ORDER BY created_at LIMIT 1`)
		if err == nil {
			ids := []string{}
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
			for _, id := range ids {
				_, _ = s.store.resolve(op, s.pg, id)
			}
		}
		cancel()
		op, cancel = context.WithTimeout(ctx, 8*time.Second)
		checks, environment := s.probe.Check(op)
		_ = s.store.recordSnapshot(op, checks, environment)
		if time.Since(s.started) >= 180*time.Second {
			for _, check := range checks {
				_ = s.store.transition(op, check)
			}
		}
		cancel()
		sendCtx, stop := context.WithTimeout(ctx, 20*time.Second)
		_ = s.sendOne(sendCtx)
		stop()
		if !waitRetry(ctx, 10*time.Second) {
			return
		}
	}
}
func (s *hostWatchdogStore) recordSnapshot(ctx context.Context, checks []HostWatchdogCheck, environment HostWatchdogEnvironment) error {
	raw, _ := json.Marshal(struct {
		At          time.Time               `json:"at"`
		Checks      []HostWatchdogCheck     `json:"checks"`
		Environment HostWatchdogEnvironment `json:"environment"`
	}{time.Now().UTC(), checks, environment})
	_, err := s.db.ExecContext(ctx, `INSERT INTO observations(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload`, raw)
	return err
}
func (s *hostWatchdogStore) publicSnapshot(ctx context.Context) (HostWatchdogStatus, error) {
	out, err := s.status(ctx)
	if err != nil {
		return out, err
	}
	var raw []byte
	if err = s.db.QueryRowContext(ctx, `SELECT payload FROM observations WHERE id=1`).Scan(&raw); err == sql.ErrNoRows {
		out.ObservedAt = time.Time{}
		return out, nil
	} else if err != nil {
		return out, err
	}
	var observation struct {
		At          time.Time               `json:"at"`
		Checks      []HostWatchdogCheck     `json:"checks"`
		Environment HostWatchdogEnvironment `json:"environment"`
	}
	if json.Unmarshal(raw, &observation) != nil {
		return out, errHostWatchdog
	}
	out.ObservedAt, out.Checks, out.Environment = observation.At, observation.Checks, observation.Environment
	return out, nil
}
func (s *hostWatchdogStore) transition(ctx context.Context, c HostWatchdogCheck) error {
	if !hostComponent(c.Component) || (c.State != "normal" && c.State != "abnormal") {
		return nil
	}
	tx, err := persist.BeginWrite(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var suppress bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM maintenance WHERE component=? AND expires_at>?)`, c.Component, time.Now().Unix()).Scan(&suppress); err != nil {
		return err
	}
	if suppress {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO components(component) VALUES(?)`, c.Component); err != nil {
		return err
	}
	var phase, incident string
	var failures, successes int
	if err = tx.QueryRowContext(ctx, `SELECT phase,incident,failures,successes FROM components WHERE component=?`, c.Component).Scan(&phase, &incident, &failures, &successes); err != nil {
		return err
	}
	next, notice := phase, ""
	if c.State == "normal" {
		successes++
		failures = 0
		if phase == "firing" && successes >= 2 {
			next, notice = "normal", "resolved"
		}
	} else {
		failures++
		successes = 0
		if phase != "firing" && failures >= 3 {
			next, notice, incident = "firing", "firing", token()
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE components SET phase=?,incident=?,failures=?,successes=?,observed_at=? WHERE component=?`, next, incident, failures, successes, time.Now().Unix(), c.Component); err != nil {
		return err
	}
	if notice != "" {
		version, raw, _, e := s.settings(ctx, tx)
		defer clear(raw)
		if e != nil {
			return e
		}
		var root common.Map
		if json.Unmarshal(raw, &root) != nil {
			return errHostWatchdog
		}
		category := "health_failures"
		if notice == "resolved" {
			category = "health_recoveries"
		}
		for _, channel := range []string{"email", "feishu"} {
			if !notify.Allows(root, channel, category) {
				continue
			}
			recipients := []string{""}
			if channel == "email" {
				recipients = nil
				for _, r := range common.A(common.M(root[channel])["recipients"]) {
					if a := common.S(r); a != "" {
						recipients = append(recipients, a)
					}
				}
			}
			for _, recipient := range recipients {
				id := digest([]byte(s.spec.InstallationSHA256 + ":" + incident + ":" + notice + ":" + channel + ":" + recipient))
				if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO outbox(id,component,phase,created_at,channel,recipient,version) VALUES(?,?,?,?,?,?,?)`, id, c.Component, notice, time.Now().Unix(), channel, recipient, version); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}
func hostComponent(c string) bool {
	return c == "api" || c == "postgres" || c == "metrics" || c == "storage"
}
func hostNoticeMessage(component, phase string) string {
	label := map[string]string{"api": "主控后台", "postgres": "业务数据库", "metrics": "指标存储", "storage": "宿主数据存储"}[component]
	if phase == "resolved" {
		return label + "已恢复，宿主看门狗已核验。"
	}
	return label + "持续异常，宿主看门狗已记录。"
}
func (s *hostWatchdogService) sendOne(ctx context.Context) error {
	var id, component, phase, channel, recipient string
	var version int64
	tx, err := persist.BeginWrite(ctx, s.store.db)
	if err != nil {
		return err
	}
	confirmedVersion, raw, frozen, err := s.store.settings(ctx, tx)
	tx.Rollback()
	defer clear(raw)
	if err != nil || frozen {
		return ErrHostSettingsFrozen
	}
	var root common.Map
	if json.Unmarshal(raw, &root) != nil {
		return errHostWatchdog
	}
	emailEnabled := common.B(common.M(root["email"])["enabled"])
	feishuEnabled := common.B(common.M(root["feishu"])["enabled"])
	if err := s.store.db.QueryRowContext(ctx, `SELECT id,component,phase,channel,recipient FROM outbox WHERE state='queued' AND ((channel='email' AND ?) OR (channel='feishu' AND ?)) ORDER BY created_at,id LIMIT 1`, emailEnabled, feishuEnabled).Scan(&id, &component, &phase, &channel, &recipient); err == sql.ErrNoRows {
		return nil
	} else if err != nil {
		return err
	}
	// Old queued incidents use the current confirmed channel configuration, but
	// retain their original recipient. Turning a channel off pauses the queue.
	version = confirmedVersion
	grant, err := s.store.reserve(ctx, hostQuotaInput{channel, "watchdog:" + id, version})
	if err != nil {
		return err
	}
	if !grant.New {
		if grant.ID == "" {
			return nil
		}
		// A previously consumed reservation with no durable send evidence cannot
		// be treated as permission to send again after a crash or lost reply.
		tx, err := persist.BeginWrite(ctx, s.store.db)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		res, err := tx.ExecContext(ctx, `UPDATE outbox SET state='unknown',attempts=attempts+1 WHERE id=? AND state='queued'`, id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 1 {
			_, err = tx.ExecContext(ctx, `INSERT INTO attempts(id,outbox,state,created_at,finished_at) VALUES(?,?,'unknown',?,?)`, token(), id, time.Now().Unix(), time.Now().Unix())
			if err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	attempt := token()
	tx, err = persist.BeginWrite(ctx, s.store.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE outbox SET state='sending',attempts=attempts+1 WHERE id=? AND state='queued'`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO attempts(id,outbox,state,created_at) VALUES(?,?,'sending',?)`, attempt, id, time.Now().Unix()); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	notice := &Notification{Node: "central", EventID: "host-watchdog:" + id, Channel: channel, Recipient: recipient, Settings: root, Payload: common.JSON(common.Map{"message": hostNoticeMessage(component, phase)}), DeliveryKey: "host-watchdog:" + id, HostQuotaExpiresAt: grant.ExpiresAt}
	sendErr := s.sender.Send(ctx, notice)
	state := "accepted"
	if sendErr != nil {
		state = "unknown"
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	finish, err := persist.BeginWrite(finishCtx, s.store.db)
	if err != nil {
		return err
	}
	defer finish.Rollback()
	if _, err = finish.ExecContext(finishCtx, `UPDATE attempts SET state=?,finished_at=? WHERE id=? AND state='sending'`, state, time.Now().Unix(), attempt); err != nil {
		return err
	}
	if _, err = finish.ExecContext(finishCtx, `UPDATE outbox SET state=? WHERE id=? AND state='sending'`, state, id); err != nil {
		return err
	}
	return finish.Commit()
}
