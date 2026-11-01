package controlplane

import (
	"context"
	"database/sql"
	"strconv"
	"time"
	"webscan/internal/persist"
)

type hostPGSettings struct {
	Identity string
	Version  int64
	Raw      []byte
}

func hostDatabaseIdentity(database, cluster string) string {
	return digest([]byte(database + "\x00" + cluster))
}
func readHostPGSettings(ctx context.Context, db *sql.DB) (hostPGSettings, error) {
	var out hostPGSettings
	var database, cluster string
	err := db.QueryRowContext(ctx, `SELECT current_database(),(SELECT payload::text FROM v3_cluster WHERE id=1),version,payload::text FROM v3_settings WHERE id=1`).Scan(&database, &cluster, &out.Version, &out.Raw)
	if err != nil {
		return out, err
	}
	out.Identity = hostDatabaseIdentity(database, cluster)
	return out, nil
}
func (s *hostWatchdogStore) activateTx(ctx context.Context, tx *persist.WriteTx, p hostPGSettings) error {
	key, nonce, sealed, err := s.sealSettings(p.Version, p.Raw)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE host_state SET database_identity=?,version=?,digest=?,key_id=?,nonce=?,ciphertext=?,frozen=0,reason='' WHERE id=1`, p.Identity, p.Version, digest(p.Raw), key, nonce, sealed)
	return err
}
func (s *hostWatchdogStore) initializeSettings(ctx context.Context, db *sql.DB) error {
	var cached int64
	if e := s.db.QueryRowContext(ctx, `SELECT version FROM host_state WHERE id=1`).Scan(&cached); e != nil {
		return e
	} else if cached > 0 {
		return nil
	}
	// A PG shared row lock closes the initial cache/apply race.
	pg, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer pg.Rollback()
	var p hostPGSettings
	var database, cluster string
	err = pg.QueryRowContext(ctx, `SELECT current_database(),(SELECT payload::text FROM v3_cluster WHERE id=1),version,payload::text FROM v3_settings WHERE id=1 FOR SHARE`).Scan(&database, &cluster, &p.Version, &p.Raw)
	defer clear(p.Raw)
	if err != nil {
		return err
	}
	p.Identity = hostDatabaseIdentity(database, cluster)
	tx, err := persist.BeginWrite(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int64
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT version,(SELECT count(*) FROM preparations WHERE state='frozen') FROM host_state WHERE id=1`).Scan(&version, &pending); err != nil {
		return err
	}
	if version > 0 || pending > 0 {
		return nil
	}
	if err = s.activateTx(ctx, tx, p); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return pg.Commit()
}
func (s *hostWatchdogStore) prepare(ctx context.Context, db *sql.DB, in hostSettingsInput) (HostSettingsPreparation, error) {
	out := HostSettingsPreparation{ID: in.ID, TransactionID: in.TransactionID, BaseVersion: in.BaseVersion, TargetVersion: in.TargetVersion}
	xid, err := strconv.ParseUint(in.TransactionID, 10, 64)
	if err != nil || xid < 1 || strconv.FormatUint(xid, 10) != in.TransactionID || !validArchiveSource(in.ID) || in.BaseVersion < 1 || in.TargetVersion != in.BaseVersion+1 {
		return out, ErrHostQuota
	}
	p, err := readHostPGSettings(ctx, db)
	defer clear(p.Raw)
	if err != nil || p.Identity != in.DatabaseIdentity || p.Version != in.BaseVersion || digest(p.Raw) != in.BaseDigest {
		return out, ErrHostQuota
	}
	var status sql.NullString
	if err = db.QueryRowContext(ctx, `SELECT pg_xact_status($1::xid8)`, in.TransactionID).Scan(&status); err != nil || !status.Valid || status.String != "in progress" {
		return out, ErrHostQuota
	}
	tx, err := persist.BeginWrite(ctx, s.db)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var version int64
	var frozen bool
	var hash, identity string
	if err = tx.QueryRowContext(ctx, `SELECT version,frozen,digest,database_identity FROM host_state WHERE id=1`).Scan(&version, &frozen, &hash, &identity); err != nil {
		return out, err
	}
	var prior hostSettingsInput
	if e := tx.QueryRowContext(ctx, `SELECT txid,database_identity,base_digest,base_version,target_version FROM preparations WHERE id=?`, in.ID).Scan(&prior.TransactionID, &prior.DatabaseIdentity, &prior.BaseDigest, &prior.BaseVersion, &prior.TargetVersion); e == nil {
		if prior.TransactionID != in.TransactionID || prior.DatabaseIdentity != in.DatabaseIdentity || prior.BaseDigest != in.BaseDigest || prior.BaseVersion != in.BaseVersion || prior.TargetVersion != in.TargetVersion {
			return out, ErrHostQuota
		}
		return out, tx.Commit()
	} else if e != sql.ErrNoRows {
		return out, e
	}
	if frozen || version != in.BaseVersion || hash != in.BaseDigest || identity != in.DatabaseIdentity {
		return out, ErrHostSettingsFrozen
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO preparations(id,txid,database_identity,base_digest,base_version,target_version,created_at) VALUES(?,?,?,?,?,?,?)`, in.ID, in.TransactionID, in.DatabaseIdentity, in.BaseDigest, in.BaseVersion, in.TargetVersion, time.Now().Unix()); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE host_state SET frozen=1,reason='settings_transaction_pending' WHERE id=1`); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *hostWatchdogStore) resolve(ctx context.Context, db *sql.DB, id string) (HostSettingsResolution, error) {
	out := HostSettingsResolution{State: "unknown"}
	var in hostSettingsInput
	var state string
	err := s.db.QueryRowContext(ctx, `SELECT txid,database_identity,base_digest,base_version,target_version,state FROM preparations WHERE id=?`, id).Scan(&in.TransactionID, &in.DatabaseIdentity, &in.BaseDigest, &in.BaseVersion, &in.TargetVersion, &state)
	if err != nil {
		return out, err
	}
	if state != "frozen" {
		out.State = state
		_ = s.db.QueryRowContext(ctx, `SELECT version FROM host_state WHERE id=1`).Scan(&out.RuntimeVersion)
		return out, nil
	}
	var status sql.NullString
	if err = db.QueryRowContext(ctx, `SELECT pg_xact_status($1::xid8)`, in.TransactionID).Scan(&status); err != nil || !status.Valid {
		return out, ErrHostSettingsFrozen
	}
	if status.String == "in progress" {
		out.State = "frozen"
		return out, nil
	}
	pg, err := db.BeginTx(ctx, nil)
	if err != nil {
		return out, ErrHostSettingsFrozen
	}
	defer pg.Rollback()
	var p hostPGSettings
	var database, cluster string
	err = pg.QueryRowContext(ctx, `SELECT current_database(),(SELECT payload::text FROM v3_cluster WHERE id=1),version,payload::text FROM v3_settings WHERE id=1 FOR SHARE`).Scan(&database, &cluster, &p.Version, &p.Raw)
	defer clear(p.Raw)
	p.Identity = hostDatabaseIdentity(database, cluster)
	if err != nil || p.Identity != in.DatabaseIdentity {
		return out, ErrHostSettingsFrozen
	}
	switch status.String {
	case "committed":
		if p.Version != in.TargetVersion {
			return out, ErrHostSettingsFrozen
		}
		out.State = "committed"
	case "aborted":
		if p.Version != in.BaseVersion || digest(p.Raw) != in.BaseDigest {
			return out, ErrHostSettingsFrozen
		}
		out.State = "aborted"
	default:
		return out, ErrHostSettingsFrozen
	}
	tx, err := persist.BeginWrite(ctx, s.db)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var current string
	if err = tx.QueryRowContext(ctx, `SELECT state FROM preparations WHERE id=?`, id).Scan(&current); err != nil {
		return out, err
	}
	if current == "frozen" {
		if err = s.activateTx(ctx, tx, p); err != nil {
			return out, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE preparations SET state=? WHERE id=? AND state='frozen'`, out.State, id); err != nil {
			return out, err
		}
	}
	out.RuntimeVersion = p.Version
	return out, tx.Commit()
}
func prepareSettingsFromConfigTx(ctx context.Context, tx *sql.Tx, c Config, base, target int64) (HostSettingsPreparation, error) {
	client, err := newHostQuotaClient(c)
	if err != nil {
		return HostSettingsPreparation{}, err
	}
	if client == nil {
		return HostSettingsPreparation{}, nil
	}
	return client.PrepareSettings(ctx, tx, base, target)
}

// Maintenance affects only one named center component and always expires.
// It suppresses transitions, never rewrites the observed health evidence.
func (s *hostWatchdogStore) maintain(ctx context.Context, in hostWatchdogMaintenance) error {
	if !validArchiveSource(in.Operation) || !hostComponent(in.Component) {
		return errHostWatchdog
	}
	now := time.Now().UTC()
	if !in.ExpiresAt.IsZero() && (in.ExpiresAt.Before(now) || in.ExpiresAt.After(now.Add(15*time.Minute))) {
		return errHostWatchdog
	}
	tx, err := persist.BeginWrite(ctx, s.db)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM maintenance WHERE expires_at<=?`, now.Unix()); err != nil {
		return err
	}
	if in.ExpiresAt.IsZero() {
		_, err = tx.ExecContext(ctx, `DELETE FROM maintenance WHERE operation=? AND component=?`, in.Operation, in.Component)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO maintenance(operation,component,expires_at) VALUES(?,?,?) ON CONFLICT(operation,component) DO UPDATE SET expires_at=excluded.expires_at`, in.Operation, in.Component, in.ExpiresAt.Unix())
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (c *HostQuotaClient) BeginMaintenance(ctx context.Context, operation, component string, duration time.Duration) error {
	if duration <= 0 || duration > 15*time.Minute {
		return errHostWatchdog
	}
	return c.call(ctx, "/v1/maintenance", hostWatchdogMaintenance{operation, component, time.Now().UTC().Add(duration)}, &struct{}{})
}
func (c *HostQuotaClient) EndMaintenance(ctx context.Context, operation, component string) error {
	return c.call(ctx, "/v1/maintenance", hostWatchdogMaintenance{Operation: operation, Component: component}, &struct{}{})
}
