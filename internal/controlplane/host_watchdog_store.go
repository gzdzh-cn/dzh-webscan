package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"webscan/internal/persist"
)

const hostWatchdogSchema = `
CREATE TABLE IF NOT EXISTS host_state(id INTEGER PRIMARY KEY CHECK(id=1),instance TEXT NOT NULL,installation TEXT NOT NULL,database_identity TEXT NOT NULL DEFAULT '',version INTEGER NOT NULL DEFAULT 0,digest TEXT NOT NULL DEFAULT '',key_id TEXT NOT NULL DEFAULT '',nonce BLOB,ciphertext BLOB,frozen INTEGER NOT NULL DEFAULT 1,reason TEXT NOT NULL DEFAULT 'awaiting_configuration',last_clock REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS preparations(id TEXT PRIMARY KEY,txid TEXT NOT NULL,database_identity TEXT NOT NULL,base_digest TEXT NOT NULL,base_version INTEGER NOT NULL,target_version INTEGER NOT NULL,state TEXT NOT NULL DEFAULT 'frozen',created_at INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS preparations_active ON preparations((1)) WHERE state='frozen';
CREATE TABLE IF NOT EXISTS quota(id TEXT PRIMARY KEY,channel TEXT NOT NULL,attempt_key TEXT NOT NULL,version INTEGER NOT NULL,at REAL NOT NULL,UNIQUE(channel,attempt_key));
CREATE INDEX IF NOT EXISTS quota_window ON quota(channel,at);
CREATE TABLE IF NOT EXISTS components(component TEXT PRIMARY KEY,phase TEXT NOT NULL DEFAULT 'normal',incident TEXT NOT NULL DEFAULT '',failures INTEGER NOT NULL DEFAULT 0,successes INTEGER NOT NULL DEFAULT 0,observed_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,component TEXT NOT NULL,phase TEXT NOT NULL,created_at INTEGER NOT NULL,channel TEXT NOT NULL,recipient TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'queued',attempts INTEGER NOT NULL DEFAULT 0,next_try INTEGER NOT NULL DEFAULT 0,version INTEGER NOT NULL,imported INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY CHECK(id=1),payload BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,outbox TEXT NOT NULL REFERENCES outbox(id),state TEXT NOT NULL CHECK(state IN ('sending','accepted','unknown')),created_at INTEGER NOT NULL,finished_at INTEGER);
CREATE TABLE IF NOT EXISTS maintenance(operation TEXT NOT NULL,component TEXT NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(operation,component));
PRAGMA user_version=1;`

type hostWatchdogStore struct {
	db    *sql.DB
	vault *Vault
	spec  HostWatchdogSpec
}

func openHostWatchdogStore(spec HostWatchdogSpec, v *Vault) (*hostWatchdogStore, error) {
	if !snapshotAbsolutePath(spec.StateDirectory) || v == nil {
		return nil, errHostWatchdog
	}
	if err := os.MkdirAll(spec.StateDirectory, 0700); err != nil {
		return nil, errHostWatchdog
	}
	dir, err := trustDirectory(spec.StateDirectory, true)
	if err != nil {
		return nil, errHostWatchdog
	}
	dir.Close()
	file := filepath.Join(spec.StateDirectory, "watchdog.sqlite3")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if st, e := os.Lstat(file + suffix); e == nil {
			if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !snapshotOwned(st) {
				return nil, errHostWatchdog
			}
		} else if !os.IsNotExist(e) {
			return nil, errHostWatchdog
		}
	}
	db, err := persist.OpenDB(file)
	if err != nil {
		return nil, errHostWatchdog
	}
	fail := func() (*hostWatchdogStore, error) { db.Close(); return nil, errHostWatchdog }
	var version int
	if db.QueryRow("PRAGMA user_version").Scan(&version) != nil || version > 1 {
		return fail()
	}
	if version == 0 {
		var tables int
		if db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables) != nil {
			return fail()
		}
		if tables > 0 {
			return fail()
		}
		if _, err = db.Exec(hostWatchdogSchema); err != nil {
			return fail()
		}
	}
	if _, err = db.Exec(`INSERT OR IGNORE INTO host_state(id,instance,installation) VALUES(1,?,?)`, spec.Instance, spec.InstallationSHA256); err != nil {
		return fail()
	}
	var instance, installation string
	if db.QueryRow(`SELECT instance,installation FROM host_state WHERE id=1`).Scan(&instance, &installation) != nil || instance != spec.Instance || installation != spec.InstallationSHA256 {
		return fail()
	}
	// An interrupted sender is unknown, never a new unsent request.
	if _, err = db.Exec(`UPDATE outbox SET state='unknown' WHERE id IN(SELECT outbox FROM attempts WHERE state='sending');UPDATE attempts SET state='unknown',finished_at=strftime('%s','now') WHERE state='sending'`); err != nil {
		return fail()
	}
	return &hostWatchdogStore{db: db, vault: v, spec: spec}, nil
}

func (s *hostWatchdogStore) sealSettings(version int64, raw []byte) (string, []byte, []byte, error) {
	a := s.vault.keys[s.vault.active]
	if a == nil {
		return "", nil, nil, ErrCredentialUnavailable
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, nil, err
	}
	aad := hostSettingsAAD(s.spec, version)
	return s.vault.active, nonce, a.Seal(nil, nonce, raw, aad), nil
}
func hostSettingsAAD(spec HostWatchdogSpec, version int64) []byte {
	return []byte("webscan-v3/host-settings/v1/" + spec.Instance + "/" + spec.InstallationSHA256 + "/" + string(commonJSONInt(version)))
}
func commonJSONInt(v int64) []byte { b, _ := json.Marshal(v); return b }

func (s *hostWatchdogStore) settings(ctx context.Context, q persist.SQLWriter) (int64, []byte, bool, error) {
	var version int64
	var key, hash string
	var nonce, sealed []byte
	var frozen bool
	if err := q.QueryRowContext(ctx, `SELECT version,key_id,nonce,ciphertext,frozen,digest FROM host_state WHERE id=1`).Scan(&version, &key, &nonce, &sealed, &frozen, &hash); err != nil {
		return 0, nil, true, err
	}
	a := s.vault.keys[key]
	if version < 1 || a == nil || len(nonce) != a.NonceSize() {
		return version, nil, true, ErrHostSettingsFrozen
	}
	raw, err := a.Open(nil, nonce, sealed, hostSettingsAAD(s.spec, version))
	if err != nil || digest(raw) != hash {
		clear(raw)
		return version, nil, true, errHostWatchdog
	}
	return version, raw, frozen, nil
}
func (s *hostWatchdogStore) status(ctx context.Context) (HostWatchdogStatus, error) {
	out := HostWatchdogStatus{Instance: s.spec.Instance, ObservedAt: time.Now().UTC(), Checks: []HostWatchdogCheck{}}
	if err := s.db.QueryRowContext(ctx, `SELECT version,frozen,reason FROM host_state WHERE id=1`).Scan(&out.RuntimeVersion, &out.Frozen, &out.Reason); err != nil {
		return out, err
	}
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE state IN ('queued','sending')`).Scan(&out.Pending)
	return out, err
}
