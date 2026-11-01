package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"webscan/internal/common"
)

// The keys remain compatible with v2 exports. A missing security period
// inherits the ordinary event period; a missing server period inherits the
// old monitoring period. Explicit invalid values fail closed, never delete.
type RetentionPolicy struct {
	Events        int `json:"sqlite_events_days"`
	Security      int `json:"security_events_days"`
	Websites      int `json:"website_incidents_days"`
	Servers       int `json:"server_alerts_days"`
	Notifications int `json:"delivery_records_days"`
}

func (p RetentionPolicy) Validate() error {
	for _, days := range []int{p.Events, p.Security, p.Websites, p.Servers, p.Notifications} {
		if days < 1 || days > 3650 {
			return errors.New("保留期限须为 1～3650 天整数")
		}
	}
	return nil
}

func retentionPolicy(root common.Map) (RetentionPolicy, error) {
	if v, ok := root["retention"]; ok {
		if _, valid := v.(map[string]any); !valid {
			return RetentionPolicy{}, errors.New("保留期限配置格式不正确")
		}
	}
	r := common.M(root["retention"])
	read := func(m common.Map, key string, fallback int) (int, error) {
		v, ok := m[key]
		if !ok {
			return fallback, nil
		}
		// Do not accept booleans, strings, fractions or null as day counts.
		switch v.(type) {
		case int, int64, float64, json.Number:
		default:
			return 0, errors.New("保留期限须为 1～3650 天整数")
		}
		n := common.F(v)
		if n < 1 || n > 3650 || n != float64(int(n)) {
			return 0, errors.New("保留期限须为 1～3650 天整数")
		}
		return int(n), nil
	}
	var p RetentionPolicy
	var err error
	if p.Events, err = read(r, "sqlite_events_days", 30); err != nil {
		return p, err
	}
	if p.Security, err = read(r, "security_events_days", p.Events); err != nil {
		return p, err
	}
	if p.Websites, err = read(r, "website_incidents_days", 30); err != nil {
		return p, err
	}
	server := 15
	if _, set := r["server_alerts_days"]; !set {
		if server, err = read(common.M(root["monitoring"]), "history_days", 15); err != nil {
			return p, err
		}
	}
	if p.Servers, err = read(r, "server_alerts_days", server); err != nil {
		return p, err
	}
	p.Notifications, err = read(r, "delivery_records_days", 30)
	return p, err
}

type RetentionPolicyView struct {
	Version int64           `json:"version"`
	Policy  RetentionPolicy `json:"policy"`
	Updated time.Time       `json:"updated_at"`
}

func (s *Store) RetentionPolicy(ctx context.Context) (RetentionPolicyView, error) {
	var v RetentionPolicyView
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, "SELECT version,payload,updated_at FROM v3_settings WHERE id=1").Scan(&v.Version, &raw, &v.Updated); err != nil {
		return v, err
	}
	var root common.Map
	if err := json.Unmarshal(raw, &root); err != nil {
		return v, err
	}
	p, err := retentionPolicy(root)
	v.Policy = p
	return v, err
}

// SaveRetentionPolicy edits only the five day counts. Other settings, including
// credentials, never leave the database or enter the idempotency/audit record.
func (s *Store) SaveRetentionPolicy(ctx context.Context, user, key string, p RetentionPolicy, expected int64) (json.RawMessage, error) {
	return s.saveRetentionPolicy(ctx, user, key, p, expected, nil)
}

func (s *Store) saveRetentionPolicy(ctx context.Context, user, key string, p RetentionPolicy, expected int64, before *configurationEditBackup) (json.RawMessage, error) {
	if !identifier.MatchString(user) || !identifier.MatchString(key) || expected < 1 {
		return nil, errors.New("操作账号、幂等键或配置版本不正确")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(struct {
		Kind     string
		Policy   RetentionPolicy
		Expected int64
	}{"retention-policy", p, expected})
	hash := digest(raw)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if held, e := migrationHeld(ctx, tx); e != nil {
		return nil, e
	} else if held {
		return nil, ErrMigrationPending
	}
	if err = before.lock(ctx, tx, user); err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, "INSERT INTO v3_requests(username,key,request_hash,response) VALUES($1,$2,$3,'{}') ON CONFLICT DO NOTHING", user, key, hash)
	if err != nil {
		return nil, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		var old string
		var response json.RawMessage
		if err = tx.QueryRowContext(ctx, "SELECT request_hash,response FROM v3_requests WHERE username=$1 AND key=$2", user, key).Scan(&old, &response); err != nil {
			return nil, err
		}
		if old != hash {
			return nil, ErrRequestConflict
		}
		return response, tx.Commit()
	}
	var version int64
	var saved []byte
	if err = tx.QueryRowContext(ctx, "SELECT version,payload FROM v3_settings WHERE id=1 FOR UPDATE").Scan(&version, &saved); err != nil {
		return nil, err
	}
	if version != expected {
		return nil, ErrConflict
	}
	var root configurationValues
	if err = decodeConfigurationObject(saved, &root); err != nil {
		return nil, errors.New("系统设置格式不正确")
	}
	var previous RetentionPolicy
	previous, err = retentionPolicy(common.Map(root))
	if err != nil {
		return nil, err
	}
	if err = before.capture(ctx, tx, user, "retention-policy", "history"); err != nil {
		return nil, err
	}
	var vault *Vault
	if before != nil {
		vault = before.vault
	}
	if err = mergeRetentionIntoDraftTx(ctx, tx, vault, p, version); err != nil {
		return nil, err
	}
	r := common.M(root["retention"])
	root["retention"] = r
	for k, v := range map[string]int{"sqlite_events_days": p.Events, "security_events_days": p.Security, "website_incidents_days": p.Websites, "server_alerts_days": p.Servers, "delivery_records_days": p.Notifications} {
		r[k] = v
	}
	if s.HostQuota != nil {
		if _, err = s.HostQuota.PrepareSettings(ctx, tx, version, version+1); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_settings SET version=version+1,payload=$1,updated_at=clock_timestamp() WHERE id=1", common.JSON(root)); err != nil {
		return nil, err
	}
	shortened := p.Events < previous.Events || p.Security < previous.Security || p.Websites < previous.Websites || p.Servers < previous.Servers || p.Notifications < previous.Notifications
	response, _ := json.Marshal(map[string]any{"version": version + 1, "policy": p, "shortened": shortened, "message": "保留期限已生效；记录删除后不能通过调大期限恢复，磁盘空间由后续写入复用"})
	if _, err = tx.ExecContext(ctx, "UPDATE v3_requests SET response=$3 WHERE username=$1 AND key=$2", user, key, []byte(response)); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'retention-policy','history',$2)", user, []byte(response)); err != nil {
		return nil, err
	}
	return response, tx.Commit()
}

func retentionDaysForStage(p RetentionPolicy, stage int) (int, error) {
	switch stage {
	case 0, 2:
		return p.Events, nil
	case 1, 3:
		return p.Security, nil
	case 4, 7:
		return p.Websites, nil
	case 5, 8:
		return p.Servers, nil
	case 6:
		return p.Notifications, nil
	}
	return 0, errors.New("历史清理阶段不正确")
}

func retentionTxSettings(ctx context.Context, tx *sql.Tx) (RetentionPolicy, int64, error) {
	var raw []byte
	var version int64
	if err := tx.QueryRowContext(ctx, "SELECT payload,version FROM v3_settings WHERE id=1 FOR SHARE").Scan(&raw, &version); err != nil {
		return RetentionPolicy{}, 0, err
	}
	var root common.Map
	if err := json.Unmarshal(raw, &root); err != nil {
		return RetentionPolicy{}, 0, err
	}
	p, err := retentionPolicy(root)
	return p, version, err
}
