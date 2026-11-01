package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"webscan/internal/common"
)

// Registered by the schema owner as migration 44. The archive policy remains
// immutable; these slots bind only the applied, non-secret runtime schedule.
const singleBackupRuntimePolicySchema = `
CREATE TABLE v3_single_backup_slots(
 instance text NOT NULL REFERENCES v3_single_backup_policies(instance),
 local_date date NOT NULL,settings_version bigint NOT NULL CHECK(settings_version>0),
 policy jsonb NOT NULL,run_id text NOT NULL REFERENCES v3_single_backup_runs(id),
 completed_at timestamptz,PRIMARY KEY(instance,local_date)
);
CREATE INDEX v3_single_backup_slots_completed ON v3_single_backup_slots(instance,completed_at DESC) WHERE completed_at IS NOT NULL;
INSERT INTO v3_schema(version) VALUES(44);
`

type singleBackupRuntimePolicy struct {
	Enabled    bool   `json:"enabled"`
	Time       string `json:"time"`
	Timezone   string `json:"timezone"`
	KeepDays   int    `json:"keep_days"`
	configured bool
	version    int64
	location   *time.Location
}

// An absent policy preserves the old host-local timer and count retention.
// Explicit runtime controls default to 03:00 UTC and seven days, independently
// of a container's or browser's timezone. They never rewrite schedule.json.
func singleBackupRuntimePolicyFromSettings(root configurationValues) (singleBackupRuntimePolicy, error) {
	p := singleBackupRuntimePolicy{Enabled: true, Time: "03:00", Timezone: "UTC", KeepDays: 7, location: time.UTC}
	section, exists := root["backup"]
	if !exists {
		return p, nil
	}
	backup, ok := section.(map[string]any)
	if !ok {
		if b, good := section.(common.Map); good {
			backup = b
		} else {
			return p, errSingleBackupSchedule
		}
	}
	for _, key := range []string{"enabled", "time", "timezone", "keep_days"} {
		if _, ok := backup[key]; ok {
			p.configured = true
		}
	}
	if !p.configured {
		return p, nil
	}
	if value, ok := backup["enabled"]; ok {
		var valid bool
		p.Enabled, valid = value.(bool)
		if !valid {
			return p, errSingleBackupSchedule
		}
	}
	if value, ok := backup["time"]; ok {
		var valid bool
		p.Time, valid = value.(string)
		if !valid || len(p.Time) != 5 {
			return p, errSingleBackupSchedule
		}
		if _, err := time.Parse("15:04", p.Time); err != nil {
			return p, errSingleBackupSchedule
		}
	}
	if value, ok := backup["timezone"]; ok {
		var valid bool
		p.Timezone, valid = value.(string)
		if !valid || p.Timezone == "" || p.Timezone == "Local" || len(p.Timezone) > 128 || strings.ContainsAny(p.Timezone, "\x00\r\n") {
			return p, errSingleBackupSchedule
		}
		var err error
		p.location, err = time.LoadLocation(p.Timezone)
		if err != nil {
			return p, errSingleBackupSchedule
		}
	}
	if value, ok := backup["keep_days"]; ok {
		if !(settingsField{Kind: "integer", Min: 1, Max: 3650}).valid(value) {
			return p, errSingleBackupSchedule
		}
		p.KeepDays, _ = strconv.Atoi(value.(json.Number).String())
	}
	return p, nil
}

type singleBackupRuntimeQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readSingleBackupRuntimePolicy(ctx context.Context, q singleBackupRuntimeQueryer) (singleBackupRuntimePolicy, error) {
	var raw []byte
	var version int64
	if err := q.QueryRowContext(ctx, `SELECT payload,version FROM v3_settings WHERE id=1`).Scan(&raw, &version); err != nil {
		return singleBackupRuntimePolicy{}, err
	}
	var root configurationValues
	if decodeConfigurationObject(raw, &root) != nil || version < 1 {
		return singleBackupRuntimePolicy{}, errSingleBackupSchedule
	}
	p, err := singleBackupRuntimePolicyFromSettings(root)
	p.version = version
	return p, err
}

// Compare wall-clock minute numbers instead of constructing a possibly
// nonexistent DST local time. A spring-forward gap runs at the next available
// minute, while the durable local-date slot prevents a repeated fall-back run.
func singleBackupRuntimeDue(p singleBackupRuntimePolicy, now time.Time, latest sql.NullTime) (string, bool) {
	local := now.In(p.location)
	date := local.Format("2006-01-02")
	if !p.Enabled || latest.Valid && (!latest.Time.Before(now) || latest.Time.In(p.location).Format("2006-01-02") == date) {
		return date, false
	}
	hour, _ := strconv.Atoi(p.Time[:2])
	minute, _ := strconv.Atoi(p.Time[3:])
	return date, local.Hour()*60+local.Minute() >= hour*60+minute
}

func singleBackupLegacyTimerDue(now time.Time) bool {
	local := now.In(time.Local)
	return local.Hour() >= 3
}

func singleBackupLatestSuccess(ctx context.Context, q singleBackupRuntimeQueryer, instance, policyHash string) (sql.NullTime, error) {
	var latest sql.NullTime
	err := q.QueryRowContext(ctx, `SELECT max(at) FROM (
 SELECT completed_at AS at FROM v3_single_backup_slots WHERE instance=$1 AND completed_at IS NOT NULL
 UNION ALL SELECT created_at FROM v3_single_backup_runs r WHERE instance=$1 AND policy_sha256=$2 AND status IN ('captured','purging','expired') AND NOT EXISTS(SELECT 1 FROM v3_single_backup_slots s WHERE s.run_id=r.id)
 ) successes`, instance, policyHash).Scan(&latest)
	return latest, err
}
