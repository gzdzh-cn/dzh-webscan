package controlplane

import (
	"context"
	"errors"
	"time"
)

type HostWatchdogConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Socket         string `yaml:"socket"`
	StateDirectory string `yaml:"state_directory"`
	SpecFile       string `yaml:"spec_file"`
}

type HostWatchdogSpec struct {
	Format             int    `json:"format"`
	Instance           string `json:"instance"`
	InstallationFile   string `json:"installation_file"`
	InstallationSHA256 string `json:"installation_sha256"`
	HostConfigFile     string `json:"host_config_file"`
	HostConfigSHA256   string `json:"host_config_sha256"`
	HelperFile         string `json:"helper_file"`
	HelperSHA256       string `json:"helper_sha256"`
	StateDirectory     string `json:"state_directory"`
	Socket             string `json:"socket"`
	APIURL             string `json:"api_url"`
	MetricsURL         string `json:"metrics_url"`
	KeyID              string `json:"key_id"`
	Proof              string `json:"proof"`
}

type HostQuotaReservation struct {
	ID             string     `json:"id"`
	AttemptKey     string     `json:"attempt_key"`
	RuntimeVersion int64      `json:"runtime_version"`
	GrantedAt      time.Time  `json:"granted_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	New            bool       `json:"new"`
	RetryAt        *time.Time `json:"retry_at,omitempty"`
}
type HostSettingsPreparation struct {
	ID            string `json:"id"`
	TransactionID string `json:"transaction_id"`
	BaseVersion   int64  `json:"base_version"`
	TargetVersion int64  `json:"target_version"`
}
type HostSettingsResolution struct {
	State          string `json:"state"`
	RuntimeVersion int64  `json:"runtime_version"`
}
type HostWatchdogCheck struct {
	Component           string    `json:"component"`
	State               string    `json:"state"`
	Reason              string    `json:"reason"`
	ObservedAt          time.Time `json:"observed_at"`
	LatencyMilliseconds int64     `json:"latency_ms"`
}
type HostWatchdogStatus struct {
	Instance       string                  `json:"instance"`
	ObservedAt     time.Time               `json:"observed_at"`
	RuntimeVersion int64                   `json:"runtime_version"`
	Frozen         bool                    `json:"frozen"`
	Reason         string                  `json:"reason"`
	Pending        int64                   `json:"pending"`
	Checks         []HostWatchdogCheck     `json:"checks"`
	Environment    HostWatchdogEnvironment `json:"environment"`
}
type HostWatchdogEnvironment struct {
	OS            string                `json:"os"`
	Architecture  string                `json:"architecture"`
	Kernel        string                `json:"kernel"`
	BootID        string                `json:"boot_id"`
	UptimeSeconds *float64              `json:"uptime_seconds"`
	MemoryBytes   *uint64               `json:"memory_bytes"`
	Storage       []HostWatchdogStorage `json:"storage"`
}
type HostWatchdogStorage struct {
	Component       string `json:"component"`
	TotalBytes      uint64 `json:"total_bytes"`
	AvailableBytes  uint64 `json:"available_bytes"`
	Inodes          uint64 `json:"inodes"`
	AvailableInodes uint64 `json:"available_inodes"`
}
type hostQuotaInput struct {
	Channel        string `json:"channel"`
	AttemptKey     string `json:"attempt_key"`
	RuntimeVersion int64  `json:"runtime_version"`
}
type hostSettingsInput struct {
	ID               string `json:"id"`
	TransactionID    string `json:"transaction_id"`
	DatabaseIdentity string `json:"database_identity"`
	BaseDigest       string `json:"base_digest"`
	BaseVersion      int64  `json:"base_version"`
	TargetVersion    int64  `json:"target_version"`
}
type hostWatchdogMaintenance struct {
	Operation string    `json:"operation"`
	Component string    `json:"component"`
	ExpiresAt time.Time `json:"expires_at"`
}

var ErrHostQuota = errors.New("宿主通知限速或配置核验暂不可用，通知已暂停")
var ErrHostSettingsFrozen = errors.New("宿主通知配置等待事务核验，发送已冻结")
var errHostWatchdog = errors.New("宿主看门狗资料、权限或状态校验失败")

type hostWatchdogProbe interface {
	Check(context.Context) ([]HostWatchdogCheck, HostWatchdogEnvironment)
}
