package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

// Disabled unless explicitly selected by the administrator. An executor uses
// only immutable signed artifacts and per-job private runtime configurations.
type ExecutorConfig struct {
	Mode                   string   `yaml:"mode,omitempty"`
	Enabled                bool     `yaml:"enabled"`
	ApplicationsEnabled    bool     `yaml:"applications_enabled,omitempty"`
	Concurrency            int      `yaml:"concurrency,omitempty"`
	ConfigurationDirectory string   `yaml:"configuration_directory,omitempty"`
	RulesFile              string   `yaml:"rules_file,omitempty"`
	SSHKeyDirectories      []string `yaml:"ssh_key_directories,omitempty"`
}

func (c ExecutorConfig) embedded() bool { return c.Enabled && c.Mode != "external" }

func (c ExecutorConfig) validate(trust DeploymentTrustConfig) error {
	if c.Mode != "" && c.Mode != "embedded" && c.Mode != "external" {
		return errors.New("executor.mode 只允许 embedded 或 external")
	}
	for _, p := range append(append([]string{}, c.SSHKeyDirectories...), c.RulesFile) {
		if p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.ContainsAny(p, "\x00\r\n")) {
			return errors.New("执行器规则及 SSH 密钥目录必须为规范绝对路径")
		}
	}
	if c.ApplicationsEnabled && !c.Enabled {
		return errors.New("配置应用工作器需要先启用 executor.enabled")
	}
	if !c.Enabled {
		if c.Concurrency == 0 && c.ConfigurationDirectory == "" {
			return nil
		}
	}
	if c.Concurrency < 0 || c.Concurrency > 32 || c.ConfigurationDirectory != "" && (!filepath.IsAbs(c.ConfigurationDirectory) || filepath.Clean(c.ConfigurationDirectory) != c.ConfigurationDirectory || c.ConfigurationDirectory == "/" || strings.ContainsAny(c.ConfigurationDirectory, "\x00\r\n")) || c.Enabled && (!trust.configured() || c.Mode != "external" && c.ConfigurationDirectory == "") {
		return errors.New("executor 需要完整 deployment_trust、私有绝对规范配置包目录及 1～32 并发（省略为 4）")
	}
	if c.Enabled {
		return trust.validate()
	}
	return nil
}

func newDeploymentExecutor(ctx context.Context, s *Store, c Config) (*DeploymentRunner, error) {
	if !c.Executor.Enabled {
		return nil, errors.New("部署执行器未显式启用")
	}
	if s == nil || s.DB == nil {
		return nil, errors.New("部署执行器数据库未初始化")
	}
	if err := c.Executor.validate(c.DeploymentTrust); err != nil {
		return nil, err
	}
	t, err := loadDeploymentTrust(ctx, c.DeploymentTrust)
	if err != nil {
		return nil, err
	}
	d, err := trustDirectory(c.Executor.ConfigurationDirectory, true)
	if err != nil {
		return nil, err
	}
	d.Close()
	runtime := &SSHNodeRuntime{Store: s, Vault: t.vault, Release: t.release, LocalHelper: t.config.HelperFile, LocalBundle: t.config.NativeBundleFile, LocalImageArchive: t.config.ImageArchiveFile, Lifecycle: true, ConfigurationDirectory: c.Executor.ConfigurationDirectory}
	runtime.ValidateTaskConfiguration = func(ctx context.Context, j DeploymentJob, raw []byte) error {
		return s.validateDeploymentRuntimeConfiguration(ctx, c, t.release, j, raw)
	}
	return &DeploymentRunner{Store: s, Instance: c.Central.Instance, Concurrency: c.Executor.Concurrency, Runtime: runtime, Vault: t.vault, Manifest: t.release.SHA256()}, nil
}

func validServiceRole(role string) bool {
	switch role {
	case "api", "collector", "notifier", "websites", "executor", "all":
		return true
	}
	return false
}
