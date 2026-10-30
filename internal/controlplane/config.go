// Package controlplane contains the v3 control plane. Legacy deployment and
// SQLite stores are kept separate until a verified migration has completed.
package controlplane

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Version int `yaml:"config_version"`
	Central struct {
		Topology        string   `yaml:"topology"`
		Instance        string   `yaml:"instance_id"`
		Listen          string   `yaml:"listen"`
		PublicURL       string   `yaml:"public_url"`
		CertFile        string   `yaml:"cert_file"`
		KeyFile         string   `yaml:"key_file"`
		ExportDirectory string   `yaml:"exports_directory,omitempty"`
		TrustedProxies  []string `yaml:"trusted_proxies,omitempty"`
	} `yaml:"central"`
	Database struct {
		DSNFile        string `yaml:"dsn_file"`
		MaxConnections int    `yaml:"max_connections"`
	} `yaml:"database"`
	Metrics struct {
		WriteURL string `yaml:"write_url"`
		QueryURL string `yaml:"query_url"`
		SpoolDir string `yaml:"spool_dir"`
	} `yaml:"metrics"`
	Collector struct {
		CAFile                   string `yaml:"ca_file"`
		IdentityFile             string `yaml:"identity_file,omitempty"`
		CertFile                 string `yaml:"cert_file"`
		KeyFile                  string `yaml:"key_file"`
		RevocationFile           string `yaml:"revocation_file,omitempty"`
		RevocationStateDirectory string `yaml:"revocation_state_directory,omitempty"`
		Shards                   int    `yaml:"shards"`
		Concurrency              int    `yaml:"concurrency"`
		IntervalSeconds          int    `yaml:"interval_seconds"`
	} `yaml:"collector"`
	DeploymentTrust DeploymentTrustConfig `yaml:"deployment_trust,omitempty"`
	Executor        ExecutorConfig        `yaml:"executor,omitempty"`
	NodePKI         NodePKIConfig         `yaml:"node_pki,omitempty"`
	HA              struct {
		Entrypoint string     `yaml:"entrypoint"`
		Members    []HAMember `yaml:"members"`
	} `yaml:"ha"`
}

type HAMember struct {
	ID             string `yaml:"id" json:"id"`
	Host           string `yaml:"host" json:"host"`
	PrivateAddress string `yaml:"private_address" json:"private_address"`
	SSHPort        int    `yaml:"ssh_port" json:"ssh_port"`
	SSHKeyFile     string `yaml:"ssh_key_file" json:"-"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, errors.New("无法读取 v3 配置")
	}
	if len(b) > 2<<20 {
		return c, errors.New("v3 配置超过 2 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return c, errors.New("v3 配置格式或字段不正确")
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, errors.New("配置只允许一个 YAML 文档")
	}
	return c, c.Validate()
}

func (c *Config) Validate() error {
	if len(c.Central.TrustedProxies) > 32 {
		return errors.New("central.trusted_proxies 最多配置 32 个代理 IP 或 CIDR")
	}
	for _, raw := range c.Central.TrustedProxies {
		prefix, err := trustedProxyPrefix(raw)
		if err != nil || prefix.Bits() == 0 {
			return errors.New("central.trusted_proxies 必须为明确的代理 IP 或 CIDR，不能信任全部地址")
		}
	}
	if c.Central.ExportDirectory == "" {
		c.Central.ExportDirectory = "/var/lib/webscan-v3/exports"
	}
	if !filepath.IsAbs(c.Central.ExportDirectory) || strings.ContainsAny(c.Central.ExportDirectory, "\x00\r\n") {
		return errors.New("历史导出目录必须为绝对路径")
	}
	if c.Version != 3 {
		return errors.New("此入口只接受 config_version: 3，旧配置请先执行迁移预览")
	}
	if c.Central.Topology == "" {
		c.Central.Topology = "single"
	}
	if c.Central.Topology != "single" && c.Central.Topology != "ha" {
		return errors.New("central.topology 只允许 single 或 ha")
	}
	if !identifier.MatchString(c.Central.Instance) {
		return errors.New("central.instance_id 必填，最多 128 字节且只允许字母、数字、点、下划线和横线")
	}
	if c.Central.Listen == "" {
		c.Central.Listen = "127.0.0.1:19444"
	}
	host, port, err := net.SplitHostPort(c.Central.Listen)
	p, pe := strconv.Atoi(port)
	if err != nil || pe != nil || p < 1 || p > 65535 {
		return errors.New("central.listen 格式错误")
	}
	if (c.Central.CertFile == "") != (c.Central.KeyFile == "") {
		return errors.New("后台证书及私钥必须同时配置")
	}
	if c.Central.CertFile == "" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
		return errors.New("未配置后台 TLS 时只允许监听回环地址，由 HTTPS 入口代理")
	}
	u, e := url.Parse(c.Central.PublicURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("central.public_url 必须为不含凭据的 HTTPS 地址")
	}
	if c.Database.DSNFile == "" {
		return errors.New("database.dsn_file 必填，数据库凭据不能放入命令行")
	}
	if c.Database.MaxConnections == 0 {
		c.Database.MaxConnections = 20
	}
	if c.Database.MaxConnections < 2 || c.Database.MaxConnections > 200 {
		return errors.New("数据库连接数须为 2～200")
	}
	for _, v := range []string{c.Metrics.WriteURL, c.Metrics.QueryURL} {
		u, e := url.Parse(v)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("时序库地址格式错误，不允许内嵌凭据")
		}
	}
	if file := c.Collector.IdentityFile; file != "" && (!filepath.IsAbs(file) || filepath.Clean(file) != file || strings.ContainsAny(file, "\x00\r\n") || c.Collector.CertFile != "" || c.Collector.KeyFile != "") {
		return errors.New("collector.identity_file 必须为绝对规范路径，不能同时配置 cert_file 或 key_file")
	}
	if c.Collector.Shards == 0 {
		c.Collector.Shards = 256
	}
	if c.Collector.RevocationFile != "" && !filepath.IsAbs(c.Collector.RevocationFile) {
		return errors.New("collector.revocation_file 必须为绝对路径")
	}
	if dir := c.Collector.RevocationStateDirectory; dir != "" && (c.Collector.RevocationFile == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir) {
		return errors.New("collector.revocation_state_directory 必须为绝对规范路径，且同时配置 revocation_file")
	}
	if c.Collector.Shards < 1 || c.Collector.Shards > 4096 {
		return errors.New("采集分片数须为 1～4096")
	}
	if c.Collector.Concurrency == 0 {
		c.Collector.Concurrency = 128
	}
	if c.Collector.Concurrency < 1 || c.Collector.Concurrency > 2048 {
		return errors.New("采集并发须为 1～2048")
	}
	if c.Collector.IntervalSeconds == 0 {
		c.Collector.IntervalSeconds = 30
	}
	if c.Collector.IntervalSeconds < 10 || c.Collector.IntervalSeconds > 3600 {
		return errors.New("采集间隔须为 10～3600 秒")
	}
	if err := c.DeploymentTrust.validate(); err != nil {
		return err
	}
	if err := c.Executor.validate(c.DeploymentTrust); err != nil {
		return err
	}
	if err := c.NodePKI.validate(); err != nil {
		return err
	}
	if c.Central.Topology == "ha" {
		if len(c.HA.Members) < 3 {
			return errors.New("高可用至少需要三台独立中心机器")
		}
		entry, e := url.Parse(c.HA.Entrypoint)
		if e != nil || entry.Scheme != "https" || entry.Hostname() == "" || entry.User != nil || entry.RawQuery != "" || entry.Fragment != "" || entry.Path != "" && entry.Path != "/" {
			return errors.New("高可用需要已配置的 HTTPS 入口")
		}
		ids, hosts, private := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, m := range c.HA.Members {
			if !identifier.MatchString(m.ID) || ids[m.ID] || m.Host == "" || hosts[m.Host] || net.ParseIP(m.PrivateAddress) == nil || private[m.PrivateAddress] {
				return errors.New("高可用机器编号、主机及内部地址必须独立且有效")
			}
			if m.SSHPort < 1 || m.SSHPort > 65535 || !filepath.IsAbs(m.SSHKeyFile) {
				return errors.New("高可用 SSH 端口或私钥路径不完整")
			}
			ids[m.ID], hosts[m.Host], private[m.PrivateAddress] = true, true, true
			if entry.Hostname() == m.Host || entry.Hostname() == m.PrivateAddress {
				return errors.New("高可用入口不能直接指向某一台中心机器")
			}
		}
	}
	return nil
}

func trustedProxyPrefix(raw string) (netip.Prefix, error) {
	if addr, err := netip.ParseAddr(raw); err == nil && addr.Zone() == "" {
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.ParsePrefix(raw)
}

func ReadSecret(path string) (string, error) {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return "", errors.New("凭据文件必须为普通文件且仅所有者可读写")
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", errors.New("无法读取凭据文件")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) || opened.Mode().Perm()&0077 != 0 {
		return "", errors.New("凭据文件在读取期间发生变化")
	}
	owner, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return "", errors.New("凭据文件必须属于服务运行账号")
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return "", errors.New("凭据文件读取失败或超限")
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("凭据文件为空")
	}
	return v, nil
}

const LeaseDuration = 30 * time.Second
