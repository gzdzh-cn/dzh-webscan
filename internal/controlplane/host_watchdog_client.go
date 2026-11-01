package controlplane

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"
)

type HostQuotaClient struct {
	spec  HostWatchdogSpec
	vault *Vault
	http  *http.Client
}
type hostRPCEnvelope struct {
	KeyID string          `json:"key_id"`
	Nonce string          `json:"nonce"`
	At    int64           `json:"at"`
	Body  json.RawMessage `json:"body"`
	MAC   string          `json:"mac"`
}

func (h HostWatchdogConfig) validate(c Config) error {
	if !h.Enabled {
		if h.Socket != "" || h.StateDirectory != "" || h.SpecFile != "" {
			return errHostWatchdog
		}
		return nil
	}
	if c.Central.Topology != "single" || !snapshotAbsolutePath(h.Socket) || !snapshotAbsolutePath(h.SpecFile) || len(h.Socket) > 100 || h.StateDirectory != "" && !snapshotAbsolutePath(h.StateDirectory) {
		return errHostWatchdog
	}
	return nil
}
func hostSpecMAC(v *Vault, s HostWatchdogSpec) (string, error) {
	s.Proof = ""
	key := v.receiptKeys[s.KeyID]
	if len(key) == 0 {
		return "", errHostWatchdog
	}
	raw, _ := json.Marshal(s)
	h := hmac.New(sha256.New, key)
	h.Write([]byte("webscan-v3/host-watchdog-spec/v1\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func validateHostSpec(s HostWatchdogSpec) error {
	if s.Format != 1 || !identifier.MatchString(s.Instance) || !releaseDigest(s.InstallationSHA256) || !releaseDigest(s.HelperSHA256) || !releaseDigest(s.HostConfigSHA256) || !snapshotAbsolutePath(s.InstallationFile) || !snapshotAbsolutePath(s.HostConfigFile) || !snapshotAbsolutePath(s.HelperFile) || !snapshotAbsolutePath(s.StateDirectory) || !snapshotAbsolutePath(s.Socket) || len(s.Socket) > 100 || filepath.Dir(s.Socket) == s.StateDirectory {
		return errHostWatchdog
	}
	for _, raw := range []string{s.APIURL, s.MetricsURL} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
			return errHostWatchdog
		}
	}
	return nil
}
func loadHostSpec(path string, v *Vault) (HostWatchdogSpec, error) {
	var s HostWatchdogSpec
	raw, err := readTrustData(path, false, 64<<10)
	if err != nil || singleDecode(raw, &s) != nil || validateHostSpec(s) != nil {
		return s, errHostWatchdog
	}
	proof, err := hostSpecMAC(v, s)
	if err != nil || !hmac.Equal([]byte(proof), []byte(s.Proof)) {
		return s, errHostWatchdog
	}
	return s, nil
}
func newHostQuotaClient(c Config) (*HostQuotaClient, error) {
	if !c.HostWatchdog.Enabled {
		return nil, nil
	}
	if c.HostWatchdog.validate(c) != nil {
		return nil, errHostWatchdog
	}
	v, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return nil, err
	}
	s, err := loadHostSpec(c.HostWatchdog.SpecFile, v)
	if err != nil || s.Socket != c.HostWatchdog.Socket || s.Instance != c.Central.Instance {
		return nil, errHostWatchdog
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", s.Socket)
	}, DisableKeepAlives: true}
	return &HostQuotaClient{spec: s, vault: v, http: &http.Client{Transport: transport, Timeout: 4 * time.Second}}, nil
}
func hostRPCMAC(v *Vault, path string, e hostRPCEnvelope) (string, error) {
	key := v.receiptKeys[e.KeyID]
	if len(key) == 0 {
		return "", ErrHostQuota
	}
	e.MAC = ""
	raw, _ := json.Marshal(e)
	h := hmac.New(sha256.New, key)
	h.Write([]byte("webscan-v3/host-rpc/v1\x00" + path + "\x00"))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (c *HostQuotaClient) call(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return ErrHostQuota
	}
	e := hostRPCEnvelope{KeyID: c.vault.active, Nonce: token(), At: time.Now().Unix(), Body: raw}
	e.MAC, err = hostRPCMAC(c.vault, path, e)
	if err != nil {
		return err
	}
	raw, _ = json.Marshal(e)
	req, err := http.NewRequestWithContext(ctx, "POST", "http://host"+path, bytes.NewReader(raw))
	if err != nil {
		return ErrHostQuota
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return ErrHostQuota
	}
	defer res.Body.Close()
	value, err := io.ReadAll(io.LimitReader(res.Body, (256<<10)+1))
	if err != nil || len(value) > 256<<10 {
		return ErrHostQuota
	}
	if res.StatusCode == 423 {
		return ErrHostSettingsFrozen
	}
	if res.StatusCode != 200 || singleDecode(value, out) != nil {
		return ErrHostQuota
	}
	return nil
}
func (c *HostQuotaClient) Reserve(ctx context.Context, channel, key string, version int64) (HostQuotaReservation, error) {
	var out HostQuotaReservation
	err := c.call(ctx, "/v1/quota", hostQuotaInput{channel, key, version}, &out)
	return out, err
}
func (c *HostQuotaClient) PrepareSettings(ctx context.Context, tx *sql.Tx, base, target int64) (HostSettingsPreparation, error) {
	var out HostSettingsPreparation
	var in hostSettingsInput
	var database, cluster, raw string
	if tx == nil || base < 1 || target != base+1 {
		return out, ErrHostQuota
	}
	err := tx.QueryRowContext(ctx, `SELECT pg_current_xact_id()::text,current_database(),(SELECT payload::text FROM v3_cluster WHERE id=1),(SELECT payload::text FROM v3_settings WHERE id=1)`).Scan(&in.TransactionID, &database, &cluster, &raw)
	if err != nil {
		return out, err
	}
	in.ID = token()
	in.DatabaseIdentity = hostDatabaseIdentity(database, cluster)
	in.BaseDigest = digest([]byte(raw))
	in.BaseVersion, in.TargetVersion = base, target
	err = c.call(ctx, "/v1/settings/prepare", in, &out)
	return out, err
}
func (c *HostQuotaClient) ResolveSettings(ctx context.Context, id string) (HostSettingsResolution, error) {
	var out HostSettingsResolution
	err := c.call(ctx, "/v1/settings/resolve", map[string]string{"id": id}, &out)
	return out, err
}
func (c *HostQuotaClient) Snapshot(ctx context.Context) (HostWatchdogStatus, error) {
	var out HostWatchdogStatus
	err := c.call(ctx, "/v1/status", struct{}{}, &out)
	return out, err
}

func prepareHostWatchdogFiles(ctx context.Context, c Config, s HostWatchdogSpec) (map[string][]byte, error) {
	if validateHostSpec(s) != nil || s.Instance != c.Central.Instance {
		return nil, errHostWatchdog
	}
	v, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		return nil, err
	}
	metadata, err := loadDeploymentMetadata(ctx, c.DeploymentTrust)
	if err != nil || metadata.release.manifest.Helper.SHA256 != s.HelperSHA256 {
		return nil, errHostWatchdog
	}
	artifact, err := hashTrustArtifact(ctx, s.HelperFile, 256<<20)
	if err != nil || artifact.SHA256 != s.HelperSHA256 {
		return nil, errHostWatchdog
	}
	installation, err := hashTrustArtifact(ctx, s.InstallationFile, 256<<20)
	if err != nil || installation.SHA256 != s.InstallationSHA256 {
		return nil, errHostWatchdog
	}
	s.KeyID = v.active
	s.Proof, err = hostSpecMAC(v, s)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(s)
	unit := []byte("[Unit]\nDescription=Webscan independent host watchdog and notification quota\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUMask=0077\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths=" + strconv.Quote(s.StateDirectory) + " " + strconv.Quote(filepath.Dir(s.Socket)) + "\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nExecStart=" + strconv.Quote(s.HelperFile) + " control-v3 --action run-host-watchdog --source " + strconv.Quote(c.HostWatchdog.SpecFile) + "\n\n[Install]\nWantedBy=multi-user.target\n")
	return map[string][]byte{"watchdog.json": raw, "watchdog.service": unit}, nil
}
