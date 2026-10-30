package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
	"webscan/internal/common"
	"webscan/internal/nodeconfig"
	"webscan/internal/notify"
)

// This is a PRIVATE, versioned configuration document, not an API/status model.
// It contains desired settings, not events, accounts, SSH vault contents, PKI,
// deployment checkpoints or proof that any setting has been applied. In v3 the
// bootstrap YAML alone is not a complete configuration backup.
//
// The combined document has a separate bound from the unchanged 2 MiB bootstrap
// and v2 YAML limits: metadata for 20,000 nodes cannot fit in those older bounds.
const configurationDocumentLimit = 32 << 20
const configurationEncryptedLimit = 34 << 20
const configurationNodeLimit = 20000

var errConfigurationDocument = errors.New("部署配置备份版本、格式、参数或大小不正确")
var errConfigurationPassword = errors.New("密码不正确、加密包损坏或解密参数超限")

type configurationDocument struct {
	Format              int                           `yaml:"format_version"`
	Kind                string                        `yaml:"kind"`
	Created             string                        `yaml:"created_at"`
	SettingsVersion     int64                         `yaml:"settings_version"`
	SettingsGeneration  int64                         `yaml:"settings_generation,omitempty"`
	BootstrapGeneration int64                         `yaml:"bootstrap_generation,omitempty"`
	Bootstrap           configurationValues           `yaml:"bootstrap"`
	Settings            configurationValues           `yaml:"settings"`
	Nodes               configurationDocumentNodes    `yaml:"nodes"`
	Profiles            configurationDocumentProfiles `yaml:"profiles"`
	Omitted             []string                      `yaml:"omitted_fields"`
}

type configurationDocumentNode struct {
	Name       string   `yaml:"name,omitempty"`
	Endpoint   string   `yaml:"endpoint,omitempty"`
	ServerName string   `yaml:"server_name,omitempty"`
	Enabled    bool     `yaml:"enabled"`
	Mode       string   `yaml:"mode"`
	Version    int64    `yaml:"version"`
	Profile    string   `yaml:"profile"`
	Omitted    []string `yaml:"omitted_fields"`
}

type configurationDocumentRules struct {
	Config  configurationValues `yaml:"config"`
	Omitted []string            `yaml:"omitted_fields"`
}

// Keep unknown configuration numbers lossless as well. A JSON -> float64 ->
// YAML conversion otherwise changes identifiers/counters above 2^53. The YAML
// node tree preserves their decimal text without interpreting it as a float.
type configurationValues map[string]any

func (m configurationValues) MarshalYAML() (any, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, errConfigurationDocument
	}
	v, err := common.Decode(raw)
	if err != nil {
		return nil, errConfigurationDocument
	}
	return configurationYAMLNode(v), nil
}

func configurationYAMLNode(v any) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode}
	switch x := v.(type) {
	case map[string]any:
		n.Kind, n.Tag = yaml.MappingNode, "!!map"
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			n.Content = append(n.Content, configurationYAMLNode(key), configurationYAMLNode(x[key]))
		}
	case []any:
		n.Kind, n.Tag = yaml.SequenceNode, "!!seq"
		for _, value := range x {
			n.Content = append(n.Content, configurationYAMLNode(value))
		}
	case json.Number:
		n.Tag, n.Value = "!!int", x.String()
		if strings.ContainsAny(n.Value, ".eE") {
			n.Tag = "!!float"
		}
	case string:
		n.Tag, n.Value = "!!str", x
	case bool:
		n.Tag, n.Value = "!!bool", strconv.FormatBool(x)
	case nil:
		n.Tag, n.Value = "!!null", "null"
	}
	return n
}

func (m *configurationValues) UnmarshalYAML(n *yaml.Node) error {
	v, err := configurationYAMLValue(n)
	object, ok := v.(map[string]any)
	if err != nil || !ok {
		return errConfigurationDocument
	}
	*m = object
	return nil
}

func configurationYAMLValue(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			value, err := configurationYAMLValue(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[n.Content[i].Value] = value
		}
		return out, nil
	case yaml.SequenceNode:
		out := []any{}
		for _, child := range n.Content {
			value, err := configurationYAMLValue(child)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			return n.Value, nil
		case "!!null":
			return nil, nil
		case "!!bool":
			if n.Value == "true" {
				return true, nil
			}
			if n.Value == "false" {
				return false, nil
			}
		case "!!int", "!!float":
			dec := json.NewDecoder(strings.NewReader(n.Value))
			dec.UseNumber()
			var v any
			if dec.Decode(&v) == nil && dec.Decode(new(any)) == io.EOF {
				if number, ok := v.(json.Number); ok {
					return number, nil
				}
			}
		}
	}
	return nil, errConfigurationDocument
}

func (configurationDocument) String() string   { return "[private v3 configuration document]" }
func (configurationDocument) GoString() string { return "[private v3 configuration document]" }

// Refuse accidental use as an HTTP response or audit/idempotency payload.
func (configurationDocument) MarshalJSON() ([]byte, error) {
	return nil, errors.New("部署配置备份不能作为 JSON 状态返回")
}

func configurationMap(v any) (configurationValues, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > configurationDocumentLimit {
		return nil, errConfigurationDocument
	}
	var out configurationValues
	if decodeConfigurationObject(raw, &out) != nil {
		return nil, errConfigurationDocument
	}
	return out, nil
}

// Only capture a single repeatable-read PG snapshot. No workers, remote calls,
// file credentials or writes are involved. The caller supplies its already
// validated bootstrap snapshot; capturing the disk/applied difference belongs
// to the later staged settings workflow, not this read-only primitive.
func (s *Store) captureConfigurationDocument(ctx context.Context, c Config) (configurationDocument, error) {
	if c.Validate() != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return configurationDocument{}, safeMappingError(err)
	}
	defer tx.Rollback()
	doc, err := captureConfigurationDocumentTx(ctx, tx, c)
	if err != nil {
		return configurationDocument{}, err
	}
	if err = tx.Commit(); err != nil {
		return configurationDocument{}, safeMappingError(err)
	}
	return doc, nil
}

// The caller must use repeatable-read (or stronger), or a read-committed
// transaction holding the configuration restore relation gate, and validated
// bootstrap settings. A manual backup uses its receipt's snapshot and insert.
func captureConfigurationDocumentTx(ctx context.Context, tx *sql.Tx, c Config, vaults ...*Vault) (configurationDocument, error) {
	if c.Validate() != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	state, err := readSettingsDraftTx(ctx, tx, false)
	if err != nil {
		return configurationDocument{}, safeMappingError(err)
	}
	var v *Vault
	if len(vaults) > 0 {
		v = vaults[0]
	}
	if state.Generation > 0 {
		if len(vaults) == 0 {
			v, err = OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		}
		if err != nil || checkSettingsDraftProof(v, state) != nil {
			return configurationDocument{}, errSettingsDraft
		}
	}
	bootstrap, err := readBootstrapDraftTx(ctx, tx, v, c)
	if err != nil {
		return configurationDocument{}, err
	}
	settings, version, generation, now := []byte(state.Desired), state.RuntimeVersion, state.Generation, time.Now().UTC()
	rows, err := tx.QueryContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL ORDER BY id")
	if err != nil {
		return configurationDocument{}, safeMappingError(err)
	}
	defer rows.Close()
	nodes := []Node{}
	size := len(settings)
	configs := map[string]json.RawMessage{}
	for rows.Next() {
		n, e := scanNode(rows)
		if e != nil {
			return configurationDocument{}, safeMappingError(e)
		}
		if len(n.Config) > nodeconfig.MaxBytes {
			return configurationDocument{}, errConfigurationDocument
		}
		// Bound allocation even before profile deduplication. This guard counts
		// node metadata plus unique config bodies, not repeated common rules.
		size += len(n.ID) + len(n.Name) + len(n.Endpoint) + len(n.ServerName) + 128
		key := digest(n.Config)
		if previous, ok := configs[key]; ok {
			n.Config = previous
		} else {
			configs[key] = n.Config
			size += len(n.Config)
		}
		if len(nodes) >= configurationNodeLimit || size > configurationDocumentLimit {
			return configurationDocument{}, errConfigurationDocument
		}
		nodes = append(nodes, n)
	}
	if err = rows.Err(); err != nil {
		return configurationDocument{}, safeMappingError(err)
	}
	doc, err := newConfigurationDocument(c, settings, version, nodes, now)
	doc.SettingsGeneration = generation
	if err != nil {
		return configurationDocument{}, err
	}
	doc.Bootstrap = bootstrap.Desired
	doc.BootstrapGeneration = bootstrap.Generation
	if doc.validate() != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	return doc, nil
}

func newConfigurationDocument(c Config, settings []byte, version int64, nodes []Node, now time.Time) (configurationDocument, error) {
	doc := configurationDocument{Format: 3, Kind: "webscan-configuration", Created: now.UTC().Format(time.RFC3339Nano), SettingsVersion: version,
		Nodes: map[string]configurationDocumentNode{}, Profiles: map[string]configurationDocumentRules{}, Omitted: []string{}}
	if c.Validate() != nil || len(nodes) > configurationNodeLimit || len(settings) > 2<<20 {
		return configurationDocument{}, errConfigurationDocument
	}
	bootstrap, err := yaml.Marshal(c)
	if err != nil || yaml.Unmarshal(bootstrap, &doc.Bootstrap) != nil || decodeConfigurationObject(settings, &doc.Settings) != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	// Never sort the caller's slice in place or retain aliases to mutable data.
	nodes = append([]Node{}, nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	profiles := map[string]string{}
	validatedProfiles := map[string]string{}
	uniqueBytes := 0
	for _, n := range nodes {
		if n.Validate() != nil || n.Version < 1 || doc.Nodes[n.ID].Version != 0 || len(n.Config) > nodeconfig.MaxBytes {
			return configurationDocument{}, errConfigurationDocument
		}
		if len(n.Config) == 0 {
			n.Config = []byte(`{}`)
		}
		// Identical shared rules need decoding/validation only once. This cache
		// is local to the capture; every node identity is still validated above.
		rawKey := digest(n.Config)
		profile, validated := validatedProfiles[rawKey]
		if !validated {
			var config configurationValues
			if decodeConfigurationObject(n.Config, &config) != nil || validateConfigurationRules(config) != nil {
				return configurationDocument{}, errConfigurationDocument
			}
			body := common.JSON(config)
			// Hashes only index private in-memory maps. Public IDs are sequential.
			key := digest(body)
			var exists bool
			profile, exists = profiles[key]
			if !exists {
				uniqueBytes += len(body)
				if uniqueBytes > configurationDocumentLimit {
					return configurationDocument{}, errConfigurationDocument
				}
				profile = "p" + strconv.Itoa(len(profiles)+1)
				profiles[key] = profile
				doc.Profiles[profile] = configurationDocumentRules{Config: config, Omitted: []string{}}
			}
			validatedProfiles[rawKey] = profile
		}
		doc.Nodes[n.ID] = configurationDocumentNode{Name: n.Name, Endpoint: n.Endpoint, ServerName: n.ServerName,
			Enabled: n.Enabled, Mode: n.Mode, Version: n.Version, Profile: profile, Omitted: []string{}}
	}
	if doc.validate() != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	return doc, nil
}

func decodeConfigurationObject(raw []byte, target *configurationValues) error {
	check := json.NewDecoder(bytes.NewReader(raw))
	check.UseNumber()
	if len(raw) == 0 || !utf8.Valid(raw) || uniqueBackupJSON(check, 0) != nil {
		return errConfigurationDocument
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(target) != nil || *target == nil || d.Decode(new(any)) != io.EOF {
		return errConfigurationDocument
	}
	return nil
}

func validateConfigurationRules(m common.Map) error {
	if _, err := nodeRuntimeSettings(common.JSON(m)); err != nil || configurationMasks(m) {
		return errConfigurationDocument
	}
	return nil
}

func configurationMasks(v any) bool {
	switch x := v.(type) {
	case configurationValues:
		return configurationMasks(common.Map(x))
	case map[string]any:
		for key, value := range x {
			k := strings.ToLower(key)
			if strings.Contains(k, "password") || strings.Contains(k, "secret") || strings.Contains(k, "private_key") || strings.Contains(k, "token") {
				if text, ok := value.(string); ok {
					text = strings.TrimSpace(text)
					if text == "已配置" || text == "[已隐藏]" || text == "<redacted>" || text != "" && strings.Trim(text, "*•●") == "" {
						return true
					}
				}
			}
			if configurationMasks(value) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if configurationMasks(value) {
				return true
			}
		}
	}
	return false
}

func (d configurationDocument) validate() error {
	if d.Format != 3 || d.Kind != "webscan-configuration" || d.SettingsVersion < 1 || d.SettingsGeneration < 0 || d.BootstrapGeneration < 0 || d.Bootstrap == nil || d.Settings == nil || d.Nodes == nil || d.Profiles == nil || len(d.Nodes) > configurationNodeLimit || len(d.Profiles) > len(d.Nodes) || configurationMasks(d.Bootstrap) || configurationMasks(d.Settings) {
		return errConfigurationDocument
	}
	if _, err := time.Parse(time.RFC3339Nano, d.Created); err != nil || !validConfigurationOmissions(d.Omitted, map[string]any{"bootstrap": common.Map(d.Bootstrap), "settings": common.Map(d.Settings)}) {
		return errConfigurationDocument
	}
	used := map[string]bool{}
	for id, n := range d.Nodes {
		if !identifier.MatchString(id) || n.Version < 1 || !identifier.MatchString(n.Profile) || n.Mode != "native" && n.Mode != "docker" || len(n.Omitted) > 3 {
			return errConfigurationDocument
		}
		fields := map[string]any{}
		for k, v := range map[string]string{"name": n.Name, "endpoint": n.Endpoint, "server_name": n.ServerName} {
			if v != "" {
				fields[k] = v
			}
		}
		if !validConfigurationOmissions(n.Omitted, fields) {
			return errConfigurationDocument
		}
		for _, path := range n.Omitted {
			if path != "/name" && path != "/endpoint" && path != "/server_name" {
				return errConfigurationDocument
			}
		}
		if n.Name == "" && !containsConfigurationPath(n.Omitted, "/name") || n.Endpoint == "" && !containsConfigurationPath(n.Omitted, "/endpoint") || n.ServerName == "" && !containsConfigurationPath(n.Omitted, "/server_name") {
			return errConfigurationDocument
		}
		// Validate available values without inventing values for omitted ones.
		if n.Name != "" && (strings.TrimSpace(n.Name) == "" || len(n.Name) > 256) {
			return errConfigurationDocument
		}
		if n.Endpoint != "" || n.ServerName != "" {
			candidate := Node{ID: id, Name: "validation", Endpoint: n.Endpoint, ServerName: n.ServerName, Mode: n.Mode}
			if candidate.Endpoint == "" {
				candidate.Endpoint = "127.0.0.1:19100"
			}
			if candidate.ServerName == "" {
				candidate.ServerName = "validation.invalid"
			}
			if candidate.Validate() != nil {
				return errConfigurationDocument
			}
		}
		if _, ok := d.Profiles[n.Profile]; !ok {
			return errConfigurationDocument
		}
		used[n.Profile] = true
	}
	for id, profile := range d.Profiles {
		if !used[id] || profile.Config == nil || !validConfigurationOmissions(profile.Omitted, profile.Config) || len(common.JSON(profile.Config)) > nodeconfig.MaxBytes || validateConfigurationRules(profile.Config) != nil {
			return errConfigurationDocument
		}
	}
	if _, err := retentionPolicy(d.Settings); err != nil {
		return errConfigurationDocument
	}
	if len(common.JSON(d.Settings)) > 2<<20 {
		return errConfigurationDocument
	}
	for _, channel := range []string{"email", "feishu"} {
		if value, exists := d.Settings[channel]; exists {
			if _, ok := value.(map[string]any); !ok {
				return errConfigurationDocument
			}
		}
	}
	if err := notify.Validate(common.M(d.Settings["email"])); err != nil {
		return errConfigurationDocument
	}
	var c Config
	raw, err := json.Marshal(d.Bootstrap)
	if err != nil || len(raw) > 2<<20 {
		return errConfigurationDocument
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if dec.Decode(&c) != nil {
		return errConfigurationDocument
	}
	// A redacted channel is absent, never a fake password accepted as a value.
	if len(d.Omitted) == 0 {
		if c.Validate() != nil {
			return errConfigurationDocument
		}
	}
	return nil
}

func containsConfigurationPath(paths []string, path string) bool {
	for _, p := range paths {
		if p == path {
			return true
		}
	}
	return false
}

func configurationPointer(key string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(key)
}
func configurationParts(path string) ([]string, bool) {
	if len(path) < 2 || len(path) > 1024 || path[0] != '/' {
		return nil, false
	}
	parts := strings.Split(path[1:], "/")
	if len(parts) > 16 {
		return nil, false
	}
	for i, p := range parts {
		if p == "" || strings.ContainsAny(p, "\x00\r\n") {
			return nil, false
		}
		decoded := strings.NewReplacer("~1", "/", "~0", "~").Replace(p)
		if configurationPointer(decoded) != p {
			return nil, false
		}
		parts[i] = decoded
	}
	return parts, true
}

// Omissions must name absent map fields, never list offsets. This makes a
// restore stable when node order changes and prevents omissions overwriting a
// supplied value. Ancestor/child overlaps and duplicate paths are rejected.
func validConfigurationOmissions(paths []string, root map[string]any) bool {
	if paths == nil || len(paths) > 4096 {
		return false
	}
	seen := map[string]bool{}
	for _, path := range paths {
		parts, ok := configurationParts(path)
		if !ok || seen[path] {
			return false
		}
		seen[path] = true
		m := root
		for i, p := range parts {
			value, exists := m[p]
			if i == len(parts)-1 {
				if exists {
					return false
				}
				break
			}
			var mapOK bool
			m, mapOK = value.(map[string]any)
			if !exists || !mapOK {
				return false
			}
		}
	}
	for path := range seen {
		for p := path; strings.LastIndex(p, "/") > 0; {
			p = p[:strings.LastIndex(p, "/")]
			if seen[p] {
				return false
			}
		}
	}
	return true
}

// Public projection is allowlisted. Unrecognized future/private fields are
// omitted with an explicit path instead of accidentally exporting credentials.
// Full encrypted documents preserve all JSON fields, including unknown ones.
func projectConfiguration(m, shape common.Map, prefix string, omitted *[]string) common.Map {
	out := common.Map{}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := m[key]
		pattern, ok := shape[key]
		path := prefix + "/" + configurationPointer(key)
		if !ok {
			*omitted = append(*omitted, path)
			continue
		}
		if object, ok := pattern.(map[string]any); ok {
			child, valid := value.(map[string]any)
			if !valid {
				*omitted = append(*omitted, path)
				continue
			}
			out[key] = projectConfiguration(child, object, path, omitted)
		} else if matchingConfigurationType(value, pattern) {
			if list, ok := value.([]any); ok {
				out[key] = append([]any{}, list...)
			} else {
				out[key] = value
			}
		} else {
			*omitted = append(*omitted, path)
		}
	}
	return out
}

func matchingConfigurationType(value, pattern any) bool {
	switch pattern.(type) {
	case string:
		_, ok := value.(string)
		return ok
	case bool:
		_, ok := value.(bool)
		return ok
	case float64, json.Number:
		switch value.(type) {
		case float64, json.Number:
			return true
		}
		return false
	case []any:
		list, ok := value.([]any)
		if !ok {
			return false
		}
		for _, v := range list {
			if _, ok := v.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}

func (d configurationDocument) redacted() (configurationDocument, error) {
	if d.validate() != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	bootstrapShape := common.Map{
		"config_version": float64(3), "central": common.Map{"topology": "", "instance_id": ""},
		"database": common.Map{"max_connections": float64(0)}, "metrics": common.Map{},
		"collector": common.Map{"shards": float64(0), "concurrency": float64(0), "interval_seconds": float64(0)},
		"executor":  common.Map{"enabled": false, "concurrency": float64(0), "applications_enabled": false}, "node_pki": common.Map{"enabled": false},
	}
	// Normalize YAML-derived numeric/map types before the public projection.
	bootstrap, err := configurationMap(d.Bootstrap)
	if err != nil {
		return configurationDocument{}, err
	}
	out := d
	out.Omitted = append([]string{}, d.Omitted...)
	out.Bootstrap = projectConfiguration(bootstrap, bootstrapShape, "/bootstrap", &out.Omitted)
	settingsShape := common.Map{}
	for _, section := range []string{"retention", "backup", "monitoring", "website_monitor"} {
		// Only recognized policy fields are public; channel configuration is
		// always omitted as a whole, including recipient addresses.
		settingsShape[section] = configurationPublicSettingsShape(section)
	}
	out.Settings = projectConfiguration(d.Settings, settingsShape, "/settings", &out.Omitted)
	ruleShape, _ := configurationMap(nodeconfig.DefaultSettings())
	delete(ruleShape, "metrics_source_ip")
	out.Nodes = map[string]configurationDocumentNode{}
	out.Profiles = map[string]configurationDocumentRules{}
	profiles := map[string]string{}
	ids := make([]string, 0, len(d.Nodes))
	for id := range d.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := d.Nodes[id]
		p := configurationDocumentRules{Omitted: append([]string{}, d.Profiles[n.Profile].Omitted...)}
		p.Config = projectConfiguration(d.Profiles[n.Profile].Config, ruleShape, "", &p.Omitted)
		p.Omitted = normalizeConfigurationOmissions(p.Omitted)
		key := digest(common.JSON([]any{p.Config, p.Omitted}))
		profile, ok := profiles[key]
		if !ok {
			profile = "p" + strconv.Itoa(len(profiles)+1)
			profiles[key] = profile
			out.Profiles[profile] = p
		}
		n.Name, n.Endpoint, n.ServerName, n.Profile = "", "", "", profile
		n.Omitted = []string{"/name", "/endpoint", "/server_name"}
		out.Nodes[id] = n
	}
	out.Omitted = normalizeConfigurationOmissions(out.Omitted)
	if out.validate() != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	return out, nil
}

func normalizeConfigurationOmissions(paths []string) []string {
	paths = append([]string{}, paths...)
	sort.Strings(paths)
	out := []string{}
	for _, path := range paths {
		if len(out) > 0 && (path == out[len(out)-1] || strings.HasPrefix(path, out[len(out)-1]+"/")) {
			continue
		}
		out = append(out, path)
	}
	return out
}

func configurationPublicSettingsShape(section string) common.Map {
	shape := common.Map{}
	var numbers, booleans, texts string
	switch section {
	case "retention":
		numbers = "sqlite_events_days security_events_days website_incidents_days server_alerts_days delivery_records_days prometheus_days loki_days local_logs_days"
	case "backup":
		numbers = "keep_days"
		booleans = "enabled include_sqlite include_runtime_config include_node_passwords"
		texts = "time timezone"
	case "website_monitor":
		numbers = "interval_seconds timeout_seconds max_concurrent"
		booleans = "enabled"
	case "monitoring":
		numbers = "raw_hours history_days interval_seconds repeat_hours group_wait_seconds group_interval_seconds"
		booleans = "alert_on_inotify_overflow alert_on_dropped_events"
		texts = "mode"
		alerts := common.Map{}
		for _, k := range strings.Fields("cpu_warning_percent cpu_recovery_percent cpu_duration_seconds memory_warning_percent memory_recovery_percent memory_duration_seconds node_unreachable_seconds agent_stopped_seconds local_probe_stale_seconds central_probe_stale_seconds loki_probe_stale_seconds oldest_pending_task_seconds disk_warning_percent disk_critical_percent inode_warning_percent inode_critical_percent clock_offset_warning_seconds clock_failure_duration_seconds") {
			alerts[k] = float64(0)
		}
		alerts["cpu_enabled"], alerts["memory_enabled"] = false, false
		shape["alerts"] = alerts
	}
	for _, key := range strings.Fields(numbers) {
		shape[key] = float64(0)
	}
	for _, key := range strings.Fields(booleans) {
		shape[key] = false
	}
	for _, key := range strings.Fields(texts) {
		shape[key] = ""
	}
	return shape
}

func marshalConfigurationDocument(d configurationDocument) ([]byte, error) {
	if d.validate() != nil {
		return nil, errConfigurationDocument
	}
	raw, err := yaml.Marshal(d)
	if err != nil || len(raw) > configurationDocumentLimit {
		return nil, errConfigurationDocument
	}
	return raw, nil
}

func parseConfigurationDocument(raw []byte) (configurationDocument, error) {
	var d configurationDocument
	if len(raw) == 0 || len(raw) > configurationDocumentLimit || !utf8.Valid(raw) {
		return d, errConfigurationDocument
	}
	var tree yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if dec.Decode(&tree) != nil || dec.Decode(new(any)) != io.EOF || !safeConfigurationYAML(&tree, 0) {
		return d, errConfigurationDocument
	}
	// The tree has already passed recursive duplicate/type/alias checks. Decode
	// that tree once rather than scanning the complete large YAML a second time.
	// Custom map decoders enforce their own entry fields; keep root fields strict
	// here because Node.Decode does not expose KnownFields.
	fields := map[string]bool{"format_version": true, "kind": true, "created_at": true, "settings_version": true,
		"settings_generation": true, "bootstrap_generation": true, "bootstrap": true, "settings": true,
		"nodes": true, "profiles": true, "omitted_fields": true}
	if len(tree.Content) != 1 || tree.Content[0].Kind != yaml.MappingNode {
		return configurationDocument{}, errConfigurationDocument
	}
	for i := 0; i < len(tree.Content[0].Content); i += 2 {
		if !fields[tree.Content[0].Content[i].Value] {
			return configurationDocument{}, errConfigurationDocument
		}
	}
	if tree.Decode(&d) != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	// YAML does not normalize numbers to JSON float64. Reuse the JSON-backed
	// policy validators and projection with a detached, normalized map.
	var err error
	if d.Bootstrap, err = configurationMap(d.Bootstrap); err != nil {
		return configurationDocument{}, err
	}
	if d.Settings, err = configurationMap(d.Settings); err != nil {
		return configurationDocument{}, err
	}
	for id, p := range d.Profiles {
		if p.Config, err = configurationMap(p.Config); err != nil {
			return configurationDocument{}, err
		}
		d.Profiles[id] = p
	}
	if d.validate() != nil {
		return configurationDocument{}, errConfigurationDocument
	}
	return d, nil
}

func safeConfigurationYAML(n *yaml.Node, depth int) bool {
	if depth > 20 || n.Alias != nil || n.Anchor != "" || n.Kind == yaml.AliasNode {
		return false
	}
	if n.Kind == yaml.MappingNode && n.Tag != "!!map" || n.Kind == yaml.SequenceNode && n.Tag != "!!seq" {
		return false
	}
	if n.Kind == yaml.ScalarNode && n.Tag != "!!str" && n.Tag != "!!int" && n.Tag != "!!bool" && n.Tag != "!!float" && n.Tag != "!!null" {
		return false
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" || seen[key.Value] {
				return false
			}
			seen[key.Value] = true
		}
	}
	for _, child := range n.Content {
		if !safeConfigurationYAML(child, depth+1) {
			return false
		}
	}
	return true
}

// No password is retained in a document or error. Admission/rate limiting and
// the trusted HTTPS boundary belong to the eventual authenticated API layer.
func encryptConfigurationDocument(d configurationDocument, password, confirm string) ([]byte, error) {
	if len(password) < 12 || len(password) > 1024 || password != confirm {
		return nil, errors.New("加密密码至少 12 字节、最多 1024 字节且两次输入必须一致")
	}
	raw, err := marshalConfigurationDocument(d)
	if err != nil {
		return nil, err
	}
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, errConfigurationPassword
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, errConfigurationPassword
	}
	if _, err = w.Write(raw); err != nil {
		return nil, errConfigurationPassword
	}
	if err = w.Close(); err != nil || out.Len() > configurationEncryptedLimit {
		return nil, errConfigurationPassword
	}
	return out.Bytes(), nil
}

func decryptConfigurationDocument(raw []byte, password string) (configurationDocument, error) {
	if len(raw) == 0 || len(raw) > configurationEncryptedLimit || len(password) < 12 || len(password) > 1024 {
		return configurationDocument{}, errConfigurationPassword
	}
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return configurationDocument{}, errConfigurationPassword
	}
	identity.SetMaxWorkFactor(18)
	r, err := age.Decrypt(bytes.NewReader(raw), identity)
	if err != nil {
		return configurationDocument{}, errConfigurationPassword
	}
	plain, err := io.ReadAll(io.LimitReader(r, configurationDocumentLimit+1))
	if err != nil || len(plain) > configurationDocumentLimit {
		return configurationDocument{}, errConfigurationPassword
	}
	d, err := parseConfigurationDocument(plain)
	if err != nil {
		return configurationDocument{}, errConfigurationPassword
	}
	return d, nil
}

// Resolve omitted values only; never activate them. Profiles are expanded per
// node before merging, so a shared redacted profile cannot borrow another
// node's private settings. The caller must still preview, stage, validate and
// apply through the future settings workflow; this helper performs no writes.
func resolveConfigurationOmissions(imported, current configurationDocument) (configurationDocument, []string, error) {
	if imported.validate() != nil || current.validate() != nil || !current.complete() {
		return configurationDocument{}, nil, errConfigurationDocument
	}
	raw, err := marshalConfigurationDocument(imported)
	if err != nil {
		return configurationDocument{}, nil, err
	}
	// Keep the encoded size gate, but do not parse our already validated in-memory
	// document again just to detach mutable maps. Each profile is cloned below
	// before merging; no input map or omission slice may become a write target.
	clear(raw)
	out := imported
	out.Bootstrap, err = configurationMap(imported.Bootstrap)
	if err != nil {
		return configurationDocument{}, nil, err
	}
	out.Settings, err = configurationMap(imported.Settings)
	if err != nil {
		return configurationDocument{}, nil, err
	}
	out.Omitted = append([]string{}, imported.Omitted...)
	out.Nodes = make(configurationDocumentNodes, len(imported.Nodes))
	for id, n := range imported.Nodes {
		n.Omitted = append([]string{}, n.Omitted...)
		out.Nodes[id] = n
	}
	out.Profiles = make(configurationDocumentProfiles, len(imported.Profiles))
	for id, p := range imported.Profiles {
		p.Omitted = append([]string{}, p.Omitted...)
		out.Profiles[id] = p
	}
	missing := []string{}
	root := map[string]any{"bootstrap": common.Map(out.Bootstrap), "settings": common.Map(out.Settings)}
	old := map[string]any{"bootstrap": common.Map(current.Bootstrap), "settings": common.Map(current.Settings)}
	out.Omitted = mergeConfigurationPaths(root, old, out.Omitted)
	missing = append(missing, out.Omitted...)
	profiles := map[string]configurationDocumentRules{}
	profileKeys := map[string]string{}
	// A common rule body may be shared by 20,000 nodes. Resolve once per pair
	// of source/current profile identities, while still matching metadata and
	// reporting missing paths for each individual node identity.
	type profilePair struct{ source, current string }
	resolvedProfiles := map[profilePair]string{}
	resolvedBytes := len(common.JSON(out.Bootstrap)) + len(common.JSON(out.Settings)) + len(common.JSON(out.Nodes)) + len(common.JSON(out.Omitted))
	ids := make([]string, 0, len(out.Nodes))
	for id := range out.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n, previous := out.Nodes[id], current.Nodes[id]
		fields := map[string]any{}
		oldFields := map[string]any{}
		for key, value := range map[string]string{"name": previous.Name, "endpoint": previous.Endpoint, "server_name": previous.ServerName} {
			if previous.Version > 0 {
				oldFields[key] = value
			}
		}
		n.Omitted = mergeConfigurationPaths(fields, oldFields, n.Omitted)
		if v, ok := fields["name"].(string); ok {
			n.Name = v
		}
		if v, ok := fields["endpoint"].(string); ok {
			n.Endpoint = v
		}
		if v, ok := fields["server_name"].(string); ok {
			n.ServerName = v
		}
		pair := profilePair{n.Profile, previous.Profile}
		profile, cached := resolvedProfiles[pair]
		if !cached {
			p := out.Profiles[n.Profile]
			p.Config, err = configurationMap(p.Config)
			if err != nil {
				return configurationDocument{}, nil, err
			}
			p.Omitted = mergeConfigurationPaths(p.Config, current.Profiles[previous.Profile].Config, p.Omitted)
			body := common.JSON([]any{p.Config, p.Omitted})
			key := digest(body)
			var exists bool
			profile, exists = profileKeys[key]
			if !exists {
				resolvedBytes += len(body)
				if resolvedBytes > configurationDocumentLimit {
					return configurationDocument{}, nil, errConfigurationDocument
				}
				profile = "p" + strconv.Itoa(len(profiles)+1)
				profileKeys[key] = profile
				profiles[profile] = p
			}
			resolvedProfiles[pair] = profile
		}
		for _, path := range n.Omitted {
			missing = append(missing, "/nodes/"+configurationPointer(id)+path)
		}
		for _, path := range profiles[profile].Omitted {
			missing = append(missing, "/nodes/"+configurationPointer(id)+"/config"+path)
		}
		n.Profile = profile
		out.Nodes[id] = n
	}
	out.Profiles = profiles
	if out.validate() != nil {
		return configurationDocument{}, nil, errConfigurationDocument
	}
	return out, missing, nil
}

func (d configurationDocument) complete() bool {
	if len(d.Omitted) != 0 {
		return false
	}
	for _, n := range d.Nodes {
		if len(n.Omitted) != 0 {
			return false
		}
	}
	for _, p := range d.Profiles {
		if len(p.Omitted) != 0 {
			return false
		}
	}
	return true
}

func mergeConfigurationPaths(target, old map[string]any, paths []string) []string {
	missing := []string{}
	for _, path := range paths {
		parts, _ := configurationParts(path)
		to, from := target, old
		for _, part := range parts[:len(parts)-1] {
			to, _ = to[part].(map[string]any)
			from, _ = from[part].(map[string]any)
		}
		last := parts[len(parts)-1]
		value, found := from[last]
		if !found || to == nil {
			missing = append(missing, path)
			continue
		}
		// Normalize/detach without exposing this private value in any receipt.
		body := common.JSON(value)
		copy, err := common.Decode(body)
		if err != nil {
			missing = append(missing, path)
			continue
		}
		to[last] = copy
	}
	return missing
}

var _ fmt.Stringer = configurationDocument{}
