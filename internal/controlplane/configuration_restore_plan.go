package controlplane

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"webscan/internal/common"
)

// Planning is deliberately pure: it does not read local keys, open a network
// connection, write settings, restore a node version, or create a deployment.
// The later staging transaction must bind a fresh plan to the account, archive,
// desired-state snapshot, options and expiry before accepting destructive work.
type configurationRestoreOptions struct {
	UseBackupCredentials bool `json:"use_backup_credentials"`
}

type configurationRestoreNodeChange struct {
	Node   string   `json:"node"`
	Action string   `json:"action"`
	Fields []string `json:"fields"`
}

// Credential counters count protected branches, including opaque groups;
// they do not assert that a password/key is usable or that SSH will succeed.
type configurationRestoreSummary struct {
	SettingsChanged         bool                             `json:"settings_changed"`
	BootstrapChanged        bool                             `json:"bootstrap_changed"`
	Sections                []string                         `json:"sections"`
	Added                   int                              `json:"added"`
	Updated                 int                              `json:"updated"`
	Unchanged               int                              `json:"unchanged"`
	Removed                 int                              `json:"removed"`
	Nodes                   []configurationRestoreNodeChange `json:"nodes"`
	CredentialsKept         int                              `json:"credentials_kept"`
	CredentialsReplaced     int                              `json:"credentials_replaced"`
	CredentialsMissing      int                              `json:"credentials_missing"`
	MissingNodes            []string                         `json:"missing_nodes"`
	MissingSettings         bool                             `json:"missing_settings"`
	MissingBootstrap        bool                             `json:"missing_bootstrap"`
	RequiresCenterRestart   bool                             `json:"requires_center_restart"`
	RequiresLocalValidation bool                             `json:"requires_local_validation"`
	BlockedReasons          []string                         `json:"blocked_reasons"`
	CanPrepare              bool                             `json:"can_prepare"`
}

type configurationRestorePlan struct {
	Summary   configurationRestoreSummary
	Candidate configurationDocument
	// Present only after transactional stage revalidation. Never cached across
	// transactions or accepted from an API caller.
	Revision privateConfigurationRevision
}

var errConfigurationRestorePrivate = errors.New("私有恢复计划不能作为接口响应或日志输出")

func (configurationRestorePlan) String() string   { return "[private configuration restore plan]" }
func (configurationRestorePlan) GoString() string { return "[private configuration restore plan]" }
func (configurationRestorePlan) MarshalJSON() ([]byte, error) {
	return nil, errConfigurationRestorePrivate
}

func configurationRestoreEqual(a, b any) bool {
	return string(common.JSON(a)) == string(common.JSON(b))
}
func configurationRestoreClone(v any) (any, error) { return common.Decode(common.JSON(v)) }

// Full channels are an intentional credential boundary. Keeping only an SMTP
// password while restoring a different host would send that password to the
// backup's host. Recipients, endpoint and authentication therefore stay together
// by default. A caller must explicitly opt into the backup's channel identity.
func configurationRestorePrivateField(key string) bool {
	key = strings.ToLower(key)
	for _, part := range []string{"password", "secret", "token", "credential", "private_key", "webhook", "authorization"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	for _, suffix := range []string{"key_file", "key_files", "cert_file", "certificate_file"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	switch key {
	case "ca_file", "dsn_file", "revocation_file", "revocation_state_directory", "deployment_trust", "node_pki", "private", "email", "feishu":
		return true
	}
	return false
}
func configurationRestoreContainsPrivate(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if configurationRestorePrivateField(k) || configurationRestoreContainsPrivate(v) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if configurationRestoreContainsPrivate(v) {
				return true
			}
		}
	}
	return false
}

// Preserve private/opaque branches as a unit, including arrays whose elements
// contain identities. Never match credentials by an array position. Unknown
// settings and node groups cannot silently acquire restore/apply privileges.
func configurationRestoreMergePrivate(target, current map[string]any, prefix string, opaque func(string) bool, options configurationRestoreOptions, stats *configurationRestoreSummary) ([]string, error) {
	keys := map[string]bool{}
	for k := range target {
		keys[k] = true
	}
	for k := range current {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	missing := []string{}
	for _, k := range ordered {
		value, exists := target[k]
		old, oldExists := current[k]
		_, list := value.([]any)
		_, oldList := old.([]any)
		private := configurationRestorePrivateField(k) || (opaque != nil && opaque(k)) || ((list || oldList) && (configurationRestoreContainsPrivate(value) || configurationRestoreContainsPrivate(old)))
		if private {
			if options.UseBackupCredentials {
				if exists {
					if oldExists && configurationRestoreEqual(value, old) {
						stats.CredentialsKept++
					} else {
						stats.CredentialsReplaced++
					}
				}
				continue
			}
			if oldExists {
				copy, err := configurationRestoreClone(old)
				if err != nil {
					return nil, errConfigurationDocument
				}
				target[k] = copy
				stats.CredentialsKept++
			} else if exists {
				delete(target, k)
				missing = append(missing, prefix+"/"+configurationPointer(k))
				stats.CredentialsMissing++
			}
			continue
		}
		child, childOK := value.(map[string]any)
		oldChild, _ := old.(map[string]any)
		if childOK {
			paths, err := configurationRestoreMergePrivate(child, oldChild, prefix+"/"+configurationPointer(k), nil, options, stats)
			if err != nil {
				return nil, err
			}
			missing = append(missing, paths...)
		}
	}
	return missing, nil
}

func prepareConfigurationRestore(imported, current configurationDocument, options configurationRestoreOptions) (configurationRestorePlan, error) {
	var plan configurationRestorePlan
	candidate, _, err := resolveConfigurationOmissions(imported, current)
	if err != nil {
		return plan, err
	}
	summary := configurationRestoreSummary{Sections: []string{}, Nodes: []configurationRestoreNodeChange{}, MissingNodes: []string{}, BlockedReasons: []string{}}
	// Detect architectural changes before credential retention can replace a
	// branch that also contains topology information (for example HA members).
	beforeCentral, afterCentral := common.M(current.Bootstrap["central"]), common.M(candidate.Bootstrap["central"])
	beforeCollector, afterCollector := common.M(current.Bootstrap["collector"]), common.M(candidate.Bootstrap["collector"])
	topologyChanged := !configurationRestoreEqual(beforeCentral["topology"], afterCentral["topology"]) || !configurationRestoreEqual(beforeCollector["shards"], afterCollector["shards"]) || !configurationRestoreEqual(current.Bootstrap["ha"], candidate.Bootstrap["ha"])
	paths, err := configurationRestoreMergePrivate(candidate.Bootstrap, current.Bootstrap, "/bootstrap", nil, options, &summary)
	if err != nil {
		return plan, err
	}
	candidate.Omitted = append(candidate.Omitted, paths...)
	knownSettings := map[string]bool{"retention": true, "backup": true, "monitoring": true, "website_monitor": true}
	paths, err = configurationRestoreMergePrivate(candidate.Settings, current.Settings, "/settings", func(k string) bool { return !knownSettings[k] }, options, &summary)
	if err != nil {
		return plan, err
	}
	candidate.Omitted = normalizeConfigurationOmissions(append(candidate.Omitted, paths...))
	// Parsed documents use map[string]any throughout. Resolved profiles are
	// detached from both inputs and shared only for identical source/current
	// pairs; metadata and missing-field reporting remain bound to each node ID.
	profiles := map[string]configurationDocumentRules{}
	profileIDs := map[string]string{}
	ids := make([]string, 0, len(candidate.Nodes))
	for id := range candidate.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	knownRules := map[string]bool{"monitor": true, "scan": true, "resources": true, "transport": true, "probe_directory": true, "probe_seconds": true, "retention_days": true, "metrics_source_ip": true}
	type restorePair struct{ source, current string }
	type resolvedProfile struct {
		id             string
		kept, replaced int
		rulesChanged   bool
	}
	resolved := map[restorePair]resolvedProfile{}
	resolvedBytes := len(common.JSON(candidate.Bootstrap)) + len(common.JSON(candidate.Settings)) + len(common.JSON(candidate.Nodes)) + len(common.JSON(candidate.Omitted))
	modeChanged := false
	for _, id := range ids {
		n := candidate.Nodes[id]
		old, existed := current.Nodes[id]
		pair := restorePair{n.Profile, old.Profile}
		cached, exists := resolved[pair]
		profile := cached.id
		if exists {
			summary.CredentialsKept += cached.kept
			summary.CredentialsReplaced += cached.replaced
		} else {
			p := candidate.Profiles[n.Profile]
			config, err := configurationMap(p.Config)
			if err != nil {
				return plan, err
			}
			var previous map[string]any
			if existed {
				previous = current.Profiles[old.Profile].Config
			}
			kept, replaced := summary.CredentialsKept, summary.CredentialsReplaced
			paths, err := configurationRestoreMergePrivate(config, previous, "", func(k string) bool { return !knownRules[k] }, options, &summary)
			if err != nil {
				return plan, err
			}
			p.Config = config
			p.Omitted = normalizeConfigurationOmissions(append(p.Omitted, paths...))
			body := common.JSON([]any{p.Config, p.Omitted})
			key := digest(body)
			var reused bool
			profile, reused = profileIDs[key]
			if !reused {
				resolvedBytes += len(body)
				if resolvedBytes > configurationDocumentLimit {
					return plan, errConfigurationDocument
				}
				profile = "p" + strconv.Itoa(len(profiles)+1)
				profileIDs[key] = profile
				profiles[profile] = p
			}
			cached = resolvedProfile{profile, summary.CredentialsKept - kept, summary.CredentialsReplaced - replaced,
				!configurationRestoreEqual(p.Config, previous) || len(p.Omitted) > 0}
			resolved[pair] = cached
		}
		p := profiles[profile]

		n.Profile = profile
		fields := []string{}
		if !existed {
			n.Version = 1
			summary.Added++
			summary.Nodes = append(summary.Nodes, configurationRestoreNodeChange{id, "add", []string{"configuration"}})
		} else {
			// Backup versions are provenance, never desired-state version counters.
			n.Version = old.Version
			if n.Name != old.Name {
				fields = append(fields, "name")
			}
			if n.Endpoint != old.Endpoint {
				fields = append(fields, "endpoint")
			}
			if n.ServerName != old.ServerName {
				fields = append(fields, "server_name")
			}
			if n.Enabled != old.Enabled {
				fields = append(fields, "enabled")
			}
			if n.Mode != old.Mode {
				fields = append(fields, "mode")
				modeChanged = true
			}
			if cached.rulesChanged {
				fields = append(fields, "rules")
			}
			if len(fields) == 0 {
				summary.Unchanged++
			} else {
				summary.Updated++
				summary.Nodes = append(summary.Nodes, configurationRestoreNodeChange{id, "update", fields})
			}
		}
		candidate.Nodes[id] = n
		if len(n.Omitted) > 0 || len(p.Omitted) > 0 {
			summary.MissingNodes = append(summary.MissingNodes, id)
		}
	}
	candidate.Profiles = profiles
	candidate.SettingsVersion = current.SettingsVersion
	candidate.SettingsGeneration = current.SettingsGeneration
	candidate.BootstrapGeneration = current.BootstrapGeneration
	candidate.Created = current.Created
	for id := range current.Nodes {
		if _, exists := candidate.Nodes[id]; !exists {
			summary.Removed++
			summary.Nodes = append(summary.Nodes, configurationRestoreNodeChange{id, "remove", []string{"requires_uninstall"}})
		}
	}
	sort.Slice(summary.Nodes, func(i, j int) bool { return summary.Nodes[i].Node < summary.Nodes[j].Node })
	for _, path := range candidate.Omitted {
		if strings.HasPrefix(path, "/bootstrap/") {
			summary.MissingBootstrap = true
		}
		if strings.HasPrefix(path, "/settings/") {
			summary.MissingSettings = true
		}
	}
	summary.SettingsChanged = !configurationRestoreEqual(candidate.Settings, current.Settings)
	summary.BootstrapChanged = !configurationRestoreEqual(candidate.Bootstrap, current.Bootstrap)
	summary.RequiresCenterRestart = summary.BootstrapChanged
	// Even identical paths must be checked again: a key may have been removed
	// after capture. Pure document comparison cannot establish local readiness.
	summary.RequiresLocalValidation = true
	for _, section := range []string{"retention", "backup", "monitoring", "website_monitor", "email", "feishu"} {
		if !configurationRestoreEqual(candidate.Settings[section], current.Settings[section]) {
			summary.Sections = append(summary.Sections, section)
		}
	}
	// Unknown field names may themselves contain sensitive input. The public
	// summary reports only a fixed label rather than raw keys/values or digests.
	unknownChanged := false
	for k, v := range candidate.Settings {
		if !knownSettings[k] && k != "email" && k != "feishu" && !configurationRestoreEqual(v, current.Settings[k]) {
			unknownChanged = true
		}
	}
	for k := range current.Settings {
		if !knownSettings[k] && k != "email" && k != "feishu" {
			if _, exists := candidate.Settings[k]; !exists {
				unknownChanged = true
			}
		}
	}
	if unknownChanged {
		summary.Sections = append(summary.Sections, "other")
	}
	if topologyChanged {
		summary.BlockedReasons = append(summary.BlockedReasons, "topology_migration_required")
	}
	if modeChanged {
		summary.BlockedReasons = append(summary.BlockedReasons, "node_mode_migration_required")
	}
	if summary.Removed > 0 {
		summary.BlockedReasons = append(summary.BlockedReasons, "node_uninstall_required")
	}
	if !candidate.complete() {
		summary.BlockedReasons = append(summary.BlockedReasons, "configuration_incomplete")
	}
	if candidate.validate() != nil {
		return plan, errConfigurationDocument
	}
	// Count unresolved private branches after all omission resolution, including
	// fields absent from a redacted archive rather than present in its payload.
	summary.CredentialsMissing = 0
	for _, path := range candidate.Omitted {
		parts, ok := configurationParts(path)
		if !ok {
			continue
		}
		if len(parts) >= 2 && parts[0] == "settings" && !knownSettings[parts[1]] {
			summary.CredentialsMissing++
			continue
		}
		for _, part := range parts {
			if configurationRestorePrivateField(part) {
				summary.CredentialsMissing++
				break
			}
		}
	}
	for _, n := range candidate.Nodes {
		for _, path := range candidate.Profiles[n.Profile].Omitted {
			parts, ok := configurationParts(path)
			if !ok || len(parts) == 0 {
				continue
			}
			if !knownRules[parts[0]] {
				summary.CredentialsMissing++
				continue
			}
			for _, part := range parts {
				if configurationRestorePrivateField(part) {
					summary.CredentialsMissing++
					break
				}
			}
		}
	}
	summary.CanPrepare = len(summary.BlockedReasons) == 0
	plan.Summary, plan.Candidate = summary, candidate
	return plan, nil
}
