package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type migrationCommandRequest struct {
	Session              string            `json:"session"`
	Expected             int64             `json:"expected_version,string"`
	Roles                []string          `json:"roles,omitempty"`
	Role                 string            `json:"role,omitempty"`
	SourceID             string            `json:"source_id,omitempty"`
	Snapshot             string            `json:"snapshot,omitempty"`
	Revision             string            `json:"revision,omitempty"`
	Base                 string            `json:"base,omitempty"`
	Target               string            `json:"target,omitempty"`
	Delta                string            `json:"delta,omitempty"`
	Manifest             string            `json:"manifest,omitempty"`
	BackupDirectory      string            `json:"backup_directory,omitempty"`
	YAML                 string            `json:"yaml,omitempty"`
	NodeIDs              []string          `json:"node_ids,omitempty"`
	Shadow               string            `json:"shadow_id,omitempty"`
	Generation           string            `json:"generation,omitempty"`
	WebsiteBackups       map[string]string `json:"website_backup_directories,omitempty"`
	Sources              map[string]string `json:"source_snapshots,omitempty"`
	Output               string            `json:"output_directory,omitempty"`
	Consumer             string            `json:"consumer,omitempty"`
	Evidence             string            `json:"evidence_file,omitempty"`
	ConfigurationBackups map[string]string `json:"configuration_backup_directories,omitempty"`
	RestoreVerification  string            `json:"restore_verification_directory,omitempty"`
	Start                time.Time         `json:"start,omitempty"`
	End                  time.Time         `json:"end,omitempty"`
	Original             *singleBackupSpec `json:"original,omitempty"`
}

func isMigrationCommand(action string) bool {
	switch action {
	case "archive-migration-reverse-metrics":
		return true
	case "begin-migration-session", "migration-session-status", "bind-migration-revision", "resume-migration-revision", "compare-migration-revisions", "resume-migration-delta", "freeze-migration-session", "reconcile-migration-session", "map-migration-nodes", "bind-migration-shadow", "run-migration-shadow", "migration-shadow-status", "arm-migration-target-journal", "seal-migration-target-journal", "migration-target-journal-status", "map-migration-final-domains", "prepare-migration-metric-history", "run-migration-metric-history", "migration-metric-history-status", "prepare-migration-legacy-sink", "migration-legacy-sink-status", "project-migration-legacy-baseline", "replay-migration-target-journal", "verify-migration-legacy-rollback", "verify-migration-cutover", "activate-migration-session", "rollback-migration-session", "archive-migration-prometheus", "map-migration-legacy-history", "migration-legacy-history-status":
		return true
	}
	return false
}

func decodeMigrationCommand(path, action string) (migrationCommandRequest, error) {
	var in migrationCommandRequest
	if !isMigrationCommand(action) {
		return in, ErrMigrationSession
	}
	raw, err := readTrustData(path, true, 64<<10)
	if err != nil || singleDecode(raw, &in) != nil || !validArchiveSource(in.Session) || in.Expected < 0 {
		return in, ErrMigrationSession
	}
	allowed := map[string]bool{"session": true, "expected_version": true}
	var keys []string
	switch action {
	case "begin-migration-session":
		keys = []string{"roles"}
	case "bind-migration-revision":
		keys = []string{"role", "source_id", "snapshot"}
	case "resume-migration-revision":
		keys = []string{"revision"}
	case "compare-migration-revisions":
		keys = []string{"base", "target"}
	case "resume-migration-delta":
		keys = []string{"delta"}
	case "freeze-migration-session":
		keys = []string{"manifest", "backup_directory"}
	case "map-migration-nodes":
		keys = []string{"yaml", "source_id"}
	case "bind-migration-shadow":
		keys = []string{"node_ids"}
	case "run-migration-shadow", "migration-shadow-status":
		keys = []string{"shadow_id"}
	case "map-migration-final-domains":
		keys = []string{"website_backup_directories"}
	case "prepare-migration-metric-history":
		keys = []string{"revision"}
	case "run-migration-metric-history", "migration-metric-history-status":
		keys = []string{"generation"}
	case "prepare-migration-legacy-sink":
		keys = []string{"source_snapshots", "output_directory"}
	case "archive-migration-reverse-metrics":
		keys = []string{"output_directory", "original"}
	case "migration-legacy-sink-status":
		keys = []string{"output_directory"}
	case "project-migration-legacy-baseline", "replay-migration-target-journal", "verify-migration-legacy-rollback":
		keys = []string{"output_directory", "consumer"}
	case "verify-migration-cutover", "activate-migration-session", "rollback-migration-session":
		keys = []string{"manifest", "output_directory", "consumer", "evidence_file"}
	case "archive-migration-prometheus":
		keys = []string{"source_id", "revision", "start", "end", "output_directory"}
	case "map-migration-legacy-history":
		keys = []string{"revision", "configuration_backup_directories", "restore_verification_directory"}
	case "migration-legacy-history-status":
		keys = []string{"revision"}
	}
	for _, key := range keys {
		allowed[key] = true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return in, ErrMigrationSession
	}
	for key := range object {
		if !allowed[key] {
			return in, ErrMigrationSession
		}
	}
	if _, ok := object["expected_version"]; !ok {
		return in, ErrMigrationSession
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return in, ErrMigrationSession
		}
	}
	return in, nil
}

// Host CLI only. There is no public migration or arbitrary SQL/command API.
// Complete values and paths remain in private inputs, not in reports/errors.
func (s *Store) localMigrationCommand(ctx context.Context, c Config, o Options, out io.Writer) error {
	in, err := decodeMigrationCommand(o.Source, o.Action)
	if err != nil {
		return ErrMigrationSession
	}
	var result any
	switch o.Action {
	case "begin-migration-session":
		result, err = s.BeginMigrationSession(ctx, in.Session, in.Expected, in.Roles)
	case "migration-session-status":
		result, err = s.MigrationSession(ctx, in.Session)
	case "bind-migration-revision":
		result, err = s.BindMigrationRevision(ctx, in.Session, in.Expected, MigrationRevisionInput{Role: in.Role, SourceID: in.SourceID, Snapshot: in.Snapshot})
	case "resume-migration-revision":
		result, err = s.ResumeMigrationRevision(ctx, in.Session, in.Expected, in.Revision)
	case "compare-migration-revisions":
		result, err = s.CompareMigrationRevisions(ctx, in.Session, in.Expected, in.Base, in.Target)
	case "resume-migration-delta":
		result, err = s.ResumeMigrationDelta(ctx, in.Session, in.Expected, in.Delta)
	case "freeze-migration-session":
		result, err = s.FreezeMigrationSession(ctx, in.Session, in.Expected, in.Manifest, in.BackupDirectory)
	case "reconcile-migration-session":
		result, err = s.ReconcileMigrationSession(ctx, in.Session, in.Expected)
	case "map-migration-nodes":
		v, e := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		if e != nil {
			return ErrMigrationSession
		}
		result, err = s.MapLegacyNodes(ctx, in.Session, in.Expected, in.YAML, in.SourceID, v)
	case "bind-migration-shadow":
		result, err = s.BindMigrationShadow(ctx, in.Session, in.Expected, in.NodeIDs)
	case "run-migration-shadow":
		result, err = s.RunMigrationShadow(ctx, c, in.Session, in.Expected, in.Shadow)
	case "migration-shadow-status":
		result, err = s.MigrationShadow(ctx, in.Session, in.Expected, in.Shadow)
	case "arm-migration-target-journal":
		result, err = s.ArmMigrationTargetJournal(ctx, in.Session, in.Expected)
	case "seal-migration-target-journal":
		result, err = s.SealMigrationTargetJournal(ctx, in.Session, in.Expected)
	case "migration-target-journal-status":
		result, err = s.MigrationTargetJournal(ctx, in.Session)
	case "map-migration-final-domains":
		v, e := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		if e != nil {
			return ErrMigrationSession
		}
		result, err = s.MapMigrationFinalDomains(ctx, in.Session, in.Expected, MigrationFinalMappingInput{WebsiteBackupDirectories: in.WebsiteBackups}, v)
	case "prepare-migration-metric-history":
		m := &Metrics{WriteURL: c.Metrics.WriteURL, QueryURL: c.Metrics.QueryURL, HTTP: &http.Client{Timeout: 15 * time.Second}}
		result, err = s.PrepareMigrationMetricHistory(ctx, m, in.Session, in.Expected, in.Revision)
	case "run-migration-metric-history":
		m := &Metrics{WriteURL: c.Metrics.WriteURL, QueryURL: c.Metrics.QueryURL, HTTP: &http.Client{Timeout: 15 * time.Second}}
		result, err = s.RunMigrationMetricHistory(ctx, m, in.Session, in.Expected, in.Generation)
	case "migration-metric-history-status":
		result, err = s.MigrationMetricHistoryReport(ctx, in.Session, in.Generation)
	case "prepare-migration-legacy-sink":
		v, e := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		if e != nil {
			return ErrMigrationSession
		}
		sink, e := s.PrepareMigrationLegacySink(ctx, in.Session, in.Expected, in.Sources, in.Output, v)
		if e != nil {
			return safeMigrationSessionError(e)
		}
		defer sink.Close()
		result, err = sink.Report(ctx)
	case "migration-legacy-sink-status", "project-migration-legacy-baseline", "replay-migration-target-journal", "verify-migration-legacy-rollback", "verify-migration-cutover", "activate-migration-session", "rollback-migration-session", "archive-migration-reverse-metrics":
		sink, e := OpenMigrationLegacySink(ctx, in.Session, in.Output)
		if e != nil {
			return ErrMigrationSession
		}
		defer sink.Close()
		v, e := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		if e != nil {
			return ErrMigrationSession
		}
		switch o.Action {
		case "migration-legacy-sink-status":
			result, err = sink.Report(ctx)
		case "archive-migration-reverse-metrics":
			if in.Original == nil {
				return ErrMigrationSession
			}
			result, err = s.ArchiveMigrationReverseMetrics(ctx, c, in.Session, in.Expected, sink, v, *in.Original)
		case "project-migration-legacy-baseline":
			result, err = s.ProjectMigrationLegacyBaseline(ctx, in.Session, in.Expected, in.Consumer, sink, v)
		case "replay-migration-target-journal":
			if err = s.AuthorizeMigrationLegacyNodeActivations(ctx, in.Session, sink, v); err != nil {
				return err
			}
			result, err = s.ReplayMigrationTargetJournal(ctx, in.Session, in.Expected, in.Consumer, sink)
		case "verify-migration-legacy-rollback":
			result, err = s.VerifyMigrationLegacyRollback(ctx, in.Session, in.Expected, in.Consumer, sink, v, c)
		default:
			raw, e := readTrustData(in.Evidence, true, 64<<10)
			var evidence MigrationLegacyProjectionEvidence
			if e != nil || singleDecode(raw, &evidence) != nil {
				return ErrMigrationSession
			}
			proof := MigrationCutoverInput{FreezeManifest: in.Manifest, Consumer: in.Consumer, LegacySink: sink, LegacyEvidence: evidence, Vault: v, Config: c, Metrics: migrationRecoveryHostMetrics(c)}
			switch o.Action {
			case "verify-migration-cutover":
				result, err = s.ReconcileMigrationSessionWithEvidence(ctx, in.Session, in.Expected, proof)
			case "activate-migration-session":
				err = s.ActivateMigrationSessionWithEvidence(ctx, in.Session, in.Expected, proof)
				if err == nil {
					result, err = s.MigrationSession(ctx, in.Session)
				}
			case "rollback-migration-session":
				err = s.RollbackMigrationSessionWithEvidence(ctx, in.Session, in.Expected, proof)
				if err == nil {
					result, err = s.MigrationSession(ctx, in.Session)
				}
			}
		}
	case "archive-migration-prometheus":
		v, e := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		if e != nil {
			return ErrMigrationSession
		}
		result, err = s.ArchiveMigrationPrometheus(ctx, v, in.Session, in.Expected, in.SourceID, in.Revision, in.Start, in.End, in.Output)
	case "map-migration-legacy-history":
		v, e := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...)
		if e != nil {
			return ErrMigrationSession
		}
		result, err = s.MapMigrationLegacyHistory(ctx, in.Session, in.Expected, in.Revision, MigrationLegacyHistoryInput{ConfigurationBackupDirectories: in.ConfigurationBackups, RestoreVerificationDirectory: in.RestoreVerification}, v)
	case "migration-legacy-history-status":
		result, err = s.MigrationLegacyHistory(ctx, in.Session, in.Revision)
	default:
		return ErrMigrationSession
	}
	if err != nil {
		return safeMigrationSessionError(err)
	}
	return json.NewEncoder(out).Encode(result)
}
