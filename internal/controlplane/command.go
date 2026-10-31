package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

type Options struct {
	Config, Action, Role, Topology, Username, PasswordFile, Source, Snapshot, Output, PublicURL string
	NotificationsSource                                                                         string
	BackupDirectory                                                                             string
	RequestKey                                                                                  string
	NonInteractive                                                                              bool
}

func Command(ctx context.Context, o Options, in io.Reader, out io.Writer) error {
	if o.Action == "prepare-single-backup-schedule" || o.Action == "configure-single-backup-schedule" || o.Action == "enable-single-backup-schedule" || o.Action == "run-single-backup" {
		return singleBackupScheduleCommand(ctx, o, out)
	}
	if o.Action == "backup-single" || o.Action == "verify-single-backup" || o.Action == "restore-single-offline" {
		return singleBackupCommand(ctx, o, out)
	}
	if o.Action == "backup-metrics" || o.Action == "verify-metrics-backup" || o.Action == "restore-metrics-offline" {
		return metricsSnapshotCommand(ctx, o, out)
	}
	if o.Action == "preview-single-pki-upgrade" || o.Action == "prepare-single-pki-upgrade" || o.Action == "check-single-pki-upgrade" || o.Action == "maintain-single-pki-upgrade" {
		return singlePKIUpgradeCommand(ctx, o, out)
	}
	if o.Action == "preview-single-web-upgrade" || o.Action == "prepare-single-web-upgrade" {
		return singleWebUpgradeCommand(ctx, o, out)
	}
	identityRecoveryAction := o.Action == "prepare-node-identity-recovery" || o.Action == "run-node-identity-recovery" || o.Action == "cancel-node-identity-recovery" || o.Action == "node-identity-recovery-status"
	nameChangeAction := o.Action == "prepare-node-name-change" || o.Action == "run-node-name-change" || o.Action == "cancel-node-name-change" || o.Action == "node-name-change-status"
	namePruningAction := o.Action == "prepare-node-name-pruning" || o.Action == "run-node-name-pruning" || o.Action == "cancel-node-name-pruning" || o.Action == "node-name-pruning-status"
	historyRetirementAction := o.Action == "preview-node-history-retirement" || o.Action == "retire-node-history"
	retirementCheckpointAction := o.Action == "export-node-retirements" || o.Action == "reconcile-node-retirements"
	rootRotationAction := o.Action == "prepare-root-rotation" || o.Action == "run-root-rotation" || o.Action == "finalize-root-rotation" || o.Action == "root-rotation-status" || o.Action == "reauthorize-root-rotation" || o.Action == "cancel-root-rotation"
	if (identityRecoveryAction || nameChangeAction || namePruningAction || historyRetirementAction || retirementCheckpointAction || rootRotationAction) && (runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0) {
		return errors.New("身份维护命令仅允许在 Linux amd64 主控宿主机以 root 执行")
	}
	if o.Action == "maintain-single-pki" {
		return singlePKICommand(ctx, o, out)
	}
	if o.Action == "preview-single-install" || o.Action == "install-single" || o.Action == "resume-single-install" {
		return singleInstallCommand(ctx, o, out)
	}
	if o.Action == "configure" {
		return Initialize(o, in, out)
	}
	c, e := LoadConfig(o.Config)
	if e != nil {
		return e
	}
	if _, e = SelectTopology(c.Central.Topology, o.Topology, false, o.NonInteractive, in, out); e != nil {
		return e
	}
	if o.Action == "check" || o.Action == "layout" {
		p, e := PlanLayout(c)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(p)
	}
	if o.Action == "preview-v2" {
		tables, e := InventorySQLite(ctx, o.Source)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(tables)
	}
	if o.Action == "preview-settings-v2" {
		report, err := PreviewLegacySettings(o.Source)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	}
	if o.Action == "run" {
		return Serve(ctx, c, o.Role)
	}
	if o.Action == "check-deployment-trust" {
		return checkDeploymentTrust(ctx, c.DeploymentTrust, out)
	}
	s, e := Open(ctx, c)
	if e != nil {
		return e
	}
	defer s.DB.Close()
	if rootRotationAction {
		return s.localRootRotationCommand(ctx, c, o, out)
	}
	if retirementCheckpointAction {
		return s.localRetirementCheckpointCommand(ctx, c, o, out)
	}
	if historyRetirementAction {
		return s.localNodeHistoryRetirementCommand(ctx, o, out)
	}
	if namePruningAction {
		return s.localNodeNamePruningCommand(ctx, c, o, out)
	}
	if nameChangeAction {
		return s.localNodeNameChangeCommand(ctx, c, o, out)
	}
	if identityRecoveryAction {
		return s.localNodeIdentityRecoveryCommand(ctx, c, o, out)
	}
	switch o.Action {
	case "queue-configuration-application", "control-configuration-application":
		return s.localConfigurationApplicationCommand(ctx, c, o, out)
	case "check-configuration-apply":
		return s.localConfigurationEnvironmentCommand(ctx, c, o, out)
	case "store-ssh-credential", "issue-node-certificate", "bind-node-provisioning", "prepare-deployment", "queue-deployment", "queue-deployment-recovery", "preview-deployment", "confirm-deployment":
		return s.localProvisioningCommand(ctx, c, o, out)
	case "init-db":
		return s.Migrate(ctx)
	case "migrate-db":
		return s.Upgrade(ctx, o.Output)
	case "backup-db":
		path, err := s.BackupPostgres(ctx, o.Output)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"backup": path})
	case "restore-db":
		return s.RestorePostgres(ctx, o.Snapshot)
	case "map-operation-audit-v2":
		report, err := s.MapOperationAuditArchive(ctx, o.Source)
		if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
			return encodeErr
		}
		return err
	case "map-settings-v2":
		report, err := s.ImportLegacySettings(ctx, o.Source, o.Output)
		if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
			return encodeErr
		}
		return err
	case "map-website-backups-v2":
		report, err := s.MapWebsiteBackupArchive(ctx, o.Source, o.BackupDirectory)
		if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
			return encodeErr
		}
		return err
	case "map-websites-v2", "map-notifications-v2", "map-health-v2", "map-events-v2":
		var report DomainImportReport
		var err error
		switch o.Action {
		case "map-websites-v2":
			report, err = s.MapWebsiteArchive(ctx, o.Source)
		case "map-notifications-v2":
			report, err = s.MapNotificationArchive(ctx, o.Source)
		case "map-health-v2":
			report, err = s.MapHealthArchive(ctx, o.Source, o.NotificationsSource)
		case "map-events-v2":
			report, err = s.MapEventArchive(ctx, o.Source)
		}
		if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
			return encodeErr
		}
		return err
	case "provision-admin", "reset-password":
		password, e := ReadSecret(o.PasswordFile)
		if e != nil {
			return e
		}
		if o.Action == "reset-password" {
			return s.ResetPassword(ctx, o.Username, password)
		}
		return s.Provision(ctx, o.Username, password)
	case "archive-v2":
		if o.Snapshot != "" {
			if o.Source != "" || o.Output != "" {
				return errors.New("继续归档仅提供 --snapshot，不同时指定 --source 或 --output")
			}
			report, e := s.ArchiveSnapshot(ctx, o.Snapshot)
			if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
				return encodeErr
			}
			return e
		}
		report, e := s.ArchiveSQLite(ctx, o.Source, o.Output)
		if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
			return encodeErr
		}
		return e
	default:
		return errors.New("操作须为 configure、check、layout、check-deployment-trust、check-configuration-apply、queue-configuration-application、control-configuration-application、store-ssh-credential、issue-node-certificate、bind-node-provisioning、prepare-deployment、queue-deployment、queue-deployment-recovery、preview-deployment、confirm-deployment、prepare-node-name-change、run-node-name-change、cancel-node-name-change、node-name-change-status、prepare-node-name-pruning、run-node-name-pruning、cancel-node-name-pruning、node-name-pruning-status、prepare-node-identity-recovery、run-node-identity-recovery、cancel-node-identity-recovery、node-identity-recovery-status、init-db、migrate-db、backup-db、restore-db、provision-admin、reset-password、preview-v2、archive-v2、preview-settings-v2、map-settings-v2、map-websites-v2、map-website-backups-v2、map-notifications-v2、map-health-v2、map-events-v2、map-operation-audit-v2 或 run")
	}
}

// NewAPI is shared by isolated integration runners and future role launchers.
func NewAPI(s *Store, c Config) *API {
	return &API{Store: s, Config: c, bootstrapConfig: &c, Metrics: &Metrics{WriteURL: c.Metrics.WriteURL, QueryURL: c.Metrics.QueryURL, HTTP: &http.Client{Timeout: 15 * time.Second}}}
}
