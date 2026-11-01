package nodeops

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// This is troubleshooting evidence only. No authorization or recovery decision
// reads it. Never persist the original error: command and filesystem errors may
// include credentials, private configuration or local paths.
type uninstallDiagnostic struct {
	Phase string `json:"phase"`
	Code  string `json:"code"`
}

func uninstallDiagnosticCode(err error) string {
	if err == nil {
		return "operation-failed"
	}
	switch err.Error() {
	case "activation-intent-mismatch":
		return "activation-intent-mismatch"
	case "agent-command-not-owned":
		return "agent-command-not-owned"
	case "agent-data-mount-not-owned":
		return "agent-data-mount-not-owned"
	case "captured-configuration-copy-failed":
		return "captured-configuration-copy-failed"
	case "container-lookup-not-unique":
		return "container-lookup-not-unique"
	case "container-ownership-not-proven":
		return "container-ownership-not-proven"
	case "container-restore-not-confirmed":
		return "container-restore-not-confirmed"
	case "container-transition-pending":
		return "container-transition-pending"
	case "docker-restore-state-not-confirmed":
		return "docker-restore-state-not-confirmed"
	case "effective-file-changed":
		return "effective-file-changed"
	case "effective-pointer-changed":
		return "effective-pointer-changed"
	case "effective-unit-changed":
		return "effective-unit-changed"
	case "historical-reinstall-binding-changed":
		return "historical-reinstall-binding-changed"
	case "historical-removal-not-proven":
		return "historical-removal-not-proven"
	case "historical-removal-source-mismatch":
		return "historical-removal-source-mismatch"
	case "historical-removal-tombstone-changed":
		return "historical-removal-tombstone-changed"
	case "historical-restoration-not-proven":
		return "historical-restoration-not-proven"
	case "historical-restoration-reference-invalid":
		return "historical-restoration-reference-invalid"
	case "invalid-container-id":
		return "invalid-container-id"
	case "invalid-installation":
		return "invalid-installation"
	case "invalid-native-restore":
		return "invalid-native-restore"
	case "invalid-native-status":
		return "invalid-native-status"
	case "invalid-original-pointer":
		return "invalid-original-pointer"
	case "invalid-restoration-evidence":
		return "invalid-restoration-evidence"
	case "invalid-uninstall-tombstone":
		return "invalid-uninstall-tombstone"
	case "native-probe-not-owned":
		return "native-probe-not-owned"
	case "native-process-proof-unavailable":
		return "native-process-proof-unavailable"
	case "native-program-not-owned":
		return "native-program-not-owned"
	case "native-restore-not-confirmed":
		return "native-restore-not-confirmed"
	case "native-restore-state-not-confirmed":
		return "native-restore-state-not-confirmed"
	case "native-running-configuration-mismatch":
		return "native-running-configuration-mismatch"
	case "native-running-program-mismatch":
		return "native-running-program-mismatch"
	case "native-service-enable-state-unknown":
		return "native-service-enable-state-unknown"
	case "native-service-identity-unknown":
		return "native-service-identity-unknown"
	case "native-service-ownership-not-proven":
		return "native-service-ownership-not-proven"
	case "native-service-state-unknown":
		return "native-service-state-unknown"
	case "native-service-transition-pending":
		return "native-service-transition-pending"
	case "native-target-not-disabled":
		return "native-target-not-disabled"
	case "native-unit-changed":
		return "native-unit-changed"
	case "native-unit-not-owned":
		return "native-unit-not-owned"
	case "no-effects-original-object-missing":
		return "no-effects-original-object-missing"
	case "node-writers-not-stopped":
		return "node-writers-not-stopped"
	case "original-configuration-changed":
		return "original-configuration-changed"
	case "original-configuration-restore-failed":
		return "original-configuration-restore-failed"
	case "original-container-name-changed":
		return "original-container-name-changed"
	case "original-native-transition-not-supported":
		return "original-native-transition-not-supported"
	case "original-pointer-invalid":
		return "original-pointer-invalid"
	case "original-service-proof-unavailable":
		return "original-service-proof-unavailable"
	case "original-unit-not-preserved":
		return "original-unit-not-preserved"
	case "owned-container-changed":
		return "owned-container-changed"
	case "owned-container-name-not-restored":
		return "owned-container-name-not-restored"
	case "owned-container-state-not-restored":
		return "owned-container-state-not-restored"
	case "removal-evidence-phase-invalid":
		return "removal-evidence-phase-invalid"
	case "removed-container-name-reused":
		return "removed-container-name-reused"
	case "removed-native-service-state-unknown":
		return "removed-native-service-state-unknown"
	case "restoration-active-changed":
		return "restoration-active-changed"
	case "restoration-binding-changed":
		return "restoration-binding-changed"
	case "restoration-container-create-unconfirmed":
		return "restoration-container-create-unconfirmed"
	case "restoration-evidence-invalid":
		return "restoration-evidence-invalid"
	case "restoration-evidence-phase-invalid":
		return "restoration-evidence-phase-invalid"
	case "restoration-export-not-proven":
		return "restoration-export-not-proven"
	case "restoration-final-not-proven":
		return "restoration-final-not-proven"
	case "restoration-intent-changed":
		return "restoration-intent-changed"
	case "restoration-object-changed":
		return "restoration-object-changed"
	case "restoration-predecessor-not-proven":
		return "restoration-predecessor-not-proven"
	case "restoration-previous-tombstone-not-proven":
		return "restoration-previous-tombstone-not-proven"
	case "restoration-reference-invalid":
		return "restoration-reference-invalid"
	case "restoration-reference-required":
		return "restoration-reference-required"
	case "restoration-tombstone-changed":
		return "restoration-tombstone-changed"
	case "restore-export-receipt-mismatch":
		return "restore-export-receipt-mismatch"
	case "restore-native-unit-changed":
		return "restore-native-unit-changed"
	case "restored-active-not-proven":
		return "restored-active-not-proven"
	case "rollback-already-started":
		return "rollback-already-started"
	case "target-service-proof-unavailable":
		return "target-service-proof-unavailable"
	case "unexpected-native-unit":
		return "unexpected-native-unit"
	case "unexpected-node-writer-active":
		return "unexpected-node-writer-active"
	case "unexpected-original-docker-writer":
		return "unexpected-original-docker-writer"
	case "unexpected-uninstall-writer":
		return "unexpected-uninstall-writer"
	case "uninstall-active-changed":
		return "uninstall-active-changed"
	case "uninstall-active-not-canonical":
		return "uninstall-active-not-canonical"
	case "uninstall-active-not-proven":
		return "uninstall-active-not-proven"
	case "uninstall-attempt-changed":
		return "uninstall-attempt-changed"
	case "uninstall-capture-changed":
		return "uninstall-capture-changed"
	case "uninstall-captured-installation-invalid":
		return "uninstall-captured-installation-invalid"
	case "uninstall-current-tombstone-changed":
		return "uninstall-current-tombstone-changed"
	case "uninstall-database-presence-unknown":
		return "uninstall-database-presence-unknown"
	case "uninstall-definition-not-preserved":
		return "uninstall-definition-not-preserved"
	case "uninstall-effects-not-excluded":
		return "uninstall-effects-not-excluded"
	case "uninstall-file-identity-unavailable":
		return "uninstall-file-identity-unavailable"
	case "uninstall-incomplete":
		return "uninstall-incomplete"
	case "uninstall-intent-not-proven":
		return "uninstall-intent-not-proven"
	case "uninstall-live-data-replaced":
		return "uninstall-live-data-replaced"
	case "uninstall-no-effects-invalid":
		return "uninstall-no-effects-invalid"
	case "uninstall-no-effects-not-proven":
		return "uninstall-no-effects-not-proven"
	case "uninstall-no-effects-original-missing":
		return "uninstall-no-effects-original-missing"
	case "uninstall-object-not-proven":
		return "uninstall-object-not-proven"
	case "uninstall-object-still-present":
		return "uninstall-object-still-present"
	case "uninstall-original-not-supported":
		return "uninstall-original-not-supported"
	case "uninstall-original-service-invalid":
		return "uninstall-original-service-invalid"
	case "uninstall-preservation-invalid":
		return "uninstall-preservation-invalid"
	case "uninstall-preservation-not-canonical":
		return "uninstall-preservation-not-canonical"
	case "uninstall-preservation-not-proven":
		return "uninstall-preservation-not-proven"
	case "uninstall-preservation-special-file":
		return "uninstall-preservation-special-file"
	case "uninstall-preservation-symlink":
		return "uninstall-preservation-symlink"
	case "uninstall-preservation-too-large":
		return "uninstall-preservation-too-large"
	case "uninstall-preserved-file-missing":
		return "uninstall-preserved-file-missing"
	case "uninstall-preserved-material-changed":
		return "uninstall-preserved-material-changed"
	case "uninstall-removed-snapshot-missing":
		return "uninstall-removed-snapshot-missing"
	case "uninstall-restoration-evidence-mismatch":
		return "uninstall-restoration-evidence-mismatch"
	case "uninstall-restoration-intent-invalid":
		return "uninstall-restoration-intent-invalid"
	case "uninstall-restoration-not-canonical":
		return "uninstall-restoration-not-canonical"
	case "uninstall-restoration-object-mismatch":
		return "uninstall-restoration-object-mismatch"
	case "uninstall-restoration-pointer-mismatch":
		return "uninstall-restoration-pointer-mismatch"
	case "uninstall-restoration-reference-required":
		return "uninstall-restoration-reference-required"
	case "uninstall-restoration-source-mismatch":
		return "uninstall-restoration-source-mismatch"
	case "uninstall-restore-capture-changed":
		return "uninstall-restore-capture-changed"
	case "uninstall-restored-object-mismatch":
		return "uninstall-restored-object-mismatch"
	case "uninstall-restored-object-not-canonical":
		return "uninstall-restored-object-not-canonical"
	case "uninstall-restored-object-not-proven":
		return "uninstall-restored-object-not-proven"
	case "uninstall-runtime-not-preserved":
		return "uninstall-runtime-not-preserved"
	case "uninstall-snapshot-changed":
		return "uninstall-snapshot-changed"
	case "uninstall-source-activation-invalid":
		return "uninstall-source-activation-invalid"
	case "uninstall-source-capture-changed":
		return "uninstall-source-capture-changed"
	case "uninstall-source-invalid":
		return "uninstall-source-invalid"
	case "uninstall-source-pointer-mismatch":
		return "uninstall-source-pointer-mismatch"
	case "uninstall-stage-not-proven":
		return "uninstall-stage-not-proven"
	case "uninstall-target-mismatch":
		return "uninstall-target-mismatch"
	case "uninstall-tombstone-intent-changed":
		return "uninstall-tombstone-intent-changed"
	case "uninstall-tombstone-not-anchored":
		return "uninstall-tombstone-not-anchored"
	case "uninstall-tombstone-not-proven":
		return "uninstall-tombstone-not-proven"
	case "uninstall-unit-changed":
		return "uninstall-unit-changed"
	case "uninstall-writer-not-stopped":
		return "uninstall-writer-not-stopped"
	case "uninstalled-node-not-proven":
		return "uninstalled-node-not-proven"
	case "uninstalled-service-not-absent":
		return "uninstalled-service-not-absent"
	case "unrecorded-restoration-writer":
		return "unrecorded-restoration-writer"
	case "unsupported-uninstall-phase":
		return "unsupported-uninstall-phase"
	default:
		return "operation-failed"
	}
}

func (u *uninstallLifecycle) recordDiagnostic(r Request, cause error) {
	if !u.valid(r) || phaseIndex(r.Phase) < 0 {
		return
	}
	directory := u.directory(r)
	if ensurePrivateDirectory(directory) != nil {
		return
	}
	path := filepath.Join(directory, "diagnostic.json")
	previous, err := readPrivate(path, 4096)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	raw, err := json.Marshal(uninstallDiagnostic{r.Phase, uninstallDiagnosticCode(cause)})
	if err != nil {
		return
	}
	_ = replacePrivateFile(path, raw, previous)
}
