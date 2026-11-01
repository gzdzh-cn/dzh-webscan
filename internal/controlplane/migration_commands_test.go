package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationCommandStrictPrivateActionFields(t *testing.T) {
	root := privateTestDir(t)
	path := filepath.Join(root, "request.json")
	session := strings.Repeat("a", 64)
	for _, tc := range []struct{ action, extra string }{
		{"begin-migration-session", `,"roles":["central"]`},
		{"map-migration-final-domains", `,"website_backup_directories":{}`},
		{"prepare-migration-metric-history", `,"revision":"revision"`},
		{"run-migration-metric-history", `,"generation":"generation"`},
		{"migration-metric-history-status", `,"generation":"generation"`},
		{"migration-target-journal-status", ""},
		{"prepare-migration-legacy-sink", `,"source_snapshots":{},"output_directory":"/private/target"`},
		{"archive-migration-reverse-metrics", `,"output_directory":"/private/target","original":{"format":1,"installation":"/private/install.json","host_config":"/private/executor.yaml","api_config":"/private/config.yaml","compose_file":"/private/compose.yaml"}`},
		{"migration-legacy-sink-status", `,"output_directory":"/private/target"`},
		{"project-migration-legacy-baseline", `,"output_directory":"/private/target","consumer":"test"`},
		{"replay-migration-target-journal", `,"output_directory":"/private/target","consumer":"test"`},
		{"verify-migration-legacy-rollback", `,"output_directory":"/private/target","consumer":"test"`},
		{"verify-migration-cutover", `,"output_directory":"/private/target","consumer":"test","evidence_file":"/private/evidence","manifest":"/private/manifest"`},
		{"activate-migration-session", `,"output_directory":"/private/target","consumer":"test","evidence_file":"/private/evidence","manifest":"/private/manifest"`},
		{"rollback-migration-session", `,"output_directory":"/private/target","consumer":"test","evidence_file":"/private/evidence","manifest":"/private/manifest"`},
		{"archive-migration-prometheus", `,"source_id":"source","revision":"revision","start":"2026-11-01T00:00:00Z","end":"2026-11-01T00:01:00Z","output_directory":"/private/target"`},
		{"map-migration-legacy-history", `,"revision":"revision","configuration_backup_directories":{},"restore_verification_directory":"/private/restore"`},
		{"migration-legacy-history-status", `,"revision":"revision"`},
	} {
		t.Run(tc.action, func(t *testing.T) {
			valid := `{"session":"` + session + `","expected_version":"5"` + tc.extra + `}`
			if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := decodeMigrationCommand(path, tc.action); err != nil || got.Session != session || got.Expected != 5 {
				t.Fatal(got, err)
			}
			for _, body := range []string{
				strings.Replace(valid, `"expected_version":"5"`, `"expected_version":"-1"`, 1),
				strings.Replace(valid, `"expected_version":"5"`, `"expected_version":5`, 1),
				strings.Replace(valid, `"expected_version":"5"`, `"expected_version":"5","expected_version":"6"`, 1),
				strings.TrimSuffix(valid, "}") + `,"command":"private-command-never-execute"}`,
				strings.TrimSuffix(valid, "}") + `,"url":"https://private-target.invalid"}`,
			} {
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := decodeMigrationCommand(path, tc.action); err == nil || strings.Contains(err.Error(), "private-") {
					t.Fatal("unsafe request accepted or leaked", err)
				}
			}
			if err := os.WriteFile(path, []byte(valid), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := decodeMigrationCommand(path, tc.action); err == nil {
				t.Fatal("public-readable request accepted")
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := decodeMigrationCommand(path, "arbitrary-operation"); err == nil {
				t.Fatal("unknown operation accepted")
			}
		})
	}
}
