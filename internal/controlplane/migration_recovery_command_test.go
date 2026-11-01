package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrationRecoveryCommandStrictPrivateInput(t *testing.T) {
	path := filepath.Join(privateTestDir(t), "request.json")
	gen := strings.Repeat("a", 64)
	for _, tc := range []struct {
		action, raw string
		ok          bool
	}{
		{"migration-recovery-status", `{"format":1}`, true},
		{"begin-migration-recovery", `{"format":1,"generation":"` + gen + `"}`, true},
		{"suppress-migration-recovery-notifications", `{"format":1,"generation":"` + gen + `","confirm":true}`, true},
		{"suppress-migration-recovery-notifications", `{"format":1,"generation":"` + gen + `"}`, false},
		{"begin-migration-recovery", `{"format":1,"generation":"` + gen + `","confirm":true}`, false},
		{"begin-migration-recovery", `{"format":1,"generation":"` + gen + `","generation":"` + gen + `"}`, false},
		{"run-migration-recovery", `{"format":1,"generation":"` + gen + `","url":"http://private.invalid"}`, false},
		{"activate-migration-recovery-host", `{"format":1,"generation":"` + gen + `"}`, false},
		{"migration-recovery-status", `{"format":1,"generation":"unknown"}`, false},
	} {
		if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := decodeMigrationRecoveryCommand(path, tc.action)
		if (err == nil) != tc.ok {
			t.Fatal(tc.action, tc.raw, err)
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeMigrationRecoveryCommand(path, "begin-migration-recovery"); err == nil {
		t.Fatal("public request accepted")
	}
}
