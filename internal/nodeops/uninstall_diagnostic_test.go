package nodeops

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallDiagnosticContainsOnlyFixedCodes(t *testing.T) {
	x := newUninstallFixture(t, "native")
	r := x.request
	r.Phase = "restore"
	path := filepath.Join(x.u.directory(r), "diagnostic.json")
	for _, test := range []struct{ cause, want string }{
		{"native-running-program-mismatch", "native-running-program-mismatch"},
		{"/private/secret-password.pem: permission denied", "operation-failed"},
		{"native-running-program-mismatch secret-password", "operation-failed"},
	} {
		x.u.recordDiagnostic(r, errors.New(test.cause))
		var d uninstallDiagnostic
		raw, err := decodePrivateJSON(path, &d, 4096)
		if err != nil || d.Phase != "restore" || d.Code != test.want || strings.Contains(string(raw), "secret-password") {
			t.Fatal("unsafe diagnostic", err)
		}
		var fields map[string]any
		if json.Unmarshal(raw, &fields) != nil || len(fields) != 2 {
			t.Fatal("unexpected diagnostic fields")
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("diagnostic permissions", err)
		}
	}
}

func TestUninstallDiagnosticFailurePreservesOperationError(t *testing.T) {
	x := newUninstallFixture(t, "native")
	x.phase(t, "preflight")
	x.phase(t, "stage")
	outside := filepath.Join(x.u.runtime.root, "outside")
	if err := os.WriteFile(outside, []byte("do-not-touch"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(x.u.directory(x.request), "diagnostic.json")); err != nil {
		t.Fatal(err)
	}
	x.lostBefore = "show"
	r := x.request
	r.Phase = "backup"
	requireResult(t, x.journal.Handle(r), "unknown", "backup-failed")
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != "do-not-touch" {
		t.Fatal("diagnostic followed symlink", err)
	}
}
