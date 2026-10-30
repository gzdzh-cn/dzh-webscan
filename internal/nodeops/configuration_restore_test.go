package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationRestorePublishesOnlyVerifiedCompleteFiles(t *testing.T) {
	for _, kind := range []string{"valid", "cancelled", "damaged-source", "partial-staging", "foreign-file", "foreign-link"} {
		t.Run(kind, func(t *testing.T) {
			root := testRoot(t)
			source := filepath.Join(root, "capture")
			destination := filepath.Join(root, "active")
			original := "credential-and-config\n"
			writeResourceFixture(t, source, original)
			expected, err := describePrivateFile(context.Background(), source, "config/runtime.json", 4096)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			switch kind {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "damaged-source":
				writeResourceFixture(t, source, "damaged")
			case "partial-staging":
				writeResourceFixture(t, filepath.Join(root, ".config-restore-crashed/file"), "partial")
			case "foreign-file":
				writeResourceFixture(t, destination, "operator-config")
			case "foreign-link":
				if err := os.Symlink(source, destination); err != nil {
					t.Fatal(err)
				}
			}
			err = restoreCapturedFile(ctx, source, destination, expected)
			if kind == "valid" || kind == "partial-staging" {
				if err != nil {
					t.Fatal(err)
				}
				if err := verifyBackupFile(context.Background(), destination, expected); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil {
					t.Fatal("unverified or conflicting copy succeeded")
				}
				if kind == "foreign-file" {
					raw, err := os.ReadFile(destination)
					if err != nil || string(raw) != "operator-config" {
						t.Fatal("existing config overwritten", err)
					}
				} else if kind == "foreign-link" {
					st, err := os.Lstat(destination)
					if err != nil || st.Mode()&os.ModeSymlink == 0 {
						t.Fatal("link overwritten", err)
					}
				} else if _, err := os.Lstat(destination); !os.IsNotExist(err) {
					t.Fatal("failed copy exposed active partial file", err)
				}
			}
		})
	}
}
