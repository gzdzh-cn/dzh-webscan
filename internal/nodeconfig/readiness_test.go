package nodeconfig

import (
	"path/filepath"
	"testing"

	"webscan/internal/common"
)

func TestSettingsReservePrivateScannerScratchBeforeInstallation(t *testing.T) {
	reserved := filepath.Join("/var/lib/webscan-v1", common.ScannerReadinessSubdirectory)
	for _, field := range []string{"root", "critical", "probe", "probe-parent"} {
		t.Run(field, func(t *testing.T) {
			s := DefaultSettings()
			s.Monitor.Roots = []string{"/var/lib/webscan-v1"}
			s.Monitor.ExcludePaths = []string{}
			s.Monitor.CriticalPaths = []string{}
			s.ProbeDirectory = "/var/lib/webscan-v1/probe"
			switch field {
			case "root":
				s.Monitor.Roots = []string{reserved}
				s.ProbeDirectory = filepath.Join(reserved, "probe")
			case "critical":
				s.Monitor.CriticalPaths = []string{filepath.Join(reserved, "scan.php")}
			case "probe":
				s.ProbeDirectory = reserved
			case "probe-parent":
				s.ProbeDirectory = "/var/lib/webscan-v1"
			}
			if s.Validate() == nil {
				t.Fatal("reserved scratch accepted", field)
			}
		})
	}
	s := DefaultSettings()
	s.Monitor.Roots = []string{"/var/lib/webscan-v1"}
	s.Monitor.ExcludePaths, s.Monitor.CriticalPaths = []string{}, []string{}
	s.ProbeDirectory = "/var/lib/webscan-v1/probe"
	if s.Validate() != nil {
		t.Fatal("containing root rejected instead of excluding private scratch")
	}
}
