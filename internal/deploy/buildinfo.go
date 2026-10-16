package deploy

import (
	"os"
	"runtime/debug"
	"strings"
)

// Values are injected by the release build; empty values are deliberately unknown.
var BuildCommit = ""
var BuildTime = ""
var BuildSource = ""

func BuildInfo() map[string]any {
	commit := BuildCommit
	if commit == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" {
					commit = s.Value
				}
				if s.Key == "vcs.modified" && s.Value == "true" {
					commit += "-dirty"
				}
			}
		}
	}
	return map[string]any{"release": Release, "commit": commit, "built_at": BuildTime, "source_digest": BuildSource}
}

// ExecutableMount identifies the specific temporary file mount used for emergency replacement.
func ExecutableMount() string {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == "/usr/local/bin/webscan" {
			return "mounted"
		}
	}
	if BuildSource == "" {
		return "unknown"
	}
	return "none"
}
