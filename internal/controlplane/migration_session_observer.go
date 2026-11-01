package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"webscan/internal/common"
)

func migrationSafeAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, " \t\r\n\x00\"'\\%$;")
}
func migrationExpectedWriterArgs(w MigrationFreezeWriter) ([]string, error) {
	if !migrationSafeAbsolute(w.ConfigFile) {
		return nil, ErrMigrationSession
	}
	config := w.ConfigFile
	if w.Kind == "docker" {
		config = w.ContainerConfigFile
		if !migrationSafeAbsolute(config) {
			return nil, ErrMigrationSession
		}
	}
	switch w.Role {
	case "central":
		return []string{"central", "--config", config}, nil
	case "host-manager":
		if w.Kind != "systemd" || !migrationSafeAbsolute(w.StateDirectory) {
			return nil, ErrMigrationSession
		}
		return []string{"manager", "--config", config, "--state", w.StateDirectory, "--socket", "/run/webscan-management/control.sock"}, nil
	}
	return nil, ErrMigrationSession
}
func migrationWriterConfiguration(w MigrationFreezeWriter) (common.Map, error) {
	raw, e := readTrustData(w.ConfigFile, true, 2<<20)
	if e != nil || !releaseDigest(w.ConfigSHA256) || digest(raw) != w.ConfigSHA256 {
		return nil, ErrMigrationSession
	}
	var root common.Map
	if yaml.Unmarshal(raw, &root) != nil || root == nil {
		return nil, ErrMigrationSession
	}
	return root, nil
}
func migrationWriterDatabase(root common.Map, w MigrationFreezeWriter, role string) (string, error) {
	var directory string
	name := ""
	switch role {
	case "central", "health":
		directory = common.S(root["data_dir"])
		if directory == "" {
			directory = common.S(common.M(root["central"])["data_dir"])
		}
		name = "events-v1.sqlite3"
		if role == "health" {
			name = "metrics-v1.sqlite3"
		}
	case "host-manager":
		if w.Role != "host-manager" {
			return "", ErrMigrationSession
		}
		directory = w.StateDirectory
		name = "management.sqlite3"
	default:
		return "", ErrMigrationSession
	}
	if !migrationSafeAbsolute(directory) {
		return "", ErrMigrationSession
	}
	return filepath.Join(directory, name), nil
}
func observeMigrationFrozenSource(ctx context.Context, source MigrationFreezeSource) (string, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return "", ErrMigrationSession
	}
	file, e := openTrustFile(source.SQLite, true, 1<<40)
	if e != nil {
		return "", ErrMigrationSession
	}
	file.Close()
	proofs := []string{}
	seen := map[string]bool{}
	for _, w := range source.Writers {
		identity := w.Kind + ":" + w.ID
		if seen[identity] {
			return "", ErrMigrationSession
		}
		seen[identity] = true
		config, e := migrationWriterConfiguration(w)
		if e != nil {
			return "", e
		}
		configured, e := migrationWriterDatabase(config, w, source.Role)
		if e != nil {
			return "", e
		}
		args, e := migrationExpectedWriterArgs(w)
		if e != nil {
			return "", e
		}
		var evidence string
		switch w.Kind {
		case "systemd":
			if configured != source.SQLite {
				return "", ErrMigrationSession
			}
			evidence, e = observeMigrationUnit(ctx, w, args)
		case "docker":
			evidence, e = observeMigrationContainer(ctx, w, args, configured, source.SQLite)
		default:
			return "", ErrMigrationSession
		}
		if e != nil {
			return "", ErrMigrationSession
		}
		proofs = append(proofs, evidence)
	}
	sort.Strings(proofs)
	raw, _ := json.Marshal(struct {
		Role, Source, SQLite string
		Writers              []string
	}{source.Role, source.SourceID, source.SQLite, proofs})
	return digest(raw), nil
}

// Only these two tools and fixed read-only verbs can be invoked by the private
// freeze operation. No executable, command, address or environment comes from
// a request field.
func migrationObserveCommand(ctx context.Context, tool string, args ...string) ([]byte, error) {
	if tool != "systemctl" && tool != "docker" {
		return nil, ErrMigrationSession
	}
	path := ""
	// Docker's signed static installation uses /usr/local/bin. Do not search
	// a caller-controlled PATH or execute an unverified alternate program.
	for _, candidate := range []string{"/usr/bin/" + tool, "/usr/local/bin/" + tool} {
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			continue
		}
		f, err := openTrustFile(candidate, false, 512<<20)
		if err != nil {
			return nil, ErrMigrationSession
		}
		f.Close()
		path = candidate
		break
	}
	if path == "" {
		return nil, ErrMigrationSession
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	var output migrationObserveOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	if cmd.Run() != nil {
		return nil, ErrMigrationSession
	}
	return output.Bytes(), nil
}

type migrationObserveOutput struct{ bytes.Buffer }

func (w *migrationObserveOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 8<<20 {
		return 0, errors.New("controlled observation exceeds limit")
	}
	return w.Buffer.Write(p)
}
func observeMigrationUnit(ctx context.Context, w MigrationFreezeWriter, args []string) (string, error) {
	if !strings.HasPrefix(w.ID, "webscan-") || !strings.HasSuffix(w.ID, ".service") || strings.ContainsAny(w.ID, " /\\\t\r\n\x00") || len(w.ID) > 180 || !migrationSafeAbsolute(w.Executable) || !releaseDigest(w.ExecutableSHA256) || !migrationSafeAbsolute(w.DefinitionFile) || !releaseDigest(w.DefinitionSHA256) {
		return "", ErrMigrationSession
	}
	raw, e := migrationObserveCommand(ctx, "systemctl", "show", "--no-pager", "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,DropInPaths,ExecStart", w.ID)
	if e != nil {
		return "", e
	}
	properties := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return "", ErrMigrationSession
		}
		if _, exists := properties[parts[0]]; exists {
			return "", ErrMigrationSession
		}
		properties[parts[0]] = parts[1]
	}
	if properties["LoadState"] != "loaded" || properties["ActiveState"] != "inactive" || properties["SubState"] != "dead" || properties["MainPID"] != "0" || properties["DropInPaths"] != "" || properties["FragmentPath"] != w.DefinitionFile || properties["UnitFileState"] != "disabled" && properties["UnitFileState"] != "masked" {
		return "", ErrMigrationSession
	}
	definition, e := readTrustData(w.DefinitionFile, false, 256<<10)
	if e != nil || digest(definition) != w.DefinitionSHA256 {
		return "", ErrMigrationSession
	}
	binary, e := openTrustFile(w.Executable, false, 512<<20)
	if e != nil {
		return "", ErrMigrationSession
	}
	hash, e := migrationFileDigest(binary)
	binary.Close()
	if e != nil || hash != w.ExecutableSHA256 {
		return "", ErrMigrationSession
	}
	expected := append([]string{w.Executable}, args...)
	count := 0
	for _, line := range strings.Split(string(definition), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		count++
		command := strings.TrimPrefix(line, "ExecStart=")
		// The legacy generator uses only absolute paths and double quotes around
		// its config argument. Reject expansion, escapes and alternate commands.
		if strings.ContainsAny(command, "'\\%$;\r\x00") || strings.Count(command, "\"")%2 != 0 || !reflect.DeepEqual(strings.Fields(strings.ReplaceAll(command, "\"", "")), expected) {
			return "", ErrMigrationSession
		}
	}
	if count != 1 || !strings.Contains(properties["ExecStart"], "path="+w.Executable+" ;") || !strings.Contains(properties["ExecStart"], "argv[]="+strings.Join(expected, " ")+" ;") {
		return "", ErrMigrationSession
	}
	normalized, _ := json.Marshal(struct {
		Properties                 map[string]string
		Config, Binary, Definition string
	}{properties, w.ConfigSHA256, w.ExecutableSHA256, w.DefinitionSHA256})
	return digest(normalized), nil
}

type migrationObservedContainer struct {
	ID    string `json:"Id"`
	Image string `json:"Image"`
	State struct {
		Running, Paused, Restarting bool
		Pid                         int
		Status                      string
	} `json:"State"`
	Config struct {
		Cmd, Entrypoint []string
		Labels          map[string]string
	} `json:"Config"`
	HostConfig struct{ RestartPolicy struct{ Name string } } `json:"HostConfig"`
	Mounts     []struct {
		Type, Source, Destination string
		RW                        bool
	} `json:"Mounts"`
}

func migrationContainerHostPath(c migrationObservedContainer, path string) (string, error) {
	best := ""
	host := ""
	for _, m := range c.Mounts {
		if m.Type != "bind" || !migrationSafeAbsolute(m.Source) || !migrationSafeAbsolute(m.Destination) {
			continue
		}
		if path == m.Destination || strings.HasPrefix(path, m.Destination+"/") {
			if len(m.Destination) == len(best) {
				return "", ErrMigrationSession
			}
			if len(m.Destination) > len(best) {
				best = m.Destination
				host = filepath.Join(m.Source, strings.TrimPrefix(strings.TrimPrefix(path, best), "/"))
			}
		}
	}
	if best == "" {
		return "", ErrMigrationSession
	}
	return host, nil
}
func observeMigrationContainer(ctx context.Context, w MigrationFreezeWriter, args []string, configured, sqlite string) (string, error) {
	if !validArchiveSource(w.ID) || w.Role != "central" || !strings.HasPrefix(w.ComposeProject, "webscan") || len(w.ComposeProject) > 128 || !identifier.MatchString(w.ComposeProject) {
		return "", ErrMigrationSession
	}
	raw, e := migrationObserveCommand(ctx, "docker", "inspect", "--type", "container", w.ID)
	if e != nil {
		return "", e
	}
	var objects []migrationObservedContainer
	if json.Unmarshal(raw, &objects) != nil || len(objects) != 1 {
		return "", ErrMigrationSession
	}
	c := objects[0]
	if c.ID != w.ID || c.State.Running || c.State.Paused || c.State.Restarting || c.State.Pid != 0 || c.State.Status != "exited" && c.State.Status != "created" || c.HostConfig.RestartPolicy.Name != "no" || c.Config.Labels["com.docker.compose.project"] != w.ComposeProject || c.Config.Labels["com.docker.compose.service"] != "receiver" || !reflect.DeepEqual(c.Config.Cmd, args) {
		return "", ErrMigrationSession
	}
	if len(c.Config.Entrypoint) != 1 || filepath.Base(c.Config.Entrypoint[0]) != "webscan" {
		return "", ErrMigrationSession
	}
	configHost, e := migrationContainerHostPath(c, w.ContainerConfigFile)
	if e != nil || configHost != w.ConfigFile {
		return "", ErrMigrationSession
	}
	sourceHost, e := migrationContainerHostPath(c, configured)
	if e != nil || sourceHost != sqlite {
		return "", ErrMigrationSession
	}
	canonical, e := json.Marshal(struct {
		Container migrationObservedContainer
		Config    string
	}{c, w.ConfigSHA256})
	if e != nil {
		return "", fmt.Errorf("%w", ErrMigrationSession)
	}
	return digest(canonical), nil
}
