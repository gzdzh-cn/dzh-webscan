package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

type NodeConfigurationInput struct {
	Node            string
	Expected        int64
	Identity        nodepki.Bundle
	CRL             []byte
	Collectors      []string
	Rules           []byte
	Directory       string
	ManagedIdentity bool
}
type PreparedNodeConfiguration struct {
	Artifact ReleaseArtifact `json:"artifact"`
	Path     string          `json:"-"`
}

// PrepareNodeConfiguration only creates a private immutable file. It does not
// save a desired config, create a task, SSH to the node or apply a runtime. All
// secret material comes from server-side provisioning, never a public path.
func (s *Store) PrepareNodeConfiguration(ctx context.Context, release *TrustedRelease, in NodeConfigurationInput) (PreparedNodeConfiguration, error) {
	fail := func() (PreparedNodeConfiguration, error) {
		return PreparedNodeConfiguration{}, DeploymentFailure{"artifact-invalid"}
	}
	if release == nil || release.digest == "" || in.Expected < 1 {
		return fail()
	}
	n, err := scanNode(s.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE id=$1", in.Node))
	if err != nil {
		return PreparedNodeConfiguration{}, err
	}
	if n.Version != in.Expected || !n.Enabled {
		return PreparedNodeConfiguration{}, ErrConflict
	}
	material, err := nodeConfigurationMaterial(n, release, in)
	if err != nil {
		return fail()
	}
	raw, err := json.Marshal(material)
	defer clear(raw)
	if err != nil || len(raw) > nodeconfig.MaxBytes {
		return fail()
	}
	if err := ctx.Err(); err != nil {
		return PreparedNodeConfiguration{}, err
	}
	artifact := ReleaseArtifact{SHA256: digest(raw), Bytes: uint64(len(raw))}
	path, err := writeNodeConfiguration(in.Directory, artifact, raw)
	if err != nil {
		return fail()
	}
	return PreparedNodeConfiguration{artifact, path}, nil
}

func nodeConfigurationMaterial(n Node, release *TrustedRelease, in NodeConfigurationInput) (nodeconfig.Material, error) {
	if release == nil || release.digest == "" || n.ID != in.Node || n.Version != in.Expected || !n.Enabled {
		return nodeconfig.Material{}, errProvisioning
	}
	settings, err := nodeRuntimeSettings(n.Config)
	if err != nil {
		return nodeconfig.Material{}, err
	}
	port, err := endpointPort(n.Endpoint)
	if err != nil {
		return nodeconfig.Material{}, err
	}
	material := nodeconfig.Material{Format: 2, Node: n.ID, Version: n.Version, SourceSHA256: digest(n.Config), Mode: n.Mode, Release: release.manifest.Release, BundleSHA256: release.manifest.Native.SHA256, ServerName: n.ServerName, MetricsPort: port, Collectors: append([]string{}, in.Collectors...), Settings: settings, CA: in.Identity.CA, Certificate: in.Identity.Certificate, Key: in.Identity.Key, CRL: in.CRL, YARA: in.Rules}
	if in.ManagedIdentity {
		material.Format = 3
		material.Certificate, material.Key = nil, nil
	}
	if material.Validate(time.Now()) != nil {
		return nodeconfig.Material{}, errProvisioning
	}
	return material, nil
}

func nodeRuntimeSettings(raw []byte) (nodeconfig.Settings, error) {
	settings := nodeconfig.DefaultSettings()
	var fields map[string]json.RawMessage
	if len(raw) != 0 && json.Unmarshal(raw, &fields) != nil {
		return settings, nodeconfig.ErrInvalid
	}
	// Unknown top-level fields may hold internal state or encrypted references.
	// Only these typed settings are eligible for the Agent artifact. Nested
	// unknown fields in any copied group are rejected rather than misapplied.
	selected := map[string]json.RawMessage{}
	for _, name := range []string{"monitor", "scan", "resources", "transport", "probe_directory", "probe_seconds", "retention_days", "metrics_source_ip"} {
		if value, ok := fields[name]; ok {
			selected[name] = value
		}
	}
	body, err := json.Marshal(selected)
	if err != nil {
		return settings, nodeconfig.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&settings) != nil || decoder.Decode(new(any)) != io.EOF {
		return settings, nodeconfig.ErrInvalid
	}
	if _, provided := fields["probe_directory"]; !provided && len(settings.Monitor.Roots) > 0 {
		settings.ProbeDirectory = filepath.Join(settings.Monitor.Roots[0], ".webscan-probe")
	}
	if settings.Validate() != nil {
		return settings, nodeconfig.ErrInvalid
	}
	return settings, nil
}

func writeNodeConfiguration(root string, artifact ReleaseArtifact, raw []byte) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || digest(raw) != artifact.SHA256 {
		return "", errors.New("unsafe-private-configuration-directory")
	}
	if err := privateConfigurationDirectory(root); err != nil {
		return "", err
	}
	dir := filepath.Join(root, artifact.SHA256)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	if err := privateConfigurationDirectory(dir); err != nil {
		return "", err
	}
	target := filepath.Join(dir, "node.json")
	if _, err := os.Lstat(target); os.IsNotExist(err) {
		f, err := os.CreateTemp(dir, ".configuration-")
		if err != nil {
			return "", err
		}
		name := f.Name()
		defer os.Remove(name)
		if _, err = f.Write(raw); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
		if err = os.Link(name, target); err != nil && !os.IsExist(err) {
			return "", err
		}
		if err = os.Remove(name); err != nil {
			return "", err
		}
	}
	file, err := verifiedReleaseFile(context.Background(), target, artifact, nodeconfig.MaxBytes)
	if err != nil {
		return "", err
	}
	file.Close()
	for _, path := range []string{dir, root} {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return "", err
		}
	}
	return target, nil
}
func privateConfigurationDirectory(dir string) error {
	for path := dir; path != "/"; path = filepath.Dir(path) {
		st, err := os.Lstat(path)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe-private-configuration-directory")
		}
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0700 {
		return errors.New("unsafe-private-configuration-directory")
	}
	return nil
}

func endpointPort(endpoint string) (int, error) {
	_, raw, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1024 || port > 65535 {
		return 0, nodeconfig.ErrInvalid
	}
	return port, nil
}
