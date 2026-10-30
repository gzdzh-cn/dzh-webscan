package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"webscan/internal/common"
)

// Private building block, not yet selected by either lifecycle driver. A
// caller must enforce Journal fencing and prove/capture the whole set before
// quiescing its first member. Nothing here installs Docker or removes
// a container, image, volume, original log or database.
type legacyWrapperTransition struct{ host installationHost }

type legacyWrapperObject struct {
	Identity                        containerIdentity `json:"identity"`
	Network, PIDMode, User, LogType string
	ReadOnly, Privileged            bool
	CapAdd, CapDrop, SecurityOpt    []string
	LogOptions                      map[string]string
	Propagation                     []legacyBindPropagation
}
type legacyBindPropagation struct{ Destination, Propagation string }
type legacyWrapperImage struct {
	ID, OS, Arch, User string
	Entrypoint, Cmd    []string
}

const legacyWrapperObjectFormat = `{"identity":` + inventoryContainerFormat + `,"Network":{{json .HostConfig.NetworkMode}},"PIDMode":{{json .HostConfig.PidMode}},"User":{{json .Config.User}},"LogType":{{json .HostConfig.LogConfig.Type}},"ReadOnly":{{json .HostConfig.ReadonlyRootfs}},"Privileged":{{json .HostConfig.Privileged}},"CapAdd":{{json .HostConfig.CapAdd}},"CapDrop":{{json .HostConfig.CapDrop}},"SecurityOpt":{{json .HostConfig.SecurityOpt}},"LogOptions":{{json .HostConfig.LogConfig.Config}},"Propagation":{{json .Mounts}}}`
const legacyWrapperImageFormat = `{"ID":{{json .Id}},"OS":{{json .Os}},"Arch":{{json .Architecture}},"User":{{json .Config.User}},"Entrypoint":{{json .Config.Entrypoint}},"Cmd":{{json .Config.Cmd}}}`

func (o legacyWrapperObject) fingerprint() string {
	// Running state is inspected separately on every operation; a stopped old
	// object has exactly the same ownership proof. Preserve every other setting.
	c := o.Identity.fingerprint()
	o.Identity = containerIdentity{}
	o.SecurityOpt = append(o.SecurityOpt[:0:0], o.SecurityOpt...)
	sort.Strings(o.SecurityOpt)
	o.Propagation = append(o.Propagation[:0:0], o.Propagation...)
	sort.Slice(o.Propagation, func(i, j int) bool { return o.Propagation[i].Destination < o.Propagation[j].Destination })
	raw, _ := json.Marshal(struct {
		Container string
		Settings  legacyWrapperObject
	}{c, o})
	return sha(raw)
}

func knownLegacySecurity(u legacySidecarUnit, o legacyWrapperObject) bool {
	nnp, label := false, false
	for _, option := range o.SecurityOpt {
		switch option {
		case "no-new-privileges", "no-new-privileges=true":
			if nnp {
				return false
			}
			nnp = true
		case "label=disable":
			// Docker adds this to --pid=host containers itself, including on
			// engines without SELinux. It is not an arbitrary accepted override.
			if u.Role != "exporter" || o.PIDMode != "host" || label {
				return false
			}
			label = true
		default:
			return false
		}
	}
	return nnp
}

func validateLegacyWrapperObject(u legacySidecarUnit, o legacyWrapperObject, image legacyWrapperImage) error {
	c := o.Identity
	if !u.valid() || !validDigest(c.ID) || c.Name != "/webscan-"+u.Role+"-v1" || c.Image != u.alias() || c.ImageID != image.ID || !strings.HasPrefix(image.ID, "sha256:") || !validDigest(strings.TrimPrefix(image.ID, "sha256:")) || image.OS != "linux" || image.Arch != "amd64" || c.Project != "" || c.Service != "" || c.Managed != "" || c.Node != "" || c.Configuration != "" || c.Restart != "no" || c.MaxRetries != 0 || c.Status != "running" && c.Status != "exited" && c.Status != "created" {
		return errors.New("legacy-wrapper-container-not-owned")
	}
	if o.Network != "host" || !o.ReadOnly || o.Privileged || len(o.CapAdd) != 0 || !equalStrings(o.CapDrop, []string{"ALL"}) || !knownLegacySecurity(u, o) || o.LogType != "json-file" && o.LogType != "local" || len(o.LogOptions) != 2 || o.LogOptions["max-size"] != "10m" || o.LogOptions["max-file"] != "3" || !equalStrings(c.Entrypoint, image.Entrypoint) {
		return errors.New("legacy-wrapper-container-not-owned")
	}
	// Derive the complete expected bind set and explicit command from the
	// already recognized producer template, without executing its Docker run.
	args := u.runArguments()
	binds := map[string]string{}
	for j := 0; j < len(args)-1; j++ {
		if args[j] == "-v" {
			parts := strings.Split(args[j+1], ":")
			if len(parts) < 2 || len(parts) > 3 {
				return errors.New("legacy-wrapper-container-not-owned")
			}
			binds[parts[1]] = args[j+1]
		}
	}
	if len(c.Mounts) != len(binds) || len(o.Propagation) != len(binds) {
		return errors.New("legacy-wrapper-container-not-owned")
	}
	propagation := map[string]string{}
	for _, m := range o.Propagation {
		if _, duplicate := propagation[m.Destination]; duplicate {
			return errors.New("legacy-wrapper-container-not-owned")
		}
		propagation[m.Destination] = m.Propagation
	}
	for _, m := range c.Mounts {
		want, ok := binds[m.Destination]
		parts := strings.Split(want, ":")
		if !ok || m.Type != "bind" || m.Source != parts[0] {
			return errors.New("legacy-wrapper-container-not-owned")
		}
		readOnly, prop := len(parts) == 3, "rprivate"
		if len(parts) == 3 && parts[2] == "ro,rslave" {
			prop = "rslave"
		}
		if m.RW == readOnly || propagation[m.Destination] != prop {
			return errors.New("legacy-wrapper-container-not-owned")
		}
		delete(binds, m.Destination)
	}
	if len(binds) != 0 {
		return errors.New("legacy-wrapper-container-not-owned")
	}
	if u.Role == "vector" {
		if o.PIDMode != "" || o.User != image.User || !equalStrings(c.Command, image.Cmd) {
			return errors.New("legacy-wrapper-container-not-owned")
		}
	} else {
		if o.PIDMode != "host" || o.User != "0:0" {
			return errors.New("legacy-wrapper-container-not-owned")
		}
		for j, arg := range args {
			if arg == u.alias() && !equalStrings(c.Command, args[j+1:]) {
				return errors.New("legacy-wrapper-container-not-owned")
			}
		}
	}
	return nil
}

func (w legacyWrapperTransition) object(ctx context.Context, id string) (legacyWrapperObject, error) {
	var o legacyWrapperObject
	if !validDigest(id) {
		return o, errors.New("invalid-container-id")
	}
	raw, err := w.host.docker(ctx, "container", "inspect", id, "--format", legacyWrapperObjectFormat)
	if err != nil || json.Unmarshal([]byte(raw), &o) != nil || o.Identity.ID != id {
		return o, errors.New("legacy-wrapper-inspection-unavailable")
	}
	return o, nil
}

type legacyWrapperIntent struct {
	Format                int `json:"format"`
	Binding               transitionBinding
	UnitPath, RuntimePath string
	RuntimeSHA256         string
	Unit                  []byte
	Object                legacyWrapperObject
	Image                 legacyWrapperImage
	Running, Enabled      bool
	RetainedSHA256        string `json:"retained_sha256,omitempty"`
}
type legacyWrapperReceipt struct {
	Format    int `json:"format"`
	Binding   transitionBinding
	IntentSHA string
}

// Keep the old object under systemd supervision without ever running the
// original ExecStartPre (docker rm -f). This remains installed after recovery;
// original bytes are retained privately in the immutable intent.
func retainedWrapperUnit(u legacySidecarUnit, id string) []byte {
	return []byte(fmt.Sprintf("[Unit]\nDescription=Webscan retained %s\nRequires=docker.service\nPartOf=docker.service\nAfter=docker.service network-online.target\n[Service]\nExecStart=/usr/bin/docker --host unix:///var/run/docker.sock start --attach %s\nExecStop=/usr/bin/docker --host unix:///var/run/docker.sock stop --time 20 %s\nRestart=always\nRestartSec=5\nTimeoutStopSec=35\n[Install]\nWantedBy=multi-user.target docker.service\n", u.Role, id, id))
}

func (w legacyWrapperTransition) directory(r Request, name string) (string, error) {
	if r.Validate() != nil || !r.Spec.configurationValid() || r.Operation != "apply" || w.host.command == nil || !safeServicePath(w.host.root) || name != "webscan-vector-v1.service" && name != "webscan-exporter-v1.service" {
		return "", errors.New("invalid-legacy-wrapper-operation")
	}
	return filepath.Join(w.host.root, "transitions", r.Job, "wrappers", name), nil
}
func (w legacyWrapperTransition) runtimeSHA(r Request) (string, error) {
	raw, err := readPrivate(filepath.Join(w.host.configRoot, "runtime.json"), 2<<20)
	if err != nil {
		return "", errors.New("legacy-wrapper-runtime-changed")
	}
	value, err := common.Decode(raw)
	m := common.M(value)
	if err != nil || common.S(m["node_id"]) != r.Node || common.S(m["data_dir"]) != agentDataDirectory || common.S(m["log_dir"]) != agentLogDirectory {
		return "", errors.New("legacy-wrapper-runtime-changed")
	}
	return sha(raw), nil
}
func (w legacyWrapperTransition) read(r Request, name string) (legacyWrapperIntent, []byte, error) {
	var i legacyWrapperIntent
	dir, err := w.directory(r, name)
	if err != nil {
		return i, nil, err
	}
	raw, err := decodePrivateJSON(filepath.Join(dir, "intent.json"), &i, MaxRequestBytes)
	u, parseErr := parseLegacySidecarUnit(name, i.Unit)
	if err != nil || parseErr != nil || i.Format != 1 || i.Binding != binding(r) || i.UnitPath != filepath.Join(filepath.Dir(w.host.unitPath), name) || i.RuntimePath != filepath.Join(w.host.configRoot, "runtime.json") || !validDigest(i.RuntimeSHA256) || validateLegacyWrapperObject(u, i.Object, i.Image) != nil || i.Running != (i.Object.Identity.Status == "running") {
		return i, nil, errors.New("legacy-wrapper-intent-invalid")
	}
	if i.RetainedSHA256 != "" {
		if err := w.verifyRetainedIntent(i); err != nil {
			return i, nil, err
		}
	}
	return i, raw, nil
}

func (w legacyWrapperTransition) status(ctx context.Context, i legacyWrapperIntent, safe bool) (nativeStatus, error) {
	raw, err := w.host.command(ctx, "systemctl", "show", filepath.Base(i.UnitPath), "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
	s, parseErr := decodeNativeStatus(raw, safe, false)
	if err != nil || parseErr != nil || s.FragmentPath != i.UnitPath || s.UnitFileState != "enabled" && s.UnitFileState != "disabled" {
		return s, errors.New("legacy-wrapper-state-unknown")
	}
	if s.MainPID > 0 {
		if w.host.processExecutable == nil || w.host.processArguments == nil {
			return s, errors.New("legacy-wrapper-process-unknown")
		}
		exe, err := w.host.processExecutable(s.MainPID)
		if err != nil || exe != "/usr/bin/docker" {
			return s, errors.New("legacy-wrapper-process-unknown")
		}
		u, _ := parseLegacySidecarUnit(filepath.Base(i.UnitPath), i.Unit)
		argv, err := w.host.processArguments(s.MainPID)
		original := append([]string{"/usr/bin/docker"}, u.runArguments()...)
		retained := []string{"/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "start", "--attach", i.Object.Identity.ID}
		if err != nil || !equalStrings(argv, original) && !(safe && equalStrings(argv, retained)) {
			return s, errors.New("legacy-wrapper-process-unknown")
		}
	}
	return s, nil
}

// capture is read-only with respect to services. Its only writes are a private
// immutable intent, published before the first effective unit mutation.
func (w legacyWrapperTransition) capture(ctx context.Context, r Request, name string) (legacyWrapperIntent, error) {
	var empty legacyWrapperIntent
	dir, err := w.directory(r, name)
	if err != nil || r.Phase != "backup" {
		return empty, errors.New("invalid-legacy-wrapper-operation")
	}
	if _, err := os.Lstat(filepath.Join(dir, "intent.json")); !os.IsNotExist(err) {
		i, _, err := w.read(r, name)
		return i, err
	}
	i, err := w.observe(ctx, r, name)
	if err != nil {
		return empty, err
	}
	for _, part := range []string{filepath.Join(w.host.root, "transitions"), filepath.Join(w.host.root, "transitions", r.Job), filepath.Dir(dir), dir} {
		if err := ensurePrivateDirectory(part); err != nil {
			return empty, err
		}
	}
	encoded, _ := json.Marshal(i)
	if err := replacePrivateFile(filepath.Join(dir, "intent.json"), encoded, nil); err != nil {
		return empty, err
	}
	verified, _, err := w.read(r, name)
	return verified, err
}

// observe proves current ownership without publishing files or touching services.
// Backup repeats the observation and publishes immutable evidence before stop.
func (w legacyWrapperTransition) observe(ctx context.Context, r Request, name string) (legacyWrapperIntent, error) {
	var empty legacyWrapperIntent
	if _, err := w.directory(r, name); err != nil {
		return empty, err
	}
	path := filepath.Join(filepath.Dir(w.host.unitPath), name)
	unit, err := readLegacyWrapperUnit(path)
	if err != nil {
		return empty, err
	}
	i := legacyWrapperIntent{Format: 1, Binding: binding(r), UnitPath: path, RuntimePath: filepath.Join(w.host.configRoot, "runtime.json"), Unit: unit}
	u, parseErr := parseLegacySidecarUnit(name, unit)
	var source *legacyWrapperIntent
	if parseErr != nil {
		original, pointerRaw, err := w.authority(r.Node, name)
		if err != nil || expectedWrapperUnit(original, true) != nil {
			return empty, errors.New("legacy-wrapper-not-owned")
		}
		i.Unit, i.RetainedSHA256 = original.Unit, sha(pointerRaw)
		u, _ = parseLegacySidecarUnit(name, i.Unit)
		source = &original
	} else if err := w.rejectExistingAuthority(name); err != nil {
		return empty, err
	}
	i.RuntimeSHA256, err = w.runtimeSHA(r)
	if err != nil {
		return empty, err
	}
	service := "webscan-" + u.Role + "-v1"
	raw, err := w.host.docker(ctx, "ps", "-a", "--no-trunc", "--filter", "name=^/"+service+"$", "--format", "{{.ID}}")
	if err != nil {
		return empty, errors.New("legacy-wrapper-inspection-unavailable")
	}
	i.Object, err = w.object(ctx, strings.TrimSpace(raw))
	if err != nil {
		return empty, err
	}
	// Resolve the original source (including containerd manifest IDs) to its
	// config ID. A retagged source cannot authorize a different existing object.
	imageRef := u.SourceImage
	if source != nil {
		imageRef = source.Image.ID
	}
	raw, err = w.host.docker(ctx, "image", "inspect", imageRef, "--format", legacyWrapperImageFormat)
	if err != nil || json.Unmarshal([]byte(raw), &i.Image) != nil || validateLegacyWrapperObject(u, i.Object, i.Image) != nil {
		return empty, errors.New("legacy-wrapper-container-not-owned")
	}
	if source != nil && !sameWrapperOrigin(*source, i) {
		return empty, errors.New("retained-wrapper-provenance-invalid")
	}
	s, err := w.status(ctx, i, source != nil)
	if err != nil || s.NeedDaemonReload != "no" || (s.MainPID > 0) != (i.Object.Identity.Status == "running") {
		return empty, errors.New("legacy-wrapper-state-unknown")
	}
	i.Running, i.Enabled = s.MainPID > 0, s.UnitFileState == "enabled"
	final, object, err := w.state(ctx, r, i, source != nil)
	if err != nil || final.MainPID != s.MainPID || final.UnitFileState != s.UnitFileState || object.Identity.Status != i.Object.Identity.Status {
		return empty, errors.New("legacy-wrapper-state-unknown")
	}
	return i, nil
}

func (w legacyWrapperTransition) state(ctx context.Context, r Request, i legacyWrapperIntent, allowSafe bool) (nativeStatus, legacyWrapperObject, error) {
	var empty nativeStatus
	if i.RetainedSHA256 != "" {
		if err := w.verifyRetainedIntent(i); err != nil {
			return empty, legacyWrapperObject{}, err
		}
		allowSafe = true
	}
	unit, err := readLegacyWrapperUnit(i.UnitPath)
	u, _ := parseLegacySidecarUnit(filepath.Base(i.UnitPath), i.Unit)
	safe := allowSafe && bytes.Equal(unit, retainedWrapperUnit(u, i.Object.Identity.ID))
	if err != nil || !bytes.Equal(unit, i.Unit) && !safe || i.RetainedSHA256 != "" && !safe {
		return empty, legacyWrapperObject{}, errors.New("legacy-wrapper-unit-changed")
	}
	config, err := w.runtimeSHA(r)
	if err != nil || config != i.RuntimeSHA256 {
		return empty, legacyWrapperObject{}, errors.New("legacy-wrapper-runtime-changed")
	}
	o, err := w.object(ctx, i.Object.Identity.ID)
	if err != nil || o.fingerprint() != i.Object.fingerprint() || o.Identity.Name != i.Object.Identity.Name || o.Identity.Restart != "no" || o.Identity.MaxRetries != 0 || o.Identity.Status != "running" && o.Identity.Status != "exited" && o.Identity.Status != "created" {
		return empty, o, errors.New("legacy-wrapper-container-changed")
	}
	s, err := w.status(ctx, i, safe)
	if err != nil {
		return s, o, err
	}
	current, err := readLegacyWrapperUnit(i.UnitPath)
	if err != nil || !bytes.Equal(current, unit) {
		return s, o, errors.New("legacy-wrapper-unit-changed")
	}
	return s, o, nil
}

func wrapperReceipt(i legacyWrapperIntent, raw []byte) []byte {
	b, _ := json.Marshal(legacyWrapperReceipt{1, i.Binding, sha(raw)})
	return b
}

func (w legacyWrapperTransition) mark(r Request, name, file string, i legacyWrapperIntent, raw []byte, create bool) error {
	dir, err := w.directory(r, name)
	if err != nil || file != "quiesce.json" && file != "restore.json" && file != "restored.json" {
		return errors.New("invalid-legacy-wrapper-operation")
	}
	want := wrapperReceipt(i, raw)
	if create {
		return replacePrivateFile(filepath.Join(dir, file), want, nil)
	}
	got, err := readPrivate(filepath.Join(dir, file), 4096)
	if err != nil || !bytes.Equal(got, want) {
		return errors.New("legacy-wrapper-checkpoint-invalid")
	}
	return nil
}

func expectedWrapperUnit(i legacyWrapperIntent, retained bool) error {
	want := i.Unit
	if retained {
		u, _ := parseLegacySidecarUnit(filepath.Base(i.UnitPath), i.Unit)
		want = retainedWrapperUnit(u, i.Object.Identity.ID)
	}
	got, err := readLegacyWrapperUnit(i.UnitPath)
	if err != nil || !bytes.Equal(got, want) {
		return errors.New("legacy-wrapper-unit-changed")
	}
	return nil
}

// Verification never loads a unit, changes a policy or starts/stops a process.
// The integrating phase holds service-operation.lock for a stable whole set.
func (w legacyWrapperTransition) quiescent(ctx context.Context, r Request, name string) error {
	i, raw, err := w.read(r, name)
	if err != nil {
		return err
	}
	if err := w.mark(r, name, "quiesce.json", i, raw, false); err != nil {
		return err
	}
	if err := w.verifyAuthority(r, i); err != nil {
		return err
	}
	if err := expectedWrapperUnit(i, true); err != nil {
		return err
	}
	s, o, err := w.state(ctx, r, i, true)
	if err != nil || s.MainPID != 0 || s.UnitFileState != "disabled" || s.NeedDaemonReload != "no" || o.Identity.Status == "running" {
		return errors.New("legacy-wrapper-not-quiescent")
	}
	return nil
}

func (w legacyWrapperTransition) restored(ctx context.Context, r Request, name string) error {
	i, raw, err := w.read(r, name)
	if err != nil {
		return err
	}
	for _, file := range []string{"restore.json", "restored.json"} {
		if err := w.mark(r, name, file, i, raw, false); err != nil {
			return err
		}
	}
	dir, _ := w.directory(r, name)
	retained := i.RetainedSHA256 != ""
	if _, err := os.Lstat(filepath.Join(dir, "quiesce.json")); !os.IsNotExist(err) {
		if err := w.mark(r, name, "quiesce.json", i, raw, false); err != nil {
			return err
		}
		retained = true
	}
	if err := expectedWrapperUnit(i, retained); err != nil {
		return err
	}
	if retained {
		if err := w.verifyAuthority(r, i); err != nil {
			return err
		}
	}
	s, o, err := w.state(ctx, r, i, retained)
	if err != nil || s.NeedDaemonReload != "no" || (s.MainPID > 0) != i.Running || (s.UnitFileState == "enabled") != i.Enabled || (o.Identity.Status == "running") != i.Running {
		return errors.New("legacy-wrapper-restore-not-confirmed")
	}
	return nil
}

// The caller holds the node-wide service lock. The checked replacement never
// permits a foreign unit, a link, a missing original or unknown intermediate.
func installRetainedWrapper(i legacyWrapperIntent) error {
	u, _ := parseLegacySidecarUnit(filepath.Base(i.UnitPath), i.Unit)
	want := retainedWrapperUnit(u, i.Object.Identity.ID)
	current, err := readLegacyWrapperUnit(i.UnitPath)
	if err != nil {
		return err
	}
	if bytes.Equal(current, want) {
		return nil
	}
	if !bytes.Equal(current, i.Unit) {
		return errors.New("legacy-wrapper-unit-changed")
	}
	f, err := os.CreateTemp(filepath.Dir(i.UnitPath), ".webscan-retained-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	_, err = f.Write(want)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	current, err = readLegacyWrapperUnit(i.UnitPath)
	if err != nil || !bytes.Equal(current, i.Unit) {
		return errors.New("legacy-wrapper-unit-changed")
	}
	if err := os.Rename(f.Name(), i.UnitPath); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(i.UnitPath))
}

func (w legacyWrapperTransition) retained(ctx context.Context, r Request, i legacyWrapperIntent) (nativeStatus, legacyWrapperObject, error) {
	if err := w.publishAuthority(r, i); err != nil {
		return nativeStatus{}, legacyWrapperObject{}, err
	}
	if err := installRetainedWrapper(i); err != nil {
		return nativeStatus{}, legacyWrapperObject{}, err
	}
	s, _, err := w.state(ctx, r, i, true)
	if err != nil {
		return s, legacyWrapperObject{}, err
	}
	// Reload even if NeedDaemonReload says no. A previous client may have died
	// between publishing the unit and notifying the manager; only an explicit
	// successful reload authorizes the immutable-ID stop/start commands.
	if _, err := w.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
		return s, legacyWrapperObject{}, err
	}
	s, o, err := w.state(ctx, r, i, true)
	if err == nil && s.NeedDaemonReload != "no" {
		err = errors.New("legacy-wrapper-state-unknown")
	}
	return s, o, err
}

func (w legacyWrapperTransition) quiesce(ctx context.Context, r Request, name string) error {
	if r.Phase != "backup" {
		return errors.New("invalid-legacy-wrapper-operation")
	}
	ctx, unlock, err := acquireServiceOperation(ctx, w.host.root)
	if err != nil {
		return err
	}
	defer unlock()
	dir, err := w.directory(r, name)
	if err != nil {
		return err
	}
	for _, file := range []string{"restore.json", "restored.json"} {
		if _, err := os.Lstat(filepath.Join(dir, file)); !os.IsNotExist(err) {
			return errors.New("rollback-already-started")
		}
	}
	i, err := w.capture(ctx, r, name)
	if err != nil {
		return err
	}
	i, raw, err := w.read(r, name)
	if err != nil {
		return err
	}
	allowSafe := false
	if _, err := os.Lstat(filepath.Join(dir, "quiesce.json")); !os.IsNotExist(err) {
		if err := w.mark(r, name, "quiesce.json", i, raw, false); err != nil {
			return err
		}
		allowSafe = true
	}
	if _, _, err := w.state(ctx, r, i, allowSafe); err != nil {
		return err
	}
	if err := w.mark(r, name, "quiesce.json", i, raw, true); err != nil {
		return err
	}
	s, o, err := w.retained(ctx, r, i)
	if err != nil {
		return err
	}
	if s.MainPID > 0 || s.UnitFileState != "disabled" {
		if _, err := w.host.command(ctx, "systemctl", "disable", "--now", name); err != nil {
			return err
		}
	}
	s, o, err = w.state(ctx, r, i, true)
	if err != nil || s.MainPID != 0 || s.UnitFileState != "disabled" || s.NeedDaemonReload != "no" {
		return errors.New("legacy-wrapper-not-quiescent")
	}
	// A client may have exited before its orphaned container. After disabling
	// the proven wrapper, stop only the captured immutable ID.
	if o.Identity.Status == "running" {
		if _, err := w.host.docker(ctx, "stop", "--time", "60", i.Object.Identity.ID); err != nil {
			return err
		}
	}
	s, o, err = w.state(ctx, r, i, true)
	if err != nil || s.MainPID != 0 || s.UnitFileState != "disabled" || s.NeedDaemonReload != "no" || o.Identity.Status == "running" {
		return errors.New("legacy-wrapper-not-quiescent")
	}
	return w.quiescent(ctx, r, name)
}

func (w legacyWrapperTransition) restore(ctx context.Context, r Request, name string) error {
	if r.Phase != "restore" {
		return errors.New("invalid-legacy-wrapper-operation")
	}
	ctx, unlock, err := acquireServiceOperation(ctx, w.host.root)
	if err != nil {
		return err
	}
	defer unlock()
	i, raw, err := w.read(r, name)
	if err != nil {
		return err
	}
	dir, _ := w.directory(r, name)
	if _, err := os.Lstat(filepath.Join(dir, "restored.json")); !os.IsNotExist(err) {
		return w.restored(ctx, r, name)
	}
	if err := w.mark(r, name, "restore.json", i, raw, true); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, "quiesce.json")); os.IsNotExist(err) {
		// Capture alone never grants permission to repair external changes.
		s, o, err := w.state(ctx, r, i, false)
		if err != nil || (s.MainPID > 0) != i.Running || (s.UnitFileState == "enabled") != i.Enabled || (o.Identity.Status == "running") != i.Running {
			return errors.New("legacy-wrapper-original-state-changed")
		}
		return w.mark(r, name, "restored.json", i, raw, true)
	} else if err != nil {
		return err
	}
	if err := w.mark(r, name, "quiesce.json", i, raw, false); err != nil {
		return err
	}
	before, currentObject, err := w.state(ctx, r, i, true)
	if err != nil {
		return err
	}
	if !i.Running && (before.MainPID > 0 || currentObject.Identity.Status == "running") {
		return errors.New("unexpected-original-wrapper-writer")
	}
	s, o, err := w.retained(ctx, r, i)
	if err != nil {
		return err
	}
	if !i.Running && (s.MainPID > 0 || o.Identity.Status == "running") {
		return errors.New("unexpected-original-wrapper-writer")
	}
	if (s.UnitFileState == "enabled") != i.Enabled {
		verb := "disable"
		if i.Enabled {
			verb = "enable"
		}
		if _, err := w.host.command(ctx, "systemctl", verb, name); err != nil {
			return err
		}
	}
	if i.Running && s.MainPID == 0 {
		if _, err := w.host.command(ctx, "systemctl", "start", name); err != nil {
			return err
		}
	}
	if err := w.waitRestoredProcess(ctx, r, i); err != nil {
		return err
	}
	if err := expectedWrapperUnit(i, true); err != nil {
		return err
	}
	return w.mark(r, name, "restored.json", i, raw, true)
}

// Type=simple confirms the attached Docker client's start before its daemon
// necessarily starts the container. Wait only while that exact client and
// captured immutable object still pass all ownership checks. Never repeat a
// start or repair changed units, objects, permissions or enable states here.
func (w legacyWrapperTransition) waitRestoredProcess(ctx context.Context, r Request, i legacyWrapperIntent) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		s, o, err := w.state(ctx, r, i, true)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.NeedDaemonReload != "no" || (s.UnitFileState == "enabled") != i.Enabled {
			return errors.New("legacy-wrapper-restore-not-confirmed")
		}
		if (s.MainPID > 0) == i.Running && (o.Identity.Status == "running") == i.Running {
			return nil
		}
		if !i.Running || s.MainPID == 0 || s.ActiveState != "active" || s.SubState != "running" {
			return errors.New("legacy-wrapper-restore-not-confirmed")
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
