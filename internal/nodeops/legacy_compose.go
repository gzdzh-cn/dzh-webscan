package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Compose-only sidecars have no unit to rewrite. Their private evidence binds
// the declarative owner, runtime, actual image and complete container settings.
// Recovery only changes policy/running state of the captured immutable ID.
type legacyComposeIntent struct {
	Format                           int
	Binding                          transitionBinding
	RuntimeSHA256, ComposeSHA256     string
	Project, Service, ImageReference string
	Object                           legacyWrapperObject
	Image                            legacyWrapperImage
}
type legacyComposeMember struct{ Name, IntentSHA256 string }
type legacyComposeTransition struct{ host installationHost }

var legacyComposeNames = []string{"webscan-vector-v1", "webscan-exporter-v1"}

func hasLegacyMembers(i Installation) bool { return len(i.Wrappers) > 0 || len(i.Sidecars) > 0 }
func composeSidecarName(name string) bool {
	return name == legacyComposeNames[0] || name == legacyComposeNames[1]
}

func (q legacyComposeTransition) directory(r Request, name string) (string, error) {
	if r.Validate() != nil || !r.Spec.configurationValid() || r.Operation != "apply" || !composeSidecarName(name) || q.host.command == nil || !safeServicePath(q.host.root) {
		return "", errors.New("invalid-legacy-compose-operation")
	}
	return filepath.Join(q.host.root, "transitions", r.Job, "sidecars", name), nil
}

// Known systemd container wrappers are incompatible with Compose-only capture:
// a manager can recreate a stopped ID. Prove absence, including vendor units
// loaded from /usr/lib, rather than checking only an /etc filename.
func (q legacyComposeTransition) noSupervisor(ctx context.Context) error {
	for _, name := range append([]string{"webscan-agent-v1.service"}, legacyWrapperNames...) {
		if _, err := os.Lstat(filepath.Join(filepath.Dir(q.host.unitPath), name)); !os.IsNotExist(err) {
			return errors.New("legacy-compose-supervisor-present")
		}
		if _, err := os.Stat("/run/systemd/system"); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return errors.New("legacy-compose-supervisor-unknown")
		}
		raw, _ := q.host.command(ctx, "systemctl", "show", name, "--property=LoadState,ActiveState,SubState,FragmentPath,DropInPaths,NeedDaemonReload,UnitFileState,Job,MainPID")
		status, err := decodeNativeStatus(raw, false, true)
		if err != nil || status.LoadState != "not-found" {
			return errors.New("legacy-compose-supervisor-present")
		}
	}
	return nil
}

func (q legacyComposeTransition) definition(name string) (string, string, string, error) {
	raw, err := readPrivate(filepath.Join(q.host.configRoot, "compose.yml"), 2<<20)
	var c struct {
		Name     string
		Services map[string]struct {
			Image         string
			ContainerName string `yaml:"container_name"`
		}
	}
	if err != nil || yaml.Unmarshal(raw, &c) != nil || c.Name == "" || !strings.HasPrefix(c.Name, "webscan") {
		return "", "", "", errors.New("legacy-compose-definition-invalid")
	}
	service, image := "", ""
	for key, s := range c.Services {
		if s.ContainerName == name {
			if service != "" || key == "" || s.Image == "" {
				return "", "", "", errors.New("legacy-compose-definition-invalid")
			}
			service, image = key, s.Image
		}
	}
	if service == "" {
		return "", "", "", errors.New("legacy-compose-member-not-configured")
	}
	return c.Name, service, image, nil
}
func validateComposeSidecar(i legacyComposeIntent) error {
	c := i.Object.Identity
	if i.Format != 1 || !validDigest(i.RuntimeSHA256) || !validDigest(i.ComposeSHA256) || !composeSidecarName(strings.TrimPrefix(c.Name, "/")) || verifyLegacyContainer(c, i.Service, i.Project, i.ImageReference, legacyConfigurationRoot) != nil || c.Managed != "" || c.Node != "" || c.Configuration != "" {
		return errors.New("legacy-compose-member-not-owned")
	}
	role := strings.TrimSuffix(strings.TrimPrefix(c.Name, "/webscan-"), "-v1")
	u := legacySidecarUnit{Role: role, SourceImage: i.Image.ID}
	if role == "exporter" {
		for _, arg := range c.Command {
			if port, ok := strings.CutPrefix(arg, "--web.listen-address=:"); ok {
				u.MetricsPort, _ = strconv.Atoi(port)
			}
		}
	}
	for _, m := range c.Mounts {
		if m.Destination == "/etc/webscan-v1/pki" || role == "vector" && m.Destination == "/etc/webscan-v1/pki/ca.crt" {
			u.TLS = true
		}
	}
	// Share the known safe vendor command/mount validation, while keeping all
	// actual Compose identity and policy in the immutable stored evidence.
	normalized := i.Object
	normalized.Identity.Project, normalized.Identity.Service = "", ""
	normalized.Identity.Image = u.alias()
	normalized.Identity.Restart, normalized.Identity.MaxRetries = "no", 0
	if validateLegacyWrapperObject(u, normalized, i.Image) != nil {
		return errors.New("legacy-compose-member-not-owned")
	}
	return nil
}
func (q legacyComposeTransition) observe(ctx context.Context, r Request, name string) (legacyComposeIntent, error) {
	var i legacyComposeIntent
	if _, err := q.directory(r, name); err != nil {
		return i, err
	}
	if err := q.noSupervisor(ctx); err != nil {
		return i, err
	}
	runtime, err := (legacyWrapperTransition{q.host}).runtimeSHA(r)
	if err != nil {
		return i, err
	}
	raw, err := readPrivate(filepath.Join(q.host.configRoot, "compose.yml"), 2<<20)
	if err != nil {
		return i, err
	}
	project, service, image, err := q.definition(name)
	if err != nil {
		return i, err
	}
	c, err := q.host.containerNamed(ctx, name)
	if err != nil || c == nil {
		return i, errors.New("legacy-compose-member-unavailable")
	}
	object, err := (legacyWrapperTransition{q.host}).object(ctx, c.ID)
	if err != nil {
		return i, err
	}
	imageRaw, err := q.host.docker(ctx, "image", "inspect", object.Identity.ImageID, "--format", legacyWrapperImageFormat)
	var identity legacyWrapperImage
	if err != nil || json.Unmarshal([]byte(imageRaw), &identity) != nil {
		return i, errors.New("legacy-compose-image-unavailable")
	}
	i = legacyComposeIntent{1, binding(r), runtime, sha(raw), project, service, image, object, identity}
	if err := validateComposeSidecar(i); err != nil {
		return i, err
	}
	current, err := q.state(ctx, r, i)
	if err != nil || current.Identity.Status != i.Object.Identity.Status || current.Identity.Restart != i.Object.Identity.Restart || current.Identity.MaxRetries != i.Object.Identity.MaxRetries {
		return i, errors.New("legacy-compose-observation-changed")
	}
	return i, nil
}
func (q legacyComposeTransition) read(r Request, name string) (legacyComposeIntent, []byte, error) {
	var i legacyComposeIntent
	dir, err := q.directory(r, name)
	if err != nil {
		return i, nil, err
	}
	raw, err := decodePrivateJSON(filepath.Join(dir, "intent.json"), &i, MaxRequestBytes)
	if err != nil || i.Binding != binding(r) || i.Object.Identity.Name != "/"+name || validateComposeSidecar(i) != nil {
		return i, nil, errors.New("legacy-compose-intent-invalid")
	}
	return i, raw, nil
}
func (q legacyComposeTransition) capture(ctx context.Context, r Request, name string) (legacyComposeIntent, error) {
	dir, err := q.directory(r, name)
	if err != nil || r.Phase != "backup" {
		return legacyComposeIntent{}, errors.New("invalid-legacy-compose-operation")
	}
	if _, err := os.Lstat(filepath.Join(dir, "intent.json")); !os.IsNotExist(err) {
		i, _, err := q.read(r, name)
		return i, err
	}
	i, err := q.observe(ctx, r, name)
	if err != nil {
		return i, err
	}
	for _, d := range []string{filepath.Join(q.host.root, "transitions"), filepath.Join(q.host.root, "transitions", r.Job), filepath.Dir(dir), dir} {
		if err := ensurePrivateDirectory(d); err != nil {
			return i, err
		}
	}
	raw, _ := json.Marshal(i)
	if err := replacePrivateFile(filepath.Join(dir, "intent.json"), raw, nil); err != nil {
		return i, err
	}
	saved, _, err := q.read(r, name)
	return saved, err
}
func (q legacyComposeTransition) state(ctx context.Context, r Request, i legacyComposeIntent) (legacyWrapperObject, error) {
	var empty legacyWrapperObject
	if err := q.noSupervisor(ctx); err != nil {
		return empty, err
	}
	runtime, err := (legacyWrapperTransition{q.host}).runtimeSHA(r)
	if err != nil || runtime != i.RuntimeSHA256 {
		return empty, errors.New("legacy-compose-runtime-changed")
	}
	raw, err := readPrivate(filepath.Join(q.host.configRoot, "compose.yml"), 2<<20)
	if err != nil || sha(raw) != i.ComposeSHA256 {
		if !os.IsNotExist(err) || q.retiredDefinition(ctx, r, i) != nil {
			return empty, errors.New("legacy-compose-definition-changed")
		}
	}
	c := i.Object.Identity
	current, err := (legacyWrapperTransition{q.host}).object(ctx, c.ID)
	if err != nil || current.fingerprint() != i.Object.fingerprint() || current.Identity.Name != c.Name || current.Identity.Status != "running" && current.Identity.Status != "exited" && current.Identity.Status != "created" || current.Identity.Restart != "no" && (current.Identity.Restart != c.Restart || current.Identity.MaxRetries != c.MaxRetries) || current.Identity.Restart == "no" && current.Identity.MaxRetries != 0 || c.Status != "running" && current.Identity.Status == "running" {
		return empty, errors.New("legacy-compose-object-changed")
	}
	named, err := q.host.containerNamed(ctx, strings.TrimPrefix(c.Name, "/"))
	if err != nil || named == nil || named.ID != c.ID {
		return empty, errors.New("legacy-compose-name-changed")
	}
	return current, nil
}
func (q legacyComposeTransition) mark(r Request, name, file string, i legacyComposeIntent, raw []byte, create bool) error {
	dir, err := q.directory(r, name)
	if err != nil || file != "quiesce.json" && file != "restore.json" && file != "restored.json" {
		return errors.New("invalid-legacy-compose-operation")
	}
	want, _ := json.Marshal(legacyWrapperReceipt{1, i.Binding, sha(raw)})
	if create {
		return replacePrivateFile(filepath.Join(dir, file), want, nil)
	}
	got, err := readPrivate(filepath.Join(dir, file), 4096)
	if err != nil || !bytes.Equal(got, want) {
		return errors.New("legacy-compose-checkpoint-invalid")
	}
	return nil
}
func (q legacyComposeTransition) inspect(ctx context.Context, r Request, name string, forward bool) error {
	i, raw, err := q.read(r, name)
	if err != nil {
		return err
	}
	dir, _ := q.directory(r, name)
	for _, file := range []string{"restore.json", "restored.json"} {
		if _, err := os.Lstat(filepath.Join(dir, file)); !os.IsNotExist(err) {
			if forward {
				return errors.New("rollback-already-started")
			}
			if err := q.mark(r, name, file, i, raw, false); err != nil {
				return err
			}
			if file == "restored.json" {
				if err := q.restored(ctx, r, name); err != nil {
					return err
				}
			}
		}
	}
	current, err := q.state(ctx, r, i)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, "quiesce.json")); os.IsNotExist(err) {
		c := i.Object.Identity
		if current.Identity.Status != c.Status || current.Identity.Restart != c.Restart || current.Identity.MaxRetries != c.MaxRetries {
			return errors.New("legacy-compose-original-state-changed")
		}
	} else if err := q.mark(r, name, "quiesce.json", i, raw, false); err != nil {
		return err
	}
	return nil
}
func (q legacyComposeTransition) quiesce(ctx context.Context, r Request, name string) error {
	if r.Phase != "backup" {
		return errors.New("invalid-legacy-compose-operation")
	}
	ctx, release, err := acquireServiceOperation(ctx, q.host.root)
	if err != nil {
		return err
	}
	defer release()
	if err := q.inspect(ctx, r, name, true); err != nil {
		return err
	}
	i, raw, err := q.read(r, name)
	if err != nil {
		return err
	}
	if err := q.mark(r, name, "quiesce.json", i, raw, true); err != nil {
		return err
	}
	current, err := q.state(ctx, r, i)
	if err != nil {
		return err
	}
	if current.Identity.Restart != "no" {
		if _, err := q.host.docker(ctx, "update", "--restart=no", i.Object.Identity.ID); err != nil {
			return err
		}
	}
	if current.Identity.Status == "running" {
		if _, err := q.host.docker(ctx, "stop", "--time", "60", i.Object.Identity.ID); err != nil {
			return err
		}
	}
	return q.quiescent(ctx, r, name)
}
func (q legacyComposeTransition) quiescent(ctx context.Context, r Request, name string) error {
	i, raw, err := q.read(r, name)
	if err != nil {
		return err
	}
	if err := q.mark(r, name, "quiesce.json", i, raw, false); err != nil {
		return err
	}
	current, err := q.state(ctx, r, i)
	if err != nil {
		return err
	}
	if current.Identity.Status == "running" || current.Identity.Restart != "no" || current.Identity.MaxRetries != 0 {
		return errors.New("legacy-compose-not-quiescent")
	}
	return nil
}
func (q legacyComposeTransition) restore(ctx context.Context, r Request, name string) error {
	if r.Phase != "restore" {
		return errors.New("invalid-legacy-compose-operation")
	}
	ctx, release, err := acquireServiceOperation(ctx, q.host.root)
	if err != nil {
		return err
	}
	defer release()
	i, raw, err := q.read(r, name)
	if err != nil {
		return err
	}
	if err := q.inspect(ctx, r, name, false); err != nil {
		return err
	}
	dir, _ := q.directory(r, name)
	if _, err := os.Lstat(filepath.Join(dir, "restored.json")); !os.IsNotExist(err) {
		return q.restored(ctx, r, name)
	}
	if err := q.mark(r, name, "restore.json", i, raw, true); err != nil {
		return err
	}
	current, err := q.state(ctx, r, i)
	if err != nil {
		return err
	}
	c := i.Object.Identity
	if current.Identity.Restart != c.Restart || current.Identity.MaxRetries != c.MaxRetries {
		policy := c.Restart
		if policy == "on-failure" && c.MaxRetries > 0 {
			policy += ":" + strconv.Itoa(c.MaxRetries)
		}
		if _, err := q.host.docker(ctx, "update", "--restart="+policy, c.ID); err != nil {
			return err
		}
	}
	if c.Status == "running" && current.Identity.Status != "running" {
		if _, err := q.host.docker(ctx, "start", c.ID); err != nil {
			return err
		}
	}
	if err := q.restoredState(ctx, r, i); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return q.mark(r, name, "restored.json", i, raw, true)
}
func (q legacyComposeTransition) restoredState(ctx context.Context, r Request, i legacyComposeIntent) error {
	current, err := q.state(ctx, r, i)
	if err != nil {
		return err
	}
	c := i.Object.Identity
	if (current.Identity.Status == "running") != (c.Status == "running") || current.Identity.Restart != c.Restart || current.Identity.MaxRetries != c.MaxRetries {
		return errors.New("legacy-compose-restore-not-confirmed")
	}
	return nil
}
func (q legacyComposeTransition) restored(ctx context.Context, r Request, name string) error {
	i, raw, err := q.read(r, name)
	if err != nil {
		return err
	}
	for _, file := range []string{"restore.json", "restored.json"} {
		if err := q.mark(r, name, file, i, raw, false); err != nil {
			return err
		}
	}
	return q.restoredState(ctx, r, i)
}
