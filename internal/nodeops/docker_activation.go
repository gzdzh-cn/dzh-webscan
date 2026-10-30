package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"webscan/internal/nodeconfig"
)

// Private until Docker recovery/verification and central deployment readiness
// form a complete lifecycle. LocalRuntime still exposes only preflight/stage.
type dockerActivation struct {
	runtime *LocalRuntime
	backup  *transitionBackup
	host    installationHost
}

type dockerActivationIntent struct {
	Format                        int               `json:"format"`
	Binding                       transitionBinding `json:"binding"`
	CaptureSHA256, SnapshotSHA256 string
	Target                        ActiveInstallation `json:"target"`
	ImageID                       string             `json:"image_id"`
	RetiredName                   string             `json:"retired_name"`
}
type dockerActivationPlan struct {
	agent                    Installation
	intent                   dockerActivationIntent
	original                 backupIntent
	material                 nodeconfig.Material
	pointer, previousPointer []byte
	definition               string
}
type dockerCreatedReceipt struct {
	Format                      int               `json:"format"`
	Binding                     transitionBinding `json:"binding"`
	ActivationSHA256, ID, Proof string
}

func newDockerActivation(w *LocalRuntime) *dockerActivation {
	return &dockerActivation{runtime: w, backup: newTransitionBackup(w.root), host: newInstallationHost(w.root)}
}
func (a *dockerActivation) valid(r Request, phase string) bool {
	return a != nil && a.runtime != nil && a.backup != nil && a.host.root == a.runtime.root && a.backup.root == a.runtime.root && a.backup.unit == a.host.unitPath && r.Validate() == nil && r.Operation == "apply" && r.Phase == phase && r.Spec.Mode == "docker" && r.Spec.configurationValid()
}
func (a *dockerActivation) intentPath(r Request) string {
	return filepath.Join(a.backup.directory(r), "activation", "intent.json")
}
func (a *dockerActivation) createdPath(r Request) string {
	return filepath.Join(a.backup.directory(r), "activation", "created.json")
}

func singleDockerOriginal(i Installation) bool {
	if hasLegacyMembers(i) {
		return false
	}
	if i.Generation == "absent" {
		return len(i.Services) == 0
	}
	return i.Mode == "docker" && len(i.Services) == 1 && i.Services[0].Kind == "docker" && i.Services[0].Name == agentContainerName
}

func (a *dockerActivation) imageID(ctx context.Context, s Spec) (string, error) {
	ref := s.AgentImage
	if s.imageArchiveValid() {
		f, err := verifiedImageArchive(ctx, a.runtime.root, s)
		if err != nil {
			return "", err
		}
		f.Close()
		ref, err = dockerLaunchIdentity(a.runtime.root, s)
		if err != nil {
			return "", err
		}
	}
	raw, err := a.host.docker(ctx, "image", "inspect", ref, "--format", imageIdentityFormat)
	if err != nil {
		return "", err
	}
	var image struct{ ID, OS, Arch string }
	if len(raw) > 8192 || json.Unmarshal([]byte(raw), &image) != nil || image.OS != "linux" || image.Arch != "amd64" || !strings.HasPrefix(image.ID, "sha256:") || !validDigest(strings.TrimPrefix(image.ID, "sha256:")) {
		return "", errors.New("image-identity-not-verified")
	}
	if s.imageArchiveValid() {
		if image.ID != ref {
			return "", errors.New("image-config-identity-mismatch")
		}
	} else if err := verifyDockerImageIdentity(raw, s.AgentImage); err != nil {
		return "", err
	}
	return image.ID, nil
}

func (a *dockerActivation) plan(ctx context.Context, r Request) (dockerActivationPlan, error) {
	var p dockerActivationPlan
	if !a.valid(r, "activate") {
		return p, errors.New("invalid-docker-activation")
	}
	if err := a.runtime.verifyPrepared(ctx, r.Spec); err != nil {
		return p, err
	}
	if err := a.runtime.verifyConfiguration(ctx, r); err != nil {
		return p, err
	}
	m, err := a.runtime.configurationMaterial(ctx, r)
	if err != nil {
		return p, err
	}
	i, err := a.backup.readIntent(ctx, r)
	if err != nil {
		return p, err
	}
	p.agent, err = a.backup.transitionAgent(i)
	if err != nil {
		return p, err
	}
	if !supportedDockerOriginal(p.agent) {
		return p, errors.New("original-docker-transition-not-supported")
	}

	if _, err := a.backup.verify(ctx, r); err != nil {
		return p, err
	}
	capture, err := readPrivate(filepath.Join(a.backup.directory(r), "capture/intent.json"), 4<<20)
	if err != nil {
		return p, err
	}
	snapshot, err := readPrivate(filepath.Join(a.backup.directory(r), "snapshot/receipt.json"), 16<<20)
	if err != nil {
		return p, err
	}
	files, err := a.runtime.configurationFiles(m, r.Spec)
	if err != nil {
		return p, err
	}
	image, err := a.imageID(ctx, r.Spec)
	if err != nil {
		return p, err
	}
	target := ActiveInstallation{Format: 1, Node: r.Node, Spec: r.Spec, RuntimeSHA256: sha(files["runtime.json"]), DefinitionSHA256: sha(files["compose.json"]), Job: r.Job, PlanDigest: r.PlanDigest, CaptureSHA256: sha(capture)}
	target = retainPriorPointerEncoding(a.intentPath(r), target)
	p.pointer, err = json.Marshal(target)
	if err != nil {
		return p, err
	}
	for _, f := range i.Files {
		if f.Path == "active.json" {
			p.previousPointer, err = readPrivate(filepath.Join(a.backup.directory(r), "capture", f.Path), MaxRequestBytes)
			if err != nil {
				return p, err
			}
		}
	}
	p.material, p.original, p.definition = m, i, filepath.Join(a.runtime.configurationDir(r.Spec), "compose.json")
	p.intent = dockerActivationIntent{1, binding(r), sha(capture), sha(snapshot), target, image, "webscan-retired-" + sha([]byte(r.Node + "\x00" + r.Job + "\x00" + r.PlanDigest))[:24]}
	if err := a.originalFiles(ctx, i); err != nil {
		return p, err
	}
	if singleNativeOriginal(p.agent) {
		authorized, err := a.nativeRetirementAuthorized(r, p)
		if err != nil {
			return p, err
		}
		if _, _, err := a.originalNative(ctx, r, i, authorized); err != nil {
			return p, err
		}
	}
	return p, nil
}

func (a *dockerActivation) publishIntent(r Request, p dockerActivationPlan) error {
	if err := ensurePrivateDirectory(filepath.Dir(a.intentPath(r))); err != nil {
		return err
	}
	raw, err := json.Marshal(p.intent)
	if err != nil {
		return err
	}
	return replacePrivateFile(a.intentPath(r), raw, nil)
}

func (h installationHost) containerNamed(ctx context.Context, name string) (*containerIdentity, error) {
	if !idPattern.MatchString(name) {
		return nil, errors.New("invalid-container-name")
	}
	raw, err := h.docker(ctx, "ps", "-a", "--no-trunc", "--filter", "name=^/"+name+"$", "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(raw)
	if id == "" {
		return nil, nil
	}
	if !validDigest(id) {
		return nil, errors.New("container-lookup-not-unique")
	}
	c, err := h.container(ctx, id)
	if err != nil {
		return nil, err
	}
	if c.Name != "/"+name {
		return nil, errors.New("container-name-raced")
	}
	return &c, nil
}

func (h installationHost) taskContainer(ctx context.Context, a ActiveInstallation) (*containerIdentity, error) {
	if !idPattern.MatchString(a.Node) || !idPattern.MatchString(a.Job) || !validDigest(a.PlanDigest) {
		return nil, errors.New("invalid-container-task")
	}
	raw, err := h.docker(ctx, "ps", "-a", "--no-trunc", "--filter", "label=com.docker.compose.project="+dockerProject(a), "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(raw)
	if id == "" {
		return nil, nil
	}
	if !validDigest(id) {
		return nil, errors.New("task-container-lookup-not-unique")
	}
	c, err := h.container(ctx, id)
	if err != nil {
		return nil, err
	}
	if c.Project != dockerProject(a) {
		return nil, errors.New("task-container-project-raced")
	}
	return &c, nil
}

func (a *dockerActivation) originalStopped(ctx context.Context, r Request, p dockerActivationPlan) error {
	if err := a.backup.targetWrappersQuiescent(ctx, p.original); err != nil {
		return err
	}
	if err := a.nativeOriginalStopped(ctx, r, p, false); err != nil {
		return err
	}
	if err := a.originalFiles(ctx, p.original); err != nil {
		return err
	}
	for _, s := range p.agent.Services {
		if s.Kind != "docker" {
			continue
		}
		c, err := a.host.ownedContainer(ctx, s)
		if err != nil {
			return err
		}
		if c.Name != "/"+s.Name && c.Name != "/"+p.intent.RetiredName {
			return errors.New("original-container-name-changed")
		}
		if c.Status == "running" || c.Restart != "no" {
			return errors.New("original-container-not-quiescent")
		}
	}
	return nil
}

func (a *dockerActivation) originalFiles(ctx context.Context, i backupIntent) error {
	agent, err := a.backup.transitionAgent(i)
	if err != nil {
		return err
	}
	// The task may already have switched active.json. Original runtime files
	// remain immutable; pointer transitions are checked separately against both
	// captured and intended bytes under the same operation lock. A retired native
	// unit has its own capture, activation-intent and manager-state proof.
	files := []backupFile{}
	for _, f := range i.Files {
		if f.Path != "active.json" && !(singleNativeOriginal(agent) && f.Path == "native.service") {
			files = append(files, f)
		}
	}
	i.Files = files
	return a.backup.unchanged(ctx, i)
}

func (a *dockerActivation) target(ctx context.Context, r Request, p dockerActivationPlan) (*containerIdentity, error) {
	task, err := a.host.taskContainer(ctx, p.intent.Target)
	if err != nil {
		return nil, err
	}
	c, err := a.host.containerNamed(ctx, agentContainerName)
	if err != nil {
		return nil, err
	}
	if c == nil || len(p.agent.Services) > 0 && c.ID == p.agent.Services[0].ID {
		if task != nil {
			return nil, errors.New("task-container-name-changed")
		}
		if _, err := os.Lstat(a.createdPath(r)); !os.IsNotExist(err) {
			return nil, errors.New("recorded-target-container-missing")
		}
		return nil, nil
	}
	if task == nil || task.ID != c.ID {
		return nil, errors.New("task-container-identity-mismatch")
	}
	if err := a.host.verifyV3Container(*c, p.intent.Target); err != nil {
		return nil, err
	}
	if c.ImageID != p.intent.ImageID || c.MaxRetries != 0 || (c.Restart != "no" && c.Restart != "unless-stopped") {
		return nil, errors.New("target-container-identity-changed")
	}
	// A saved receipt binds the exact object even if another local object copied
	// all project labels. Without it, only this task's deterministic create can
	// be reconciled, and the new receipt is persisted before any start.
	var receipt dockerCreatedReceipt
	if _, err := os.Lstat(a.createdPath(r)); err == nil {
		if _, err := decodePrivateJSON(a.createdPath(r), &receipt, 4096); err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(p.intent)
		if receipt.Format != 1 || receipt.Binding != binding(r) || receipt.ActivationSHA256 != sha(raw) || receipt.ID != c.ID || receipt.Proof != c.fingerprint() {
			return nil, errors.New("created-container-receipt-mismatch")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	} else if c.Status != "created" {
		// A lost create response is replayable only before the first start.
		// An exited object may already have written data; it needs its saved ID
		// receipt just as a running object does.
		return nil, errors.New("unrecorded-target-writer")
	}
	return c, nil
}

func (a *dockerActivation) recordCreated(r Request, p dockerActivationPlan, c containerIdentity) error {
	raw, _ := json.Marshal(p.intent)
	receipt, err := json.Marshal(dockerCreatedReceipt{1, binding(r), sha(raw), c.ID, c.fingerprint()})
	if err != nil {
		return err
	}
	return replacePrivateFile(a.createdPath(r), receipt, nil)
}

func (a *dockerActivation) run(ctx context.Context, r Request) error {
	if !a.valid(r, "activate") {
		return errors.New("invalid-docker-activation")
	}
	ctx, release, err := acquireServiceOperation(ctx, a.runtime.root)
	if err != nil {
		return err
	}
	defer release()
	if a.backup.rollbackStarted(r) {
		return errors.New("rollback-already-started")
	}
	p, err := a.plan(ctx, r)
	if err != nil {
		return err
	}
	if err := a.publishIntent(r, p); err != nil {
		return err
	}
	if _, _, err := allowedEffectiveFile(filepath.Join(a.runtime.root, "active.json"), p.pointer, p.previousPointer); err != nil {
		return err
	}
	if err := a.originalStopped(ctx, r, p); err != nil {
		return err
	}
	target, err := a.target(ctx, r, p)
	if err != nil {
		return err
	}
	if target != nil && target.Status == "running" {
		if _, err := readPrivate(a.createdPath(r), 4096); err != nil {
			return errors.New("unrecorded-target-writer")
		}
		return a.confirm(ctx, r, p)
	}
	lock, err := a.backup.agentLock()
	if err != nil {
		return err
	}
	locked := true
	defer func() {
		if locked {
			lock.Close()
		}
	}()
	if err := a.originalStopped(ctx, r, p); err != nil {
		return err
	}
	if err := a.backup.reconcileLegacyLogsLocked(ctx, r); err != nil {
		return err
	}
	for _, root := range r.Spec.MonitorDirectories {
		stat, err := os.Stat(root)
		if err != nil || !stat.IsDir() {
			return errors.New("monitor-directory-not-accessible")
		}
	}
	probe := p.material.Settings.ProbeDirectory
	if err := directoryAncestors(filepath.Dir(probe)); err != nil {
		return err
	}
	if _, err := os.Lstat(probe); os.IsNotExist(err) {
		if err := os.Mkdir(probe, 0700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := privateDirectoryTree(probe); err != nil {
		return err
	}
	for _, dir := range []string{a.backup.data, a.backup.logs} {
		if err := ensurePrivateDirectory(dir); err != nil {
			return err
		}
	}
	if err := a.retireNative(ctx, r, p); err != nil {
		return err
	}
	for _, s := range p.agent.Services {
		if s.Kind != "docker" {
			continue
		}
		old, err := a.host.ownedContainer(ctx, s)
		if err != nil {
			return err
		}
		if old.Name == "/"+s.Name {
			other, err := a.host.containerNamed(ctx, p.intent.RetiredName)
			if err != nil {
				return err
			}
			if other != nil {
				return errors.New("retired-container-name-in-use")
			}
			if _, err := a.host.docker(ctx, "rename", s.ID, p.intent.RetiredName); err != nil {
				return err
			}
		}
	}
	target, err = a.target(ctx, r, p)
	if err != nil {
		return err
	}
	if target == nil {
		// -p isolates reconciliation from the original project's retained object.
		// No dependencies/build/pull or volume deletion is allowed here.
		_, err = a.host.docker(ctx, "compose", "--project-directory", filepath.Dir(p.definition), "-p", dockerProject(p.intent.Target), "-f", p.definition, "create", "--no-build", "--pull", "never", "--no-recreate", "agent")
		if err != nil {
			return err
		}
		target, err = a.target(ctx, r, p)
		if err != nil {
			return err
		}
		if target == nil {
			return errors.New("target-container-not-created")
		}
	}
	if target.Status == "running" {
		return errors.New("unexpected-node-writer-active")
	}
	loaded, err := a.host.dockerRuntime(ctx, target.ID)
	if err != nil {
		return err
	}
	if loaded.State.Pid != 0 || loaded.State.Running || loaded.State.Paused || loaded.State.Restarting || loaded.State.Dead || loaded.State.OOMKilled || loaded.State.Status != target.Status {
		return errors.New("target-container-not-quiescent")
	}
	if err := loaded.verifyPolicy(p.material.Settings.Resources, target.Restart); err != nil {
		return err
	}
	if err := a.recordCreated(r, p, *target); err != nil {
		return err
	}
	if err := replacePrivateFile(filepath.Join(a.runtime.root, "active.json"), p.pointer, p.previousPointer); err != nil {
		return err
	}
	if err := a.backup.targetWrappersQuiescent(ctx, p.original); err != nil {
		return err
	}
	lock.Close()
	locked = false
	if _, err := a.host.docker(ctx, "update", "--restart=unless-stopped", target.ID); err != nil {
		return err
	}
	if _, err := a.host.docker(ctx, "start", target.ID); err != nil {
		return err
	}
	return a.confirm(ctx, r, p)
}

func (a *dockerActivation) confirm(ctx context.Context, r Request, p dockerActivationPlan) error {
	if err := a.backup.verifyLegacyReconciliation(p.original, p.intent.SnapshotSHA256); err != nil {
		return err
	}
	if err := a.nativeOriginalStopped(ctx, r, p, true); err != nil {
		return err
	}
	if err := a.originalStopped(ctx, r, p); err != nil {
		return err
	}
	raw, err := readPrivate(filepath.Join(a.runtime.root, "active.json"), MaxRequestBytes)
	if err != nil || !bytes.Equal(raw, p.pointer) {
		return errors.New("target-pointer-not-confirmed")
	}
	c, err := a.target(ctx, r, p)
	if err != nil {
		return err
	}
	if c == nil {
		return errors.New("target-container-not-confirmed")
	}
	_, err = a.host.verifyRunningDocker(ctx, c.ID, p.intent.Target, p.material.Settings.Resources)
	return err
}
