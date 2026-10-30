package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Capture references are private recovery evidence, never configuration input.
// Preserve the exact encoding of an already-published pre-anchor intent on
// resume; publishIntent still compares its entire canonical contents.
func retainPriorPointerEncoding(path string, target ActiveInstallation) ActiveInstallation {
	raw, err := readPrivate(path, MaxRequestBytes)
	if err != nil {
		return target
	}
	var prior struct {
		Target ActiveInstallation `json:"target"`
	}
	if json.Unmarshal(raw, &prior) != nil || prior.Target.CaptureSHA256 != "" {
		return target
	}
	legacy := target
	legacy.CaptureSHA256 = ""
	a, _ := json.Marshal(legacy)
	b, _ := json.Marshal(prior.Target)
	if bytes.Equal(a, b) {
		return legacy
	}
	return target
}

type installationHistoryLink struct {
	request  Request
	captured backupIntent
	target   ActiveInstallation
}

// Traverse only the active pointer and exact predecessor pointers in its
// immutable captures. New pointers bind the whole capture; losing even the
// first capture cannot silently downgrade a migrated native node to fresh.
func (h installationHost) installationHistory(ctx context.Context, active *ActiveInstallation) ([]installationHistoryLink, error) {
	var result []installationHistoryLink
	seen := map[string]bool{}
	b := newTransitionBackup(h.root)
	b.unit = h.unitPath
	for depth := 0; active != nil && (active.Job != "" || active.PlanDigest != ""); depth++ {
		if depth >= 128 || seen[active.Job] {
			return nil, errors.New("installation-history-invalid")
		}
		seen[active.Job] = true
		r := Request{Protocol: 1, Job: active.Job, Node: active.Node, PlanDigest: active.PlanDigest, Epoch: 1, Phase: "backup", Operation: "apply", Spec: active.Spec}
		if r.Validate() != nil || !r.Spec.configurationValid() || active.CaptureSHA256 != "" && !validDigest(active.CaptureSHA256) {
			return nil, errors.New("installation-history-invalid")
		}
		path := filepath.Join(b.directory(r), "capture/intent.json")
		if _, err := os.Lstat(path); os.IsNotExist(err) && depth == 0 && active.CaptureSHA256 == "" {
			return result, nil
		}
		i, err := b.readIntent(ctx, r)
		if err != nil {
			return nil, err
		}
		raw, err := readPrivate(path, 4<<20)
		if err != nil || active.CaptureSHA256 != "" && sha(raw) != active.CaptureSHA256 {
			return nil, errors.New("installation-capture-changed")
		}
		result = append(result, installationHistoryLink{r, i, *active})
		if i.Installed.Generation != "v3" {
			return result, nil
		}
		listed := map[string]backupFile{}
		for _, f := range i.Files {
			listed[f.Path] = f
		}
		var previous ActiveInstallation
		_, err = decodePrivateJSON(filepath.Join(b.directory(r), "capture/active.json"), &previous, MaxRequestBytes)
		definition := "config/compose.json"
		if previous.Spec.Mode == "native" {
			definition = "native.service"
		}
		if err != nil || listed["active.json"].Path == "" || previous.Format != 1 || previous.Node != r.Node || previous.Spec.Validate() != nil || !previous.Spec.configurationValid() || previous.CaptureSHA256 != "" && (!validDigest(previous.CaptureSHA256) || previous.Job == "" || previous.PlanDigest == "") || (previous.Job != "" || previous.PlanDigest != "") && (!idPattern.MatchString(previous.Job) || !validDigest(previous.PlanDigest)) || previous.Spec.Mode != i.Installed.Mode || i.Installed.Runtime != filepath.Join(h.root, "configurations", previous.Spec.RuntimeSHA256, "runtime.json") || previous.RuntimeSHA256 != listed["config/runtime.json"].SHA256 || previous.DefinitionSHA256 != listed[definition].SHA256 {
			return nil, errors.New("installation-history-invalid")
		}
		active = &previous
	}
	return result, nil
}

func (h installationHost) historicalActivation(ctx context.Context, link installationHistoryLink) error {
	r := link.request
	root := filepath.Join(h.root, "transitions", r.Job)
	capture, err := readPrivate(filepath.Join(root, "capture/intent.json"), 4<<20)
	if err != nil {
		return err
	}
	var snapshot backupSnapshot
	raw, err := decodePrivateJSON(filepath.Join(root, "snapshot/receipt.json"), &snapshot, 16<<20)
	if err != nil || snapshot.Format != 1 || snapshot.Binding != binding(r) || snapshot.IntentSHA256 != sha(capture) {
		return errors.New("historical-snapshot-not-proven")
	}
	var target ActiveInstallation
	path := filepath.Join(root, "activation/intent.json")
	switch r.Spec.Mode {
	case "native":
		var activation nativeActivationIntent
		_, err = decodePrivateJSON(path, &activation, MaxRequestBytes)
		if err != nil || activation.Format != 1 || activation.Binding != binding(r) || activation.CaptureSHA256 != sha(capture) || activation.SnapshotSHA256 != sha(raw) || len(activation.Unit) == 0 || len(activation.Unit) > 64<<10 || sha(activation.Unit) != activation.Target.DefinitionSHA256 {
			return errors.New("historical-activation-not-proven")
		}
		target = activation.Target
	case "docker":
		var activation dockerActivationIntent
		_, err = decodePrivateJSON(path, &activation, MaxRequestBytes)
		if err != nil || activation.Format != 1 || activation.Binding != binding(r) || activation.CaptureSHA256 != sha(capture) || activation.SnapshotSHA256 != sha(raw) || activation.RetiredName != retiredDockerName(r) || !strings.HasPrefix(activation.ImageID, "sha256:") || !validDigest(strings.TrimPrefix(activation.ImageID, "sha256:")) {
			return errors.New("historical-activation-not-proven")
		}
		target = activation.Target
	default:
		return errors.New("historical-activation-not-proven")
	}
	want, _ := json.Marshal(link.target)
	got, _ := json.Marshal(target)
	if !bytes.Equal(want, got) {
		return errors.New("historical-pointer-not-proven")
	}
	return ctx.Err()
}

// Every captured Docker Agent must remain the exact retired, stopped object,
// even after a later native upgrade no longer has an active Compose file.
// Do not inspect the reusable live Agent name: it belongs to the new target.
func (h installationHost) retainedAgentHistory(ctx context.Context, active *ActiveInstallation) error {
	links, err := h.installationHistory(ctx, active)
	if err != nil {
		return err
	}
	for _, link := range links {
		if err := h.historicalActivation(ctx, link); err != nil {
			return err
		}
		i := agentOnly(link.captured.Installed)
		if i.Generation == "absent" || i.Mode != "docker" {
			continue
		}
		if !singleDockerOriginal(i) || len(i.Services) != 1 {
			return errors.New("historical-agent-not-proven")
		}
		c, err := h.ownedContainer(ctx, i.Services[0])
		if err != nil {
			return err
		}
		name := retiredDockerName(link.request)
		named, err := h.containerNamed(ctx, name)
		if err != nil || named == nil || named.ID != c.ID || c.Name != "/"+name || c.Status == "running" || c.Restart != "no" || c.MaxRetries != 0 {
			return errors.New("historical-agent-not-quiescent")
		}
	}
	return nil
}
