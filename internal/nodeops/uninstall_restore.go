package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type uninstallRestoreIntent struct {
	Format            int                `json:"format"`
	Binding           transitionBinding  `json:"binding"`
	Spec              Spec               `json:"spec"`
	Reference         UninstallReference `json:"reference"`
	CaptureSHA256     string             `json:"capture_sha256,omitempty"`
	AttemptSHA256     string             `json:"attempt_sha256,omitempty"`
	OriginalActive    json.RawMessage    `json:"original_active"`
	OriginalService   ServiceRecord      `json:"original_service"`
	PreservedSHA256   string             `json:"preserved_sha256"`
	PreviousTombstone json.RawMessage    `json:"previous_tombstone,omitempty"`
	NoEffects         bool               `json:"no_effects,omitempty"`
}
type uninstallRestoredObject struct {
	Format        int               `json:"format"`
	Binding       transitionBinding `json:"binding"`
	IntentSHA256  string            `json:"intent_sha256"`
	OriginalID    string            `json:"original_id"`
	OriginalProof string            `json:"original_proof"`
	Service       ServiceRecord     `json:"service"`
}

func (u *uninstallLifecycle) restoreIntent(ctx context.Context, r Request, publish bool) (uninstallRestoreIntent, []byte, error) {
	var p uninstallRestoreIntent
	path := filepath.Join(u.directory(r), "restoration-intent.json")
	if _, err := os.Lstat(path); err == nil {
		raw, e := decodePrivateJSON(path, &p, 4<<20)
		if e != nil || p.Format != 1 || p.Binding != binding(r) || p.Spec.digest() != r.Spec.digest() || !sameUninstall(p.Reference, *r.Uninstall) || !validDigest(p.PreservedSHA256) || sha(p.OriginalActive) != r.Uninstall.ActiveSHA256 {
			return p, nil, errors.New("uninstall-restoration-intent-invalid")
		}
		if p.NoEffects {
			if p.CaptureSHA256 != "" || !validDigest(p.AttemptSHA256) {
				return p, nil, errors.New("uninstall-no-effects-invalid")
			}
			q := r
			q.Phase = "restore"
			if untouched, e := u.backup.restoreUncaptured(q, false); e != nil || !untouched {
				return p, nil, errors.New("uninstall-no-effects-not-proven")
			}
			attempt, e := readPrivate(filepath.Join(u.backup.directory(r), "backup-attempt.json"), 4096)
			if e != nil || sha(attempt) != p.AttemptSHA256 {
				return p, nil, errors.New("uninstall-attempt-changed")
			}
		} else {
			capture, e := readPrivate(filepath.Join(u.backup.directory(r), "capture/intent.json"), 4<<20)
			if e != nil || sha(capture) != p.CaptureSHA256 {
				return p, nil, errors.New("uninstall-restore-capture-changed")
			}
		}
		inst := Installation{Node: r.Node, Generation: "v3", Mode: r.Spec.Mode, Runtime: p.OriginalService.Configuration, Services: []ServiceRecord{p.OriginalService}}
		if r.Spec.Mode == "docker" {
			var a ActiveInstallation
			if json.Unmarshal(p.OriginalActive, &a) != nil {
				return p, nil, errors.New("invalid-original-pointer")
			}
			inst.Runtime = filepath.Join(u.runtime.configurationDir(a.Spec), "runtime.json")
		}
		if !inst.valid(r.Node) {
			return p, nil, errors.New("uninstall-original-service-invalid")
		}
		canonical, _ := json.Marshal(p)
		if !bytes.Equal(raw, canonical) {
			return p, nil, errors.New("uninstall-restoration-not-canonical")
		}
		return p, raw, nil
	} else if !os.IsNotExist(err) {
		return p, nil, err
	}
	if !publish {
		return p, nil, os.ErrNotExist
	}
	active, pointer, err := u.source(ctx, r)
	if err != nil {
		return p, nil, err
	}
	if err = u.recoveryMaterials(ctx, r); err != nil {
		return p, nil, err
	}
	p = uninstallRestoreIntent{Format: 1, Binding: binding(r), Spec: r.Spec, Reference: *r.Uninstall, OriginalActive: pointer}
	if _, e := os.Lstat(filepath.Join(u.backup.directory(r), "capture")); os.IsNotExist(e) {
		q := r
		q.Phase = "restore"
		untouched, e := u.backup.restoreUncaptured(q, true)
		if e != nil || !untouched {
			return p, nil, errors.New("uninstall-effects-not-excluded")
		}
		attempt, e := readPrivate(filepath.Join(u.backup.directory(r), "backup-attempt.json"), 4096)
		if e != nil {
			return p, nil, e
		}
		p.NoEffects = true
		p.AttemptSHA256 = sha(attempt)
		installed, e := u.host.inventory(ctx, r.Node, r.Spec.Mode)
		if e != nil || len(installed.Services) != 1 {
			return p, nil, errors.New("uninstall-no-effects-original-missing")
		}
		p.OriginalService = installed.Services[0]
	} else if e != nil {
		return p, nil, e
	} else {
		captured, e := u.removalInstallation(ctx, r)
		if e != nil {
			return p, nil, e
		}
		capture, e := readPrivate(filepath.Join(u.backup.directory(r), "capture/intent.json"), 4<<20)
		if e != nil {
			return p, nil, e
		}
		p.CaptureSHA256 = sha(capture)
		p.OriginalService = captured.Installed.Services[0]
		if _, e := os.Lstat(filepath.Join(u.backup.directory(r), "snapshot")); e == nil {
			if _, e = u.backup.verify(ctx, r); e != nil {
				return p, nil, e
			}
		} else if !os.IsNotExist(e) {
			return p, nil, e
		} else {
			if _, e := os.Lstat(filepath.Join(u.directory(r), "intent.json")); !os.IsNotExist(e) {
				return p, nil, errors.New("uninstall-removed-snapshot-missing")
			}
		}
		if captured.DatabasePresent == nil {
			return p, nil, errors.New("uninstall-database-presence-unknown")
		}
		if *captured.DatabasePresent {
			if err := privateFile(filepath.Join(u.backup.data, "agent.sqlite3"), false); err != nil {
				return p, nil, err
			}
		}
		if _, e := os.Lstat(filepath.Join(u.directory(r), "intent.json")); e == nil {
			i, _, e := u.plan(ctx, r, false)
			if e != nil {
				return p, nil, e
			}
			p.PreservedSHA256 = i.PreservedSHA256
		} else if !os.IsNotExist(e) {
			return p, nil, e
		}
	}
	_ = active
	if p.PreservedSHA256 == "" {
		p.PreservedSHA256, err = u.publishPreservation(ctx, r)
		if err != nil {
			return p, nil, err
		}
	}
	if i, _, e := u.plan(ctx, r, false); e == nil {
		p.PreviousTombstone = i.PreviousTombstone
	} else if os.IsNotExist(e) {
		previous, e := readPrivate(filepath.Join(u.runtime.root, "uninstalled.json"), 4<<20)
		if e != nil && !os.IsNotExist(e) {
			return p, nil, e
		}
		if len(previous) > 0 {
			if _, source, e := u.host.readRemovalTombstone(ctx, previous); e != nil || source.Node != r.Node {
				return p, nil, errors.New("restoration-predecessor-not-proven")
			}
		}
		p.PreviousTombstone = previous
	} else {
		return p, nil, e
	}
	raw, _ := json.Marshal(p)
	if err = ensurePrivateDirectory(u.directory(r)); err != nil {
		return p, nil, err
	}
	if err = replacePrivateFile(path, raw, nil); err != nil {
		return p, nil, err
	}
	return p, raw, nil
}
func (u *uninstallLifecycle) restoredObject(ctx context.Context, r Request, p uninstallRestoreIntent, intent []byte) (uninstallRestoredObject, []byte, error) {
	var o uninstallRestoredObject
	raw, err := decodePrivateJSON(filepath.Join(u.directory(r), "restoration-object.json"), &o, 64<<10)
	if err != nil || o.Format != 1 || o.Binding != binding(r) || o.IntentSHA256 != sha(intent) || o.OriginalID != p.OriginalService.ID || o.OriginalProof != p.OriginalService.Proof {
		return o, nil, errors.New("uninstall-restored-object-not-proven")
	}
	want := p.OriginalService
	want.ID = o.Service.ID
	want.Proof = o.Service.Proof
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(o.Service)
	if !bytes.Equal(a, b) || !validDigest(o.Service.Proof) || o.Service.Kind == "docker" && !validDigest(o.Service.ID) || o.Service.Kind == "native" && (o.Service.ID != p.OriginalService.ID || o.Service.Proof != p.OriginalService.Proof) {
		return o, nil, errors.New("uninstall-restored-object-mismatch")
	}
	canonical, _ := json.Marshal(o)
	if !bytes.Equal(raw, canonical) {
		return o, nil, errors.New("uninstall-restored-object-not-canonical")
	}
	return o, raw, nil
}
func (u *uninstallLifecycle) recordRestoredObject(r Request, p uninstallRestoreIntent, intent []byte, s ServiceRecord) (uninstallRestoredObject, []byte, error) {
	o := uninstallRestoredObject{1, binding(r), sha(intent), p.OriginalService.ID, p.OriginalService.Proof, s}
	raw, _ := json.Marshal(o)
	if err := replacePrivateFile(filepath.Join(u.directory(r), "restoration-object.json"), raw, nil); err != nil {
		return o, nil, err
	}
	return o, raw, nil
}
func (u *uninstallLifecycle) restoredPointer(r Request, p uninstallRestoreIntent, intent, object []byte) ([]byte, error) {
	if p.NoEffects {
		return p.OriginalActive, nil
	}
	var a ActiveInstallation
	if json.Unmarshal(p.OriginalActive, &a) != nil {
		return nil, errors.New("original-pointer-invalid")
	}
	a.Restoration = &ActiveRestorationReference{r.Job, r.PlanDigest, sha(intent), sha(object)}
	return json.Marshal(a)
}
func (u *uninstallLifecycle) restorationResumable(ctx context.Context, r Request) error {
	p, _, err := u.restoreIntent(ctx, r, false)
	if os.IsNotExist(err) {
		if _, e := os.Lstat(filepath.Join(u.backup.directory(r), "capture")); e == nil {
			_, e = u.backup.readIntent(ctx, r)
			return e
		}
		q := r
		q.Phase = "restore"
		_, _, e := u.backup.uncaptured(q)
		return e
	}
	if err != nil {
		return err
	}
	var active ActiveInstallation
	if json.Unmarshal(p.OriginalActive, &active) != nil {
		return errors.New("original-pointer-invalid")
	}
	raw, err := readPrivate(filepath.Join(u.runtime.root, "active.json"), MaxRequestBytes)
	if err == nil && !bytes.Equal(raw, p.OriginalActive) {
		if _, e := u.restorationEvidenceForCurrent(ctx, r, p); e != nil {
			return e
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
func (u *uninstallLifecycle) restore(ctx context.Context, r Request) error {
	p, intent, err := u.restoreIntent(ctx, r, true)
	if err != nil {
		return err
	}
	// A retry after a lost start response must not stop a restored writer or
	// compare its evolving queue to the stopped byte manifest.
	if err = u.verifyRestoration(ctx, r, false); err == nil {
		return nil
	}
	if err = u.restorationResumable(ctx, r); err != nil {
		return err
	}
	var lock *os.File
	if !p.NoEffects {
		lock, err = u.backup.agentLock()
		if err != nil {
			return err
		}
		defer func() {
			if lock != nil {
				lock.Close()
			}
		}()
	}
	mutable := p.NoEffects
	if existing, _, e := u.restoredObject(ctx, r, p, intent); e == nil {
		if existing.Service.Kind == "native" {
			if s, e := u.host.native(ctx, existing.Service); e == nil && s.MainPID > 0 {
				mutable = true
			}
		} else if c, e := u.host.ownedContainer(ctx, existing.Service); e == nil && c.Status == "running" {
			mutable = true
		}
	}
	if err = u.verifyPreservation(ctx, r, p.PreservedSHA256, mutable); err != nil {
		return err
	}
	var original ActiveInstallation
	if json.Unmarshal(p.OriginalActive, &original) != nil {
		return errors.New("original-pointer-invalid")
	}
	captured := backupIntent{}
	if !p.NoEffects {
		captured, err = u.backup.readIntent(ctx, r)
		if err != nil {
			return err
		}
		if err = u.backup.restoreOriginalConfiguration(ctx, r, captured); err != nil {
			return err
		}
	}
	o, object, objectErr := u.restoredObject(ctx, r, p, intent)
	if objectErr != nil {
		if _, e := os.Lstat(filepath.Join(u.directory(r), "restoration-object.json")); !os.IsNotExist(e) {
			return objectErr
		}
		s := p.OriginalService
		if s.Kind == "native" {
			unit, err := readPrivate(filepath.Join(u.runtime.configurationDir(original.Spec), nativeServiceName), 64<<10)
			if err != nil || sha(unit) != s.Proof {
				return errors.New("original-unit-not-preserved")
			}
			if current, e := readPrivate(u.host.unitPath, 64<<10); e == nil {
				if !bytes.Equal(current, unit) {
					return errors.New("restore-native-unit-changed")
				}
			} else if os.IsNotExist(e) {
				if err = restoreCapturedFile(ctx, filepath.Join(u.backup.directory(r), "capture/native.service"), u.host.unitPath, backupFile{Path: "native.service", Bytes: int64(len(unit)), SHA256: sha(unit), Mode: 0600}); err != nil {
					return err
				}
			} else {
				return e
			}
			if !p.NoEffects {
				if _, err = u.host.command(ctx, "systemctl", "daemon-reload"); err != nil {
					return err
				}
			}
		} else {
			c, err := u.restoreDockerObject(ctx, r, p, original)
			if err != nil {
				return err
			}
			s.ID, s.Proof = c.ID, c.fingerprint()
		}
		o, object, err = u.recordRestoredObject(r, p, intent, s)
		if err != nil {
			return err
		}
	}
	pointer, err := u.restoredPointer(r, p, intent, object)
	if err != nil {
		return err
	}
	// Allowed previous bytes are the captured pointer or its absence after the
	// explicit removal. Never overwrite an unrelated operator installation.
	current, readErr := readPrivate(filepath.Join(u.runtime.root, "active.json"), MaxRequestBytes)
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if len(current) > 0 && !bytes.Equal(current, p.OriginalActive) && !bytes.Equal(current, pointer) {
		return errors.New("restoration-active-changed")
	}
	if err = replacePrivateFile(filepath.Join(u.runtime.root, "active.json"), pointer, current); err != nil {
		return err
	}
	if err = u.restorePreviousTombstone(ctx, r); err != nil {
		return err
	}
	restored := Installation{Node: r.Node, Generation: "v3", Mode: original.Spec.Mode, Runtime: filepath.Join(u.runtime.configurationDir(original.Spec), "runtime.json"), Services: []ServiceRecord{o.Service}}
	if !p.NoEffects {
		lock.Close()
		lock = nil
		if err = u.host.restoreServices(ctx, restored); err != nil {
			return err
		}
	}
	return u.verifyRestoration(ctx, r, false)
}
func (u *uninstallLifecycle) restoreDockerObject(ctx context.Context, r Request, p uninstallRestoreIntent, active ActiveInstallation) (containerIdentity, error) {
	var empty containerIdentity
	s := p.OriginalService
	absent, err := u.host.containerAbsent(ctx, s.ID)
	if err != nil {
		return empty, err
	}
	if !absent {
		c, e := u.host.ownedContainer(ctx, s)
		if e != nil {
			return c, e
		}
		if c.Name != "/"+s.Name {
			return c, errors.New("original-container-name-changed")
		}
		return c, nil
	}
	if p.NoEffects {
		return empty, errors.New("no-effects-original-object-missing")
	}
	// The exact removal intent and snapshot must exist before a new ID is legal.
	if _, _, err = u.plan(ctx, r, false); err != nil {
		return empty, err
	}
	c, err := u.host.containerNamed(ctx, s.Name)
	if err != nil {
		return empty, err
	}
	if c == nil {
		definition := filepath.Join(u.runtime.configurationDir(active.Spec), "compose.json")
		if _, err = u.host.docker(ctx, "compose", "--project-directory", filepath.Dir(definition), "-p", dockerProject(active), "-f", definition, "create", "--no-build", "--pull", "never", "--no-recreate", "agent"); err != nil {
			return empty, err
		}
		c, err = u.host.containerNamed(ctx, s.Name)
		if err != nil || c == nil {
			return empty, errors.New("restoration-container-create-unconfirmed")
		}
	}
	// A lost create response may be adopted only before a writer starts, against
	// the original immutable definition/image/project and durable restore intent.
	if c.Status != "created" {
		return *c, errors.New("unrecorded-restoration-writer")
	}
	if err = u.host.verifyV3Container(*c, withoutRestoration(active)); err != nil {
		return *c, err
	}
	return *c, nil
}
func withoutRestoration(a ActiveInstallation) ActiveInstallation { a.Restoration = nil; return a }
func (u *uninstallLifecycle) restorePreviousTombstone(ctx context.Context, r Request) error {
	i, _, err := u.plan(ctx, r, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	path := filepath.Join(u.runtime.root, "uninstalled.json")
	current, err := readPrivate(path, 4<<20)
	if os.IsNotExist(err) {
		if len(i.PreviousTombstone) == 0 {
			return nil
		}
		return replacePrivateFile(path, i.PreviousTombstone, nil)
	}
	if err != nil {
		return err
	}
	if bytes.Equal(current, i.PreviousTombstone) {
		return nil
	}
	tomb, err := readPrivate(filepath.Join(u.directory(r), "tombstone.json"), 4<<20)
	if err != nil || !bytes.Equal(current, tomb) {
		return errors.New("restoration-tombstone-changed")
	}
	if len(i.PreviousTombstone) == 0 {
		return removeExpectedPrivate(path, current)
	}
	return replacePrivateFile(path, i.PreviousTombstone, current)
}
func (u *uninstallLifecycle) restorationEvidenceForCurrent(ctx context.Context, r Request, p uninstallRestoreIntent) (RestorationEvidence, error) {
	var e RestorationEvidence
	_, intent, err := u.restoreIntent(ctx, r, false)
	if err != nil {
		return e, err
	}
	_, object, err := u.restoredObject(ctx, r, p, intent)
	if err != nil {
		return e, err
	}
	pointer, err := u.restoredPointer(r, p, intent, object)
	if err != nil {
		return e, err
	}
	current, err := readPrivate(filepath.Join(u.runtime.root, "active.json"), MaxRequestBytes)
	if err != nil || !bytes.Equal(current, pointer) {
		return e, errors.New("restored-active-not-proven")
	}
	e = RestorationEvidence{p.CaptureSHA256, sha(intent), sha(pointer), sha(object), p.PreservedSHA256, p.NoEffects}
	return e, nil
}
func (u *uninstallLifecycle) verifyRestoration(ctx context.Context, r Request, final bool) error {
	p, intent, err := u.restoreIntent(ctx, r, false)
	if err != nil {
		return err
	}
	o, _, err := u.restoredObject(ctx, r, p, intent)
	if err != nil {
		return err
	}
	e, err := u.restorationEvidenceForCurrent(ctx, r, p)
	if err != nil {
		return err
	}
	if !e.Valid() {
		return errors.New("invalid-restoration-evidence")
	}
	current, markerErr := readPrivate(filepath.Join(u.runtime.root, "uninstalled.json"), 4<<20)
	if len(p.PreviousTombstone) == 0 {
		if !os.IsNotExist(markerErr) {
			return errors.New("restoration-previous-tombstone-not-proven")
		}
	} else if markerErr != nil || !bytes.Equal(current, p.PreviousTombstone) {
		return errors.New("restoration-previous-tombstone-not-proven")
	}
	if err = u.verifyPreservation(ctx, r, p.PreservedSHA256, true); err != nil {
		return err
	}
	if o.Service.Kind == "native" {
		s, err := u.host.native(ctx, o.Service)
		if err != nil {
			return err
		}
		if (s.MainPID > 0) != o.Service.Running || (s.UnitFileState == "enabled") != o.Service.Enabled {
			return errors.New("native-restore-state-not-confirmed")
		}
	} else {
		c, err := u.host.ownedContainer(ctx, o.Service)
		if err != nil {
			return err
		}
		if c.Name != "/"+o.Service.Name || (c.Status == "running") != o.Service.Running || c.Restart != o.Service.Restart || c.MaxRetries != o.Service.MaxRetries {
			return errors.New("docker-restore-state-not-confirmed")
		}
		var active ActiveInstallation
		if json.Unmarshal(p.OriginalActive, &active) != nil {
			return errors.New("original-pointer-invalid")
		}
		if err = u.host.verifyV3Container(c, withoutRestoration(active)); err != nil {
			return err
		}
	}
	if final {
		raw, err := readPrivate(filepath.Join(u.directory(r), "restoration-final.json"), 4096)
		want, _ := json.Marshal(e)
		if err != nil || !bytes.Equal(raw, want) {
			return errors.New("restoration-final-not-proven")
		}
	}
	return nil
}
func (u *uninstallLifecycle) sealRestoration(ctx context.Context, r Request) error {
	if err := u.verifyRestoration(ctx, r, false); err != nil {
		return err
	}
	p, _, err := u.restoreIntent(ctx, r, false)
	if err != nil {
		return err
	}
	e, err := u.restorationEvidenceForCurrent(ctx, r, p)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(e)
	return replacePrivateFile(filepath.Join(u.directory(r), "restoration-final.json"), raw, nil)
}
func (u *uninstallLifecycle) verifyRestorationReference(ctx context.Context, r Request, a ActiveInstallation, depth int) error {
	q := r.Uninstall
	root := filepath.Join(u.runtime.root, "transitions", q.RestorationJob, "uninstall")
	var e RestorationEvidence
	raw, err := decodePrivateJSON(filepath.Join(root, "restoration-final.json"), &e, 4096)
	if err != nil || !e.Valid() || sha(raw) != q.RestorationSHA256 || e.ActiveSHA256 != q.ActiveSHA256 {
		return errors.New("uninstall-restoration-evidence-mismatch")
	}
	var p uninstallRestoreIntent
	intent, err := decodePrivateJSON(filepath.Join(root, "restoration-intent.json"), &p, 4<<20)
	prior := Request{Protocol: Protocol, Operation: "apply", Job: q.RestorationJob, Node: r.Node, PlanDigest: q.RestorationPlanDigest, Epoch: 1, Phase: "verify-rollback", Spec: p.Spec, Uninstall: &p.Reference}
	if err != nil || prior.Validate() != nil || p.Binding != binding(prior) || e.IntentSHA256 != sha(intent) || p.Reference.SourceJob != q.SourceJob || p.Reference.SourcePlanDigest != q.SourcePlanDigest || p.Reference.CaptureSHA256 != q.CaptureSHA256 {
		return errors.New("uninstall-restoration-source-mismatch")
	}
	if _, _, err = u.sourceDepth(ctx, prior, depth); err != nil {
		return err
	}
	_, object, err := u.restoredObject(ctx, prior, p, intent)
	if err != nil || sha(object) != e.ObjectSHA256 {
		return errors.New("uninstall-restoration-object-mismatch")
	}
	pointer, err := u.restoredPointer(prior, p, intent, object)
	current, _ := json.Marshal(a)
	if err != nil || sha(pointer) != e.ActiveSHA256 || !bytes.Equal(pointer, current) || e.CaptureSHA256 != p.CaptureSHA256 || e.PreservedSHA256 != p.PreservedSHA256 || e.NoEffects != p.NoEffects {
		return errors.New("uninstall-restoration-pointer-mismatch")
	}
	return nil
}
