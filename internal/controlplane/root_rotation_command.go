package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"time"
)

type rootRotationFile struct {
	ID      string                  `json:"id,omitempty"`
	Members []rootRotationNodeInput `json:"members,omitempty"`
	Confirm bool                    `json:"confirm"`
}

type rootRotationView struct {
	ID          string                   `json:"id"`
	Status      string                   `json:"status"`
	Revision    int64                    `json:"revision"`
	ExpiresAt   time.Time                `json:"expires_at"`
	RestoreHold bool                     `json:"restore_hold"`
	Members     []rootRotationMemberView `json:"members"`
}

type rootRotationMemberView struct {
	Role       string    `json:"role"`
	ID         string    `json:"id"`
	Trust      bool      `json:"dual_trust"`
	Activated  bool      `json:"activated"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
	Final      bool      `json:"old_root_removed"`
}

func rootTaskView(j rootRotationTask, hold bool) rootRotationView {
	out := rootRotationView{ID: j.ID, Status: j.Status, Revision: j.Revision, ExpiresAt: j.ExpiresAt, RestoreHold: hold, Members: make([]rootRotationMemberView, 0, len(j.Members))}
	for i, m := range j.Members {
		state := j.State[i]
		out.Members = append(out.Members, rootRotationMemberView{m.Role, m.ID, state.Trust, state.Activated, state.ObservedAt, state.Final})
	}
	return out
}

// Dedicated bounded host input supports large explicit membership without
// relaxing the much smaller generic credential-input limit.
func rootRotationInput(path string) (rootRotationFile, error) {
	var in rootRotationFile
	raw, err := readTrustData(path, true, 32<<20)
	if err != nil {
		return in, errRootRotationTask
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if !uniqueProvisioningJSON(json.NewDecoder(bytes.NewReader(raw)), 0) || d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		return rootRotationFile{}, errRootRotationTask
	}
	return in, nil
}

func (s *Store) localRootRotationCommand(ctx context.Context, c Config, o Options, out io.Writer) error {
	if err := provisioningAdmin(ctx, s.DB, o.Username); err != nil {
		return err
	}
	in, err := rootRotationInput(o.Source)
	if err != nil {
		return err
	}
	trust, err := loadDeploymentTrust(ctx, c.DeploymentTrust)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	if o.Action == "prepare-root-rotation" {
		if !in.Confirm || in.ID != "" || !identifier.MatchString(o.RequestKey) {
			return errRootRotationTask
		}
		j, err := s.prepareRootRotation(ctx, c, trust.vault, o.Username, o.RequestKey, trust.release, in.Members)
		if err != nil {
			return err
		}
		return encoder.Encode(rootTaskView(j, false))
	}
	if !releaseDigest(in.ID) || len(in.Members) != 0 {
		return errRootRotationTask
	}
	j, hold, err := s.readRootTask(ctx, trust.vault, in.ID)
	if err != nil || j.User != o.Username {
		return errRootRotationTask
	}
	if o.Action == "root-rotation-status" {
		return encoder.Encode(rootTaskView(j, hold))
	}
	if !in.Confirm {
		return errRootRotationTask
	}
	if o.Action == "reauthorize-root-rotation" || o.Action == "cancel-root-rotation" {
		if !identifier.MatchString(o.RequestKey) {
			return errRootRotationTask
		}
		j, err = s.controlRootTask(ctx, c, trust.vault, o.Username, o.RequestKey, in.ID, o.Action == "cancel-root-rotation")
		if err != nil {
			return err
		}
		return encoder.Encode(rootTaskView(j, false))
	}
	remote := &sshRootRotation{store: s, vault: trust.vault, config: c, release: trust.release, localHelper: trust.config.HelperFile}
	w := rootRotationRunner{store: s, vault: trust.vault, config: c, release: trust.release, runtime: remote}
	switch o.Action {
	case "run-root-rotation", "finalize-root-rotation":
		return w.run(ctx, o.Username, in.ID, o.Action == "finalize-root-rotation", func(p rootRotationProgress) error { return encoder.Encode(p) })
	}
	return errRootRotationTask
}

// Reauthorization renews only the SAME frozen operation, after a fresh current
// administrator check. It cannot replace members, pins, credentials or release
// material. Restored checkpoints require this explicit step before execution.
func (s *Store) controlRootTask(ctx context.Context, c Config, v *Vault, user, key, id string, cancel bool) (rootRotationTask, error) {
	ctx = rootTaskContext(ctx, id)
	raw, err := s.guardedMutation(ctx, user, key, "control-root-rotation", id, []any{id, cancel}, func(tx *sql.Tx) error {
		if err := lockConfigurationOperationTx(ctx, tx, true); err != nil {
			return err
		}
		return provisioningAdmin(ctx, tx, user)
	}, func(tx *sql.Tx) (any, error) {
		j, _, err := scanRootTask(tx.QueryRowContext(ctx, `SELECT `+rootTaskColumns+` FROM v3_root_rotations WHERE id=$1 FOR UPDATE`, id), v)
		if err != nil || j.User != user || j.Status == "completed" || j.Status == "canceled" {
			return nil, errRootRotationTask
		}
		// A live runner owns the original authority until it releases or loses
		// its lease. Never change an actor revision underneath an active call.
		var busy bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_leases WHERE resource='pki-root-rotation' AND expires_at>clock_timestamp())`).Scan(&busy); err != nil {
			return nil, err
		}
		if busy {
			return nil, ErrDeploymentBusy
		}
		actor, err := deploymentPreviewAccount(ctx, tx, user)
		if err != nil {
			return nil, err
		}
		j.ActorRevision, j.ExpiresAt = actor, time.Now().UTC().Add(24*time.Hour)
		if err := checkRootTaskBindingsTx(ctx, tx, c, v, j); err != nil {
			return nil, err
		}
		if cancel {
			// After an authorization is signed, response loss may hide remote
			// progress. Keep that task resumable rather than abandoning trust.
			if j.Roots != nil || j.Status != "prepared" {
				return nil, errRootRotationTask
			}
			j.Status = "canceled"
		}
		j.Revision++
		doc, err := json.Marshal(j)
		if err != nil {
			return nil, err
		}
		proof, err := rootTaskMAC(v, v.active, doc)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE v3_root_rotations SET revision=$2,document=$3,key_id=$4,proof=$5,status=$6,restore_hold=false,updated_at=clock_timestamp() WHERE id=$1`, id, j.Revision, doc, v.active, proof, j.Status); err != nil {
			return nil, err
		}
		if err := advanceConfigurationOperationTx(ctx, tx); err != nil {
			return nil, err
		}
		return map[string]string{"id": id, "status": j.Status}, nil
	})
	if err != nil {
		return rootRotationTask{}, err
	}
	var ref struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &ref) != nil || ref.ID != id {
		return rootRotationTask{}, errRootRotationTask
	}
	j, _, err := s.readRootTask(ctx, v, id)
	return j, err
}
