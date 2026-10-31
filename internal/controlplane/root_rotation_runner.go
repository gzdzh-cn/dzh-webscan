package controlplane

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"time"

	"webscan/internal/nodeops"
	"webscan/internal/nodepki"
)

type rootRotationRuntime interface {
	operation(context.Context, Lease, string, int, string) (nodeops.RootRotationOutput, error)
	observe(context.Context, Lease, string, int) (*x509.Certificate, error)
}

type rootRotationRunner struct {
	store   *Store
	vault   *Vault
	config  Config
	release *TrustedRelease
	runtime rootRotationRuntime
}

type rootRotationProgress struct {
	ID     string `json:"id"`
	Member string `json:"member,omitempty"`
	Phase  string `json:"phase"`
	Status string `json:"status"`
}

func (w rootRotationRunner) run(parent context.Context, user, id string, finalize bool, report func(rootRotationProgress) error) error {
	if w.store == nil || w.vault == nil || w.release == nil || w.runtime == nil || report == nil {
		return errRootRotationTask
	}
	j, hold, err := w.store.readRootTask(parent, w.vault, id)
	if err != nil || hold || j.User != user || j.Release != w.release.SHA256() || j.Helper != w.release.manifest.Helper.SHA256 {
		return errRootRotationTask
	}
	if j.Status == "completed" {
		return report(rootRotationProgress{ID: id, Phase: "complete", Status: "completed"})
	}
	if j.Status == "canceled" || !time.Now().Before(j.ExpiresAt) {
		return errRootRotationTask
	}
	if finalize && j.Status != "ready" && j.Status != "finalizing" {
		return errRootRotationTask
	}
	l, err := w.store.Acquire(parent, "pki-root-rotation", "root-rotation-"+token())
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
		defer stop()
		_ = w.store.Release(cleanup, l)
	}()
	return withRecoveryHeartbeat(parent, j.ExpiresAt, 10*time.Second, 3*time.Second, func(ctx context.Context) error {
		return w.store.renewRootTaskLease(ctx, w.config, w.vault, l, id)
	}, func(ctx context.Context) error {
		var err error
		j, err = w.store.authorizeRootTask(ctx, w.config, w.vault, l, id)
		if err != nil {
			return err
		}
		j, err = w.store.refreshRootTask(ctx, w.config, w.vault, l, id)
		if err != nil {
			return err
		}
		if j.Status == "finalizing" {
			return w.finish(ctx, l, j, report)
		}
		if j.Status != "dual" && j.Status != "ready" {
			return errRootRotationTask
		}
		// Every host gets dual trust before any leaf changes. A retry republishes
		// the exact authorization with current CRLs and a fresh target token.
		for i, m := range j.Members {
			if err := report(rootRotationProgress{id, m.ID, "dual-trust", "running"}); err != nil {
				return err
			}
			if m.Role == nodepki.Collector {
				err = publishCollectorRootTask(ctx, w.config, j, i)
			} else {
				_, err = w.runtime.operation(ctx, l, id, i, "trust")
			}
			if err != nil {
				return err
			}
			j, err = w.store.rootTaskCheckpoint(ctx, w.config, w.vault, l, j, func(current *rootRotationTask, _ *sql.Tx) error { current.State[i].Trust = true; return nil })
			if err != nil {
				return err
			}
		}
		// Change nodes first, collector last. This leaves a still-valid client
		// during every partial rollout and never requires a central restart.
		for _, role := range []string{nodepki.Node, nodepki.Collector} {
			for i, m := range j.Members {
				if m.Role != role {
					continue
				}
				if err := report(rootRotationProgress{id, m.ID, "identity", "running"}); err != nil {
					return err
				}
				if len(j.State[i].Request) == 0 {
					var raw []byte
					if role == nodepki.Collector {
						expected, e := rootMemberCertificateSHA(m)
						if e != nil {
							return e
						}
						r, e := nodepki.PrepareRootIdentity(ctx, w.config.Collector.CAFile, w.config.Collector.IdentityFile, w.config.Collector.RevocationStateDirectory, role, m.ID, nodepki.RootAuthorizationSHA256(j.Roots.Dual), expected, time.Now())
						if e != nil {
							return e
						}
						raw, _ = json.Marshal(r)
					} else {
						out, e := w.runtime.operation(ctx, l, id, i, "prepare")
						if e != nil {
							return e
						}
						raw = out.Request
					}
					j, err = w.store.admitRootTaskRequest(ctx, w.config, w.vault, l, j, i, raw)
					if err != nil {
						return err
					}
				}
				j, err = w.store.signRootTaskMember(ctx, w.config, w.vault, l, id, i)
				if err != nil {
					return err
				}
				if role == nodepki.Collector {
					r, e := nodepki.ParseRootIdentityRequest(j.State[i].Request)
					if e != nil {
						return e
					}
					_, err = nodepki.ActivateRootIdentity(ctx, w.config.Collector.CAFile, w.config.Collector.IdentityFile, w.config.Collector.RevocationStateDirectory, role, m.ID, r.Authorization, r.CertificateSHA256, r.SHA256(), j.State[i].Certificate, time.Now())
				} else {
					_, err = w.runtime.operation(ctx, l, id, i, "activate")
				}
				if err != nil {
					return err
				}
				j, err = w.store.rootTaskCheckpoint(ctx, w.config, w.vault, l, j, func(current *rootRotationTask, _ *sql.Tx) error { current.State[i].Activated = true; return nil })
				if err != nil {
					return err
				}
			}
		}
		// SSH claims cannot complete a task. A new normally verified TLS channel
		// must present the exact committed successor and fresh healthy metrics.
		j, err = w.observeAll(ctx, l, j, report)
		if err != nil {
			return err
		}
		j, err = w.store.rootTaskCheckpoint(ctx, w.config, w.vault, l, j, func(current *rootRotationTask, _ *sql.Tx) error { current.Status = "ready"; return nil })
		if err != nil {
			return err
		}
		if !finalize {
			return report(rootRotationProgress{ID: id, Phase: "await-explicit-finalization", Status: "ready"})
		}
		confirmations, _ := json.Marshal(struct {
			Members string
			State   []rootRotationMemberState
		}{j.MembersSHA256, j.State})
		var finalized rootRotationTask
		err = nodepki.AuthorizeStoredRootSet(ctx, w.config.NodePKI.AuthorityDirectory, j.Anchor, j.ID, j.MembersSHA256, j.Roots, digest(confirmations), time.Now(), func(roots nodepki.RootSetSnapshot) error {
			var e error
			finalized, e = w.store.rootTaskCheckpoint(ctx, w.config, w.vault, l, j, func(current *rootRotationTask, _ *sql.Tx) error {
				if current.Status != "ready" {
					return errRootRotationTask
				}
				for _, state := range current.State {
					if !state.Trust || !state.Activated || state.ObservedAt.IsZero() {
						return errRootRotationTask
					}
				}
				current.Roots, current.Status = &roots, "finalizing"
				return nil
			})
			return e
		})
		if err != nil {
			return err
		}
		return w.finish(ctx, l, finalized, report)
	})
}

func (w rootRotationRunner) observeAll(ctx context.Context, l Lease, j rootRotationTask, report func(rootRotationProgress) error) (rootRotationTask, error) {
	for i, m := range j.Members {
		if err := report(rootRotationProgress{j.ID, m.ID, "readiness", "running"}); err != nil {
			return rootRotationTask{}, err
		}
		if err := w.observeMember(ctx, l, j, i); err != nil {
			return rootRotationTask{}, err
		}
		var err error
		j, err = w.store.rootTaskCheckpoint(ctx, w.config, w.vault, l, j, func(current *rootRotationTask, _ *sql.Tx) error {
			current.State[i].ObservedAt = time.Now().UTC()
			return nil
		})
		if err != nil {
			return rootRotationTask{}, err
		}
	}
	return j, nil
}

func (w rootRotationRunner) observeMember(ctx context.Context, l Lease, j rootRotationTask, i int) error {
	m, state := j.Members[i], j.State[i]
	if m.Role == nodepki.Collector {
		b, record, err := nodepki.ReadIdentityWithRootState(w.config.Collector.CAFile, w.config.Collector.IdentityFile, w.config.Collector.RevocationStateDirectory, m.Role, m.ID, time.Now())
		defer clear(b.Key)
		cert, parseErr := provisioningCertificate(state.Certificate)
		if err != nil || parseErr != nil || !bytes.Equal(b.Certificate, state.Certificate) || record.CertificateSHA256 != digest(cert.Raw) {
			return errRootRotationTask
		}
		roots, err := nodepki.NewRootSet(j.Anchor, *j.Roots, time.Now())
		if err != nil || roots.Verify(cert, m.Role, m.ID, time.Now()) != nil {
			return errRootRotationTask
		}
		return nil
	}
	if _, err := w.runtime.operation(ctx, l, j.ID, i, "verify"); err != nil {
		return err
	}
	peer, err := w.runtime.observe(ctx, l, j.ID, i)
	cert, parseErr := provisioningCertificate(state.Certificate)
	if err != nil || parseErr != nil || peer == nil || !bytes.Equal(peer.Raw, cert.Raw) {
		return errRootRotationTask
	}
	return nil
}

func (w rootRotationRunner) finish(ctx context.Context, l Lease, j rootRotationTask, report func(rootRotationProgress) error) error {
	if j.Roots == nil || j.Roots.Final == nil || j.Status != "finalizing" {
		return errRootRotationTask
	}
	// First remove the old root on every node, then on the local collector.
	// A partial finalization remains durable and is never downgraded to dual.
	for _, role := range []string{nodepki.Node, nodepki.Collector} {
		for i, m := range j.Members {
			if m.Role != role {
				continue
			}
			if err := report(rootRotationProgress{j.ID, m.ID, "retire-old-root", "running"}); err != nil {
				return err
			}
			if role == nodepki.Collector {
				if err := publishCollectorRootTask(ctx, w.config, j, i); err != nil {
					return err
				}
			} else {
				if _, err := w.runtime.operation(ctx, l, j.ID, i, "trust"); err != nil {
					return err
				}
			}
			if err := w.observeMember(ctx, l, j, i); err != nil {
				return err
			}
			var err error
			j, err = w.store.rootTaskCheckpoint(ctx, w.config, w.vault, l, j, func(current *rootRotationTask, _ *sql.Tx) error {
				current.State[i].Final = true
				current.State[i].ObservedAt = time.Now().UTC()
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	var err error
	j, err = w.store.rootTaskCheckpoint(ctx, w.config, w.vault, l, j, func(current *rootRotationTask, _ *sql.Tx) error {
		for _, state := range current.State {
			if !state.Final || !state.Activated || state.ObservedAt.IsZero() {
				return errRootRotationTask
			}
		}
		current.Status = "completed"
		return nil
	})
	if err != nil {
		return err
	}
	return report(rootRotationProgress{ID: j.ID, Phase: "complete", Status: "completed"})
}
