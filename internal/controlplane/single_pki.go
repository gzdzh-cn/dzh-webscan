package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"webscan/internal/nodepki"
)

var errSinglePKI = errors.New("本中心证书维护失败；原身份与数据保留，请检查证书资料、权限、吊销下限和维护服务")

type singlePKIBinding struct {
	Format int    `json:"format"`
	Spec   string `json:"spec_sha256"`
	CA     string `json:"ca_sha256"`
	ID     string `json:"collector_id"`
}
type singlePKIReceipt struct {
	State        string                    `json:"state"`
	CheckedAt    time.Time                 `json:"checked_at"`
	Identity     nodepki.IdentityRecord    `json:"identity"`
	CRLSHA256    string                    `json:"crl_sha256,omitempty"`
	NodeRenewals *nodeRenewalSigningResult `json:"node_renewals,omitempty"`
}

func singlePKIUnits(s singleInstallSpec) ([]byte, []byte) {
	name := singleProject(s.Root) + "-pki"
	service := []byte("[Unit]\nDescription=Webscan single-center collector certificate maintenance\n\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=90\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths=" + strconv.Quote(filepath.Join(s.Root, "authority")) + " " + strconv.Quote(filepath.Join(s.Root, "collector-pki")) + " " + strconv.Quote(filepath.Join(s.Root, "state")) + "\nExecStart=" + strconv.Quote(filepath.Join(s.Root, "webscan")) + " control-v3 --action maintain-single-pki --source " + strconv.Quote(filepath.Join(s.Root, "install.json")) + "\n")
	timer := []byte("[Unit]\nDescription=Webscan hourly certificate maintenance\n\n[Timer]\nOnBootSec=1m\nOnCalendar=hourly\nRandomizedDelaySec=5m\nPersistent=true\nUnit=" + name + ".service\n\n[Install]\nWantedBy=timers.target\n")
	return service, timer
}

func singlePKIBound(s singleInstallSpec) error {
	if s.Format < 2 {
		return errSinglePKI
	}
	dir, err := trustDirectory(filepath.Join(s.Root, "collector-pki"), true)
	if err != nil {
		return errSinglePKI
	}
	dir.Close()
	raw, err := readTrustData(filepath.Join(s.Root, "collector-pki", "binding.json"), true, 4096)
	if err != nil {
		return errSinglePKI
	}
	var b singlePKIBinding
	if singleDecode(raw, &b) != nil {
		return errSinglePKI
	}
	ca, err := readTrustData(filepath.Join(s.Root, "ca.crt"), true, 64<<10)
	if err != nil {
		return errSinglePKI
	}
	installed, err := readTrustData(s.configuration().Collector.CAFile, true, 64<<10)
	if err != nil || !bytes.Equal(ca, installed) {
		return errSinglePKI
	}
	spec, _ := json.Marshal(s)
	if b.Format != 1 || b.Spec != digest(spec) || b.CA != digest(ca) || b.ID != s.Instance {
		return errSinglePKI
	}
	return nil
}

func initializeSinglePKI(ctx context.Context, s singleInstallSpec, now time.Time) error {
	if s.Format < 2 {
		return errSinglePKI
	}
	read := func(name string) ([]byte, error) { return readTrustData(filepath.Join(s.Root, name), true, 128<<10) }
	ca, err := read("ca.crt")
	if err != nil {
		return errSinglePKI
	}
	key, err := read("ca.key")
	if err != nil {
		return errSinglePKI
	}
	defer clear(key)
	crl, err := read("seed.crl")
	if err != nil {
		return errSinglePKI
	}
	if err := nodepki.SeedAuthority(ctx, filepath.Join(s.Root, "authority"), nodepki.Bundle{CA: ca, Key: key}, crl, now); err != nil {
		return errSinglePKI
	}
	directory := filepath.Join(s.Root, "collector-pki")
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		// Establish the durable trust floor before publishing the runtime
		// directory. Resuming a partially initialized install can validate the
		// same floor, but an existing runtime may never recreate a lost floor.
		if _, _, _, err := nodepki.RefreshCRL(ctx, filepath.Join(s.Root, "authority"), now, 12*time.Hour, 24*time.Hour); err != nil {
			return errSinglePKI
		}
		if _, err := nodepki.NewPersistentFileTrust(filepath.Join(s.Root, "authority", "ca.crt"), filepath.Join(s.Root, "authority", "ca.crl"), s.configuration().Collector.RevocationStateDirectory, now); err != nil {
			return errSinglePKI
		}
		crl, err = readTrustData(filepath.Join(s.Root, "authority", "ca.crl"), true, nodepki.MaxCRLBytes)
		if err != nil {
			return errSinglePKI
		}
		cert, err := read("collector.crt")
		if err != nil {
			return errSinglePKI
		}
		leafKey, err := read("collector.key")
		if err != nil {
			return errSinglePKI
		}
		defer clear(leafKey)
		identity := append(append([]byte{}, cert...), leafKey...)
		defer clear(identity)
		spec, _ := json.Marshal(s)
		binding, _ := json.Marshal(singlePKIBinding{Format: 1, Spec: digest(spec), CA: digest(ca), ID: s.Instance})
		if err := publishTrustFiles(ctx, directory, map[string][]byte{"ca.crt": ca, "ca.crl": crl, "collector.pem": identity, "binding.json": binding}); err != nil {
			return errSinglePKI
		}
	}
	if singlePKIBound(s) != nil {
		return errSinglePKI
	}
	_, err = maintainSinglePKI(ctx, s, now)
	return err
}

func singlePKILock(ctx context.Context, s singleInstallSpec) (*os.File, error) {
	dir, err := trustDirectory(filepath.Join(s.Root, "state"), true)
	if err != nil {
		return nil, errSinglePKI
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), ".pki-maintenance.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errSinglePKI
	}
	f := os.NewFile(uintptr(fd), "pki-maintenance-lock")
	if !singlePrivateFile(f) {
		f.Close()
		return nil, errSinglePKI
	}
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return f, nil
		} else if err != unix.EAGAIN && err != unix.EWOULDBLOCK {
			f.Close()
			return nil, errSinglePKI
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func singleReplacePrivate(ctx context.Context, path string, raw []byte, allowNew bool) error {
	dir, err := trustDirectory(filepath.Dir(path), true)
	if err != nil {
		return errSinglePKI
	}
	dir.Close()
	if _, err := os.Lstat(path); err == nil {
		if _, err := readTrustData(path, true, 4<<20); err != nil {
			return errSinglePKI
		}
	} else if !os.IsNotExist(err) || !allowNew {
		return errSinglePKI
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pki-publish-*")
	if err != nil {
		return errSinglePKI
	}
	name := f.Name()
	defer os.Remove(name)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil || closed != nil || ctx.Err() != nil {
		return errSinglePKI
	}
	if err := os.Rename(name, path); err != nil {
		return errSinglePKI
	}
	dir, err = trustDirectory(filepath.Dir(path), true)
	if err != nil {
		return errSinglePKI
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errSinglePKI
	}
	return nil
}

func maintainSinglePKI(ctx context.Context, s singleInstallSpec, now time.Time) (receipt singlePKIReceipt, result error) {
	return maintainSinglePKIIdentityMode(ctx, s, now, true)
}

func maintainSinglePKIIdentityMode(ctx context.Context, s singleInstallSpec, now time.Time, allowRenewal bool) (receipt singlePKIReceipt, result error) {
	if singlePKIBound(s) != nil {
		return receipt, errSinglePKI
	}
	lock, err := singlePKILock(ctx, s)
	if err != nil {
		return receipt, err
	}
	defer lock.Close()
	receipt = singlePKIReceipt{State: "failed", CheckedAt: now}
	defer func() {
		if result != nil {
			receipt.State = "failed"
		}
		raw, _ := json.Marshal(receipt)
		// A failed receipt must not turn a previously successful status into
		// apparent success. Storage failure is itself returned to systemd.
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if singleReplacePrivate(writeCtx, filepath.Join(s.Root, "state", "pki-maintenance.json"), raw, true) != nil {
			result = errSinglePKI
		}
	}()
	c := s.configuration()
	rootState, err := nodepki.ReadRootState(c.Collector.CAFile, c.Collector.RevocationStateDirectory, now)
	if err != nil {
		return receipt, errSinglePKI
	}
	if rootState.Format != 0 {
		state, err := nodepki.RefreshAuthorizedRootSet(ctx, filepath.Join(s.Root, "authority"), c.Collector.CAFile, c.Collector.RevocationStateDirectory, now)
		if err != nil {
			return receipt, errSinglePKI
		}
		identity, err := maintainSingleCollectorIdentity(ctx, s, now, allowRenewal)
		if err != nil {
			return receipt, errSinglePKI
		}
		b, _, err := nodepki.ReadIdentityWithRootState(c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, s.Instance, now)
		defer clear(b.Key)
		if err != nil {
			return receipt, errSinglePKI
		}
		crl := state.OldCRL
		if bytes.Equal(b.CA, state.Dual.NewCA) {
			crl = state.NewCRL
		}
		receipt.State, receipt.Identity, receipt.CRLSHA256 = "healthy", identity, digest(crl)
		return receipt, nil
	}
	ca, crl, _, err := nodepki.RefreshCRL(ctx, filepath.Join(s.Root, "authority"), now, 12*time.Hour, 24*time.Hour)
	if err != nil {
		return receipt, errSinglePKI
	}
	pinned, err := readTrustData(c.Collector.CAFile, true, 64<<10)
	if err != nil || !bytes.Equal(pinned, ca) {
		return receipt, errSinglePKI
	}
	previous, err := readTrustData(c.Collector.RevocationFile, true, nodepki.MaxCRLBytes)
	if err != nil || nodepki.ValidateCRLAdvance(ca, previous, crl, now) != nil {
		return receipt, errSinglePKI
	}
	floor, err := readTrustData(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crl"), true, nodepki.MaxCRLBytes)
	if err != nil || nodepki.ValidateCRLAdvance(ca, floor, crl, now) != nil {
		return receipt, errSinglePKI
	}
	if !bytes.Equal(previous, crl) {
		if err := singleReplacePrivate(ctx, c.Collector.RevocationFile, crl, false); err != nil {
			return receipt, err
		}
	}
	identity, err := maintainSingleCollectorIdentity(ctx, s, now, allowRenewal)
	if err != nil {
		return receipt, errSinglePKI
	}
	if _, err := nodepki.NewPersistentFileTrust(c.Collector.CAFile, c.Collector.RevocationFile, c.Collector.RevocationStateDirectory, now); err != nil {
		return receipt, errSinglePKI
	}
	receipt.State, receipt.Identity, receipt.CRLSHA256 = "healthy", identity, digest(crl)
	return receipt, nil
}

// If the database is starting or a root task freezes this identity, refresh
// revocation evidence but never replace the task's parent certificate. A live
// installed identity can still bring up the stack without a PG boot cycle.
func maintainSingleCollectorIdentity(ctx context.Context, s singleInstallSpec, now time.Time, allowRenewal bool) (nodepki.IdentityRecord, error) {
	c := s.configuration()
	if allowRenewal {
		return nodepki.MaintainIdentityWithRootState(ctx, filepath.Join(s.Root, "authority"), c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, s.Instance, now, 7*24*time.Hour, 30*24*time.Hour)
	}
	b, record, err := nodepki.ReadIdentityWithRootState(c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, s.Instance, now)
	defer clear(b.Key)
	if err != nil {
		return nodepki.IdentityRecord{}, err
	}
	leaf, err := provisioningCertificate(b.Certificate)
	if err != nil {
		return nodepki.IdentityRecord{}, err
	}
	// ReadRootState authenticates both issuers and their current CRLs. The
	// ordinary file trust applies only before any administrator root rollout.
	roots, err := nodepki.ReadRootState(c.Collector.CAFile, c.Collector.RevocationStateDirectory, now)
	if err != nil {
		return nodepki.IdentityRecord{}, err
	}
	if roots.Format != 0 {
		anchor, err := readTrustData(c.Collector.CAFile, true, 64<<10)
		if err != nil {
			return nodepki.IdentityRecord{}, err
		}
		policy, err := nodepki.NewRootSet(anchor, roots, now)
		if err != nil || policy.Verify(leaf, nodepki.Collector, s.Instance, now) != nil {
			return nodepki.IdentityRecord{}, errSinglePKI
		}
	} else {
		trust, err := nodepki.NewFileTrust(c.Collector.CAFile, c.Collector.RevocationFile, now)
		if err != nil || trust.Verify(leaf, nodepki.Collector, s.Instance, now) != nil {
			return nodepki.IdentityRecord{}, errSinglePKI
		}
	}
	return record, nil
}

func verifySinglePKI(s singleInstallSpec, now time.Time) error {
	if singlePKIBound(s) != nil {
		return errSinglePKI
	}
	c := s.configuration()
	issuerCA, err := readTrustData(filepath.Join(s.Root, "authority", "ca.crt"), true, 64<<10)
	if err != nil {
		return errSinglePKI
	}
	pinned, err := readTrustData(c.Collector.CAFile, true, 64<<10)
	if err != nil || !bytes.Equal(pinned, issuerCA) {
		return errSinglePKI
	}
	b, record, err := nodepki.ReadIdentityWithRootState(c.Collector.CAFile, c.Collector.IdentityFile, c.Collector.RevocationStateDirectory, nodepki.Collector, s.Instance, now)
	if err != nil {
		return errSinglePKI
	}
	defer clear(b.Key)
	issuer, err := nodepki.RootFingerprint(b.CA)
	if err != nil {
		return errSinglePKI
	}
	directory, err := nodepki.IdentityAuthority(filepath.Join(s.Root, "authority"), c.Collector.CAFile, c.Collector.RevocationStateDirectory, issuer, now)
	if err != nil {
		return errSinglePKI
	}
	issuerKey, err := readTrustData(filepath.Join(directory, "ca.key"), true, 64<<10)
	if err != nil {
		return errSinglePKI
	}
	defer clear(issuerKey)
	if _, err := nodepki.ParseAuthority(b.CA, issuerKey, now); err != nil {
		return errSinglePKI
	}
	// Verification must not initialize a deleted trust directory as though this
	// were a fresh installation. Only initialization may establish the floor.
	if _, err := readTrustData(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crl"), true, nodepki.MaxCRLBytes); err != nil {
		return errSinglePKI
	}
	trust, err := nodepki.NewPersistentFileTrust(c.Collector.CAFile, c.Collector.RevocationFile, c.Collector.RevocationStateDirectory, now)
	if err != nil {
		return errSinglePKI
	}
	leaf, err := provisioningCertificate(b.Certificate)
	if err != nil || trust.Verify(leaf, nodepki.Collector, s.Instance, now) != nil || !record.ExpiresAt.After(now) {
		return errSinglePKI
	}
	return nil
}

func singlePKICommand(ctx context.Context, o Options, out io.Writer) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || o.PasswordFile != "" || o.Topology != "" {
		return errSinglePKI
	}
	raw, err := readTrustData(o.Source, true, 64<<10)
	var manifest singleInstallManifest
	if err != nil || singleDecode(raw, &manifest) != nil || manifest.Spec.validate() != nil || manifest.Spec.Format < 2 || o.Source != filepath.Join(manifest.Spec.Root, "install.json") {
		return errSinglePKI
	}
	executable, err := os.Executable()
	if err != nil {
		return errSinglePKI
	}
	binary, err := readTrustData(executable, true, 256<<20)
	if err != nil {
		return errSinglePKI
	}
	j, err := readSingleInstallation(manifest.Spec, digest(binary))
	if err != nil || j.Step < 2 {
		return errSinglePKI
	}
	receipt, err := maintainSinglePKIHostCycle(ctx, manifest.Spec, time.Now().UTC(), j.Step >= 3)
	if encode := json.NewEncoder(out).Encode(receipt); encode != nil {
		return encode
	}
	return err
}

// Local trust maintenance is a prerequisite for starting the center. The
// public node queue depends on PostgreSQL, which may itself still be starting.
// Record that independent result without creating a circular boot dependency.
func maintainSinglePKICycle(ctx context.Context, spec singleInstallSpec, now time.Time, databaseInitialized bool, renew func(context.Context, singleInstallSpec) (nodeRenewalSigningResult, error)) (singlePKIReceipt, error) {
	receipt, err := maintainSinglePKI(ctx, spec, now)
	return finishSinglePKICycle(ctx, spec, receipt, err, databaseInitialized, renew)
}

// The actual installed timer serializes collector replacement against root
// task admission. A pending task continues to freeze its exact parent between
// invocations, not merely while its runner owns a short lease.
func maintainSinglePKIHostCycle(ctx context.Context, spec singleInstallSpec, now time.Time, initialized bool) (singlePKIReceipt, error) {
	if !initialized {
		return maintainSinglePKICycle(ctx, spec, now, false, maintainSingleNodeRenewals)
	}
	guard, cancel := context.WithTimeout(ctx, 3*time.Second)
	store, err := Open(guard, spec.configuration())
	if err == nil {
		defer store.DB.Close()
		var version int
		version, err = currentSchema(guard, store.DB)
		if err == nil && version != SchemaVersion {
			err = errSinglePKI
		}
	}
	var release func()
	if err == nil {
		tx, begin := store.DB.BeginTx(ctx, nil)
		err = begin
		if err == nil {
			release = func() { _ = tx.Rollback() }
			err = lockConfigurationOperationTx(guard, tx, false)
		}
	}
	cancel()
	if release != nil {
		defer func() {
			if release != nil {
				release()
			}
		}()
	}
	if err == nil {
		receipt, localErr := maintainSinglePKIIdentityMode(ctx, spec, now, true)
		release()
		release = nil
		return finishSinglePKICycle(ctx, spec, receipt, localErr, true, maintainSingleNodeRenewals)
	}
	if release != nil {
		release()
		release = nil
	}
	receipt, localErr := maintainSinglePKIIdentityMode(ctx, spec, now, false)
	return finishSinglePKICycle(ctx, spec, receipt, localErr, true, func(context.Context, singleInstallSpec) (nodeRenewalSigningResult, error) {
		return nodeRenewalSigningResult{}, errSinglePKI
	})
}

func finishSinglePKICycle(ctx context.Context, spec singleInstallSpec, receipt singlePKIReceipt, err error, databaseInitialized bool, renew func(context.Context, singleInstallSpec) (nodeRenewalSigningResult, error)) (singlePKIReceipt, error) {
	// Initial trust bootstrapping precedes PostgreSQL schema initialization.
	// Only the installed host maintenance command, after that checkpoint, may
	// open the database and process public node renewal jobs with the CA key.
	if err == nil && databaseInitialized {
		batch, cancel := context.WithTimeout(ctx, 45*time.Second)
		result, renewalErr := renew(batch, spec)
		cancel()
		result.State = "healthy"
		if renewalErr != nil {
			result.State, result.Error = "deferred", "节点签发暂不可用，已保留队列；请检查数据库、配置版本及宿主签发服务"
		} else if result.Failed > 0 {
			result.State, result.Error = "failed", "部分节点签发失败，已保留任务及重试记录"
		}
		receipt.NodeRenewals = &result
		raw, _ := json.Marshal(receipt)
		writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		if singleReplacePrivate(writeCtx, filepath.Join(spec.Root, "state", "pki-maintenance.json"), raw, false) != nil {
			err = errSinglePKI
		}
		writeCancel()
	}
	return receipt, err
}

func maintainSingleNodeRenewals(ctx context.Context, s singleInstallSpec) (result nodeRenewalSigningResult, resultErr error) {
	var empty nodeRenewalSigningResult
	if s.Format < 2 || singlePKIBound(s) != nil {
		return empty, errSinglePKI
	}
	c := s.configuration()
	c.NodePKI = NodePKIConfig{Enabled: true, AuthorityDirectory: filepath.Join(s.Root, "authority")}
	if c.Validate() != nil {
		return empty, errSinglePKI
	}
	store, err := Open(ctx, c)
	if err != nil {
		return empty, errSinglePKI
	}
	defer store.DB.Close()
	if version, err := currentSchema(ctx, store.DB); err != nil || version != SchemaVersion {
		return empty, errSinglePKI // Never silently migrate from a timer.
	}
	defer func() {
		status, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if recordSinglePKIMaintenance(status, store, s, result, resultErr) != nil {
			resultErr = errSinglePKI
		}
	}()
	return store.processNodeRenewalQueue(ctx, c, s.Instance, 500)
}
