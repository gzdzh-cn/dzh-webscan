package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"time"
	"webscan/internal/nodepki"
)

type webDeploymentWorker struct {
	store    *Store
	config   Config
	trust    *deploymentTrust
	instance string
}

func (w *webDeploymentWorker) Run(ctx context.Context) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		// Private request payloads and capabilities have a bounded lifetime.
		_, _ = w.store.DB.ExecContext(ctx, `DELETE FROM v3_deployment_private_inputs WHERE id IN (SELECT id FROM v3_deployment_preparations WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 200)`)
		_, _ = w.store.DB.ExecContext(ctx, `UPDATE v3_deployment_preparations SET status='expired',phase='expired',updated_at=clock_timestamp() WHERE id IN (SELECT id FROM v3_deployment_preparations WHERE status IN ('queued','running') AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 200)`)
		issuer, rules := w.readiness()
		_, _ = w.store.DB.ExecContext(ctx, `INSERT INTO v3_role_status(role,instance,heartbeat,details) VALUES('deployment-preparations',$1,clock_timestamp(),jsonb_build_object('manifest',$2::text,'vault',$3::text,'issuer',$4::boolean,'rules',$5::boolean)) ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error='',details=excluded.details`, w.instance, w.trust.release.SHA256(), w.trust.vault.active, issuer, rules)
		p, err := w.claim(ctx)
		if err == nil {
			w.execute(ctx, p)
			continue
		}
		if err != sql.ErrNoRows && ctx.Err() == nil {
			_, _ = w.store.DB.ExecContext(ctx, "UPDATE v3_role_status SET error='部署准备暂时不可用' WHERE role='deployment-preparations' AND instance=$1", w.instance)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
	return ctx.Err()
}
func (w *webDeploymentWorker) claim(ctx context.Context) (deploymentPreparation, error) {
	return scanPreparation(w.store.DB.QueryRowContext(ctx, `UPDATE v3_deployment_preparations SET status='running',phase='validating',lease_owner=$1,lease_epoch=lease_epoch+1,lease_until=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp() WHERE id=(SELECT id FROM v3_deployment_preparations WHERE expires_at>clock_timestamp() AND (status='queued' OR status='running' AND lease_until<=clock_timestamp()) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+preparationColumns, w.instance))
}
func (w *webDeploymentWorker) stage(ctx context.Context, p deploymentPreparation, phase string) error {
	res, err := w.store.DB.ExecContext(ctx, `UPDATE v3_deployment_preparations SET phase=$4,updated_at=clock_timestamp() WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() AND expires_at>clock_timestamp() AND status='running'`, p.ID, p.Owner.String, p.Epoch, phase)
	return deploymentAffected(res, err)
}
func (w *webDeploymentWorker) execute(parent context.Context, p deploymentPreparation) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(8 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				res, err := w.store.DB.ExecContext(ctx, `UPDATE v3_deployment_preparations SET lease_until=clock_timestamp()+interval '30 seconds' WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3 AND status='running' AND lease_until>clock_timestamp() AND expires_at>clock_timestamp()`, p.ID, p.Owner.String, p.Epoch)
				if deploymentAffected(res, err) != nil {
					cancel()
					return
				}
			}
		}
	}()
	result, err := w.process(ctx, p)
	cancel()
	<-done
	if parent.Err() != nil {
		return
	} // process restart reclaims the same idempotent request
	finish, stop := context.WithTimeout(parent, 5*time.Second)
	defer stop()
	if err != nil {
		_, _ = w.store.DB.ExecContext(finish, `UPDATE v3_deployment_preparations SET status='failed',phase='failed',error_code=$4,updated_at=clock_timestamp(),lease_until=NULL WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp()`, p.ID, p.Owner.String, p.Epoch, webDeploymentError(err))
		return
	}
	raw, _ := json.Marshal(result)
	defer clear(raw)
	key, nonce, sealed, err := sealPreparation(w.trust.vault, p.ID, "result", raw)
	if err != nil {
		return
	}
	tx, err := w.store.DB.BeginTx(finish, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(finish, `UPDATE v3_deployment_preparations SET status='succeeded',phase='complete',updated_at=clock_timestamp(),lease_until=NULL WHERE id=$1 AND lease_owner=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() AND expires_at>clock_timestamp() AND status='running'`, p.ID, p.Owner.String, p.Epoch)
	if deploymentAffected(res, err) != nil {
		return
	}
	if _, err = tx.ExecContext(finish, `UPDATE v3_deployment_private_inputs SET result_key_id=$2,result_nonce=$3,result_ciphertext=$4 WHERE id=$1`, p.ID, key, nonce, sealed); err != nil {
		return
	}
	_ = tx.Commit()
}
func (w *webDeploymentWorker) process(ctx context.Context, p deploymentPreparation) (webDeploymentResult, error) {
	var out webDeploymentResult
	var rev int64
	if err := w.store.DB.QueryRowContext(ctx, "SELECT revision FROM v3_accounts WHERE username=$1 AND role='admin'", p.Username).Scan(&rev); err != nil || rev != p.AccountRevision {
		return out, errWebDeployment
	}
	n, err := scanNode(w.store.DB.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL AND id=$1", p.Node))
	if err != nil {
		return out, err
	}
	if n.Version != p.Version || p.Manifest != w.trust.release.SHA256() || !time.Now().Before(p.Expires) {
		return out, errWebDeployment
	}
	var key string
	var nonce, sealed []byte
	if err = w.store.DB.QueryRowContext(ctx, "SELECT key_id,nonce,ciphertext FROM v3_deployment_private_inputs WHERE id=$1", p.ID).Scan(&key, &nonce, &sealed); err != nil {
		return out, err
	}
	raw, err := openPreparation(w.trust.vault, p.ID, "input", key, nonce, sealed)
	defer clear(raw)
	if err != nil {
		return out, err
	}
	var in webDeploymentInput
	if json.Unmarshal(raw, &in) != nil {
		return out, errWebDeployment
	}
	if in.Kind != "uninstall" && !n.Enabled {
		return out, errWebDeployment
	}
	var source deploymentInstalledSource
	var sourceCredential string
	var sourceSSH SSHCredential
	if in.Kind == "uninstall" {
		var state string
		source, sourceCredential, sourceSSH, state, err = w.store.webUninstallSource(ctx, w.trust.vault, n)
		if err != nil {
			return out, err
		}
		if state != in.InstallationState || (p.Kind == "fingerprint" || p.Kind == "credential") && in.SSHPort != sourceSSH.Port {
			return out, errNodeUninstall
		}
	}
	credentialForOperation := func() (string, SSHCredential, error) {
		if in.Kind == "uninstall" {
			return sourceCredential, sourceSSH, nil
		}
		return w.store.latestWebCredential(ctx, w.trust.vault, n.ID)
	}
	host, _, err := net.SplitHostPort(n.Endpoint)
	if err != nil {
		return out, errWebDeployment
	}
	if in.Kind == "uninstall" {
		host = sourceSSH.Host
	}
	switch p.Kind {
	case "fingerprint":
		if in.SSHPort < 1 || in.SSHPort > 65535 {
			return out, errWebDeployment
		}
		if err = w.stage(ctx, p, "reading-fingerprint"); err != nil {
			return out, err
		}
		fp, err := readSSHHostFingerprint(ctx, host, in.SSHPort)
		if err != nil {
			return out, err
		}
		_, old, e := credentialForOperation()
		if e == nil && old.Host == host && old.Port == in.SSHPort && old.Fingerprint != fp {
			return out, errFingerprintChanged
		}
		// If a credential exists but cannot be decrypted, do not treat it as TOFU.
		if e != nil {
			var count int
			if err = w.store.DB.QueryRowContext(ctx, "SELECT count(*) FROM v3_credentials WHERE node=$1", n.ID).Scan(&count); err != nil {
				return out, err
			}
			if count > 0 {
				return out, ErrCredentialUnavailable
			}
		}
		state, err := w.store.webCredentialState(ctx, n.ID)
		if err != nil {
			return out, err
		}
		return webDeploymentResult{Host: host, Port: in.SSHPort, Fingerprint: fp, FingerprintToken: token(), CredentialState: state, SourceState: in.InstallationState}, nil
	case "credential":
		pin, err := w.store.preparation(ctx, w.trust.vault, p.Username, in.FingerprintPreparation)
		if err != nil || pin.Status != "succeeded" || pin.Kind != "fingerprint" || pin.Node != n.ID || pin.Version != n.Version || pin.Result == nil || pin.Result.Host != host || pin.Result.Port != in.SSHPort || pin.Result.SourceState != in.InstallationState || !sameCapability(pin.Result.FingerprintToken, in.FingerprintToken) {
			return out, errWebDeployment
		}
		state, e := w.store.webCredentialState(ctx, n.ID)
		if e != nil || state != pin.Result.CredentialState {
			return out, errWebDeployment
		}
		// Re-read immediately before accepting the administrator's confirmation.
		fp, err := readSSHHostFingerprint(ctx, host, in.SSHPort)
		if err != nil {
			return out, err
		}
		if fp != pin.Result.Fingerprint {
			return out, errFingerprintChanged
		}
		c := SSHCredential{Host: host, Port: in.SSHPort, Fingerprint: fp, Password: in.Password, PrivateKey: in.PrivateKey}
		if in.PrivateKeyPath != "" {
			c.PrivateKey, err = controlledSSHKey(w.config.Executor, in.PrivateKeyPath)
			if err != nil {
				return out, err
			}
		}
		if c.Password == "" && c.PrivateKey == "" {
			_, old, e := credentialForOperation()
			if e != nil {
				return out, e
			}
			if old.Host != host || old.Port != in.SSHPort || old.Fingerprint != fp {
				return out, errWebDeployment
			}
			c = old
		}
		if in.Kind == "uninstall" {
			_, err := w.store.addWebUninstallCredential(ctx, w.trust.vault, p, source, in.InstallationState, c)
			if err != nil {
				return out, err
			}
			return webDeploymentResult{Configured: true, SourceState: in.InstallationState}, nil
		}
		response, err := w.store.addCredential(ctx, w.trust.vault, p.Username, "web-credential-"+p.ID, n.ID, n.Version, c, func(tx *sql.Tx) error {
			if err := provisioningAdmin(ctx, tx, p.Username); err != nil {
				return err
			}
			var current bool
			if err := tx.QueryRowContext(ctx, `SELECT account_revision=(SELECT revision FROM v3_accounts WHERE username=$4) AND lease_owner=$2 AND lease_epoch=$3 AND lease_until>clock_timestamp() AND expires_at>clock_timestamp() FROM v3_deployment_preparations WHERE id=$1 FOR SHARE`, p.ID, p.Owner.String, p.Epoch, p.Username).Scan(&current); err != nil {
				return err
			}
			if !current {
				return errWebDeployment
			}
			_, _, _, err := deploymentPreviewState(ctx, tx, n, DeploymentRequest{})
			return err
		}, true)
		if err != nil {
			return out, err
		}
		var receipt struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(response, &receipt) != nil {
			return out, errWebDeployment
		}
		return webDeploymentResult{Configured: true}, nil
	case "prepare":
		if in.Kind == "uninstall" {
			fp, err := readSSHHostFingerprint(ctx, host, sourceSSH.Port)
			if err != nil {
				return out, err
			}
			if fp != sourceSSH.Fingerprint {
				return out, errFingerprintChanged
			}
			if err := w.stage(ctx, p, "preparing-uninstall"); err != nil {
				return out, err
			}
			req, err := w.store.prepareUninstallDeployment(ctx, w.config, w.trust, n, source, sourceCredential)
			if err != nil {
				return out, err
			}
			preview, err := w.store.previewLocalDeployment(ctx, w.config, w.trust, p.Username, req)
			if err != nil {
				return out, err
			}
			return webDeploymentResult{Preview: &preview, SourceState: in.InstallationState}, nil
		}
		if in.Kind != "install" && in.Kind != "upgrade" {
			return out, errWebDeployment
		}
		if in.Kind == "install" && n.AppliedVersion != 0 || in.Kind == "upgrade" && n.AppliedVersion == 0 {
			return out, ErrConflict
		}
		if err = w.stage(ctx, p, "preparing-identity"); err != nil {
			return out, err
		}
		credential, c, err := credentialForOperation()
		if err != nil {
			return out, err
		}
		if c.Host != host {
			return out, ErrCredentialUnavailable
		}
		fp, err := readSSHHostFingerprint(ctx, host, c.Port)
		if err != nil {
			return out, err
		}
		if fp != c.Fingerprint {
			return out, errFingerprintChanged
		}
		input := deploymentPreparationInput{Node: n.ID, Expected: n.Version, Kind: in.Kind, Credential: credential, Collectors: nil, RulesFile: w.config.Executor.RulesFile}
		collector, e := collectorIdentityMaterial(w.config, time.Now())
		if e != nil {
			return out, errNodeIdentity
		}
		defer clear(collector.Key)
		cert, e := provisioningCertificate(collector.Certificate)
		if e != nil {
			return out, errNodeIdentity
		}
		collectorID, e := nodepki.PeerID(cert, nodepki.Collector)
		if e != nil {
			return out, errNodeIdentity
		}
		input.Collectors = []string{collectorID}
		// A managed successor remains authoritative. Otherwise issue a fresh seed
		// in the host-only CA registry, with a stable replay key for crash recovery.
		_, managed, err := managedNodeAuthority(ctx, w.store.DB, w.config, n)
		if err != nil {
			return out, err
		}
		if !managed {
			receipt, err := w.store.IssueNodeCertificate(ctx, w.config, w.trust.vault, p.Username, "web-identity-"+p.ID, NodeCertificateInput{Node: n.ID, Expected: n.Version})
			if err != nil {
				return out, err
			}
			var identity NodeCertificateRecord
			if json.Unmarshal(receipt, &identity) != nil {
				return out, errWebDeployment
			}
			input.IdentityID = identity.ID
		}
		if err = w.stage(ctx, p, "preparing-configuration"); err != nil {
			return out, err
		}
		req, err := w.store.prepareLocalDeployment(ctx, w.config, w.trust, input)
		if err != nil {
			return out, err
		}
		preview, err := w.store.previewLocalDeployment(ctx, w.config, w.trust, p.Username, req)
		if err != nil {
			return out, err
		}
		out.Preview = &preview
		return out, nil
	case "confirm":
		preview, err := w.store.preparation(ctx, w.trust.vault, p.Username, in.Preparation)
		if err != nil || preview.Status != "succeeded" || preview.Kind != "prepare" || preview.Node != p.Node || preview.Version != n.Version || preview.Result == nil || preview.Result.Preview == nil || !sameCapability(preview.Result.Preview.Token, in.PreviewToken) {
			return out, errWebDeployment
		}
		if err = w.stage(ctx, p, "creating-task"); err != nil {
			return out, err
		}
		response, err := w.store.confirmLocalDeployment(ctx, w.config, w.trust, p.Username, "web-confirm-"+p.ID, in.PreviewToken)
		if err != nil {
			return out, err
		}
		var receipt struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(response, &receipt) != nil {
			return out, errWebDeployment
		}
		out.Job = receipt.ID
		return out, nil
	}
	return out, errors.New("unsupported preparation")
}

func (w *webDeploymentWorker) readiness() (bool, bool) {
	rules, e := readTrustData(w.config.Executor.RulesFile, false, 512<<10)
	rulesOK := e == nil && len(rules) > 0
	if !w.config.NodePKI.Enabled {
		return false, rulesOK
	}
	ca, e := readTrustData(filepath.Join(w.config.NodePKI.AuthorityDirectory, "ca.crt"), false, 64<<10)
	if e != nil {
		return false, rulesOK
	}
	key, e := readTrustData(filepath.Join(w.config.NodePKI.AuthorityDirectory, "ca.key"), true, 64<<10)
	defer clear(key)
	if e != nil {
		return false, rulesOK
	}
	_, e = nodepki.ParseAuthority(ca, key, time.Now())
	return e == nil, rulesOK
}
