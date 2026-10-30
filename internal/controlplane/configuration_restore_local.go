package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"webscan/internal/nodepki"
)

// Diagnostic only: a successful read cannot authorize a later apply. Files can
// change after this call; final application must re-open/recheck them. No paths,
// certificate identities, DSNs, key IDs, secrets or underlying errors escape.
type configurationLocalCheck struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
}

type configurationLocalReport struct {
	CheckedAt           time.Time                 `json:"checked_at"`
	Checks              []configurationLocalCheck `json:"checks"`
	LocalChecksPassed   bool                      `json:"local_checks_passed"`
	RequiresApplyChecks bool                      `json:"requires_apply_checks"`
}

var errConfigurationLocal = errors.New("恢复配置不完整或本机资料检查不可用；运行配置未修改")

// inspectConfigurationRestoreLocal authenticates the intent again, then reads
// only local material under the same state gate. It never creates directories,
// advances a CRL floor, connects to a DSN/SSH/HTTP endpoint, executes tools or
// marks an intent applied. The report is deliberately not a durable capability.
func (s *Store) inspectConfigurationRestoreLocal(ctx context.Context, v *Vault, c Config, user, id string) (configurationLocalReport, error) {
	op, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := s.DB.BeginTx(op, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return configurationLocalReport{}, err
	}
	defer tx.Rollback()
	plan, err := revalidateConfigurationStageTx(op, tx, v, c, user, id)
	if err != nil {
		return configurationLocalReport{}, err
	}
	if !plan.Summary.CanPrepare {
		return configurationLocalReport{}, errConfigurationRestoreBlocked
	}
	return checkConfigurationLocalMaterial(op, plan.Candidate, v, time.Now().UTC())
}

func checkConfigurationLocalMaterial(ctx context.Context, doc configurationDocument, currentVault *Vault, now time.Time) (configurationLocalReport, error) {
	r := configurationLocalReport{CheckedAt: now, Checks: []configurationLocalCheck{}, LocalChecksPassed: true, RequiresApplyChecks: true}
	if err := ctx.Err(); err != nil {
		r.LocalChecksPassed = false
		return r, err
	}
	if !doc.complete() || doc.validate() != nil {
		r.LocalChecksPassed = false
		return r, errConfigurationLocal
	}
	var c Config
	raw, err := json.Marshal(doc.Bootstrap)
	if err != nil {
		r.LocalChecksPassed = false
		return r, errConfigurationLocal
	}
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if d.Decode(&c) != nil || c.Validate() != nil {
		r.LocalChecksPassed = false
		return r, errConfigurationLocal
	}
	check := func(component, reason string, fn func() error) {
		if ctx.Err() != nil {
			return
		}
		status := "passed"
		if fn() != nil {
			status = "failed"
			r.LocalChecksPassed = false
		} else {
			reason = "local_material_verified"
		}
		r.Checks = append(r.Checks, configurationLocalCheck{component, status, reason})
	}
	disabled := func(component, reason string) {
		r.Checks = append(r.Checks, configurationLocalCheck{component, "not_configured", reason})
	}
	check("database_credentials", "private_dsn_file_unavailable", func() error {
		b, e := readTrustData(c.Database.DSNFile, true, 64<<10)
		defer clear(b)
		if e != nil || len(bytes.TrimSpace(b)) == 0 {
			return errConfigurationLocal
		}
		// This checks the independent file, not connectivity, authentication or
		// DSN syntax. Parsing libpq settings can implicitly load service/TLS files
		// or environment defaults; that belongs in the explicit final phase.
		return nil
	})
	if c.Central.CertFile == "" {
		disabled("central_tls", "https_proxy_not_checked")
	} else {
		check("central_tls", "server_certificate_key_or_hostname_invalid", func() error {
			cert, key, e := configurationLocalPair(c.Central.CertFile, c.Central.KeyFile)
			defer clear(key)
			if e != nil {
				return e
			}
			pair, e := tls.X509KeyPair(cert, key)
			if e != nil {
				return errConfigurationLocal
			}
			leaf, e := x509.ParseCertificate(pair.Certificate[0])
			u, _ := url.Parse(c.Central.PublicURL)
			if e != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(u.Hostname()) != nil {
				return errConfigurationLocal
			}
			if len(leaf.ExtKeyUsage) > 0 {
				for _, usage := range leaf.ExtKeyUsage {
					if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
						return nil
					}
				}
				return errConfigurationLocal
			}
			return nil
		})
	}
	var collectorCA, collectorCRL []byte
	check("collector_tls", "collector_identity_trust_or_revocation_invalid", func() error {
		var e error
		collectorCA, e = readTrustData(c.Collector.CAFile, false, 64<<10)
		if e != nil {
			return e
		}
		identity, e := collectorIdentityMaterial(c, now)
		certRaw, key := identity.Certificate, identity.Key
		defer clear(key)
		if e != nil {
			return e
		}
		if _, e = tls.X509KeyPair(certRaw, key); e != nil {
			return errConfigurationLocal
		}
		cert, e := provisioningCertificate(certRaw)
		if e != nil {
			return e
		}
		id, e := nodepki.PeerID(cert, nodepki.Collector)
		if e != nil {
			return e
		}
		if c.Collector.RevocationFile == "" {
			// The older no-CRL runtime is still supported, but the report names
			// the missing revocation check separately rather than claiming it.
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(collectorCA) || cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
				return errConfigurationLocal
			}
			_, e = cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
			return e
		}
		collectorCRL, e = readTrustData(c.Collector.RevocationFile, false, nodepki.MaxCRLBytes)
		if e != nil {
			return e
		}
		trust, e := nodepki.NewTrust(collectorCA, collectorCRL, now)
		if e != nil {
			return e
		}
		return trust.Verify(cert, nodepki.Collector, id, now)
	})
	if c.Collector.RevocationFile == "" {
		disabled("collector_revocation", "revocation_not_configured")
	} else if c.Collector.RevocationStateDirectory == "" {
		disabled("collector_revocation_floor", "persistent_floor_not_configured")
	} else {
		check("collector_revocation_floor", "persistent_floor_missing_or_rollback_detected", func() error {
			d, e := trustDirectory(c.Collector.RevocationStateDirectory, true)
			if e != nil {
				return e
			}
			d.Close()
			pinned, e := readTrustData(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crt"), true, 64<<10)
			if e != nil {
				return e
			}
			a, e := provisioningCertificate(collectorCA)
			b, other := provisioningCertificate(pinned)
			if e != nil || other != nil || !bytes.Equal(a.Raw, b.Raw) {
				return errConfigurationLocal
			}
			floor, e := readTrustData(filepath.Join(c.Collector.RevocationStateDirectory, "ca.crl"), true, nodepki.MaxCRLBytes)
			if e != nil {
				return e
			}
			return nodepki.ValidateCRLAdvance(collectorCA, floor, collectorCRL, now)
		})
	}
	check("exports_directory", "private_directory_or_reserve_unavailable", func() error { return configurationLocalDirectory(c.Central.ExportDirectory) })
	if c.Metrics.SpoolDir != "" {
		check("metrics_spool_directory", "private_directory_or_reserve_unavailable", func() error { return configurationLocalDirectory(c.Metrics.SpoolDir) })
	} else {
		disabled("metrics_spool_directory", "spool_not_configured")
	}
	if c.DeploymentTrust.configured() {
		var target *deploymentTrust
		check("deployment_trust", "vault_release_signature_or_artifacts_invalid", func() error {
			var e error
			target, e = loadDeploymentTrust(ctx, c.DeploymentTrust)
			return e
		})
		check("vault_continuity", "current_decryption_keys_not_retained", func() error {
			// Conservatively retain every currently configured key. Otherwise a
			// valid new key could strand SSH credentials, issued keys or archives.
			// This does not claim that every database ciphertext was inspected.
			if currentVault == nil || target == nil || currentVault.keys[currentVault.active] == nil {
				return errConfigurationLocal
			}
			for id := range currentVault.keys {
				if target.vault.keys[id] == nil {
					return errConfigurationLocal
				}
			}
			return nil
		})
	} else {
		disabled("deployment_trust", "deployment_trust_not_configured")
		if currentVault != nil {
			// Configuration archives already use an independent vault; restoring
			// away its configured material needs an explicit credential workflow.
			check("vault_continuity", "current_decryption_keys_not_retained", func() error { return errConfigurationLocal })
		}
	}
	if c.Executor.Enabled {
		check("executor_directory", "private_directory_or_reserve_unavailable", func() error { return configurationLocalDirectory(c.Executor.ConfigurationDirectory) })
	} else {
		disabled("executor_directory", "executor_disabled")
	}
	if c.NodePKI.Enabled {
		check("node_issuer", "issuer_key_or_collector_trust_mismatch", func() error {
			d, e := trustDirectory(c.NodePKI.AuthorityDirectory, true)
			if e != nil {
				return e
			}
			d.Close()
			ca, key, e := configurationLocalPair(filepath.Join(c.NodePKI.AuthorityDirectory, "ca.crt"), filepath.Join(c.NodePKI.AuthorityDirectory, "ca.key"))
			defer clear(key)
			if e != nil {
				return e
			}
			if _, e = nodepki.ParseAuthority(ca, key, now); e != nil {
				return e
			}
			a, e := provisioningCertificate(ca)
			b, other := provisioningCertificate(collectorCA)
			if e != nil || other != nil || !bytes.Equal(a.Raw, b.Raw) {
				return errConfigurationLocal
			}
			crl, e := readTrustData(filepath.Join(c.NodePKI.AuthorityDirectory, "ca.crl"), false, nodepki.MaxCRLBytes)
			if e != nil || !bytes.Equal(bytes.TrimSpace(crl), bytes.TrimSpace(collectorCRL)) {
				return errConfigurationLocal
			}
			_, e = nodepki.NewTrust(ca, crl, now)
			return e
		})
	} else {
		disabled("node_issuer", "online_issuer_disabled")
	}
	if c.Central.Topology == "ha" {
		check("ha_ssh_keys", "ha_private_key_unavailable", func() error {
			for _, m := range c.HA.Members {
				if e := ctx.Err(); e != nil {
					return e
				}
				key, e := readTrustData(m.SSHKeyFile, true, 64<<10)
				if e == nil {
					_, e = ssh.ParsePrivateKey(key)
				}
				clear(key)
				if e != nil {
					return errConfigurationLocal
				}
			}
			return nil
		})
	}
	if err := ctx.Err(); err != nil {
		r.LocalChecksPassed = false
		return r, err
	}
	return r, nil
}

func configurationLocalPair(certFile, keyFile string) ([]byte, []byte, error) {
	cert, err := readTrustData(certFile, false, 256<<10)
	if err != nil {
		return nil, nil, errConfigurationLocal
	}
	key, err := readTrustData(keyFile, true, 64<<10)
	if err != nil {
		return nil, nil, errConfigurationLocal
	}
	return cert, key, nil
}

// Metadata and free-space inspection only. No mkdir/chmod/chown, write probe,
// lock-file creation or assumptions about remote HA filesystem accessibility.
func configurationLocalDirectory(path string) error {
	if path == "/" || strings.ContainsAny(path, "\x00\r\n") {
		return errConfigurationLocal
	}
	d, err := trustDirectory(path, true)
	if err != nil {
		return errConfigurationLocal
	}
	defer d.Close()
	if unix.Faccessat(int(d.Fd()), ".", unix.W_OK|unix.X_OK, unix.AT_EACCESS) != nil {
		return errConfigurationLocal
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(d.Fd()), &fs) != nil || fs.Bsize <= 0 || fs.Bavail < (64<<20)/uint64(fs.Bsize)+1 || fs.Ffree == 0 {
		return errConfigurationLocal
	}
	return nil
}
