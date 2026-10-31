package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"webscan/internal/nodeconfig"
	"webscan/internal/nodepki"
)

var errNodeIdentity = errors.New("节点证书登记不可用或与当前信任不一致，请检查受管理 CA、吊销列表和独立密钥")

// An online issuer is an explicit choice. API/collector processes do not need
// access to ca.key merely to verify peers or read an encrypted issued identity.
type NodePKIConfig struct {
	Enabled            bool   `yaml:"enabled"`
	AuthorityDirectory string `yaml:"authority_directory,omitempty"`
}

func (c NodePKIConfig) validate() error {
	if c.Enabled && c.AuthorityDirectory == "" || c.AuthorityDirectory != "" && (!filepath.IsAbs(c.AuthorityDirectory) || filepath.Clean(c.AuthorityDirectory) != c.AuthorityDirectory || c.AuthorityDirectory == "/" || strings.ContainsAny(c.AuthorityDirectory, "\x00\r\n")) {
		return errors.New("node_pki 启用时必须配置受管理 CA 的绝对规范目录；不会自动生成或替换 CA")
	}
	return nil
}

type NodeCertificateInput struct {
	Node          string `json:"node"`
	Expected      int64  `json:"expected_version"`
	LifetimeHours int    `json:"lifetime_hours,omitempty"`
}

type NodeCertificateRecord struct {
	ID        string    `json:"id"`
	Node      string    `json:"node"`
	Version   int64     `json:"node_version"`
	Authority string    `json:"authority_sha256"`
	Serial    string    `json:"serial"`
	SHA256    string    `json:"certificate_sha256"`
	ExpiresAt time.Time `json:"expires_at"`
}

func nodeKeyAAD(id, node, authority, certificate string) []byte {
	return []byte(fmt.Sprintf("webscan-v3/node-key/%s/%s/%s/%s", id, node, authority, certificate))
}

func (v *Vault) sealNodeKey(id, node, authority, certificate string, key []byte) (string, []byte, []byte, error) {
	if v == nil || v.keys[v.active] == nil || len(key) < 1 || len(key) > 64<<10 {
		return "", nil, nil, errNodeIdentity
	}
	aead := v.keys[v.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, nil, errNodeIdentity
	}
	return v.active, nonce, aead.Seal(nil, nonce, key, nodeKeyAAD(id, node, authority, certificate)), nil
}

func (v *Vault) openNodeKey(id, node, authority, certificate, keyID string, nonce, sealed []byte) ([]byte, error) {
	if v == nil || v.keys[keyID] == nil || len(nonce) != v.keys[keyID].NonceSize() || len(sealed) < v.keys[keyID].Overhead()+1 || len(sealed) > (64<<10)+v.keys[keyID].Overhead() {
		return nil, errNodeIdentity
	}
	key, err := v.keys[keyID].Open(nil, nonce, sealed, nodeKeyAAD(id, node, authority, certificate))
	if err != nil {
		return nil, errNodeIdentity
	}
	return key, nil
}

// IssueNodeCertificate signs only the saved node ID and TLS name. Registry,
// encrypted leaf key, request receipt and audit commit together. Requests never
// choose an issuer, role, hostname or private-key path. No remote work starts.
func (s *Store) IssueNodeCertificate(ctx context.Context, c Config, v *Vault, user, key string, in NodeCertificateInput) (json.RawMessage, error) {
	if !c.NodePKI.Enabled || c.NodePKI.validate() != nil {
		return nil, errNodeIdentity
	}
	if !identifier.MatchString(in.Node) || in.Expected < 1 || in.LifetimeHours < 0 || in.LifetimeHours > 90*24 {
		return nil, errNodeIdentity
	}
	if in.LifetimeHours == 0 {
		in.LifetimeHours = 30 * 24
	}
	if err := provisioningAdmin(ctx, s.DB, user); err != nil {
		return nil, err
	}
	return s.mutation(ctx, user, key, "issue-node-certificate", in.Node, in, func(tx *sql.Tx) (any, error) {
		n, err := scanNode(tx.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM v3_nodes WHERE removed_at IS NULL AND id=$1 FOR UPDATE", in.Node))
		if err == sql.ErrNoRows {
			return nil, ErrConflict
		}
		if err != nil {
			return nil, err
		}
		if n.Version != in.Expected || !n.Enabled {
			return nil, ErrConflict
		}
		if err := provisioningAdmin(ctx, tx, user); err != nil {
			return nil, err
		}
		identity, err := collectorIdentityMaterial(c, time.Now())
		defer clear(identity.Key)
		collectorRaw := identity.Certificate
		if err != nil {
			return nil, errNodeIdentity
		}
		collector, err := provisioningCertificate(collectorRaw)
		if err != nil {
			return nil, errNodeIdentity
		}
		collectorID, err := nodepki.PeerID(collector, nodepki.Collector)
		if err != nil {
			return nil, errNodeIdentity
		}
		now := time.Now().UTC().Truncate(time.Second)
		directory := c.NodePKI.AuthorityDirectory
		roots, err := provisioningRootState(c, now)
		if err != nil {
			return nil, err
		}
		if roots.Format == 1 {
			issuer, err := nodepki.RootFingerprint(identity.CA)
			if err != nil {
				return nil, errNodeIdentity
			}
			directory, err = nodepki.IdentityAuthority(directory, c.Collector.CAFile, c.Collector.RevocationStateDirectory, issuer, now)
			if err != nil {
				return nil, errNodeIdentity
			}
		}
		var record NodeCertificateRecord
		err = nodepki.IssueRegistered(ctx, directory, nodepki.Node, n.ID, []string{n.ServerName}, now, time.Duration(in.LifetimeHours)*time.Hour, func(b nodepki.Bundle, crl []byte) error {
			m := nodeconfig.Material{Node: n.ID, ServerName: n.ServerName, CA: b.CA, Certificate: b.Certificate, CRL: crl, Collectors: []string{collectorID}}
			if validateProvisioningTrust(c, m, now) != nil {
				return errNodeIdentity
			}
			// Removing the historical singleton constraint must not permit a
			// different self-consistent host configuration to repin this cluster.
			// Only the explicit root task can register an additional authority.
			if err := checkIssuerFloor(ctx, tx, m); err != nil {
				return err
			}
			root, err := provisioningCertificate(b.CA)
			if err != nil {
				return errNodeIdentity
			}
			authority := digest(root.Raw)
			// Different hosts serialize through PostgreSQL, not a shared file lock.
			if _, err := tx.ExecContext(ctx, "INSERT INTO v3_pki_authorities(sha256,certificate,crl) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", authority, b.CA, crl); err != nil {
				return err
			}
			var pinnedCA, floor []byte
			if err := tx.QueryRowContext(ctx, "SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR UPDATE", authority).Scan(&pinnedCA, &floor); err != nil {
				return err
			}
			pinned, err := provisioningCertificate(pinnedCA)
			if err != nil || !bytes.Equal(pinned.Raw, root.Raw) || nodepki.ValidateCRLAdvance(b.CA, floor, crl, now) != nil {
				return errNodeIdentity
			}
			if _, err := tx.ExecContext(ctx, "UPDATE v3_pki_authorities SET crl=$2,updated_at=clock_timestamp() WHERE sha256=$1", authority, crl); err != nil {
				return err
			}
			cert, err := provisioningCertificate(b.Certificate)
			if err != nil {
				return errNodeIdentity
			}
			record = NodeCertificateRecord{ID: token(), Node: n.ID, Version: n.Version, Authority: authority, Serial: cert.SerialNumber.Text(16), SHA256: digest(cert.Raw), ExpiresAt: cert.NotAfter}
			keyID, nonce, sealed, err := v.sealNodeKey(record.ID, n.ID, authority, record.SHA256, b.Key)
			if err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO v3_node_certificates(id,node,authority,node_version,server_name,serial,certificate,key_id,nonce,ciphertext,not_before,not_after) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, record.ID, n.ID, authority, n.Version, n.ServerName, record.Serial, b.Certificate, keyID, nonce, sealed, cert.NotBefore, cert.NotAfter)
			return err
		})
		if err != nil {
			return nil, err
		}
		return record, nil
	})
}

// Registry floors are checked inside submission transactions too. A second
// issuer cannot make stale signed CRLs usable by restoring its local files.
func checkIssuerFloor(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, m nodeconfig.Material) error {
	return checkIssuerFloorAt(ctx, q, m, time.Now())
}

func checkIssuerFloorAt(ctx context.Context, q provisioningReader, m nodeconfig.Material, now time.Time) error {
	root, err := provisioningCertificate(m.CA)
	if err != nil {
		return errNodeIdentity
	}
	var ca, floor []byte
	err = q.QueryRowContext(ctx, "SELECT certificate,crl FROM v3_pki_authorities WHERE sha256=$1 FOR SHARE", digest(root.Raw)).Scan(&ca, &floor)
	if err == sql.ErrNoRows {
		var known bool
		if err := q.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM v3_pki_authorities)").Scan(&known); err != nil {
			return err
		}
		if known {
			return errNodeIdentity
		} // CA rollover requires an explicit migration.
		return nil // Explicit offline identities remain compatible before pinning.
	}
	if err != nil {
		return err
	}
	pinned, err := provisioningCertificate(ca)
	if err != nil || !bytes.Equal(pinned.Raw, root.Raw) || nodepki.ValidateCRLAdvance(ca, floor, m.CRL, now) != nil {
		return errNodeIdentity
	}
	return nil
}

func (s *Store) readNodeIdentity(ctx context.Context, c Config, v *Vault, id, node string) (nodepki.Bundle, error) {
	return readNodeIdentityFrom(ctx, s.DB, c, v, id, node)
}

// Provisioning can read identity and revocation floors in the same SQL
// snapshot as its authenticated binding, source node and parent lease.
func readNodeIdentityFrom(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, c Config, v *Vault, id, node string) (nodepki.Bundle, error) {
	var b nodepki.Bundle
	if !identifier.MatchString(id) || !identifier.MatchString(node) {
		return b, errNodeIdentity
	}
	var authority, keyID string
	var nonce, sealed []byte
	err := q.QueryRowContext(ctx, `SELECT a.certificate,n.certificate,n.authority,n.key_id,n.nonce,n.ciphertext FROM v3_node_certificates n JOIN v3_pki_authorities a ON a.sha256=n.authority WHERE n.id=$1 AND n.node=$2`, id, node).Scan(&b.CA, &b.Certificate, &authority, &keyID, &nonce, &sealed)
	if err != nil {
		return nodepki.Bundle{}, errNodeIdentity
	}
	cert, err := provisioningCertificate(b.Certificate)
	if err != nil {
		return nodepki.Bundle{}, errNodeIdentity
	}
	root, err := provisioningCertificate(b.CA)
	if err != nil || digest(root.Raw) != authority {
		return nodepki.Bundle{}, errNodeIdentity
	}
	b.Key, err = v.openNodeKey(id, node, authority, digest(cert.Raw), keyID, nonce, sealed)
	if err != nil {
		return nodepki.Bundle{}, err
	}
	if _, err := tls.X509KeyPair(b.Certificate, b.Key); err != nil {
		clear(b.Key)
		return nodepki.Bundle{}, errNodeIdentity
	}
	crl, err := provisioningIssuerCRL(c, b.CA, time.Now())
	if err != nil {
		clear(b.Key)
		return nodepki.Bundle{}, errNodeIdentity
	}
	m := nodeconfig.Material{CA: b.CA, CRL: crl}
	if err := checkIssuerFloor(ctx, q, m); err != nil {
		clear(b.Key)
		return nodepki.Bundle{}, err
	}
	trust, err := nodepki.NewTrust(b.CA, crl, time.Now())
	if err != nil || trust.Verify(cert, nodepki.Node, node, time.Now()) != nil {
		clear(b.Key)
		return nodepki.Bundle{}, errNodeIdentity
	}
	return b, nil
}

// RewrapNodeCertificate changes encryption only. Historical certificate bytes,
// serial, expiry and node binding stay fixed; old database backups still need
// their independent old vault keys. This is not certificate renewal/revocation.
func (s *Store) RewrapNodeCertificate(ctx context.Context, v *Vault, id, node string) error {
	if !identifier.MatchString(id) || !identifier.MatchString(node) {
		return errNodeIdentity
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if held, err := migrationHeld(ctx, tx); err != nil {
		return err
	} else if held {
		return ErrMigrationPending
	}
	var authority, keyID string
	var certificate, nonce, sealed []byte
	if err := tx.QueryRowContext(ctx, "SELECT authority,certificate,key_id,nonce,ciphertext FROM v3_node_certificates WHERE id=$1 AND node=$2 FOR UPDATE", id, node).Scan(&authority, &certificate, &keyID, &nonce, &sealed); err != nil {
		return errNodeIdentity
	}
	cert, err := provisioningCertificate(certificate)
	if err != nil {
		return errNodeIdentity
	}
	key, err := v.openNodeKey(id, node, authority, digest(cert.Raw), keyID, nonce, sealed)
	if err != nil {
		return err
	}
	defer clear(key)
	if _, err := tls.X509KeyPair(certificate, key); err != nil {
		return errNodeIdentity
	}
	if keyID == v.active {
		return tx.Commit()
	}
	keyID, nonce, sealed, err = v.sealNodeKey(id, node, authority, digest(cert.Raw), key)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v3_node_certificates SET key_id=$2,nonce=$3,ciphertext=$4 WHERE id=$1", id, keyID, nonce, sealed); err != nil {
		return err
	}
	return tx.Commit()
}
