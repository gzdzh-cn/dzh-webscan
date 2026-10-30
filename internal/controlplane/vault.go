package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

var ErrCredentialUnavailable = errors.New("SSH 凭据不可用，请检查独立密钥及凭据登记")

// Vault keys are supplied by the service's independent secret store. They are
// never placed in PostgreSQL, YAML exports, task plans or database backups.
// Existing keys remain readable during a rolling key rotation.
type Vault struct {
	active      string
	keys        map[string]cipher.AEAD
	receiptKeys map[string][]byte
}

func OpenVault(activeFile string, previousFiles ...string) (*Vault, error) {
	if len(previousFiles) > 8 {
		return nil, ErrCredentialUnavailable
	}
	v := &Vault{keys: map[string]cipher.AEAD{}, receiptKeys: map[string][]byte{}}
	for i, path := range append([]string{activeFile}, previousFiles...) {
		raw, err := readTrustData(path, true, 128)
		if err != nil {
			return nil, ErrCredentialUnavailable
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		clear(raw)
		if err != nil || len(key) != 32 {
			clear(key)
			return nil, errors.New("凭据加密密钥必须为 32 字节随机值的十六进制私有文件")
		}
		sum := sha256.Sum256(key)
		id := hex.EncodeToString(sum[:16])
		if v.keys[id] != nil {
			clear(key)
			return nil, ErrCredentialUnavailable
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrCredentialUnavailable
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrCredentialUnavailable
		}
		receiptKey := hmac.New(sha256.New, key)
		receiptKey.Write([]byte("webscan-v3/credential-receipts"))
		v.receiptKeys[id] = receiptKey.Sum(nil)
		v.keys[id] = aead
		if i == 0 {
			v.active = id
		}
		for j := range key {
			key[j] = 0
		}
	}
	return v, nil
}

// SSHCredential is an internal executor value. Do not attach it to public
// responses, errors or log output. All persisted forms are authenticated ciphertext.
type SSHCredential struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	Password    string `json:"password,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
}

func (SSHCredential) String() string   { return "[受保护的 SSH 凭据]" }
func (SSHCredential) GoString() string { return "[受保护的 SSH 凭据]" }

func (c SSHCredential) validate() error {
	if c.Host == "" || len(c.Host) > 253 || strings.ContainsAny(c.Host, "/\\?#@\x00\r\n \t") || c.Port < 1 || c.Port > 65535 {
		return errors.New("SSH 地址或端口不正确")
	}
	if strings.Contains(c.Host, ":") && net.ParseIP(c.Host) == nil {
		return errors.New("SSH 地址不正确")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(c.Fingerprint, "SHA256:"))
	if !strings.HasPrefix(c.Fingerprint, "SHA256:") || err != nil || len(raw) != 32 {
		return errors.New("请先核实并填写 SSH 主机 SHA256 指纹")
	}
	if (c.Password == "") == (c.PrivateKey == "") {
		return errors.New("SSH 密码与私钥必须且只能提供一种")
	}
	if len(c.Password) > 4096 || len(c.PrivateKey) > 64<<10 {
		return errors.New("SSH 凭据超过大小限制")
	}
	if c.PrivateKey != "" {
		if _, err = ssh.ParsePrivateKey([]byte(c.PrivateKey)); err != nil {
			return errors.New("私钥无效或需要口令；仅支持未加密私钥")
		}
	}
	return nil
}
func credentialAAD(id, node, key string, revision int64) []byte {
	return []byte(fmt.Sprintf("webscan-v3/ssh/%s/%s/%s/%d", id, node, key, revision))
}
func (v *Vault) seal(id, node string, revision int64, c SSHCredential) (string, []byte, []byte, error) {
	if v == nil || v.keys[v.active] == nil {
		return "", nil, nil, ErrCredentialUnavailable
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", nil, nil, ErrCredentialUnavailable
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	aead := v.keys[v.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", nil, nil, ErrCredentialUnavailable
	}
	return v.active, nonce, aead.Seal(nil, nonce, raw, credentialAAD(id, node, v.active, revision)), nil
}
func (v *Vault) open(id, node, key string, revision int64, nonce, ciphertext []byte) (SSHCredential, error) {
	var c SSHCredential
	if v == nil || v.keys[key] == nil || len(nonce) != v.keys[key].NonceSize() || len(ciphertext) > 128<<10 {
		return c, ErrCredentialUnavailable
	}
	raw, err := v.keys[key].Open(nil, nonce, ciphertext, credentialAAD(id, node, key, revision))
	if err != nil {
		return c, ErrCredentialUnavailable
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if json.Unmarshal(raw, &c) != nil || c.validate() != nil {
		return SSHCredential{}, ErrCredentialUnavailable
	}
	return c, nil
}

// AddCredential always creates a new immutable identity. Replacement never
// invalidates credentials referenced by a pending deployment or rollback.
func (s *Store) AddCredential(ctx context.Context, v *Vault, user, key, node string, expected int64, c SSHCredential) (json.RawMessage, error) {
	return s.addCredential(ctx, v, user, key, node, expected, c, nil, false)
}
func (s *Store) addCredential(ctx context.Context, v *Vault, user, key, node string, expected int64, c SSHCredential, guard func(*sql.Tx) error, active bool) (json.RawMessage, error) {
	if !identifier.MatchString(node) || expected < 1 {
		return nil, ErrConflict
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	id := token()
	keyID, nonce, sealed, err := v.seal(id, node, 1, c)
	if err != nil {
		return nil, err
	}
	// Keyed digests prevent request receipts from becoming an offline
	// password oracle. A separate derived key avoids reusing AEAD nonces.
	proof := hmac.New(sha256.New, v.receiptKeys[v.active])
	raw, _ := json.Marshal(c)
	proof.Write(raw)
	for i := range raw {
		raw[i] = 0
	}
	receipt := proof.Sum(nil)
	request := struct {
		Node         string
		Expected     int64
		KeyID, Proof string
	}{node, expected, keyID, digest(receipt)}
	return s.guardedMutation(ctx, user, key, "add-ssh-credential", node, request, guard, func(tx *sql.Tx) (any, error) {
		var version int64
		if err := tx.QueryRowContext(ctx, "SELECT version FROM v3_nodes WHERE id=$1 FOR UPDATE", node).Scan(&version); err != nil {
			if err == sql.ErrNoRows {
				return nil, ErrConflict
			}
			return nil, err
		}
		if version != expected {
			return nil, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO v3_credentials(id,node,key_id,nonce,ciphertext) VALUES($1,$2,$3,$4,$5)", id, node, keyID, nonce, sealed); err != nil {
			return nil, err
		}
		if active {
			if _, err := tx.ExecContext(ctx, `INSERT INTO v3_web_node_credentials(node,credential) VALUES($1,$2) ON CONFLICT(node) DO UPDATE SET credential=excluded.credential,updated_at=clock_timestamp()`, node, id); err != nil {
				return nil, err
			}
		}
		return map[string]any{"id": id, "node": node, "configured": true}, nil
	})
}
func (s *Store) ReadCredential(ctx context.Context, v *Vault, id, node string) (SSHCredential, error) {
	var key string
	var rev int64
	var nonce, sealed []byte
	if err := s.DB.QueryRowContext(ctx, "SELECT key_id,revision,nonce,ciphertext FROM v3_credentials WHERE id=$1 AND node=$2", id, node).Scan(&key, &rev, &nonce, &sealed); err != nil {
		return SSHCredential{}, ErrCredentialUnavailable
	}
	return v.open(id, node, key, rev, nonce, sealed)
}

// RewrapCredential changes only encryption, never SSH identity. The prior key
// must remain available until all rows and external backups have been handled.
func (s *Store) RewrapCredential(ctx context.Context, v *Vault, id, node string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var key string
	var rev int64
	var nonce, sealed []byte
	if err = tx.QueryRowContext(ctx, "SELECT key_id,revision,nonce,ciphertext FROM v3_credentials WHERE id=$1 AND node=$2 FOR UPDATE", id, node).Scan(&key, &rev, &nonce, &sealed); err != nil {
		return ErrCredentialUnavailable
	}
	c, err := v.open(id, node, key, rev, nonce, sealed)
	if err != nil {
		return err
	}
	if key == v.active {
		return tx.Commit()
	}
	key, nonce, sealed, err = v.seal(id, node, rev+1, c)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_credentials SET key_id=$2,revision=revision+1,nonce=$3,ciphertext=$4 WHERE id=$1", id, key, nonce, sealed); err != nil {
		return err
	}
	return tx.Commit()
}
