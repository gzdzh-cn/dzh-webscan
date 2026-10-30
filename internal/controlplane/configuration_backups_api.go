package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var errConfigurationCryptoBusy = errors.New("加密操作繁忙，请稍后重试")
var errConfigurationCryptoRate = errors.New("加密操作次数过多，请五分钟后重试")

// Forwarding headers are evidence only at an explicitly configured boundary.
// X-Forwarded-For, Forwarded and the public URL never establish this trust.
func (a *API) configurationSecureTransport(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	values := r.Header.Values("X-Forwarded-Proto")
	if len(values) != 1 || values[0] != "https" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return false
	}
	peer = peer.Unmap()
	for _, raw := range a.Config.Central.TrustedProxies {
		prefix, err := trustedProxyPrefix(raw)
		if err == nil && prefix.Bits() > 0 && prefix.Contains(peer) {
			return true
		}
	}
	return false
}

// Shared PostgreSQL rate counters survive API restarts. Transaction-scoped
// advisory locks bound expensive scrypt work to two operations across replicas,
// and cannot leak a session lock back into the connection pool on cancellation.
func (s *Store) admitConfigurationCrypto(ctx context.Context, user string) (func(), error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = configurationBackupAdmin(ctx, tx, user); err != nil {
		return nil, err
	}
	limited := false
	for _, counter := range []struct {
		key string
		max int
	}{{"configuration-crypto:global", 60}, {"configuration-crypto:user:" + user, 10}} {
		var count int
		err = tx.QueryRowContext(ctx, `INSERT INTO v3_login_attempts(key,count,expires_at) VALUES($1,1,clock_timestamp()+interval '5 minutes')
 ON CONFLICT(key) DO UPDATE SET count=CASE WHEN v3_login_attempts.expires_at<=clock_timestamp() THEN 1 ELSE LEAST(v3_login_attempts.count+1,1000000) END,
 expires_at=CASE WHEN v3_login_attempts.expires_at<=clock_timestamp() THEN EXCLUDED.expires_at ELSE v3_login_attempts.expires_at END RETURNING count`, counter.key).Scan(&count)
		if err != nil {
			return nil, err
		}
		limited = limited || count > counter.max
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if limited {
		return nil, errConfigurationCryptoRate
	}
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	// age's bounded scrypt calculation is synchronous. Request cancellation
	// must not free its slot while that calculation is still consuming memory.
	// Detach the gate transaction from request cancellation, release it only
	// when the operation actually returns, and retain a hard orphan bound.
	gateCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	gate, err := conn.BeginTx(gateCtx, nil)
	if err != nil {
		stop()
		conn.Close()
		return nil, err
	}
	release := func() { _ = gate.Rollback(); stop(); _ = conn.Close() }
	// Always leave a business connection available to read/write the backup.
	// A two-connection installation supports one crypto operation at a time.
	slots := 2
	if maximum := s.DB.Stats().MaxOpenConnections; maximum > 0 {
		slots = min(slots, maximum-1)
	}
	for slot := 0; slot < slots; slot++ {
		var ok bool
		if err = gate.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(773376014,$1)", slot).Scan(&ok); err != nil {
			release()
			return nil, err
		}
		if ok {
			return release, nil
		}
	}
	release()
	return nil, errConfigurationCryptoBusy
}

func configurationBackupFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errConfigurationDeleteQuota):
		w.Header().Set("Retry-After", "60")
		failure(w, 429, "delete_quota_exceeded", errConfigurationDeleteQuota.Error())
	case errors.Is(err, errConfigurationDeleteInput):
		failure(w, 400, "invalid_delete_request", errConfigurationDeleteInput.Error())
	case errors.Is(err, errConfigurationDeletePreview):
		failure(w, 409, "delete_preview_expired", errConfigurationDeletePreview.Error())
	case errors.Is(err, ErrConfigurationBackupPermission):
		failure(w, 403, "permission_denied", ErrConfigurationBackupPermission.Error())
	case errors.Is(err, sql.ErrNoRows):
		failure(w, 404, "backup_not_found", "备份不存在")
	case errors.Is(err, errConfigurationDocument):
		failure(w, 400, "invalid_backup", errConfigurationDocument.Error())
	case errors.Is(err, errConfigurationPassword):
		failure(w, 400, "invalid_encrypted_backup", errConfigurationPassword.Error())
	case errors.Is(err, errConfigurationCryptoRate):
		w.Header().Set("Retry-After", "300")
		failure(w, 429, "crypto_admission_rejected", err.Error())
	case errors.Is(err, errConfigurationCryptoBusy):
		w.Header().Set("Retry-After", "3")
		failure(w, 429, "crypto_admission_rejected", err.Error())
	case errors.Is(err, ErrConfigurationBackupKey):
		failure(w, 503, "backup_key_unavailable", ErrConfigurationBackupKey.Error())
	default:
		mutationReply(w, nil, err)
	}
}

// Multipart is streamed into bounded memory. ParseMultipartForm is avoided:
// neither an uploaded private package nor its password may spill to /tmp.
func readConfigurationAgeImport(w http.ResponseWriter, r *http.Request) ([]byte, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, configurationEncryptedLimit+8192)
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return nil, "", errConfigurationDocument
	}
	reader := multipart.NewReader(r.Body, params["boundary"])
	var raw []byte
	var password string
	seen := map[string]bool{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", errConfigurationDocument
		}
		name := part.FormName()
		if seen[name] || name != "file" && name != "password" {
			return nil, "", errConfigurationDocument
		}
		seen[name] = true
		limit := configurationEncryptedLimit
		if name == "password" {
			limit = 1024
		}
		data, err := io.ReadAll(io.LimitReader(part, int64(limit)+1))
		if err != nil || len(data) == 0 || len(data) > limit {
			clear(data)
			return nil, "", errConfigurationDocument
		}
		if name == "file" {
			raw = data
		} else {
			password = string(data)
			clear(data)
		}
	}
	if !seen["file"] || !seen["password"] || len(password) < 12 {
		return nil, "", errConfigurationDocument
	}
	// Consume the MIME epilogue to enforce the total body bound as well.
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		return nil, "", errConfigurationDocument
	}
	return raw, password, nil
}

func (a *API) configurationBackupRoutes(w http.ResponseWriter, r *http.Request, id identity) bool {
	const prefix = "/api/v3/configuration-backups"
	if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if id.Role != "admin" {
		configurationBackupFailure(w, ErrConfigurationBackupPermission)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	path := strings.TrimPrefix(r.URL.Path, prefix)
	if a.configurationDeleteRoutes(w, r, id, path) {
		return true
	}
	if path == "" && r.Method == "GET" {
		limit, err := pageSize(r, 20)
		if err != nil {
			failure(w, 400, "invalid_limit", err.Error())
			return true
		}
		cursor, err := decodeRetentionCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			failure(w, 400, "invalid_cursor", "分页游标不正确")
			return true
		}
		items, err := a.Store.configurationBackups(ctx, id.Username, cursor, limit)
		if err != nil {
			configurationBackupFailure(w, err)
			return true
		}
		next := ""
		if len(items) == limit {
			last := items[len(items)-1]
			next = (retentionCursor{last.Created, last.ID}).encode()
		}
		reply(w, 200, map[string]any{"items": items, "next_cursor": next, "restore_available": false, "saved_restore_available": true, "delete_available": true})
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	redactedExport := len(parts) == 2 && parts[1] == "export" && r.Method == "GET"
	ageExport := len(parts) == 2 && parts[1] == "export-age" && r.Method == "POST"
	if len(parts) == 2 && (parts[1] == "export" || parts[1] == "export-age") && !validArchiveSource(parts[0]) {
		failure(w, 400, "invalid_backup_id", "备份编号不正确")
		return true
	}
	create := path == "" && r.Method == "POST"
	plainImport := path == "/import" && r.Method == "POST"
	ageImport := path == "/import-age" && r.Method == "POST"
	if !create && !plainImport && !ageImport && !redactedExport && !ageExport {
		failure(w, 404, "not_found", "配置备份接口不存在")
		return true
	}
	if (plainImport || ageImport || ageExport) && !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "导入或包含凭据的加密导出必须通过 HTTPS；反向代理需显式配置 trusted_proxies")
		return true
	}
	vault, err := OpenVault(a.Config.DeploymentTrust.VaultKeyFile, a.Config.DeploymentTrust.PreviousKeyFiles...)
	if err != nil {
		configurationBackupFailure(w, ErrConfigurationBackupKey)
		return true
	}
	key := ""
	if create || plainImport || ageImport {
		var ok bool
		key, ok = mutationKey(w, r)
		if !ok {
			return true
		}
	}
	if ageImport || ageExport {
		release, err := a.Store.admitConfigurationCrypto(ctx, id.Username)
		if err != nil {
			configurationBackupFailure(w, err)
			return true
		}
		defer release()
	}
	if create {
		var in struct{}
		if decode(w, r, &in) != nil {
			failure(w, 400, "invalid_request", "请求格式不正确")
			return true
		}
		if a.bootstrapConfig == nil {
			failure(w, 503, "bootstrap_unavailable", "启动配置快照不可用，未创建备份")
			return true
		}
		out, err := a.Store.createConfigurationBackup(ctx, vault, *a.bootstrapConfig, id.Username, key)
		if err != nil {
			configurationBackupFailure(w, err)
		} else {
			mutationReply(w, out, nil)
		}
		return true
	}
	if plainImport || ageImport {
		var raw []byte
		var password string
		if ageImport {
			raw, password, err = readConfigurationAgeImport(w, r)
		} else {
			raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, configurationDocumentLimit))
		}
		defer clear(raw)
		if err != nil {
			configurationBackupFailure(w, errConfigurationDocument)
			return true
		}
		var out []byte
		if ageImport {
			out, err = a.Store.importEncryptedConfigurationBackup(ctx, vault, id.Username, key, raw, password)
		} else {
			out, err = a.Store.importConfigurationBackup(ctx, vault, id.Username, key, raw)
		}
		if err != nil {
			configurationBackupFailure(w, err)
		} else {
			mutationReply(w, out, nil)
		}
		return true
	}
	var out []byte
	var release func()
	format := "yaml"
	if ageExport {
		var in struct {
			Password string `json:"password"`
			Confirm  string `json:"confirm"`
		}
		if decode(w, r, &in) != nil || len(in.Password) < 12 || len(in.Password) > 1024 || in.Password != in.Confirm {
			failure(w, 400, "invalid_password", "加密密码须为 12～1024 字节且两次输入一致")
			return true
		}
		format = "age"
		out, release, err = a.Store.prepareConfigurationBackupExport(ctx, vault, id.Username, parts[0], "age", func(doc configurationDocument) ([]byte, error) {
			return encryptConfigurationDocument(doc, in.Password, in.Confirm)
		})
	} else {
		out, release, err = a.Store.prepareConfigurationBackupExport(ctx, vault, id.Username, parts[0], "redacted", func(doc configurationDocument) ([]byte, error) {
			public, err := doc.redacted()
			if err != nil {
				return nil, err
			}
			return marshalConfigurationDocument(public)
		})
	}
	if err != nil {
		configurationBackupFailure(w, err)
		return true
	}
	defer release()
	defer clear(out)
	w.Header().Set("Content-Disposition", `attachment; filename="configuration-`+parts[0]+`.`+format+`"`)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(200)
	_, _ = w.Write(out)
	// Only export preparation is audited. A successful Write cannot prove the
	// browser received or durably saved the package.
	return true
}
