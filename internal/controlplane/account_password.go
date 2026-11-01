package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

var (
	errOwnPasswordInput   = errors.New("密码参数不正确，新密码须为 12～72 字节且两次输入一致")
	errOwnPasswordCurrent = errors.New("当前密码不正确")
	errOwnPasswordSession = errors.New("账号或会话已变化，请重新登录")
	errOwnPasswordRate    = errors.New("修改密码尝试次数过多，请五分钟后重试")
)

type ownPasswordInput struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
	Confirm string `json:"confirm_password"`
}

func (ownPasswordInput) String() string   { return "[private password change]" }
func (ownPasswordInput) GoString() string { return "[private password change]" }

func decodeOwnPassword(w http.ResponseWriter, r *http.Request) (ownPasswordInput, error) {
	var in ownPasswordInput
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	defer clear(raw)
	if err != nil || !utf8.Valid(raw) || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return in, errOwnPasswordInput
	}
	check := json.NewDecoder(bytes.NewReader(raw))
	if uniqueBackupJSON(check, 0) != nil {
		return in, errOwnPasswordInput
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 {
		return in, errOwnPasswordInput
	}
	for _, name := range []string{"current_password", "new_password", "confirm_password"} {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return in, errOwnPasswordInput
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF ||
		len(in.Current) < 1 || len(in.Current) > 72 || len(in.New) < 12 || len(in.New) > 72 ||
		!utf8.ValidString(in.Current) || !utf8.ValidString(in.New) || in.New != in.Confirm {
		return ownPasswordInput{}, errOwnPasswordInput
	}
	return in, nil
}

// changeOwnPasswordTx revalidates the calling session after locking the account.
// A concurrent reset or password change cannot authorize this request with the
// old password even if HTTP authentication completed before that transaction.
func (s *Store) changeOwnPasswordTx(ctx context.Context, id identity, in ownPasswordInput) error {
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

	// Independent domains keep password-change limits separate from login and
	// backup crypto counters. Counts survive restarts and are shared by replicas.
	limited := false
	for _, counter := range []struct {
		key string
		max int
	}{{"account-password:global", 60}, {"account-password:user:" + id.Username, 10}} {
		var count int
		if err = tx.QueryRowContext(ctx, `INSERT INTO v3_login_attempts(key,count,expires_at) VALUES($1,1,clock_timestamp()+interval '5 minutes')
 ON CONFLICT(key) DO UPDATE SET count=CASE WHEN v3_login_attempts.expires_at<=clock_timestamp() THEN 1 ELSE LEAST(v3_login_attempts.count+1,1000000) END,
 expires_at=CASE WHEN v3_login_attempts.expires_at<=clock_timestamp() THEN EXCLUDED.expires_at ELSE v3_login_attempts.expires_at END RETURNING count`, counter.key).Scan(&count); err != nil {
			return err
		}
		limited = limited || count > counter.max
	}
	if limited {
		if err = tx.Commit(); err != nil {
			return err
		}
		return errOwnPasswordRate
	}
	var hash string
	var revision int64
	if err = tx.QueryRowContext(ctx, "SELECT password_hash,revision FROM v3_accounts WHERE username=$1 FOR UPDATE", id.Username).Scan(&hash, &revision); err == sql.ErrNoRows {
		return errOwnPasswordSession
	} else if err != nil {
		return err
	}
	var session bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v3_sessions WHERE token_hash=$1 AND username=$2 AND revision=$3 AND csrf=$4 AND expires_at>clock_timestamp())`, id.Hash, id.Username, revision, id.CSRF).Scan(&session); err != nil {
		return err
	}
	if !session {
		return errOwnPasswordSession
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Current)) != nil {
		if err = tx.Commit(); err != nil {
			return err
		}
		return errOwnPasswordCurrent
	}
	updated, err := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE v3_accounts SET password_hash=$2,revision=revision+1 WHERE username=$1", id.Username, string(updated)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM v3_sessions WHERE username=$1", id.Username); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'account-password-change',$1,'{"source":"web","sessions_revoked":true}')`, id.Username); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *API) changeOwnPassword(w http.ResponseWriter, r *http.Request, id identity) {
	if r.Method != http.MethodPost {
		failure(w, 405, "method_not_allowed", "请使用 POST")
		return
	}
	if !a.configurationSecureTransport(r) {
		failure(w, 403, "https_required", "修改密码需要可信 HTTPS 连接")
		return
	}
	in, err := decodeOwnPassword(w, r)
	if err != nil {
		failure(w, 400, "invalid_password", errOwnPasswordInput.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	err = a.Store.changeOwnPasswordTx(ctx, id, in)
	switch {
	case errors.Is(err, errOwnPasswordCurrent):
		// A bad current password is not a lost login session.
		failure(w, 400, "current_password_incorrect", errOwnPasswordCurrent.Error())
	case errors.Is(err, errOwnPasswordSession):
		failure(w, 401, "authentication_required", errOwnPasswordSession.Error())
	case errors.Is(err, errOwnPasswordRate):
		w.Header().Set("Retry-After", "300")
		failure(w, 429, "password_rate_limit", errOwnPasswordRate.Error())
	case errors.Is(err, ErrMigrationPending):
		failure(w, 503, "migration_pending", ErrMigrationPending.Error())
	case err != nil:
		failure(w, 503, "password_service_unavailable", "密码修改结果暂时无法确认，请稍后重新登录核对")
	default:
		http.SetCookie(w, &http.Cookie{Name: "webscan_v3_session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		reply(w, 200, map[string]bool{"ok": true, "reauthenticate": true})
	}
}
