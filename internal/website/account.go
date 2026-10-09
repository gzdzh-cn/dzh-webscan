package website

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"webscan/internal/common"
	"webscan/internal/persist"
)

const accountSchema = `CREATE TABLE IF NOT EXISTS website_admin(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT NOT NULL,password_hash TEXT NOT NULL,revision INTEGER NOT NULL,modified INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS website_backups(id TEXT PRIMARY KEY,created INTEGER NOT NULL,source TEXT NOT NULL,count INTEGER NOT NULL,digest TEXT NOT NULL,restored INTEGER NOT NULL DEFAULT 0,result TEXT NOT NULL DEFAULT '');`

type Account struct {
	Username string
	Hash     string
	Revision int64
	Modified int64
}

func ReadAccount(db *sql.DB) (Account, error) {
	var a Account
	e := db.QueryRow("SELECT username,password_hash,revision,modified FROM website_admin WHERE id=1").Scan(&a.Username, &a.Hash, &a.Revision, &a.Modified)
	return a, e
}

// Read-only discovery never creates or rewrites a deployment database.
func AccountAt(path string) (Account, error) {
	if _, e := os.Stat(path); e != nil {
		return Account{}, e
	}
	db, e := persist.OpenReadOnly(path)
	if e != nil {
		return Account{}, e
	}
	defer db.Close()
	var exists int
	if e = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='website_admin'").Scan(&exists); e != nil {
		return Account{}, e
	}
	if exists == 0 {
		return Account{}, sql.ErrNoRows
	}
	return ReadAccount(db)
}
func (m *Monitor) migrate() error {
	var exists int
	if e := m.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='website_admin'").Scan(&exists); e != nil {
		return e
	}
	if exists == 0 {
		var sites int
		if e := m.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='websites'").Scan(&sites); e != nil {
			return e
		}
		if sites > 0 {
			dir := common.S(m.Config["backup_dir"])
			if dir == "" {
				var seq int
				var name, path string
				if e := m.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); e != nil {
					return e
				}
				dir = filepath.Join(filepath.Dir(path), "backups")
			}
			if e := persist.BackupDB(m.DB, filepath.Join(dir, "website-migrations", "before-v2.0.29-"+common.ID()+".sqlite3")); e != nil {
				return fmt.Errorf("网站后台升级前数据库备份失败，已停止迁移，请检查备份目录权限和磁盘空间: %w", e)
			}
		}
	}
	tx, e := m.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(schema + accountSchema); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT OR IGNORE INTO website_admin(id,username,password_hash,revision,modified) VALUES(1,?,?,1,?)", m.Username, m.PasswordHash, time.Now().Unix()); e != nil {
		return e
	}
	return tx.Commit()
}
func validPassword(password string) error {
	if len(password) < 12 || len(password) > 72 {
		return errors.New("新密码必须为 12～72 字节，中文字符通常占 3 字节")
	}
	return nil
}

// ResetPassword is used only by the administrator's terminal command. A
// revision increment invalidates sessions in the running service as well.
func ResetPassword(db *sql.DB, password string) error {
	if e := validPassword(password); e != nil {
		return e
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if e != nil {
		return e
	}
	v, e := db.Exec("UPDATE website_admin SET password_hash=?,revision=revision+1,modified=? WHERE id=1", string(hash), time.Now().Unix())
	if e != nil {
		return e
	}
	n, e := v.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errors.New("后台账号尚未初始化，请先启动主服务器后台")
	}
	return nil
}
func (m *Monitor) changePassword(w http.ResponseWriter, r *http.Request, revision int64) {
	if r.Method != "POST" {
		apiError(w, 405, "method_not_allowed", "请使用修改密码表单", "")
		return
	}
	var input struct {
		Current  string `json:"current_password"`
		Password string `json:"new_password"`
		Confirm  string `json:"confirm_password"`
	}
	if !decode(w, r, &input) {
		return
	}
	if e := validPassword(input.Password); e != nil {
		apiError(w, 400, "invalid_password", e.Error(), "new_password")
		return
	}
	if input.Password != input.Confirm {
		apiError(w, 400, "password_mismatch", "确认密码与新密码不一致", "confirm_password")
		return
	}
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	key := "password-change"
	a := m.attempts[key]
	if now.After(a.Until) {
		a = attempt{}
	}
	if a.Count >= 5 {
		apiError(w, 429, "password_rate_limited", "当前密码验证失败过多，请 5 分钟后重试", "")
		return
	}
	account, e := ReadAccount(m.DB)
	if e != nil {
		m.dbError(w, e)
		return
	}
	if account.Revision != revision {
		apiError(w, 401, "session_expired", "账号已修改，请重新登录", "")
		return
	}
	if len(input.Current) > 72 || bcrypt.CompareHashAndPassword([]byte(account.Hash), []byte(input.Current)) != nil {
		a.Count++
		a.Until = now.Add(5 * time.Minute)
		m.attempts[key] = a
		apiError(w, 400, "current_password_invalid", "当前密码不正确", "current_password")
		return
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if e != nil {
		m.dbError(w, e)
		return
	}
	v, e := m.DB.Exec("UPDATE website_admin SET password_hash=?,revision=revision+1,modified=? WHERE id=1 AND revision=?", string(hash), time.Now().Unix(), revision)
	if e != nil {
		m.dbError(w, e)
		return
	}
	n, e := v.RowsAffected()
	if e != nil {
		m.dbError(w, e)
		return
	}
	if n != 1 {
		apiError(w, 401, "session_expired", "账号已修改，请重新登录", "")
		return
	}
	m.sessions = map[string]session{}
	delete(m.attempts, key)
	http.SetCookie(w, &http.Cookie{Name: "webscan_session", Path: "/", MaxAge: -1, Secure: m.secureCookie(r), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	respond(w, 200, common.Map{"message": "密码已修改，所有登录已退出，请使用新密码登录"})
}
func (m *Monitor) Verify(ctx context.Context) error {
	a, e := ReadAccount(m.DB)
	if e != nil {
		return e
	}
	if _, e = bcrypt.Cost([]byte(a.Hash)); e != nil {
		return e
	}
	if a.Username == "" {
		return errors.New("后台管理员账号为空")
	}
	_, e = m.sites(ctx)
	return e
}
