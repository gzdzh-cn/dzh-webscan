package controlplane

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func (s *Store) ResetPassword(ctx context.Context, username, password string) error {
	if !identifier.MatchString(username) || len(password) < 12 || len(password) > 72 {
		return errors.New("账号格式不正确或密码不在 12～72 字节范围")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
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
	result, err := tx.ExecContext(ctx, "UPDATE v3_accounts SET password_hash=$2,revision=revision+1 WHERE username=$1", username, string(hash))
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("账号不存在，未修改密码")
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM v3_sessions WHERE username=$1", username); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO v3_audit(username,kind,resource,result) VALUES($1,'reset-password',$1,'{\"source\":\"local-cli\",\"sessions_revoked\":true}')", username); err != nil {
		return err
	}
	return tx.Commit()
}
