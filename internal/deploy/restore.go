package deploy

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"webscan/internal/common"
	"webscan/internal/website"
)

// Stop the writer before restoring configuration. Never replace current SQLite
// with the historical backup: new events and unfinished tasks must survive.
func (d *Deploy) restoreCentral(ctx context.Context, j *Journal, uninstall bool) error {
	composePath := filepath.Join(d.C.CentralRoot(), "compose.yml")
	saved, remembered := j.Index[composePath]
	previous := remembered && common.M(saved)["backup"] != nil
	if _, err := os.Stat(composePath); err == nil {
		args := []string{"stop"}
		if previous {
			args = append(args, "receiver")
		}
		if _, err = d.compose(ctx, args...); err != nil {
			return errors.New("central_stop_before_restore_failed")
		}
	}
	// Read after stopping the writer, before restoring historical runtime.
	account, accountErr := website.Account{}, sql.ErrNoRows
	if previous && !uninstall {
		account, accountErr = website.AccountAt(filepath.Join(common.S(common.M(d.C.Raw["central"])["data_dir"]), "events-v1.sqlite3"))
	}
	if accountErr != nil && !errors.Is(accountErr, os.ErrNotExist) && !errors.Is(accountErr, sql.ErrNoRows) {
		return errors.New("回退前读取当前后台账号失败，已停止回退")
	}
	if err := j.Rollback(); err != nil {
		return err
	}
	if previous && !uninstall && accountErr == nil {
		if err := preserveWebsiteAccount(filepath.Join(d.C.CentralRoot(), "runtime.json"), account); err != nil {
			return err
		}
	}
	if previous && !uninstall {
		args := []string{"up", "-d", "--no-deps", "receiver"}
		for _, name := range common.SS(d.State["central_image_services"]) {
			args = append(args, name)
		}
		if _, err := d.compose(ctx, args...); err != nil {
			return errors.New("central_previous_service_start_failed")
		}
	}
	return nil
}
func (d *Deploy) centralRuntime(active []string) common.Map {
	runtime := CentralRuntime(d.C, d.Secrets, active)
	if url := common.S(d.State["external_loki_url"]); url != "" {
		runtime["loki_url"] = url
	}
	return runtime
}

func preserveWebsiteAccount(path string, account website.Account) error {
	runtime, e := common.ReadJSON(path)
	if e != nil {
		return e
	}
	wm := common.M(runtime["website_monitor"])
	if len(wm) > 0 {
		wm["admin_username"] = account.Username
		wm["password_hash"] = account.Hash
		runtime["website_monitor"] = wm
		return common.AtomicJSON(path, runtime)
	}
	return nil
}
