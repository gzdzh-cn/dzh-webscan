package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"webscan/internal/common"
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
	if err := j.Rollback(); err != nil {
		return err
	}
	if previous && !uninstall {
		if _, err := d.compose(ctx, "up", "-d", "--no-deps", "receiver"); err != nil {
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
