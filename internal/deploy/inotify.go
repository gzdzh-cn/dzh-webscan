package deploy

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"webscan/internal/common"
	"webscan/internal/progress"
)

// Limits are per host UID and are shared with services outside our containers.
// Raising the ceiling does not allocate watches; existing higher limits stay.
const minimumInotifyWatches = 262144

func inotifyTuningScript(valuePath, configPath string) string {
	return `set -eu
umask 022
task_current=$(cat -- ` + Q(valuePath) + `)
case "$task_current" in ''|*[!0-9]*) exit 31;; esac
task_target=$task_current
if [ "$task_target" -lt ` + strconv.Itoa(minimumInotifyWatches) + ` ]; then task_target=` + strconv.Itoa(minimumInotifyWatches) + `; fi
task_config=` + Q(configPath) + `
test ! -L "$task_config"
task_tmp=$(mktemp "${task_config}.XXXXXXXX")
trap 'rm -f -- "$task_tmp"' EXIT
printf '# Webscan: shared host limit; watches are allocated only as needed.\nfs.inotify.max_user_watches = %s\n' "$task_target" > "$task_tmp"
chmod 644 "$task_tmp"
if ! cmp -s "$task_tmp" "$task_config"; then mv -f -- "$task_tmp" "$task_config"; fi
sysctl -p "$task_config"
task_effective=$(cat -- ` + Q(valuePath) + `)
test "$task_effective" -ge "$task_target"
printf '目录监听额度：原上限 %s，当前上限 %s；已持久保存\n' "$task_current" "$task_effective"
`
}

func (d *Deploy) prepareInotify(ctx context.Context, n common.Map) error {
	r, err := d.remote(ctx, n)
	if err != nil {
		return err
	}
	return progress.Stage(ctx, progress.Node(n), "检查并提高共享目录监听额度（保留更高的现有上限）", func(ctx context.Context) error {
		_, err := r.ExecVisible(ctx, "bash -se", strings.NewReader(inotifyTuningScript("/proc/sys/fs/inotify/max_user_watches", "/etc/sysctl.d/90-webscan-inotify.conf")), "监听额度")
		if err != nil {
			return errors.New("node_inotify_limit_setup_failed")
		}
		return nil
	})
}
