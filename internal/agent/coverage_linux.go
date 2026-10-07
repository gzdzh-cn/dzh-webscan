//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
)

type watchFailure struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (a *Agent) recordWatchFailure(path string, err error) {
	issue := &watchFailure{path, "watch_failed", "无法建立目录监听，请检查目录和挂载"}
	switch {
	case errors.Is(err, unix.ENOSPC):
		issue.Code, issue.Message = "inotify_watch_limit", "共享目录监听额度不足（fs.inotify.max_user_watches），需提高宿主机上限"
	case errors.Is(err, os.ErrPermission):
		issue.Code, issue.Message = "watch_permission_denied", "没有权限读取或监听目录"
	case errors.Is(err, os.ErrNotExist):
		issue.Code, issue.Message = "watch_directory_missing", "监控目录不存在，请检查路径和容器挂载"
	}
	previous := a.watchFailure.Swap(issue)
	a.counter("watch_errors_total", 1, false)
	// One code transition is enough; thousands of failed directories should
	// not flood stdout. The status carries the latest representative path.
	if previous == nil || previous.Code != issue.Code {
		fmt.Println("目录监听失败：" + issue.Message + "；目录：" + issue.Path)
	}
}

func (a *Agent) refreshCoverage(ctx context.Context) error {
	ok := true
	for _, root := range a.roots(a.rules.Load().Policy) {
		ok = a.addTree(ctx, root, a.rules.Load().Policy) && ok
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ok {
		a.coverage.Store(1)
		a.watchFailure.Store(nil)
	} else {
		a.coverage.Store(0)
	}
	if err := a.counter("coverage_ok", float64(a.coverage.Load()), true); err != nil {
		return err
	}
	if err := a.Metrics(ctx); err != nil {
		return err
	}
	// Refresh a successful applied status after recovery, but preserve failed
	// rule reloads, in-progress changes and another process's retained status.
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	status, err := common.ReadJSON(filepath.Join(a.Data, "rules-status.json"))
	if err != nil {
		return err
	}
	if common.S(status["state"]) != "applied" || common.S(status["instance_id"]) != a.Instance || common.S(status["version"]) != a.rules.Load().Version {
		return nil
	}
	return a.writeStatus("applied", nil)
}
