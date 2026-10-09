package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"webscan/internal/common"
	"webscan/internal/deploy"
)

type packagePaths struct{ dir, state, command, profile string }

func systemPackagePaths() packagePaths {
	return packagePaths{"/root/webscan-deploy", deploy.StateRoot, "/usr/local/bin/webscan", "/etc/profile.d/webscan.sh"}
}

const shortcutMark = "# Managed by DZH Webscan: deployment menu entry v1"
const shortcutBody = "#!/bin/bash\n" + shortcutMark + "\nif [[ $EUID != 0 ]]; then echo '请使用 root 执行 webscan。' >&2; exit 1; fi\nif [[ ! -f /root/webscan-deploy/deploy-webscan.sh || -L /root/webscan-deploy/deploy-webscan.sh ]]; then echo '部署脚本缺失或路径不安全，请重新获取部署包。' >&2; exit 1; fi\nexec /bin/bash /root/webscan-deploy/deploy-webscan.sh \"$@\"\n"
const profileBody = shortcutMark + "\nexport WEBSCAN_DEPLOY_DIR=/root/webscan-deploy\ncase \":$PATH:\" in *:/usr/local/bin:*) ;; *) export PATH=\"/usr/local/bin:$PATH\" ;; esac\n"

func readPackageState(stateDir string) (common.Map, error) {
	m, e := common.ReadJSON(filepath.Join(stateDir, "state.json"))
	if os.IsNotExist(e) {
		return common.Map{}, nil
	}
	return m, e
}
func isInstalled(m common.Map) bool {
	return common.B(m["central_installed"]) || common.S(m["go_release"]) != ""
}
func hasPendingTask(m common.Map) bool {
	pending := common.M(m["single_uninstall"])
	return pendingDeployment(m) || common.B(m["central_uninstall_pending"]) || len(pending) > 0 && !common.B(pending["complete"])
}
func safeRegular(path string) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("路径 %s 必须为普通文件，不能是符号链接", path)
	}
	return nil
}
func safeDirectory(path string, perm os.FileMode) error {
	// Check each existing component before creating or chmodding a directory.
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e == nil && !st.IsDir() {
			return fmt.Errorf("目录路径 %s 不安全，拒绝使用符号链接或非目录", p)
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if e := os.MkdirAll(path, perm); e != nil {
		return e
	}
	return os.Chmod(path, perm)
}
func packageLock(dir, name string) (func(), error) {
	if e := safeDirectory(dir, 0700); e != nil {
		return nil, e
	}
	p := filepath.Join(dir, name)
	if e := safeRegular(p); e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("另一个下载、引导或部署任务正在运行，请等待完成后重试")
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func ownedRegular(path string) error {
	if e := safeRegular(path); e != nil {
		return e
	}
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	if owner, ok := st.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("文件 %s 的所有者不正确", path)
	}
	return nil
}
func shortcutConflict(p string) error {
	if e := safeRegular(p); os.IsNotExist(e) {
		return nil
	} else if e != nil {
		return e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	if !bytes.Contains(b, []byte(shortcutMark)) {
		return fmt.Errorf("已有非本项目管理的同名文件 %s，未覆盖；请执行 bash /root/webscan-deploy/deploy-webscan.sh", p)
	}
	return nil
}

// A local script remains usable when another application owns the command name.
func registerLocalShortcut(p packagePaths, out io.Writer) bool {
	if err := ensureShortcut(p, out); err != nil {
		fmt.Fprintf(out, "管理命令未注册：%s；本次继续使用完整部署脚本路径。\n", err)
		return false
	}
	return true
}
func ensureShortcut(p packagePaths, out io.Writer) error {
	for _, path := range []string{p.command, p.profile} {
		if e := shortcutConflict(path); e != nil {
			return e
		}
	}
	// Also refuse a different executable earlier in PATH.
	if p.command == "/usr/local/bin/webscan" {
		for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
			path := filepath.Join(dir, "webscan")
			if filepath.Clean(path) == p.command {
				break
			}
			if st, e := os.Stat(path); e == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
				return fmt.Errorf("PATH 中已有其他 webscan 命令 %s；未覆盖，请使用完整部署脚本路径", path)
			}
		}
	}
	for _, item := range []struct {
		path, body string
		mode       os.FileMode
	}{{p.command, shortcutBody, 0755}, {p.profile, profileBody, 0644}} {
		if b, e := os.ReadFile(item.path); e == nil && string(b) == item.body {
			if e = os.Chmod(item.path, item.mode); e != nil {
				return e
			}
			continue
		}
		if e := safeDirectory(filepath.Dir(item.path), 0755); e != nil {
			return e
		}
		if e := common.Atomic(item.path, []byte(item.body), item.mode); e != nil {
			return e
		}
	}
	fmt.Fprintln(out, "管理命令已就绪：在主服务器任意目录输入 webscan 即可打开菜单。")
	if p.command == "/usr/local/bin/webscan" && !strings.Contains(":"+os.Getenv("PATH")+":", ":/usr/local/bin:") {
		fmt.Fprintln(out, "当前终端请先执行 source /etc/profile.d/webscan.sh；重新登录会自动生效。")
	}
	return nil
}
func releaseVersion(script []byte) string {
	if len(script) > 2048 {
		script = script[:2048]
	}
	m := regexp.MustCompile(`(?m)^# Webscan (v\d+\.\d+\.\d+)\.`).FindSubmatch(script)
	if len(m) == 2 {
		return string(m[1])
	}
	return ""
}
func versionCompare(a, b string) int {
	parse := func(s string) []int {
		parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
		v := []int{0, 0, 0}
		for i := 0; i < len(parts) && i < 3; i++ {
			v[i], _ = strconv.Atoi(parts[i])
		}
		return v
	}
	x, y := parse(a), parse(b)
	for i := range x {
		if x[i] < y[i] {
			return -1
		}
		if x[i] > y[i] {
			return 1
		}
	}
	return 0
}
func readManifest(path string) (map[string]string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) > 4096 {
		return nil, errors.New("发布清单过大")
	}
	m := map[string]string{}
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), "=")
		if !ok || m[k] != "" {
			return nil, errors.New("发布清单格式不正确")
		}
		m[k] = v
	}
	if e = s.Err(); e != nil {
		return nil, e
	}
	if !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(m["release"]) || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(m["source_commit"]) {
		return nil, errors.New("发布版本或源码提交无效")
	}
	for _, k := range []string{"script_sha256", "example_sha256"} {
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(m[k]) {
			return nil, errors.New("发布清单缺少合法的 SHA256")
		}
	}
	return m, nil
}
func backupPackage(p packagePaths, name string, b []byte) error {
	dir := filepath.Join(p.state, "package-backups")
	if e := safeDirectory(dir, 0700); e != nil {
		return e
	}
	return common.Atomic(filepath.Join(dir, common.ID()+"-"+name), b, 0600)
}
func preparePackage(stage string, p packagePaths, out io.Writer) error {
	unlock, e := packageLock(p.state, "bootstrap.lock")
	if e != nil {
		return e
	}
	defer unlock()
	unlockDeploy, e := packageLock(p.state, "deploy.lock")
	if e != nil {
		return e
	}
	defer unlockDeploy()
	state, e := readPackageState(p.state)
	if e != nil {
		return e
	}
	config, script := filepath.Join(p.dir, "webscan.yaml"), filepath.Join(p.dir, "deploy-webscan.sh")
	for _, path := range []string{config, script} {
		if e = ownedRegular(path); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	if hasPendingTask(state) {
		if e = safeRegular(config); e != nil {
			return errors.New("存在未完成任务但 YAML 丢失，请恢复原配置，不重新初始化")
		}
		if e = safeRegular(script); e != nil {
			return errors.New("存在未完成任务但原脚本丢失，请恢复原版本脚本")
		}
		fmt.Fprintln(out, "存在未完成部署或卸载：原脚本、配置和版本未修改。请在菜单按原范围恢复任务。")
		return ensureShortcut(p, out)
	}
	if isInstalled(state) {
		if e = safeRegular(config); e != nil {
			return errors.New("系统已安装但 webscan.yaml 丢失，请恢复原配置；未下载示例覆盖")
		}
		fmt.Fprintln(out, "系统已安装，本次进入部署管理；已有 YAML、账号和数据保留。")
	}
	m, e := readManifest(filepath.Join(stage, "install-manifest.txt"))
	if e != nil {
		return e
	}
	staged, e := os.ReadFile(filepath.Join(stage, "deploy-webscan.sh"))
	if e != nil {
		return e
	}
	var example []byte
	if _, missing := os.Lstat(config); os.IsNotExist(missing) {
		example, e = os.ReadFile(filepath.Join(stage, "webscan.example.yaml"))
		if e != nil {
			return e
		}
		if common.Hash(example) != m["example_sha256"] {
			return errors.New("示例配置校验失败，未初始化配置")
		}
	}
	if common.Hash(staged) != m["script_sha256"] || releaseVersion(staged) != m["release"] {
		return errors.New("部署脚本校验失败，未更新部署包")
	}
	for _, path := range []string{p.command, p.profile} {
		if e = shortcutConflict(path); e != nil {
			return e
		}
	}
	if e = safeDirectory(p.dir, 0700); e != nil {
		return e
	}
	if old, e := os.ReadFile(script); e == nil {
		version := releaseVersion(old)
		if version == "" {
			return errors.New("本地脚本版本无法识别，未覆盖，请先核实文件")
		}
		comparison := versionCompare(version, m["release"])
		if comparison == 0 && common.Hash(old) != m["script_sha256"] {
			return errors.New("本地同版本脚本与发布摘要不一致，未覆盖；请先核实文件或恢复原脚本")
		}
		if comparison < 0 {
			if e = backupPackage(p, "deploy-webscan.sh", old); e != nil {
				return e
			}
			if e = common.Atomic(script, staged, 0700); e != nil {
				return e
			}
			fmt.Fprintf(out, "部署脚本已更新到 %s；原脚本已备份。\n", m["release"])
		} else {
			fmt.Fprintf(out, "沿用本地部署脚本 %s；不重复下载覆盖或降级。\n", version)
		}
	} else if os.IsNotExist(e) {
		if e = common.Atomic(script, staged, 0700); e != nil {
			return e
		}
	} else {
		return e
	}
	if _, e = os.Lstat(config); os.IsNotExist(e) {
		marker := filepath.Join(p.dir, ".setup-pending.json")
		if e = safeRegular(marker); e != nil && !os.IsNotExist(e) {
			return e
		}
		// Write the marker first; interruption never leaves an unmarked template.
		if e = common.AtomicJSON(marker, common.Map{"template_sha256": common.Hash(example)}); e != nil {
			return e
		}
		if e = common.Atomic(config, example, 0600); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if e = os.Chmod(script, 0700); e != nil {
		return e
	}
	if e = os.Chmod(config, 0600); e != nil {
		return e
	}
	return ensureShortcut(p, out)
}
