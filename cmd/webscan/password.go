package main

import (
	"errors"
	"fmt"
	"golang.org/x/term"
	"os"
	"path/filepath"
	"webscan/internal/common"
	"webscan/internal/persist"
	"webscan/internal/website"
)

func resetWebsitePassword(config string) error {
	if os.Geteuid() != 0 {
		return errors.New("仅 root 管理员可使用此密码重置命令")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return errors.New("请在交互终端执行，容器中请使用 docker exec -it；不接受管道、命令参数或日志传入密码")
	}
	runtime, e := common.ReadJSON(config)
	if e != nil {
		return errors.New("无法读取运行配置，请指定 runtime.json 的实际路径")
	}
	path := filepath.Join(common.S(runtime["data_dir"]), "events-v1.sqlite3")
	if _, e = os.Stat(path); e != nil {
		return errors.New("后台数据库不存在，请检查运行配置和数据卷")
	}
	db, e := persist.OpenDB(path)
	if e != nil {
		return e
	}
	defer db.Close()
	if _, e = website.ReadAccount(db); e != nil {
		return errors.New("持久化后台账号尚未初始化，请先启动新版主服务器")
	}
	fmt.Fprint(os.Stderr, "请输入新密码（12～72 字节，不回显）：")
	password, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return errors.New("读取密码中断，未修改账号")
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()
	fmt.Fprint(os.Stderr, "请再次输入新密码：")
	confirmation, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return errors.New("读取确认密码中断，未修改账号")
	}
	defer func() {
		for i := range confirmation {
			confirmation[i] = 0
		}
	}()
	if string(password) != string(confirmation) {
		return errors.New("两次密码不一致，未修改账号")
	}
	if e = website.ResetPassword(db, string(password)); e != nil {
		return e
	}
	fmt.Println("密码已重置，所有旧会话已失效；请使用新密码登录。")
	return nil
}
