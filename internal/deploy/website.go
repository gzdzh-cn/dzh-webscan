package deploy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"webscan/internal/common"
	"webscan/internal/progress"
	"webscan/internal/website"
)

func WebsiteURL(c *Config) string {
	u, _ := url.Parse(common.S(common.M(c.Raw["central"])["public_url"]))
	scheme := "https"
	if !c.SSLEnabled() {
		scheme = "http"
	}
	return scheme + "://" + u.Hostname() + ":" + strconv.Itoa(common.I(common.M(common.M(c.Raw["central"])["website_monitor"])["host_port"]))
}
func websiteCredentials(c *Config, secrets common.Map) error {
	wm := common.M(common.M(c.Raw["central"])["website_monitor"])
	if !common.B(wm["enabled"]) {
		return nil
	}
	account, e := website.AccountAt(filepath.Join(common.S(common.M(c.Raw["central"])["data_dir"]), "events-v1.sqlite3"))
	if e == nil {
		secrets["website_username"] = account.Username
		secrets["website_password_hash"] = account.Hash
		secrets["website_account_persisted"] = true
		delete(secrets, "website_password")
		return nil
	}
	if !errors.Is(e, os.ErrNotExist) && !errors.Is(e, sql.ErrNoRows) {
		return fmt.Errorf("读取已有后台账号失败，已停止更新凭据: %w", e)
	}
	// On the first v29 upgrade the table does not exist yet. Seed it from
	// the currently deployed runtime, never from newly edited YAML credentials.
	runtime, runtimeErr := common.ReadJSON(filepath.Join(c.CentralRoot(), "runtime.json"))
	if runtimeErr == nil {
		previous := common.M(runtime["website_monitor"])
		hash := common.S(previous["password_hash"])
		if hash != "" {
			if _, e = bcrypt.Cost([]byte(hash)); e != nil {
				return fmt.Errorf("当前后台密码哈希无效，已停止更新凭据")
			}
			username := common.S(previous["admin_username"])
			if username == "" {
				return fmt.Errorf("当前后台管理员账号为空，已停止更新凭据")
			}
			secrets["website_username"] = username
			secrets["website_password_hash"] = hash
			password := common.S(secrets["website_password"])
			if password == "" || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
				delete(secrets, "website_password")
			}
			return nil
		}
	} else if !errors.Is(runtimeErr, os.ErrNotExist) {
		return fmt.Errorf("无法读取已有后台运行配置，已停止更新凭据: %w", runtimeErr)
	}
	return websiteSeedCredentials(c, secrets)
}

func websiteSeedCredentials(c *Config, secrets common.Map) error {
	wm := common.M(common.M(c.Raw["central"])["website_monitor"])
	if !common.B(wm["enabled"]) {
		return nil
	}
	password := common.S(wm["admin_password"])
	if password == "" {
		password = common.S(secrets["website_password"])
	}
	if password == "" {
		password = common.ID() + common.ID()[:8]
	}
	if common.S(secrets["website_password"]) != password || common.S(secrets["website_password_hash"]) == "" {
		hash, e := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if e != nil {
			return e
		}
		secrets["website_password_hash"] = string(hash)
	}
	secrets["website_password"] = password
	secrets["website_username"] = wm["admin_username"]
	return nil
}
func websiteRuntime(c *Config, secrets common.Map) common.Map {
	wm := common.Clone(common.M(common.M(c.Raw["central"])["website_monitor"]))
	delete(wm, "admin_password")
	wm["password_hash"] = secrets["website_password_hash"]
	wm["admin_username"] = secrets["website_username"]
	wm["console_url"] = WebsiteURL(c)
	wm["ssl_enabled"] = c.SSLEnabled()
	return wm
}
func (d *Deploy) showWebsite() {
	if d.O.AddNode || !common.B(common.M(common.M(d.C.Raw["central"])["website_monitor"])["enabled"]) {
		return
	}
	fmt.Printf("网站监控后台：%s\n管理员：%s\n", WebsiteURL(d.C), common.S(d.Secrets["website_username"]))
	password := common.S(d.Secrets["website_password"])
	account, e := website.AccountAt(filepath.Join(common.S(common.M(d.C.Raw["central"])["data_dir"]), "events-v1.sqlite3"))
	if e == nil && password != "" && bcrypt.CompareHashAndPassword([]byte(account.Hash), []byte(password)) == nil {
		fmt.Printf("初始密码：%s\n凭据文件：%s/credentials.json（仅 root 可读）\n", password, StateRoot)
	} else {
		fmt.Println("后台沿用数据库中保存的账号密码；忘记密码请使用管理员终端重置命令。")
	}
}
func websiteMemory(c *Config) int {
	wm := common.M(common.M(c.Raw["central"])["website_monitor"])
	if common.B(wm["enabled"]) {
		return common.I(wm["extra_memory_mib"])
	}
	return 0
}

// Verify the selected HTTP/HTTPS listener and generated credentials before
// declaring the central upgrade complete; HTTPS validates the public IP.
func (d *Deploy) verifyWebsite(ctx context.Context) error {
	wm := common.M(common.M(d.C.Raw["central"])["website_monitor"])
	if d.addingNode() || !common.B(wm["enabled"]) {
		return nil
	}
	ca := ""
	if d.C.SSLEnabled() {
		ca = filepath.Join(d.C.CentralRoot(), "pki", "ca.crt")
	}
	client, e := common.HTTPClient(ca, 5*time.Second)
	if e != nil {
		return &progress.Failure{Code: "website_certificate_unreadable", Message: "网站后台证书无法读取，请检查主服务器 pki/ca.crt"}
	}

	bind := common.S(wm["bind_address"])
	if bind == "0.0.0.0" {
		bind = "127.0.0.1"
	}
	if bind == "::" {
		bind = "::1"
	}
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(bind, strconv.Itoa(common.I(wm["host_port"]))))
	}

	// Console serving/transport is checked without a public plaintext login.
	req, e := http.NewRequestWithContext(ctx, "GET", WebsiteURL(d.C)+"/", nil)
	if e != nil {
		return e
	}
	resp, e := client.Do(req)
	if e != nil {
		return &progress.Failure{Code: "website_console_verification_failed", Message: "网站后台连接验收失败，请检查后台端口和证书；数据与账号保持不变"}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1048576))
	if resp.StatusCode != 200 {
		return &progress.Failure{Code: "website_console_verification_failed", Message: "网站后台页面未正常响应，请检查主服务器日志"}
	}
	port := common.I(common.M(common.M(d.C.Raw["central"])["event_service"])["port"])
	code, data, e := common.Request(ctx, d.HTTP, "POST", "http://127.0.0.1:"+strconv.Itoa(port)+"/website-verify", common.Map{}, map[string]string{"Authorization": "Bearer " + common.S(d.Secrets["alert_token"])})
	if e != nil || code != 200 || !common.B(common.M(data)["ready"]) {
		return &progress.Failure{Code: "website_console_verification_failed", Message: "后台内部账号和数据库验收失败，请检查主服务器日志；验收不使用旧明文密码"}
	}
	return nil
}
