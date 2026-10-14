package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
	"webscan/internal/common"
)

func Send(ctx context.Context, c common.Map, recipient, messageID, subject, body string) error {
	return sendTLS(ctx, c, recipient, messageID, subject, body, &tls.Config{ServerName: common.S(c["smtp_host"]), MinVersion: tls.VersionTLS12})
}
func sendTLS(ctx context.Context, c common.Map, recipient, messageID, subject, body string, tlsConfig *tls.Config) error {
	if e := Validate(c); e != nil {
		return e
	}
	host := common.S(c["smtp_host"])
	timeout := time.Duration(common.I(c["timeout_seconds"])) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &net.Dialer{}
	address := net.JoinHostPort(host, strconv.Itoa(common.I(c["smtp_port"])))
	var conn net.Conn
	var e error

	if common.S(c["tls_mode"]) == "tls" {
		conn, e = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", address)
	} else {
		conn, e = dialer.DialContext(ctx, "tcp", address)
	}
	if e != nil {
		return fmt.Errorf("无法连接 SMTP 服务器或 TLS 校验失败")
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	client, e := smtp.NewClient(conn, host)
	if e != nil {
		return fmt.Errorf("SMTP 握手失败")
	}
	defer client.Close()
	if common.S(c["tls_mode"]) == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("SMTP 服务器不支持 STARTTLS，未发送账号信息")
		}
		if e = client.StartTLS(tlsConfig); e != nil {
			return fmt.Errorf("SMTP STARTTLS 证书校验失败")
		}
	}
	if e = client.Auth(smtp.PlainAuth("", common.S(c["username"]), common.S(c["password"]), host)); e != nil {
		return fmt.Errorf("SMTP 身份验证失败，请检查账号和授权码")
	}
	if e = client.Mail(common.S(c["from_address"])); e != nil {
		return fmt.Errorf("SMTP 拒绝发件邮箱")
	}
	if e = client.Rcpt(recipient); e != nil {
		return fmt.Errorf("SMTP 拒绝收件邮箱")
	}
	w, e := client.Data()
	if e != nil {
		return fmt.Errorf("SMTP 不接受邮件内容")
	}
	from := (&mail.Address{Name: common.S(c["from_name"]), Address: common.S(c["from_address"])}).String()
	subject = strings.ReplaceAll(strings.ReplaceAll(subject, "\r", " "), "\n", " ")
	content := "From: " + from + "\r\nTo: " + recipient + "\r\nSubject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\nMessage-ID: <" + messageID + "@webscan.local>\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n") + "\r\n"
	if _, e = w.Write([]byte(content)); e != nil {
		return fmt.Errorf("SMTP 内容传输中断")
	}
	if e = w.Close(); e != nil {
		return fmt.Errorf("SMTP 未确认接受邮件")
	}
	return nil
}
