package website

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

type Result struct {
	Time           int64   `json:"time"`
	OK             bool    `json:"ok"`
	Latency        float64 `json:"latency"`
	HTTP           int     `json:"http_status"`
	CertExpires    int64   `json:"cert_expires"`
	CertHost       string  `json:"cert_host"`
	CertChecked    int64   `json:"cert_checked"`
	CertApplicable bool    `json:"cert_applicable"`
	CertError      string  `json:"cert_error"`
	CertObserved   bool    `json:"-"`
	Reason         string  `json:"reason"`
}

func publicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Shared address space, documentation/reserved networks and metadata ranges.
	for _, block := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/32", "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48"} {
		_, n, _ := net.ParseCIDR(block)
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
func normalizeURL(raw string) (string, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e == nil {
		u.Scheme = strings.ToLower(u.Scheme)
	}
	if e != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || len(raw) > 2048 {
		return "", errors.New("请填写完整的公网 HTTP 或 HTTPS 首页地址，不能包含账号密码")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !publicIP(ip) {
		return "", errors.New("网站地址不能指向本机、内网或保留地址")
	}
	host, e := idna.Lookup.ToASCII(strings.ToLower(u.Hostname()))
	if e != nil {
		return "", errors.New("域名格式不正确")
	}
	port := u.Port()
	if port != "" {
		number, e := strconv.Atoi(port)
		if e != nil || number < 1 || number > 65535 {
			return "", errors.New("网站端口应为 1～65535")
		}
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	u.Host = host
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

type prober struct {
	lookup func(context.Context, string) ([]net.IPAddr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	tls    *tls.Config
}

func newProber() *prober {
	return &prober{lookup: net.DefaultResolver.LookupIPAddr, dial: (&net.Dialer{}).DialContext}
}
func (p *prober) check(ctx context.Context, site Site, timeout time.Duration) (r Result) {
	start := time.Now()
	r.Time = start.Unix()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() { r.Latency = time.Since(start).Seconds() }()
	raw, e := normalizeURL(site.URL)
	if e != nil {
		r.Reason = e.Error()
		return
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 32768, TLSClientConfig: p.tls}
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := p.lookup(ctx, host)
		if e != nil {
			return nil, fmt.Errorf("DNS 解析失败: %w", e)
		}
		if len(ips) == 0 {
			return nil, errors.New("DNS 没有返回地址")
		}
		for _, ip := range ips {
			if !publicIP(ip.IP) {
				return nil, errors.New("安全限制：域名解析到内网或保留地址")
			}
		}
		var conn net.Conn
		for _, ip := range ips {
			conn, e = p.dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if e == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, e
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: certificateTransport{tr: tr, result: &r}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("跳转超过 5 次")
		}
		_, e := normalizeURL(req.URL.String())
		return e
	}}
	req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
	req.Header.Set("User-Agent", "Dzh-Webscan/website-monitor")
	response, e := client.Do(req)
	if e != nil {
		r.Reason = probeError(ctx, e)
		return
	}
	defer response.Body.Close()
	r.HTTP = response.StatusCode
	if response.StatusCode != 200 {
		r.Reason = fmt.Sprintf("首页返回 HTTP %d，预期为 200", response.StatusCode)
		return
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
	if e != nil {
		r.Reason = probeError(ctx, e)
		return
	}
	if len(body) > 256*1024 {
		body = body[:256*1024]
	}
	if site.Keyword != "" {
		text := string(body)
		ct := strings.ToLower(response.Header.Get("Content-Type"))
		// Most GBK pages declare their encoding in either header or HTML meta.
		if strings.Contains(ct, "gbk") || strings.Contains(ct, "gb2312") || gbkCharset.MatchString(text[:min(len(text), 4096)]) {
			decoded, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), body)
			if err == nil {
				text = string(decoded)
			}
		}
		if !strings.Contains(text, site.Keyword) {
			r.Reason = "首页未找到设置的关键词（仅检查前 256 KiB）"
			return
		}
	}
	r.OK = true
	return
}

// Capture the first HTTPS hop, including verification failures. The transport
// still performs standard hostname/chain/time verification and DNS-pinned IO.
type certificateTransport struct {
	tr     http.RoundTripper
	result *Result
}

func (t certificateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target := req.URL.Scheme == "https" && !t.result.CertApplicable
	if target {
		t.result.CertApplicable = true
		t.result.CertHost = req.URL.Hostname()
	}
	resp, e := t.tr.RoundTrip(req)
	if target {
		if resp != nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			t.result.CertObserved = true
			t.result.CertExpires = resp.TLS.PeerCertificates[0].NotAfter.Unix()
			t.result.CertChecked = time.Now().Unix()
		}
		if e != nil {
			t.result.CertError = probeError(req.Context(), e)
			var verification *tls.CertificateVerificationError
			if errors.As(e, &verification) && len(verification.UnverifiedCertificates) > 0 {
				t.result.CertObserved = true
				t.result.CertExpires = verification.UnverifiedCertificates[0].NotAfter.Unix()
				t.result.CertChecked = time.Now().Unix()
			}
		}
	}
	return resp, e
}

var gbkCharset = regexp.MustCompile(`(?i)charset\s*=\s*["']?gb(?:k|2312)`)

func probeError(ctx context.Context, e error) string {
	if ctx.Err() != nil {
		return "网站检查超时，DNS、连接、HTTPS 和读取首页均计入超时"
	}
	var cert *tls.CertificateVerificationError
	if errors.As(e, &cert) {
		return "HTTPS 证书校验失败，请检查证书有效期、域名和证书链"
	}
	text := e.Error()
	for _, pair := range [][2]string{{"connection refused", "网站拒绝连接"}, {"no such host", "DNS 解析失败"}, {"DNS 解析失败", "DNS 解析失败，请检查域名是否有效及 DNS 服务"}, {"network is unreachable", "网络无法到达"}, {"跳转超过", "网站跳转超过 5 次"}, {"安全限制", "安全限制：域名解析到内网或保留地址"}, {"不能指向", "安全限制：跳转到内网或保留地址"}} {
		if strings.Contains(text, pair[0]) {
			return pair[1]
		}
	}
	return "网站连接或读取首页失败"
}
