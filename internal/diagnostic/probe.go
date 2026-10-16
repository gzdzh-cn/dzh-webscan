// Package diagnostic contains the bounded, non-business network probe used over SSH.
package diagnostic

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Probe struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Token         string `json:"token"`
	CA            string `json:"ca,omitempty"`
	Cert          string `json:"cert,omitempty"`
	Key           string `json:"key,omitempty"`
	ClientCert    string `json:"client_cert,omitempty"`
	ClientKey     string `json:"client_key,omitempty"`
	AllowedSource string `json:"allowed_source,omitempty"`
	EventURL      string `json:"event_url,omitempty"`
	EventCA       string `json:"event_ca,omitempty"`
	EventToken    string `json:"event_token,omitempty"`
	Listen        bool   `json:"listen"`
}
type Result struct {
	Ready       bool   `json:"ready"`
	Occupied    bool   `json:"occupied,omitempty"`
	EventStatus int    `json:"event_status"`
	EventError  string `json:"event_error,omitempty"`
	Source      string `json:"source,omitempty"`
}

// NewTLS creates throwaway credentials. The long-lived installation CA/private
// key is never copied to the diagnostic process.
func NewTLS(host string) (Probe, error) {
	p := Probe{Host: host}
	now := time.Now()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return p, e
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "webscan temporary diagnostic"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(5 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		return p, e
	}
	p.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	issue := func(client bool) (string, string, error) {
		pub, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return "", "", e
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		c := &x509.Certificate{SerialNumber: serial, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(host)}}
		if client {
			c.IPAddresses = nil
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		b, e := x509.CreateCertificate(rand.Reader, c, ca, pub, key)
		if e != nil {
			return "", "", e
		}
		kb, e := x509.MarshalPKCS8PrivateKey(k)
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})), e
	}
	p.Cert, p.Key, e = issue(false)
	if e != nil {
		return p, e
	}
	p.ClientCert, p.ClientKey, e = issue(true)
	return p, e
}
func Client(ca, cert, key string) (*http.Client, error) {
	t := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	if ca != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(ca)) {
			return nil, errors.New("检测证书无效")
		}
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
		if cert != "" {
			pair, e := tls.X509KeyPair([]byte(cert), []byte(key))
			if e != nil {
				return nil, errors.New("检测客户端证书无效")
			}
			t.TLSClientConfig.Certificates = []tls.Certificate{pair}
		}
	}
	return &http.Client{Transport: t, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("检测接口不允许跳转") }}, nil
}
func Failure(err error) string {
	if err == nil {
		return ""
	}
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.As(err, &dns):
		return "域名解析失败，请检查 DNS 和事件地址"
	case errors.As(err, &cert):
		return "TLS 证书或主机名验证失败，请检查证书和系统时间"
	case errors.As(err, &ne) && ne.Timeout():
		return "连接超时，请检查路由、云安全组及系统防火墙"
	default:
		return "连接或 TLS 握手失败，请检查监听地址、端口及证书"
	}
}

// Run reads one JSON line and keeps stdin open as the SSH lifetime signal.
// TTL is enforced even if the SSH peer disappears without delivering EOF.
func Run(parent context.Context, input io.Reader, output io.Writer) error {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	reader := bufio.NewReader(io.LimitReader(input, 128<<10))
	line, e := reader.ReadBytes('\n')
	if e != nil {
		return errors.New("检测参数不完整")
	}
	var p Probe
	if json.Unmarshal(line, &p) != nil || len(p.Token) < 32 || net.ParseIP(p.Host) == nil || p.Port < 1 || p.Port > 65535 {
		return errors.New("检测参数无效")
	}
	go func() { io.Copy(io.Discard, reader); cancel() }()
	result := Result{}
	if p.EventURL != "" {
		u, e := url.Parse(p.EventURL)
		if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("事件地址无效")
		}
		client, e := Client(p.EventCA, "", "")
		if e != nil {
			return e
		}
		defer client.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(p.EventURL, "/")+"/webscan/v1/receipts", strings.NewReader(`{"event_ids":[]}`))
		req.Header.Set("Content-Type", "application/json")
		if p.EventToken != "" {
			req.Header.Set("Authorization", "Bearer "+p.EventToken)
		}
		resp, e := client.Do(req)
		if e != nil {
			result.EventError = Failure(e)
		} else {
			result.EventStatus = resp.StatusCode
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
		}
	}
	if !p.Listen {
		result.Ready = true
		return json.NewEncoder(output).Encode(result)
	}
	listener, e := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(p.Port)))
	if e != nil {
		result.Occupied = true
		return json.NewEncoder(output).Encode(result)
	}
	defer listener.Close()
	if p.CA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(p.CA)) {
			return errors.New("检测 CA 无效")
		}
		pair, e := tls.X509KeyPair([]byte(p.Cert), []byte(p.Key))
		if e != nil {
			return e
		}
		listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert})
	}
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/__webscan_preflight" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+p.Token)) != 1 {
			http.NotFound(w, r)
			return
		}
		source, _, _ := net.SplitHostPort(r.RemoteAddr)
		if p.AllowedSource != "" && !net.ParseIP(source).Equal(net.ParseIP(p.AllowedSource)) {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"source": source})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"challenge": p.Token, "source": source})
	})}
	result.Ready = true
	if e = json.NewEncoder(output).Encode(result); e != nil {
		return e
	}
	go func() { <-ctx.Done(); server.Close() }()
	e = server.Serve(listener)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
