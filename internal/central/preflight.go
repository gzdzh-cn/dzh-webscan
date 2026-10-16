package central

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"webscan/internal/common"
	"webscan/internal/diagnostic"
	"webscan/internal/telemetry"
)

// This route is available only on the internal listener with the management
// credential. It has fixed HTTP paths and never accepts a command or a URL.
func (s *Store) nodePreflight(w http.ResponseWriter, r *http.Request) {
	snapshot := s.Snapshot()
	if r.Method != "POST" || common.S(snapshot["alert_token"]) == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+common.S(snapshot["alert_token"]))) != 1 {
		write(w, 401, common.Map{})
		return
	}
	var in struct {
		Node  string           `json:"node"`
		Probe diagnostic.Probe `json:"probe"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		write(w, 400, common.Map{"message": "检测参数无效"})
		return
	}
	p := in.Probe
	ip := net.ParseIP(p.Host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || p.Port < 1 || p.Port > 65535 || p.Key != "" || p.EventURL != "" || p.EventToken != "" {
		write(w, 400, common.Map{"message": "检测目标无效"})
		return
	}
	path := "/__webscan_preflight"
	scheme := "http"
	var client *http.Client
	var e error
	if p.Token != "" {
		if len(p.Token) < 32 || len(p.Token) > 128 {
			write(w, 400, common.Map{})
			return
		}
		client, e = diagnostic.Client(p.CA, p.ClientCert, p.ClientKey)
		if p.CA != "" {
			scheme = "https"
		}
	} else {
		registered := false
		for _, v := range common.A(common.M(snapshot["monitoring"])["nodes"]) {
			n := common.M(v)
			expected := "http://" + net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) + "/metrics"
			if common.I(common.M(snapshot["https"])["port"]) > 0 {
				scheme = "https"
				expected = "https://" + net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) + "/metrics"
			}
			if common.S(n["id"]) == in.Node && common.S(n["url"]) == expected {
				registered = true
			}
		}
		if !registered {
			write(w, 200, common.Map{"ok": false, "message": "指标端口已占用，且不是当前已登记的指标服务；未停止原程序"})
			return
		}
		path = "/metrics"
		client, e = telemetry.Client(common.M(snapshot["monitoring"]))
	}
	if e != nil {
		write(w, 200, common.Map{"ok": false, "message": "指标检测证书不可用，请检查中心证书配置"})
		return
	}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(r.Context(), "GET", scheme+"://"+net.JoinHostPort(p.Host, strconv.Itoa(p.Port))+path, nil)
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	resp, e := client.Do(req)
	if e != nil {
		write(w, 200, common.Map{"ok": false, "message": diagnostic.Failure(e)})
		return
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if e != nil {
		write(w, 200, common.Map{"ok": false, "message": "指标响应读取失败"})
		return
	}
	if p.Token != "" {
		var v map[string]string
		json.Unmarshal(raw, &v)
		ok := resp.StatusCode == 200 && v["challenge"] == p.Token
		message := "中心采集网络到指标端口连接通过"
		if !ok {
			message = "指标检测未通过，请检查实际来源限制与端口占用"
		}
		write(w, 200, common.Map{"ok": ok, "source": v["source"], "message": message})
		return
	}
	ok := resp.StatusCode == 200 && (strings.Contains(string(raw), "webscan_agent_heartbeat_seconds") || strings.Contains(string(raw), "webscan_collector_ready"))
	write(w, 200, common.Map{"ok": ok, "message": map[bool]string{true: "现有指标服务可从中心采集网络访问", false: "现有指标接口响应无效，请检查来源限制、证书和服务"}[ok]})
}
