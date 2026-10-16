package telemetry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
	"webscan/internal/common"
	"webscan/internal/hostmetrics"
)

func Client(c common.Map) (*http.Client, error) {
	client, e := common.HTTPClient(common.S(c["ca_file"]), 5*time.Second)
	if e != nil {
		return nil, e
	}
	if common.S(c["client_cert"]) != "" {
		pair, e := tls.LoadX509KeyPair(common.S(c["client_cert"]), common.S(c["client_key"]))
		if e != nil {
			return nil, e
		}
		client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{pair}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("指标接口不允许跳转") }
	return client, nil
}
func (s *Store) Collect(ctx context.Context, client *http.Client, n Node, extra map[string]float64) error {
	now := time.Now().Unix()
	snap := Snapshot{Time: now, Values: map[string]float64{}}
	var raw []byte
	var e error
	if n.Central && n.URL == "local://host" {
		paths := common.M(s.Settings()["host_metrics"])
		raw = []byte(hostmetrics.Collect(hostmetrics.Paths{Proc: common.S(paths["proc"]), Sys: common.S(paths["sys"]), Root: common.S(paths["root"])}))
	} else {
		var r *http.Request
		r, e = http.NewRequestWithContext(ctx, "GET", n.URL, nil)
		if e == nil {
			var resp *http.Response
			resp, e = client.Do(r)
			if e == nil {
				if resp.StatusCode != 200 {
					e = errors.New("指标采集接口返回异常状态")
				} else {
					raw, e = io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
				}
				resp.Body.Close()
			}
		}
	}
	var baseline *Baseline
	if e != nil {
		snap.Error = "无法连接指标采集服务"
	} else {
		var ms []Metric
		ms, e = Parse(string(raw))
		if e == nil {
			var previous Baseline
			previous, e = s.Baseline(ctx, n.ID)
			if e == nil {
				var b Baseline
				snap, b = Derive(ms, now, previous)
				baseline = &b
			}
		}
		if e != nil {
			snap.Error = common.SecretFree(e)
		}
	}
	for k, v := range extra {
		snap.Values[k] = v
	}
	s.collectMu.RLock()
	defer s.collectMu.RUnlock()
	s.mu.Lock()
	stale := n.generation != 0 && n.generation != s.generation
	s.mu.Unlock()
	if stale {
		return nil
	}
	if snap.OK {
		if cpu, ok := snap.Values["cpu_percent"]; ok {
			avg, known, err := s.cpuAverage(ctx, n.ID, now, cpu)
			if err != nil {
				return err
			}
			if known {
				snap.Values["cpu_5m_percent"] = avg
			}
		}
	}
	if e = s.Save(ctx, n.ID, snap, baseline); e != nil {
		return e
	}
	return s.Evaluate(ctx, n, snap)
}
func (s *Store) Run(ctx context.Context, extra func(string) map[string]float64, deliver func(context.Context, string, string, string) error) error {
	client, e := Client(s.Settings())
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	lastCompact := time.Now().Add(-time.Hour)
	for ctx.Err() == nil {
		nodes, e := s.Nodes(ctx)
		if e != nil {
			return e
		}
		var wg sync.WaitGroup
		slots := make(chan struct{}, 4)
		started := time.Now()
		interval := time.Duration(max(10, common.I(s.Settings()["interval_seconds"]))) * time.Second
		for _, node := range nodes {
			if !node.Active {
				continue
			}
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			}
			wg.Add(1)
			go func(n Node) {
				defer wg.Done()
				defer func() { <-slots }()
				values := map[string]float64{}
				if extra != nil {
					values = extra(n.ID)
				}
				if e := s.Collect(ctx, client, n, values); e != nil && ctx.Err() == nil {
					fmt.Println("指标持久化失败：", common.SecretFree(e))
				}
			}(node)
			if !common.Sleep(ctx, interval/time.Duration(max(1, len(nodes)))) {
				break
			}
		}
		wg.Wait()
		if deliver != nil && !common.B(s.Settings()["notifications_paused"]) {
			if e := s.Flush(ctx, deliver); e != nil {
				fmt.Println("资源告警入队失败：", common.SecretFree(e))
			}
		}
		if time.Since(lastCompact) > time.Hour {
			if e = s.Compact(ctx); e != nil {
				return e
			}
			lastCompact = time.Now()
		}
		remaining := interval - time.Since(started)
		if remaining > 0 && !common.Sleep(ctx, remaining) {
			break
		}
	}
	return ctx.Err()
}

// A missing or stale sample invalidates the sustained CPU window.
func (s *Store) cpuAverage(ctx context.Context, node string, now int64, current float64) (float64, bool, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT payload FROM samples WHERE node=? AND resolution=0 AND time>=? ORDER BY time", node, now-300)
	if e != nil {
		return 0, false, e
	}
	defer rows.Close()
	first, last := int64(0), int64(0)
	total, weight := 0.0, 0.0
	interval := int64(max(10, common.I(s.Settings()["interval_seconds"])))
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return 0, false, e
		}
		var p Snapshot
		if e = json.Unmarshal([]byte(raw), &p); e != nil {
			return 0, false, e
		}
		v, ok := p.Values["cpu_percent"]
		if !p.OK || !ok {
			return 0, false, nil
		}
		if first == 0 {
			first = p.Time
			last = p.Time
			continue
		}
		dt := p.Time - last
		if dt <= 0 || dt > interval*2 {
			return 0, false, nil
		}
		total += v * float64(dt)
		weight += float64(dt)
		last = p.Time
	}
	if e = rows.Err(); e != nil {
		return 0, false, e
	}
	dt := now - last
	if first == 0 || now-first < 240 || dt <= 0 || dt > interval*2 {
		return 0, false, nil
	}
	total += current * float64(dt)
	weight += float64(dt)
	return total / weight, true, nil
}
