// Package telemetry implements the bounded, fixed-metric host collector.
package telemetry

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Metric struct {
	Name   string
	Labels map[string]string
	Value  float64
}

var labelPattern = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)

func Parse(raw string) ([]Metric, error) {
	if len(raw) > 4<<20 {
		return nil, errors.New("指标响应超过 4 MiB")
	}
	out := []Metric{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var name, value string
		labels := map[string]string{}
		if p := strings.IndexByte(line, '{'); p >= 0 {
			q := strings.LastIndexByte(line, '}')
			if q < p {
				return nil, errors.New("指标标签格式错误")
			}
			name = line[:p]
			for _, m := range labelPattern.FindAllStringSubmatch(line[p+1:q], -1) {
				v, e := strconv.Unquote(`"` + m[2] + `"`)
				if e != nil {
					return nil, e
				}
				labels[m[1]] = v
			}
			fields := strings.Fields(line[q+1:])
			if len(fields) == 0 {
				return nil, errors.New("指标缺少数值")
			}
			value = fields[0]
		} else {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return nil, errors.New("指标格式错误")
			}
			name, value = fields[0], fields[1]
		}
		if !strings.HasPrefix(name, "node_") && !strings.HasPrefix(name, "webscan_") && !strings.HasPrefix(name, "vector_") {
			continue
		}
		v, e := strconv.ParseFloat(value, 64)
		if e != nil {
			return nil, e
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		out = append(out, Metric{name, labels, v})
		if len(out) > 20000 {
			return nil, errors.New("指标数量超过限制")
		}
	}
	return out, scanner.Err()
}
func key(m Metric) string {
	names := make([]string, 0, len(m.Labels))
	for k := range m.Labels {
		names = append(names, k)
	}
	sort.Strings(names)
	s := m.Name
	for _, k := range names {
		s += "|" + k + "=" + strconv.Quote(m.Labels[k])
	}
	return s
}

type Snapshot struct {
	Time   int64              `json:"time"`
	OK     bool               `json:"ok"`
	Error  string             `json:"error,omitempty"`
	Values map[string]float64 `json:"values"`
	Info   map[string]string  `json:"info,omitempty"`
}
type Baseline struct {
	Time   int64
	Values map[string]float64
}

// Derive only publishes rates when both samples exist and the counter did not reset.
func Derive(ms []Metric, now int64, previous Baseline) (Snapshot, Baseline) {
	s := Snapshot{Time: now, OK: true, Values: map[string]float64{}, Info: map[string]string{}}
	current := Baseline{Time: now, Values: map[string]float64{}}
	dt := float64(now - previous.Time)
	totals := map[string]float64{}
	disk := map[string]map[string]float64{}
	cpuTotal, cpuIdle := 0.0, 0.0
	cpus := map[string]bool{}
	rate := func(m Metric) (float64, bool) {
		v, ok := previous.Values[key(m)]
		if !ok || dt <= 0 || dt > 300 || m.Value < v {
			return 0, false
		}
		return (m.Value - v) / dt, true
	}
	for _, m := range ms {
		if m.Name == "node_cpu_seconds_total" || strings.HasPrefix(m.Name, "node_disk_") || strings.HasPrefix(m.Name, "node_network_") {
			current.Values[key(m)] = m.Value
		}
		switch m.Name {
		case "node_cpu_seconds_total":
			cpus[m.Labels["cpu"]] = true
			if m.Labels["mode"] == "guest" || m.Labels["mode"] == "guest_nice" {
				continue
			}
			if v, ok := rate(m); ok {
				cpuTotal += v
				if m.Labels["mode"] == "idle" {
					cpuIdle += v
				}
				totals["cpu_"+m.Labels["mode"]] += v
			}
		case "node_memory_MemTotal_bytes":
			s.Values["memory_total"] = m.Value
		case "node_memory_MemAvailable_bytes":
			s.Values["memory_available"] = m.Value
		case "node_memory_SwapTotal_bytes":
			s.Values["swap_total"] = m.Value
		case "node_memory_SwapFree_bytes":
			s.Values["swap_free"] = m.Value
		case "node_load1", "node_load5", "node_load15":
			s.Values[strings.TrimPrefix(m.Name, "node_")] = m.Value
		case "node_boot_time_seconds":
			s.Values["uptime"] = math.Max(0, float64(now)-m.Value)
		case "webscan_transport_error":
			if m.Value > 0 {
				s.Info["transport_error"] = m.Labels["reason"]
			}
		case "webscan_agent_info":
			for k, v := range m.Labels {
				s.Info["agent_"+k] = v
			}
		case "webscan_host_collector_error":
			s.Values[m.Name+":"+m.Labels["collector"]] = m.Value
			if m.Value > 0 {
				if s.Info["collector_errors"] != "" {
					s.Info["collector_errors"] += ", "
				}
				s.Info["collector_errors"] += m.Labels["collector"]
			}
		case "node_uname_info":
			for k, v := range m.Labels {
				s.Info[k] = v
			}
		case "node_timex_sync_status", "node_timex_offset_seconds":
			s.Values[strings.TrimPrefix(m.Name, "node_")] = m.Value
		case "node_filesystem_size_bytes", "node_filesystem_avail_bytes", "node_filesystem_files", "node_filesystem_files_free":
			fs := m.Labels["fstype"]
			if fs == "tmpfs" || fs == "overlay" || fs == "squashfs" || fs == "proc" || fs == "sysfs" {
				continue
			}
			mount := m.Labels["mountpoint"]
			if disk[mount] == nil {
				disk[mount] = map[string]float64{}
			}
			disk[mount][m.Name] = m.Value
		default:
			if strings.HasPrefix(m.Name, "node_disk_") {
				if v, ok := rate(m); ok {
					suffix := map[string]string{"node_disk_read_bytes_total": "disk_read", "node_disk_written_bytes_total": "disk_write", "node_disk_reads_completed_total": "disk_read_iops", "node_disk_writes_completed_total": "disk_write_iops"}[m.Name]
					if suffix != "" {
						s.Values[suffix+":"+m.Labels["device"]] = v
						totals[suffix] += v
					}
				}
			}
			if strings.HasPrefix(m.Name, "node_network_") {
				if v, ok := rate(m); ok {
					suffix := map[string]string{"node_network_receive_bytes_total": "net_receive", "node_network_transmit_bytes_total": "net_transmit", "node_network_receive_errs_total": "net_receive_errors", "node_network_transmit_errs_total": "net_transmit_errors", "node_network_receive_drop_total": "net_receive_drops", "node_network_transmit_drop_total": "net_transmit_drops"}[m.Name]
					if suffix != "" {
						dev := m.Labels["device"]
						s.Values[suffix+":"+dev] = v
						if dev != "lo" && !strings.HasPrefix(dev, "veth") && !strings.HasPrefix(dev, "docker") && !strings.HasPrefix(dev, "br-") {
							totals[suffix] += v
						}
					}
				}
			}
			if strings.HasPrefix(m.Name, "webscan_") || strings.HasPrefix(m.Name, "vector_") {
				if m.Name == "vector_component_discarded_events_total" {
					s.Values[m.Name] += m.Value
				} else {
					s.Values[m.Name] = m.Value
				}
			}
		}
	}
	s.Values["cpu_cores"] = float64(len(cpus))
	if cpuTotal > 0 {
		s.Values["cpu_percent"] = 100 * (1 - cpuIdle/cpuTotal)
		for k, v := range totals {
			if strings.HasPrefix(k, "cpu_") {
				s.Values[k+"_percent"] = 100 * v / cpuTotal
			}
		}
	}
	for _, pair := range [][3]string{{"memory_total", "memory_available", "memory"}, {"swap_total", "swap_free", "swap"}} {
		if total := s.Values[pair[0]]; total > 0 {
			s.Values[pair[2]+"_used"] = math.Max(0, total-s.Values[pair[1]])
			s.Values[pair[2]+"_percent"] = 100 * s.Values[pair[2]+"_used"] / total
		}
	}
	for mount, d := range disk {
		if len(disk) > 128 {
			s.OK = false
			s.Error = "挂载点数量超过 128"
			break
		}
		if size := d["node_filesystem_size_bytes"]; size > 0 {
			p := 100 * (1 - d["node_filesystem_avail_bytes"]/size)
			s.Values["disk_percent:"+mount] = p
			s.Values["disk_size:"+mount] = size
			s.Values["disk_available:"+mount] = d["node_filesystem_avail_bytes"]
			s.Values["disk_percent"] = math.Max(s.Values["disk_percent"], p)
		}
		if files := d["node_filesystem_files"]; files > 0 {
			p := 100 * (1 - d["node_filesystem_files_free"]/files)
			s.Values["inode_percent:"+mount] = p
			s.Values["inode_percent"] = math.Max(s.Values["inode_percent"], p)
		}
	}
	for k, v := range totals {
		if !strings.HasPrefix(k, "cpu_") {
			s.Values[k] = v
		}
	}
	if len(s.Values) > 4096 {
		s.OK = false
		s.Error = fmt.Sprint("指标维度超过 4096")
		s.Values = map[string]float64{}
	}
	if len(cpus) == 0 && s.Values["memory_total"] == 0 {
		s.OK = false
		s.Error = "指标接口缺少主机 CPU 和内存信息"
	}
	return s, current
}
