package controlplane

import "errors"

var errSingleMetricsLayers = errors.New("双层指标配置不正确：原始指标保留24～168小时，历史保留1～90天；需独立回环端口，旧单库安装不能隐式切换")

func (s *singleInstallSpec) validateMetricsLayers() error {
	if s.MetricsRetention && (s.Format != 3 || !s.MetricsLayers) {
		return errSingleMetricsLayers
	}
	if !s.MetricsLayers {
		if s.RawMetricsPort != 0 || s.RawMetricsHours != 0 || s.HistoryMetricsDays != 0 {
			return errSingleMetricsLayers
		}
		return nil
	}
	if s.Format != 3 {
		return errSingleMetricsLayers
	}
	if s.RawMetricsPort == 0 {
		s.RawMetricsPort = 8429
	}
	if s.RawMetricsHours == 0 {
		s.RawMetricsHours = 48
	}
	if s.HistoryMetricsDays == 0 {
		s.HistoryMetricsDays = 15
	}
	if s.RawMetricsHours < 24 || s.RawMetricsHours > 168 || s.HistoryMetricsDays < 1 || s.HistoryMetricsDays > 90 {
		return errSingleMetricsLayers
	}
	return nil
}
func (s singleInstallSpec) localPorts() []int {
	ports := []int{s.APIPort, s.PostgresPort, s.MetricsPort}
	if s.MetricsLayers {
		ports = append(ports, s.RawMetricsPort)
	}
	return ports
}
func (s singleInstallSpec) serviceNames() []string {
	names := []string{"postgres", "metrics", "central"}
	if s.MetricsLayers {
		names = append(names, "metrics-raw")
	}
	return names
}
func (s singleInstallSpec) storageServiceNames() []string {
	names := []string{"postgres", "metrics"}
	if s.MetricsLayers {
		names = append(names, "metrics-raw")
	}
	return names
}
func (s singleInstallSpec) dataDirectoryNames() []string {
	names := []string{"postgres-data", "metrics-data", "state"}
	if s.MetricsLayers {
		names = append(names, "raw-metrics-data")
	}
	return names
}
func (s singleInstallSpec) historyDays() int {
	if s.MetricsLayers {
		return s.HistoryMetricsDays
	}
	return 15
}
