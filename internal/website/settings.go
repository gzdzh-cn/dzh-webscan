package website

import (
	"webscan/internal/common"
)

func (m *Monitor) Settings() common.Map {
	if v := m.settings.Load(); v != nil {
		return *v
	}
	return m.Config
}
func (m *Monitor) Configure(config common.Map, notify bool) {
	m.WriteMu.Lock()
	defer m.WriteMu.Unlock()
	next := common.Clone(config)
	next["backup_dir"] = m.Settings()["backup_dir"]
	m.notifySetting.Store(&notify)
	m.settings.Store(&next)
	m.mu.Lock()
	for _, cancel := range m.active {
		cancel()
	}
	m.mu.Unlock()
}

func (m *Monitor) notificationsEnabled() bool {
	if n := m.notifySetting.Load(); n != nil {
		return *n
	}
	return m.Notify
}
