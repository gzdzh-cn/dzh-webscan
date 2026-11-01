//go:build !linux

package controlplane

import (
	"context"
	"database/sql"
)

type unsupportedHostWatchdogProbe struct{}

func newHostWatchdogProbe(HostWatchdogSpec, *sql.DB) hostWatchdogProbe {
	return unsupportedHostWatchdogProbe{}
}
func (unsupportedHostWatchdogProbe) Check(context.Context) ([]HostWatchdogCheck, HostWatchdogEnvironment) {
	return []HostWatchdogCheck{}, HostWatchdogEnvironment{Storage: []HostWatchdogStorage{}}
}
