//go:build !linux

package controlplane

import "net"

func hostWatchdogListener(HostWatchdogSpec) (net.Listener, func(), error) {
	return nil, nil, errHostWatchdog
}
func hostWatchdogPlatform() error { return errHostWatchdog }
