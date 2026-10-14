//go:build !linux

package agent

import (
	"context"
	"errors"
)

func Run(context.Context, string) error { return errors.New("agent_requires_linux") }

func ImportLegacyLogs(context.Context, string, string) error {
	return errors.New("agent_requires_linux")
}
func PrepareLegacyDelivery(context.Context, string, string) error {
	return errors.New("agent_requires_linux")
}
