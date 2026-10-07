//go:build !linux

package agent

import (
	"context"
	"errors"
)

func Run(context.Context, string) error { return errors.New("agent_requires_linux") }
