package website

import (
	"context"
	"time"
)

// Checker uses the existing DNS-pinned HTTP probe, including redirect, public
// address and certificate validation. It does not write to a database.
type Checker struct{ probe *prober }

func NewChecker() *Checker { return &Checker{probe: newProber()} }
func (c *Checker) Check(ctx context.Context, site Site, timeout time.Duration) Result {
	return c.probe.check(ctx, site, timeout)
}
func NormalizeURL(raw string) (string, error) { return normalizeURL(raw) }
