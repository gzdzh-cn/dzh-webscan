package controlplane

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestSinglePKIHostCycleFreezesCollectorWhileRootTaskPending(t *testing.T) {
	f, inputs := rootTaskFixture(t)
	ctx := context.Background()
	j, err := f.s.prepareRootRotation(ctx, f.c, f.t.vault, "admin", "freeze-maintenance", f.t.release, inputs)
	if err != nil {
		t.Fatal(err)
	}
	spec, _, now := prepareSinglePKIFixture(t)
	var schema string
	if err := f.s.DB.QueryRow(`SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("WEBSCAN_V3_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	localWrite(t, spec.configuration().Database.DSNFile, []byte(dsn.String()))
	// Near the ordinary seven-day threshold: a timer must refresh CRLs but
	// leave the exact parent frozen even when the root runner is not running.
	receipt, err := maintainSinglePKIHostCycle(ctx, spec, now.Add(24*24*time.Hour), true)
	if err != nil || receipt.State != "healthy" || receipt.Identity.Changed || receipt.NodeRenewals == nil || receipt.NodeRenewals.State != "deferred" {
		t.Fatal("pending root task did not freeze collector renewal", err, receipt.State)
	}
	if _, err := f.s.controlRootTask(ctx, f.c, f.t.vault, "admin", "cancel-freeze", j.ID, true); err != nil {
		t.Fatal(err)
	}
	receipt, err = maintainSinglePKIHostCycle(ctx, spec, now.Add(24*24*time.Hour), true)
	if err != nil || !receipt.Identity.Changed {
		t.Fatal("released root task prevented scheduled renewal", err)
	}
}

func TestSinglePKIHostCycleDatabaseUnavailableKeepsValidIdentity(t *testing.T) {
	spec, _, now := prepareSinglePKIFixture(t)
	localWrite(t, spec.configuration().Database.DSNFile, []byte("postgres://unused@127.0.0.1:1/unavailable?sslmode=disable"))
	receipt, err := maintainSinglePKIHostCycle(context.Background(), spec, now.Add(24*24*time.Hour), true)
	if err != nil || receipt.State != "healthy" || receipt.Identity.Changed || receipt.NodeRenewals == nil || receipt.NodeRenewals.State != "deferred" {
		t.Fatal("database startup replaced identity or blocked valid local trust", err)
	}
}
