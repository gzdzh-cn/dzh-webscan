//go:build linux

// Controlled inventory benchmark. Run in an owned directory outside websites.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"webscan/internal/agent"
	"webscan/internal/common"
)

func must(e error) {
	if e != nil {
		panic(common.SecretFree(e))
	}
}
func main() {
	root := os.Args[1]
	if !strings.HasPrefix(root, "/var/lib/webscan-deploy/benchmarks/") {
		panic("owned_benchmark_directory_required")
	}
	if os.Args[2] == "prepare" {
		for i := 0; i < 10000; i++ {
			p := filepath.Join(root, "sites", fmt.Sprintf("site-%03d", i/100), fmt.Sprintf("fixture-%05d.php", i))
			must(os.MkdirAll(filepath.Dir(p), 0700))
			must(os.WriteFile(p, []byte("<?php /* "+strings.Repeat("owned deterministic fixture ", 64)+" */"), 0600))
		}
		fmt.Println("prepared_10000_files")
		return
	}
	c, e := common.ReadJSON(filepath.Join(root, "go.json"))
	must(e)
	a, e := agent.New(c, filepath.Join(root, "go.json"))
	must(e)
	defer a.Close()
	out := common.Map{"implementation": "goframe", "files": 10000, "platform": "native_linux_amd64", "goframe": "2.10.3", "go": "1.26.3"}
	measure := func(name string, f func() error) {
		var b, z syscall.Rusage
		syscall.Getrusage(syscall.RUSAGE_SELF, &b)
		start := time.Now()
		must(f())
		syscall.Getrusage(syscall.RUSAGE_SELF, &z)
		out[name] = common.Map{"wall_seconds": time.Since(start).Seconds(), "cpu_seconds": float64(z.Utime.Nano()+z.Stime.Nano()-b.Utime.Nano()-b.Stime.Nano()) / 1e9, "peak_rss_kib": z.Maxrss}
	}
	ctx := context.Background()
	measure("baseline", func() error { return a.Reconcile(ctx, true, false, nil) })
	measure("unchanged_metadata", func() error { return a.Reconcile(ctx, false, false, nil) })
	for i := 0; i < 100; i++ {
		p := filepath.Join(root, "sites", "site-000", fmt.Sprintf("fixture-%05d.php", i))
		must(os.WriteFile(p, []byte("<?php /* owned modified fixture */"), 0600))
	}
	measure("detect_100_changes", func() error { return a.Reconcile(ctx, false, false, nil) })
	measure("full_sha256", func() error { return a.Reconcile(ctx, false, true, nil) })
	fmt.Println(string(common.JSON(out)))
}
