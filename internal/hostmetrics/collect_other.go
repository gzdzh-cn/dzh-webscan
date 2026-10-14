//go:build !linux

package hostmetrics

type Paths struct{ Proc, Sys, Root string }

func Collect(Paths) string { return "webscan_host_collector_error{collector=\"platform\"} 1\n" }
