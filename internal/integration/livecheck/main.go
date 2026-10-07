package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
	"webscan/internal/deploy"
	"webscan/internal/persist"
)

type node struct {
	n        common.Map
	r        *deploy.Remote
	root     string
	runtime  []byte
	identity string
}

func must(e error) {
	if e != nil {
		panic(common.SecretFree(e))
	}
}
func poll(ctx context.Context, f func() bool) {
	end := time.Now().Add(4 * time.Minute)
	for time.Now().Before(end) {
		if f() {
			return
		}
		if !common.Sleep(ctx, time.Second) {
			panic("verification_cancelled")
		}
	}
	panic("verification_timeout")
}
func count(db *sql.DB, n, root string, since float64) int {
	var c int
	must(db.QueryRow("SELECT count(*) FROM events WHERE node=? AND json_extract(payload,'$.path') LIKE ? AND received>=?", n, root+"%", since).Scan(&c))
	return c
}
func main() {
	defer func() {
		if e := recover(); e != nil {
			fmt.Println("online_verification_failed:", e)
			os.Exit(1)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	c, e := deploy.Load("/root/webscan-deploy/webscan.yaml")
	must(e)
	d, e := deploy.New(c, deploy.Options{})
	must(e)
	defer d.Close()
	if common.S(d.State["step"]) != "complete" {
		panic("deployment_not_complete")
	}
	db, e := persist.OpenDB(filepath.Join(common.S(common.M(c.Raw["central"])["data_dir"]), "events-v1.sqlite3"))
	must(e)
	defer db.Close()
	id := common.ID()[:12]
	nodes := []node{}
	for _, n := range c.Selected("") {
		r, e := deploy.Connect(ctx, n)
		must(e)
		root := common.SS(common.M(n["monitor"])["roots"])[0] + "/.webscan-live-" + id
		b, e := r.Read(ctx, "/etc/webscan-v1/runtime.json")
		must(e)
		identity, e := r.Run(ctx, "docker inspect --format '{{.Id}} {{.State.StartedAt}} {{.State.Pid}}' webscan-agent-go")
		must(e)
		nodes = append(nodes, node{n, r, root, b, string(identity)})
	}
	defer func() {
		for _, n := range nodes {
			n.r.Write(context.Background(), "/etc/webscan-v1/runtime.json", n.runtime, 0600)
			n.r.Run(context.Background(), "rm -rf -- "+deploy.Q(n.root))
			n.r.Close()
		}
	}()
	for _, n := range nodes {
		since := common.Now()
		for _, dir := range []string{"runtime/cache", "runtime/temp", "runtime/views", "caches/cache", "caches/temp", "caches/tpl"} {
			must(n.r.Write(ctx, n.root+"/"+dir+"/ignored.php", []byte("<?php /* owned ignored fixture */"), 0600))
		}
		common.Sleep(ctx, 7*time.Second)
		if count(db, common.S(n.n["id"]), n.root, since) != 0 {
			panic("six_cache_rules_emitted_event")
		}
		must(n.r.Write(ctx, n.root+"/hot-cache/baseline.php", []byte("<?php /* owned first */"), 0600))
		poll(ctx, func() bool { return count(db, common.S(n.n["id"]), n.root+"/hot-cache", since) > 0 })
		fmt.Println(common.S(n.n["id"]) + " six cache wildcard rules verified")
	}
	original := d.C
	candidate, e := deploy.Load("/root/webscan-deploy/webscan.yaml")
	must(e)
	pattern := nodes[0].root + "*/hot-cache"
	m := common.M(common.M(candidate.Raw["node_defaults"])["monitor"])
	m["exclude_paths"] = append(common.SS(m["exclude_paths"]), pattern)
	for _, n := range candidate.Nodes {
		m := common.M(n["monitor"])
		m["exclude_paths"] = append(common.SS(m["exclude_paths"]), pattern)
	}
	d.C = candidate
	changed := true
	defer func() {
		if changed {
			d.C = original
			if e := d.ReloadRules(context.Background()); e != nil {
				fmt.Println("rule_restore_failed")
			}
		}
	}()
	must(d.ReloadRules(ctx))
	since := common.Now()
	for _, n := range nodes {
		must(n.r.Write(ctx, n.root+"/hot-cache/baseline.php", []byte("<?php /* owned ignored modification */"), 0600))
	}
	common.Sleep(ctx, 8*time.Second)
	for _, n := range nodes {
		if count(db, common.S(n.n["id"]), n.root+"/hot-cache", since) != 0 {
			panic("temporary_ignore_failed")
		}
	}
	d.C = original
	must(d.ReloadRules(ctx))
	changed = false
	common.Sleep(ctx, 8*time.Second)
	for _, n := range nodes {
		if count(db, common.S(n.n["id"]), n.root+"/hot-cache", since) != 0 {
			panic("unignore_baseline_not_quiet")
		}
		must(n.r.Write(ctx, n.root+"/hot-cache/baseline.php", []byte("<?php /* owned detected modification "+common.ID()+" */"), 0600))
		poll(ctx, func() bool { return count(db, common.S(n.n["id"]), n.root+"/hot-cache", since) > 0 })
		fmt.Println(common.S(n.n["id"]) + " ignore, quiet reinclude and later modification verified")
	}
	for _, n := range nodes {
		raw, e := n.r.Read(ctx, "/etc/webscan-v1/runtime.json")
		must(e)
		v, e := common.Decode(raw)
		must(e)
		bad := common.M(v)
		common.M(bad["monitor"])["exclude_paths"] = []string{common.SS(common.M(n.n["monitor"])["roots"])[0]}
		status, e := n.r.Read(ctx, "/var/lib/webscan-v1/rules-status.json")
		must(e)
		sv, e := common.Decode(status)
		must(e)
		version := common.S(common.M(sv)["version"])
		must(n.r.Write(ctx, "/etc/webscan-v1/runtime.json", common.JSON(bad), 0600))
		poll(ctx, func() bool {
			b, e := n.r.Read(ctx, "/var/lib/webscan-v1/rules-status.json")
			if e != nil {
				return false
			}
			v, e := common.Decode(b)
			return e == nil && common.S(common.M(v)["state"]) == "rejected" && common.S(common.M(v)["version"]) == version
		})
		must(n.r.Write(ctx, "/etc/webscan-v1/runtime.json", raw, 0600))
		poll(ctx, func() bool {
			b, e := n.r.Read(ctx, "/var/lib/webscan-v1/rules-status.json")
			if e != nil {
				return false
			}
			v, e := common.Decode(b)
			return e == nil && common.S(common.M(v)["state"]) == "applied" && common.S(common.M(v)["version"]) == version
		})
		identity, e := n.r.Run(ctx, "docker inspect --format '{{.Id}} {{.State.StartedAt}} {{.State.Pid}}' webscan-agent-go")
		must(e)
		if strings.TrimSpace(string(identity)) != strings.TrimSpace(n.identity) {
			panic("container_restarted")
		}
		fmt.Println(common.S(n.n["id"]) + " invalid rules retained prior version; container ID/start/PID unchanged")
		must(d.WaitHealth(ctx, n.n))
	}
	fmt.Println("online_hot_rules_and_health_passed")
}
