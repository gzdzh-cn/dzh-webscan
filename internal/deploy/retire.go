package deploy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"webscan/internal/common"
)

func (d *Deploy) retirePython(ctx context.Context) error {
	for _, n := range d.C.Selected("") {
		s := common.M(common.M(d.State["nodes"])[common.S(n["id"])])
		if common.S(s["go_release"]) != Release || common.S(s["phase"]) != "complete" {
			return nil
		}
	}
	for _, n := range d.C.Selected("") {
		r, e := d.remote(ctx, n)
		if e != nil {
			return e
		}
		if _, e = r.Run(ctx, "/opt/webscan-go/bin/webscan tool --action retire-python"); e != nil {
			return e
		}
	}
	for _, name := range []string{"central.py", "common.py"} {
		path := filepath.Join(d.C.CentralRoot(), "src", name)
		if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	d.State["python_entrypoints_retired_at"] = common.Now()
	fmt.Println("全部节点验收通过，旧 Python 入口已停用；独立回退备份保留。")
	return nil
}
