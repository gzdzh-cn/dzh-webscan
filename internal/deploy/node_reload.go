package deploy

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
	"webscan/internal/common"
)

func registryRevision(c common.Map) string {
	c = common.Clone(c)
	delete(c, "runtime_path")
	return common.Hash(common.JSON(c))
}
func (d *Deploy) registryRequest(ctx context.Context, path string, body common.Map) (common.Map, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	port := common.I(common.M(common.M(d.C.Raw["central"])["event_service"])["port"])
	for attempt := 0; ; attempt++ {
		status, value, e := common.Request(ctx, d.HTTP, "POST", fmt.Sprintf("http://127.0.0.1:%d/%s", port, path), body, map[string]string{"Authorization": "Bearer " + common.S(d.Secrets["alert_token"])})
		result := common.M(value)
		if e == nil && status == 200 {
			return result, nil
		}
		if status == 404 || status == 400 && path == "node-capabilities" {
			return nil, fmt.Errorf("主服务器不支持节点动态登记，请先升级中心；本次不重建中心")
		}
		if (status != 0 && status != 429 && status < 500) || attempt >= 4 || ctx.Err() != nil {
			return nil, fmt.Errorf("节点动态登记未确认（HTTP %d），请按原范围继续任务；中心保持运行", status)
		}
		if !common.Sleep(ctx, time.Duration(1<<attempt)*time.Second) {
			return nil, ctx.Err()
		}
	}
}
func (d *Deploy) nodeCapabilities(ctx context.Context) (common.Map, error) {
	if !Native(d.C) {
		return nil, fmt.Errorf("请先升级 Go 一体化中心以支持节点动态登记")
	}
	v, e := d.registryRequest(ctx, "node-capabilities", common.Map{})
	if e != nil {
		return nil, e
	}
	if !common.B(v["node_registry_reload"]) || common.S(v["revision"]) == "" {
		return nil, fmt.Errorf("主服务器不支持节点动态登记，请先升级中心")
	}
	return v, nil
}
func (d *Deploy) reloadNodeRegistry(ctx context.Context, expected string) error {
	next, e := common.ReadJSON(filepath.Join(d.C.CentralRoot(), "runtime.json"))
	if e != nil {
		return e
	}
	revision := registryRevision(next)
	v, e := d.registryRequest(ctx, "reload-nodes", common.Map{"node": d.O.Node, "expected_revision": expected, "revision": revision})
	if e != nil {
		return e
	}
	if !common.B(v["ok"]) || common.S(v["revision"]) != revision {
		return fmt.Errorf("中心未确认目标节点配置版本，请继续原任务")
	}
	return nil
}
