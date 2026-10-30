package website

import (
	"fmt"
	"strings"
)

// Notice is an already persisted website transition. Origin keeps frozen
// legacy outboxes separate from new observations without reordering a site.
type Notice struct {
	ID, Site                    int64
	Node, Kind, Message, Origin string
}
type NoticeGroup struct {
	Node, Kind, Origin string
	IDs, Sites         []int64
	Messages           []string
}

// GroupNotices preserves input order for each site, including alternating
// failures and recoveries. Callers supply notices in persistent ID order.
func GroupNotices(items []Notice) []NoticeGroup {
	groups := []NoticeGroup{}
	type key struct{ node, kind, origin string }
	index := map[key]int{}
	last := map[int64]int{}
	for _, v := range items {
		k := key{v.Node, v.Kind, v.Origin}
		at, exists := index[k]
		previous, seen := last[v.Site]
		if !exists || seen && at < previous {
			at = len(groups)
			index[k] = at
			groups = append(groups, NoticeGroup{Node: v.Node, Kind: v.Kind, Origin: v.Origin})
		}
		last[v.Site] = at
		g := &groups[at]
		g.IDs = append(g.IDs, v.ID)
		g.Sites = append(g.Sites, v.Site)
		g.Messages = append(g.Messages, v.Message)
	}
	return groups
}
func (g NoticeGroup) NotificationMessages(consoleURL string) []string {
	if len(g.Messages) <= 5 {
		return g.Messages
	}
	return []string{fmt.Sprintf("网站可用性批量提醒：共 %d 个网站\n%s\n其余网站请查看管理后台：%s", len(g.IDs), strings.Join(g.Messages[:5], "\n\n"), consoleURL)}
}
