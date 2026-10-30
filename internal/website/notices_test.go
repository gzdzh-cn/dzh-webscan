package website

import (
	"reflect"
	"strings"
	"testing"
)

func TestNoticeGroupingPreservesSiteOrderAndOrigin(t *testing.T) {
	items := []Notice{
		{ID: 1, Site: 1, Node: "n", Kind: "outage", Message: "故障1"},
		{ID: 2, Site: 2, Node: "n", Kind: "outage", Message: "故障2"},
		{ID: 3, Site: 1, Node: "n", Kind: "recovery", Message: "恢复1"},
		{ID: 4, Site: 1, Node: "n", Kind: "outage", Message: "再次故障1"},
		{ID: 5, Site: 3, Node: "n", Kind: "outage", Message: "旧通知", Origin: "old"},
		{ID: 6, Site: 3, Node: "n", Kind: "outage", Message: "新通知"},
	}
	groups := GroupNotices(items)
	if len(groups) != 5 {
		t.Fatal(groups)
	}
	for i, ids := range [][]int64{{1, 2}, {3}, {4}, {5}, {6}} {
		if !reflect.DeepEqual(groups[i].IDs, ids) {
			t.Fatal(groups)
		}
	}
	if groups[3].Origin != "old" || groups[4].Origin != "" {
		t.Fatal(groups)
	}
}
func TestNoticeGroupingSummaryShowsOnlyFiveMessages(t *testing.T) {
	items := []Notice{}
	for i := int64(1); i <= 6; i++ {
		items = append(items, Notice{ID: i, Site: i, Node: "n", Kind: "outage", Message: strings.Repeat("站", int(i))})
	}
	g := GroupNotices(items)[0]
	messages := g.NotificationMessages("https://console.example.test")
	if len(messages) != 1 || !strings.Contains(messages[0], "共 6 个网站") || !strings.Contains(messages[0], "https://console.example.test") || strings.Contains(messages[0], strings.Repeat("站", 6)) {
		t.Fatal(messages)
	}
	if got := GroupNotices(items[:5])[0].NotificationMessages(""); len(got) != 5 {
		t.Fatal(got)
	}
}
