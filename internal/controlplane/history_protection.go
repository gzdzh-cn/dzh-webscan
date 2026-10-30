package controlplane

import "strings"

// Lists and execution share protection predicates. Aliases are private SQL
// constants; a record remains subject to a fresh check by the cleanup worker.
func historyDeleteReasonSQL(stage int, alias string) string {
	x, _ := retentionSourceFor(stage)
	tm := strings.ReplaceAll(x.tm, "t.", alias+".")
	protected := strings.ReplaceAll(strings.ReplaceAll(x.protected, "__cutoff__", "clock_timestamp()-interval '24 hours'"), "t.", alias+".")
	return `CASE WHEN ` + tm + `>=clock_timestamp()-interval '24 hours' THEN '最近 24 小时记录受保护'
 WHEN EXISTS(SELECT 1 FROM v3_migration_domains WHERE pending) THEN '数据迁移期间保护历史'
 WHEN COALESCE((` + protected + `),false) THEN '关联当前异常、未完成任务或历史操作，暂不可删除'
 ELSE '' END`
}

func historyEventDeleteReasonSQL() string {
	// The unified event view contains native and imported rows. Keep each
	// identity's stage so a queued job pins both security and ordinary events.
	return `CASE WHEN t.source='events' THEN CASE WHEN t.security THEN ` + historyDeleteReasonSQL(1, "t") + ` ELSE ` + historyDeleteReasonSQL(0, "t") + ` END ELSE CASE WHEN t.security THEN ` + historyDeleteReasonSQL(3, "t") + ` ELSE ` + historyDeleteReasonSQL(2, "t") + ` END END`
}
