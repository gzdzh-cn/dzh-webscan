package management

import (
	"errors"
	"fmt"
	"webscan/internal/common"
	"webscan/internal/config"
)

// Only locally authored guidance and safe configuration diagnostics are public.
// Raw database, network and subprocess errors may contain credentials.
type userError string

func (e userError) Error() string                 { return string(e) }
func userErrorf(format string, args ...any) error { return userError(fmt.Sprintf(format, args...)) }
func userMessage(e error) string {
	if message, ok := config.Explain(e); ok {
		return message
	}
	var guidance userError
	if errors.As(e, &guidance) {
		return guidance.Error()
	}
	var sqliteCode interface{ Code() int }
	if errors.As(e, &sqliteCode) && (sqliteCode.Code()&255 == 5 || sqliteCode.Code()&255 == 6) {
		return "数据库正在处理并发写入，本次操作未完成；现有数据和旧服务保留，请稍后重试"
	}
	return "操作失败，请查看宿主机管理日志；错误代码：" + common.SecretFree(e)
}
