package central

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"webscan/internal/retention"
	"webscan/internal/website"
)

func (s *Store) retentionAPI(w http.ResponseWriter, r *http.Request) {
	owner := website.AuthenticatedUsername(r)
	if owner == "" {
		consoleError(w, 401, "请先登录网站监控后台")
		return
	}
	if s.Retention == nil {
		consoleError(w, 503, "历史清理服务尚未启用")
		return
	}
	var value any
	var err error
	path := strings.TrimPrefix(r.URL.Path, "/api/retention/")
	switch {
	case path == "status" && r.Method == "GET":
		value, err = s.Retention.Status(r.Context())
	case path == "jobs" && r.Method == "GET":
		p, size := page(r)
		value, err = s.Retention.Jobs(r.Context(), owner, p, size)
	case strings.HasPrefix(path, "jobs/") && r.Method == "GET":
		parts := strings.Split(strings.TrimPrefix(path, "jobs/"), "/")
		if !retention.ValidID(parts[0]) {
			consoleError(w, 400, "任务编号不正确")
			return
		}
		if len(parts) == 2 && parts[1] == "download" {
			var file string
			file, err = s.Retention.Download(r.Context(), owner, parts[0])
			if err == nil {
				w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
				w.Header().Set("Content-Disposition", `attachment; filename="history-`+parts[0]+`.jsonl"`)
				http.ServeFile(w, r, file)
				return
			}
		} else if len(parts) == 1 {
			value, err = s.Retention.Job(r.Context(), owner, parts[0])
		} else {
			consoleError(w, 404, "任务接口不存在")
			return
		}
	case (path == "preview" || path == "export" || path == "cleanup") && r.Method == "POST":
		var body struct {
			retention.Filter
			Preview   string `json:"preview"`
			ExportJob string `json:"export_job"`
			Confirm   bool   `json:"confirm"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil || decoder.Decode(new(any)) != io.EOF {
			consoleError(w, 400, "请求内容格式不正确")
			return
		}
		if path == "preview" {
			value, err = s.Retention.Preview(r.Context(), owner, body.Filter)
		} else {
			if path == "cleanup" && !body.Confirm {
				consoleError(w, 400, "请确认清理范围，历史删除后不能通过调大期限恢复")
				return
			}
			kind := "cleanup"
			if path == "export" {
				kind = "export"
			}
			value, err = s.Retention.Create(r.Context(), owner, kind, body.Preview, body.ExportJob)
		}
	default:
		consoleError(w, 405, "此接口不支持当前请求方法")
		return
	}
	if err != nil {
		if path == "status" || path == "jobs" {
			consoleError(w, 503, "历史数据读取失败，请稍后重试")
		} else {
			consoleError(w, 400, retention.Message(err))
		}
		return
	}
	write(w, 200, value)
}
