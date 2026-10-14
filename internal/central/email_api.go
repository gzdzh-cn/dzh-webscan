package central

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"webscan/internal/common"
	"webscan/internal/notify"
)

func (s *Store) emailAPI(w http.ResponseWriter, r *http.Request) {
	enabled := common.B(common.M(s.Snapshot()["email"])["enabled"])
	if strings.HasSuffix(r.URL.Path, "/stats") {
		rows, e := s.DB.QueryContext(r.Context(), "SELECT strftime('%Y-%m-%d',t.created,'unixepoch','+8 hours'),sum(r.done IS NOT NULL),sum(r.done IS NULL AND r.attempts=0),sum(r.done IS NULL AND r.attempts>0) FROM tasks t JOIN email_recipients r ON r.task_id=t.id WHERE t.target='email' AND t.created>=? GROUP BY 1 ORDER BY 1", common.Now()-7*86400)
		if e != nil {
			consoleError(w, 503, "邮箱统计读取失败")
			return
		}
		defer rows.Close()
		items := []common.Map{}
		for rows.Next() {
			var day string
			var done, pending, retry int
			if e = rows.Scan(&day, &done, &pending, &retry); e != nil {
				consoleError(w, 503, "邮箱统计读取失败")
				return
			}
			items = append(items, common.Map{"day": day, "delivered": done, "pending": pending, "retrying": retry})
		}
		if rows.Err() != nil {
			consoleError(w, 503, "邮箱统计读取失败")
			return
		}
		write(w, 200, common.Map{"items": items})
		return
	}
	var selected int64
	if strings.HasPrefix(r.URL.Path, "/api/notifications/") {
		var e error
		selected, e = strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/notifications/"), 10, 64)
		if e != nil {
			consoleError(w, 400, "通知编号不正确")
			return
		}
	}
	// Query parent tasks once; recipient result data is bounded (at most 20).
	q := " FROM tasks t WHERE target='email'"
	args := []any{}
	if selected > 0 {
		q += " AND t.id=?"
		args = append(args, selected)
	}
	if node := r.URL.Query().Get("node"); node != "" {
		q += " AND (t.node=? OR json_extract(t.payload,'$.node_id')=?)"
		args = append(args, node, node)
	}
	if recipient := r.URL.Query().Get("recipient"); recipient != "" {
		q += " AND EXISTS(SELECT 1 FROM email_recipients er WHERE er.task_id=t.id AND er.recipient LIKE ?)"
		args = append(args, "%"+recipient+"%")
	}
	statusExpr := `CASE WHEN t.done IS NOT NULL THEN 'delivered' WHEN NOT ? THEN 'paused' WHEN EXISTS(SELECT 1 FROM email_recipients er WHERE er.task_id=t.id AND er.done IS NOT NULL) THEN 'partial' WHEN t.attempts>0 THEN 'retrying' ELSE 'pending' END`
	if status := r.URL.Query().Get("status"); status != "" {
		q += " AND (" + statusExpr + ")=?"
		args = append(args, enabled, status)
	}
	if search := r.URL.Query().Get("q"); search != "" {
		q += " AND payload LIKE ?"
		args = append(args, "%"+search+"%")
	}
	q, args = timeFilter(r, q, args, "created")
	var total int
	if e := s.DB.QueryRowContext(r.Context(), "SELECT count(*)"+q, args...).Scan(&total); e != nil {
		consoleError(w, 503, "邮箱历史读取失败")
		return
	}
	p, size := page(r)
	rows, e := s.DB.QueryContext(r.Context(), "SELECT id,node,payload,created,done,attempts,next_try,coalesce(result,'')"+q+" ORDER BY id DESC LIMIT ? OFFSET ?", append(args, size, (p-1)*size)...)
	if e != nil {
		consoleError(w, 503, "邮箱历史读取失败")
		return
	}
	items := []common.Map{}
	for rows.Next() {
		var id int64
		var node, raw, result string
		var tm, next float64
		var done sql.NullFloat64
		var attempts int
		if e = rows.Scan(&id, &node, &raw, &tm, &done, &attempts, &next, &result); e != nil {
			break
		}
		v, _ := common.Decode([]byte(raw))
		payload := common.M(v)
		message := common.S(payload["message"])
		if actual := common.S(payload["node_id"]); actual != "" {
			node = actual
		}
		items = append(items, common.Map{"id": id, "node": node, "message": message, "subject": emailSubject(message), "time": tm, "done": done.Float64, "attempts": attempts, "next_try": next, "result": result, "source": payload["source"]})
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		consoleError(w, 503, "邮箱历史读取失败")
		return
	}
	for _, item := range items {
		rs, err := s.DB.QueryContext(r.Context(), "SELECT recipient,attempts,next_try,done,result FROM email_recipients WHERE task_id=? ORDER BY recipient", item["id"])
		if err != nil {
			consoleError(w, 503, "收件记录读取失败")
			return
		}
		recipients := []common.Map{}
		accepted := 0
		for rs.Next() {
			var recipient, res string
			var attempts int
			var next float64
			var done sql.NullFloat64
			if err = rs.Scan(&recipient, &attempts, &next, &done, &res); err != nil {
				break
			}
			if done.Valid {
				accepted++
			}
			recipients = append(recipients, common.Map{"recipient": recipient, "attempts": attempts, "next_try": next, "done": done.Float64, "result": res})
		}
		if err == nil {
			err = rs.Err()
		}
		rs.Close()
		if err != nil {
			consoleError(w, 503, "收件记录读取失败")
			return
		}
		status := "pending"
		if common.F(item["done"]) > 0 {
			status = "delivered"
		} else if !enabled {
			status = "paused"
		} else if accepted > 0 {
			status = "partial"
		} else if common.I(item["attempts"]) > 0 {
			status = "retrying"
		}
		item["status"], item["recipients"] = status, recipients
		if selected > 0 {
			attempts, err := s.DB.QueryContext(r.Context(), "SELECT recipient,time,result FROM email_attempts WHERE task_id=? ORDER BY id", selected)
			if err != nil {
				consoleError(w, 503, "邮箱尝试记录读取失败")
				return
			}
			records := []common.Map{}
			for attempts.Next() {
				var recipient, res string
				var tm float64
				if err = attempts.Scan(&recipient, &tm, &res); err != nil {
					break
				}
				records = append(records, common.Map{"recipient": recipient, "time": tm, "result": res})
			}
			if err == nil {
				err = attempts.Err()
			}
			attempts.Close()
			if err != nil {
				consoleError(w, 503, "邮箱尝试记录读取失败")
				return
			}
			item["records"] = records
			write(w, 200, item)
			return
		}
	}
	if selected > 0 {
		consoleError(w, 404, "邮箱通知不存在或已过保留期")
		return
	}
	write(w, 200, common.Map{"items": items, "total": total, "enabled": enabled, "configured_recipients": notify.Recipients(common.M(s.Snapshot()["email"]))})
}
