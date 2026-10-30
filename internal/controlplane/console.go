package controlplane

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"webscan/internal/website"
)

// The v3 entry is separate from the released v2 index. Never fall back to a
// v2 page that would issue requests against the wrong business API.
func serveConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		failure(w, 405, "method_not_allowed", "请使用 GET 或 HEAD")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name != "" && name != path.Clean(name) || strings.Contains(name, "\\") || strings.ContainsRune(name, '\x00') {
		http.NotFound(w, r)
		return
	}
	asset := strings.HasPrefix(name, "assets/")
	if !asset {
		if name != "" && name != "v3.html" && name != "login" && name != "servers" && name != "events" && name != "alerts" && name != "settings" && name != "backups" && name != "config-backups" && name != "websites" && name != "deployments" && !consoleWebsitePath(name) && !consoleDetailPath(name, "servers/") && !consoleDetailPath(name, "deployments/") {
			http.NotFound(w, r)
			return
		}
		name = "v3.html"
	}
	data, err := fs.ReadFile(website.UI, "ui/"+name)
	if err != nil {
		if asset {
			http.NotFound(w, r)
		} else {
			failure(w, 503, "console_unavailable", "v3 网页尚未构建，请先构建前端并重新编译主控")
		}
		return
	}
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if asset {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

func consoleDetailPath(name, prefix string) bool {
	return strings.HasPrefix(name, prefix) && identifier.MatchString(strings.TrimPrefix(name, prefix))
}

func consoleWebsitePath(name string) bool {
	if !strings.HasPrefix(name, "websites/") {
		return false
	}
	raw := strings.TrimPrefix(name, "websites/")
	id, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && id > 0 && strconv.FormatInt(id, 10) == raw
}
