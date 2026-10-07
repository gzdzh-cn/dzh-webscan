//go:build linux

package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"webscan/internal/common"
)

type scanTask struct{ ID, Path, Hash string }

func (a *Agent) scans(ctx context.Context) {
	for ctx.Err() == nil {
		a.counter("scan_heartbeat_seconds", common.Now(), true)
		a.writeMu.Lock()
		tx, e := a.DB.Begin()
		task := scanTask{}
		if e == nil {
			e = tx.QueryRow("SELECT id,path,hash FROM scans WHERE lease<? LIMIT 1", common.Now()).Scan(&task.ID, &task.Path, &task.Hash)
			if e == nil {
				_, e = tx.Exec("UPDATE scans SET lease=? WHERE id=?", common.Now()+300, task.ID)
			}
			if e == nil {
				e = tx.Commit()
			} else {
				tx.Rollback()
			}
		}
		a.writeMu.Unlock()
		if e != nil {
			if e != sql.ErrNoRows {
				fmt.Println("scan_claim_error=" + common.SecretFree(e))
			}
			common.Sleep(ctx, 500*time.Millisecond)
			continue
		}
		if e = a.Scan(ctx, task); e != nil {
			fmt.Println("scan_save_error=" + common.SecretFree(e))
			common.Sleep(ctx, time.Second)
		}
	}
}
func (a *Agent) Scan(ctx context.Context, t scanTask) error {
	rules := a.rules.Load()
	results := common.Map{}
	if rules.Policy.Tracked(t.Path, a.Probe) {
		for _, tool := range []string{"yara", "clamav"} {
			spec := common.M(common.M(a.C["scan"])[tool])
			if !common.B(spec["enabled"]) {
				continue
			}
			result, e := a.scanEngine(ctx, t, tool, spec, rules.Yara)
			if e != nil {
				result = common.Map{"status": "error", "reason": common.SecretFree(e)}
			}
			results[tool] = result
		}
	}
	status := "no_match"
	for _, tool := range []string{"yara", "clamav"} {
		switch common.S(common.M(results[tool])["status"]) {
		case "matched":
			status = "matched"
		case "error":
			if status != "matched" {
				status = "error"
			}
		case "skipped":
			if status == "no_match" {
				status = "skipped"
			}
		}
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	tx, e := a.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if a.rules.Load().Policy.Tracked(t.Path, a.Probe) {
		risk := "unclassified"
		if status == "matched" {
			risk = "high"
		}
		if e = a.event(tx, "scan", t.Path, t.Hash, common.Map{"related_event_id": t.ID, "rules_version": rules.Version, "scan": common.Map{"status": status, "engines": results}, "risk": risk}); e != nil {
			return e
		}
	}
	if _, e = tx.Exec("DELETE FROM scans WHERE id=?", t.ID); e != nil {
		return e
	}
	return tx.Commit()
}
func (a *Agent) scanEngine(ctx context.Context, t scanTask, tool string, spec common.Map, yara []byte) (common.Map, error) {
	info, e := os.Lstat(t.Path)
	if e != nil {
		return nil, e
	}
	maximum := int64(common.I(spec["max_file_mib"])) * 1048576
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return common.Map{"status": "skipped", "reason": "type_or_size"}, nil
	}
	real, e := filepath.EvalSymlinks(t.Path)
	if e != nil || real != t.Path {
		return nil, errors.New("scan_symlink_path")
	}
	source, e := openSnapshotSource(t.Path)
	if e != nil {
		return nil, e
	}
	defer source.Close()
	temp, e := os.CreateTemp(a.Data, "scan-*.php")
	if e != nil {
		return nil, e
	}
	name := temp.Name()
	defer os.Remove(name)
	defer temp.Close()
	hashReader := newHashReader(source)
	n, e := io.Copy(temp, io.LimitReader(hashReader, maximum+1))
	if e != nil {
		return nil, e
	}
	if n > maximum {
		return nil, errors.New("scan_size_changed")
	}
	if hashReader.Sum() != t.Hash {
		return nil, errors.New("content_changed_before_scan")
	}
	if e = temp.Sync(); e != nil {
		return nil, e
	}
	run, cancel := context.WithTimeout(ctx, time.Duration(common.I(spec["timeout_seconds"]))*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if tool == "yara" {
		rules, e := os.CreateTemp(a.Data, "rules-snapshot-*.yar")
		if e != nil {
			return nil, e
		}
		defer os.Remove(rules.Name())
		if _, e = rules.Write(yara); e != nil {
			rules.Close()
			return nil, e
		}
		rules.Close()
		cmd = exec.CommandContext(run, "yara", "-w", rules.Name(), name)
	} else {
		cmd = exec.CommandContext(run, "clamdscan", "--fdpass", "--no-summary", name)
	}
	output := &limitedOutput{Limit: 65536}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	e = cmd.Run()
	code := 0
	if e != nil {
		exit, ok := e.(*exec.ExitError)
		if !ok {
			return nil, errors.New("scanner_failed")
		}
		code = exit.ExitCode()
	}
	if run.Err() != nil || tool == "yara" && code != 0 || tool == "clamav" && code != 0 && code != 1 {
		return nil, errors.New("scanner_exit")
	}
	matches := []string{}
	if tool == "yara" {
		for _, line := range strings.Split(strings.TrimSpace(string(output.Bytes)), "\n") {
			if line != "" {
				matches = append(matches, strings.SplitN(line, " ", 2)[0])
				if len(matches) == 50 {
					break
				}
			}
		}
	} else if code == 1 {
		matches = []string{"ClamAV"}
	}
	status := "no_match"
	if len(matches) > 0 {
		status = "matched"
	}
	return common.Map{"status": status, "matches": matches}, nil
}

type limitedOutput struct {
	Bytes []byte
	Limit int
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.Bytes) < b.Limit {
		b.Bytes = append(b.Bytes, p[:min(len(p), b.Limit-len(b.Bytes))]...)
	}
	return n, nil
}
