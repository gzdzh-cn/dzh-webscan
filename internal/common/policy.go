package common

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var RuleFields = []string{"exclude_paths", "extensions", "important_filenames", "critical_paths"}

type Exclusion struct {
	Prefix   string
	Parts    []string
	Matchers []*regexp.Regexp
}

func NewExclusion(pattern string) (Exclusion, error) {
	pattern = filepath.Clean(pattern)
	parts := strings.Split(strings.Trim(pattern, "/"), "/")
	first := len(parts)
	for i, p := range parts {
		if strings.ContainsAny(p, "*?[") {
			first = i
			break
		}
	}
	prefix := "/" + strings.Join(parts[:first], "/")
	matchers := make([]*regexp.Regexp, len(parts[first:]))
	for i, p := range parts[first:] {
		if p != "**" {
			matcher, e := segmentGlob(p)
			if e != nil {
				return Exclusion{}, errors.New("invalid_glob")
			}
			matchers[i] = matcher
		}
	}
	return Exclusion{prefix, parts[first:], matchers}, nil
}
func Inside(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimRight(root, "/")+"/")
}
func (e Exclusion) Matches(p string) bool {
	p = filepath.Clean(p)
	if !Inside(p, e.Prefix) {
		return false
	}
	if len(e.Parts) == 0 {
		return true
	}
	suffix := strings.Trim(p[len(e.Prefix):], "/")
	components := []string{}
	if suffix != "" {
		components = strings.Split(suffix, "/")
	}
	closure := func(states map[int]bool) map[int]bool {
		for i := 0; i < len(e.Parts); i++ {
			if states[i] && e.Parts[i] == "**" {
				states[i+1] = true
			}
		}
		return states
	}
	states := closure(map[int]bool{0: true})
	for _, component := range components {
		if states[len(e.Parts)] {
			return true
		}
		next := map[int]bool{}
		for i := range states {
			if i >= len(e.Parts) {
				continue
			}
			if e.Parts[i] == "**" {
				next[i] = true
			} else {
				matcher := e.Matchers[i]
				if matcher != nil && matcher.MatchString(component) {
					next[i+1] = true
				}
			}
		}
		states = closure(next)
		if len(states) == 0 {
			return false
		}
	}
	return states[len(e.Parts)]
}

type Policy struct {
	Monitor                                Map
	Roots, Extensions, Important, Critical []string
	Exclusions                             []Exclusion
}

var controls = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// FieldError keeps stable error codes while locating a rule without exposing its value.
type FieldError struct {
	Err   error
	Field string
}

func (e *FieldError) Error() string { return e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

func NewPolicy(m Map) (_ *Policy, err error) {
	field := ""
	defer func() {
		if err != nil {
			err = &FieldError{Err: err, Field: field}
		}
	}()
	m = Clone(m)
	p := &Policy{Monitor: m}
	for _, key := range []string{"roots", "exclude_paths", "critical_paths", "extensions", "important_filenames"} {
		field = key
		v, ok := m[key]
		if !ok {
			return nil, errors.New("missing_monitor_field")
		}
		a := SS(v)
		if len(a) > 10000 {
			return nil, errors.New("filter_list_too_large")
		}
		if _, ok := v.([]string); !ok {
			if _, ok = v.([]any); !ok {
				return nil, errors.New("invalid_filter_list")
			}
		}
		for i, s := range a {
			field = fmt.Sprintf("%s[%d]", key, i)
			if s == "" || controls.MatchString(s) {
				return nil, errors.New("invalid_filter")
			}
			if key == "roots" || key == "exclude_paths" || key == "critical_paths" {
				if !filepath.IsAbs(s) || Contains(strings.Split(s, "/"), "..") {
					return nil, errors.New("invalid_absolute_path")
				}
				a[i] = filepath.Clean(s)
			}
			if key == "extensions" {
				if !regexp.MustCompile(`^\.[a-zA-Z0-9]+$`).MatchString(s) {
					return nil, errors.New("invalid_extension")
				}
				a[i] = strings.ToLower(s)
			}
			if key == "important_filenames" && strings.Contains(s, "/") {
				return nil, errors.New("invalid_filename")
			}
		}
		m[key] = a
	}
	p.Roots = SS(m["roots"])
	p.Critical = SS(m["critical_paths"])
	p.Important = SS(m["important_filenames"])
	p.Extensions = SS(m["extensions"])
	field = "roots"
	if len(p.Roots) == 0 {
		return nil, errors.New("empty_roots")
	}
	for i, s := range SS(m["exclude_paths"]) {
		field = fmt.Sprintf("exclude_paths[%d]", i)
		e, err := NewExclusion(s)
		if err != nil {
			return nil, err
		}
		valid := false
		for _, root := range p.Roots {
			valid = valid || Inside(e.Prefix, root)
			if e.Matches(root) {
				return nil, errors.New("exclude_matches_root")
			}
		}
		if !valid {
			return nil, errors.New("exclude_prefix_outside_roots")
		}
		for _, critical := range p.Critical {
			if e.Matches(critical) {
				return nil, errors.New("exclude_matches_critical")
			}
		}
		p.Exclusions = append(p.Exclusions, e)
	}
	return p, nil
}
func (p *Policy) Excluded(path string) bool {
	for _, e := range p.Exclusions {
		if e.Matches(path) {
			return true
		}
	}
	return false
}
func (p *Policy) Tracked(path, probe string) bool {
	if probe != "" && strings.HasPrefix(path, strings.TrimRight(probe, "/")+"/") {
		return true
	}
	if p.Excluded(path) {
		return false
	}
	if Contains(p.Critical, path) {
		return true
	}
	inside := false
	for _, root := range p.Roots {
		inside = inside || path != root && Inside(path, root)
	}
	return inside && (Contains(p.Important, filepath.Base(path)) || Contains(p.Extensions, strings.ToLower(filepath.Ext(path))))
}
func (p *Policy) Watches(path, probe string) bool {
	if p.Excluded(path) {
		return false
	}
	for _, root := range append(append([]string{}, p.Roots...), probe) {
		if root != "" && Inside(path, root) {
			return true
		}
	}
	for _, critical := range p.Critical {
		if filepath.Dir(critical) == path {
			return true
		}
	}
	return false
}
func (p *Policy) Version(yara []byte) string {
	m := Map{"roots": p.Roots, "yara_sha256": Hash(yara)}
	for _, key := range RuleFields {
		m[key] = p.Monitor[key]
	}
	b, e := Canonical(m, true)
	if e != nil {
		panic(e)
	}
	return Hash(b)
}

// segmentGlob follows Python fnmatch classes, including [!a] and literal unmatched [.
func segmentGlob(pattern string) (*regexp.Regexp, error) {
	r := []rune(pattern)
	var b strings.Builder
	b.WriteString("^(?:")
	for i := 0; i < len(r); i++ {
		switch r[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i + 1
			if j < len(r) && r[j] == '!' {
				j++
			}
			if j < len(r) && r[j] == ']' {
				j++
			}
			for j < len(r) && r[j] != ']' {
				j++
			}
			if j == len(r) {
				b.WriteString(`\[`)
				continue
			}
			cls := string(r[i+1 : j])
			if strings.HasPrefix(cls, "!") {
				cls = "^" + cls[1:]
			} else if strings.HasPrefix(cls, "^") {
				cls = `\^` + cls[1:]
			}
			cls = strings.ReplaceAll(cls, `\`, `\\`)
			b.WriteString("[" + cls + "]")
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(r[i])))
		}
	}
	b.WriteString(")$")
	return regexp.Compile(b.String())
}
