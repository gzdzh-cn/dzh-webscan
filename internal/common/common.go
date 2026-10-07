package common

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Map = map[string]any

func M(v any) Map {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return Map{}
}
func S(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func F(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
func I(v any) int  { return int(F(v)) }
func B(v any) bool { b, _ := v.(bool); return b }
func A(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}
func SS(v any) []string {
	if a, ok := v.([]string); ok {
		return a
	}
	a := A(v)
	out := make([]string, 0, len(a))
	for _, v := range a {
		out = append(out, S(v))
	}
	return out
}
func Contains(a []string, s string) bool {
	for _, v := range a {
		if s == v {
			return true
		}
	}
	return false
}
func Clone(m Map) Map { b, _ := json.Marshal(m); out, _ := Decode(b); return M(out) }
func Merge(a, b Map) Map {
	out := Clone(a)
	for k, v := range b {
		if _, ok := v.(Map); ok {
			out[k] = Merge(M(out[k]), M(v))
		} else {
			out[k] = v
		}
	}
	return out
}
func Decode(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if e := d.Decode(&v); e != nil {
		return nil, errors.New("invalid_json")
	}
	var more any
	if d.Decode(&more) != io.EOF {
		return nil, errors.New("multiple_json_values")
	}
	return v, nil
}
func ReadJSON(path string) (Map, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	v, e := Decode(b)
	if e != nil {
		return nil, e
	}
	m, ok := v.(Map)
	if !ok {
		return nil, errors.New("expected_json_object")
	}
	return m, nil
}
func JSON(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func ID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func Hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func Now() float64         { return float64(time.Now().UnixNano()) / 1e9 }
func Stamp() string        { return time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00") }
func Atomic(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	if st, e := os.Lstat(path); e == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink_target")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".webscan-new-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func AtomicJSON(path string, v any) error { return Atomic(path, JSON(v), 0600) }
func HTTPClient(ca string, timeout time.Duration) (*http.Client, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 4
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		b, e := os.ReadFile(ca)
		if e != nil {
			return nil, e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid_ca")
		}
		t.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{Timeout: timeout, Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func Request(ctx context.Context, c *http.Client, method, url string, payload any, headers map[string]string) (int, any, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(JSON(payload))
	}
	r, e := http.NewRequestWithContext(ctx, method, url, body)
	if e != nil {
		return 0, nil, errors.New("request_invalid")
	}
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, e := c.Do(r)
	if e != nil {
		return 0, nil, errors.New("request_failed")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 4*1048576+1))
	if e != nil || len(b) > 4*1048576 {
		return resp.StatusCode, nil, errors.New("response_read_failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, nil, fmt.Errorf("http_status_%d", resp.StatusCode)
	}
	if len(b) == 0 {
		return resp.StatusCode, Map{}, nil
	}
	v, e := Decode(b)
	return resp.StatusCode, v, e
}
func Sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
func SecretFree(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if regexp.MustCompile(`^[a-z][a-z0-9_-]{1,180}$`).MatchString(message) {
		return message
	}
	return fmt.Sprintf("%T", err)
}

// Canonical produces Python json.dumps(sort_keys=True,ensure_ascii=False)
// wire bytes. Event digests use compact mode; rule versions use spaced mode.
func Canonical(v any, spaced bool) ([]byte, error) {
	var out bytes.Buffer
	var encode func(any) error
	comma, colon := ",", ":"
	if spaced {
		comma, colon = ", ", ": "
	}
	quote := func(s string) error {
		if !utf8.ValidString(s) {
			return errors.New("invalid_utf8")
		}
		out.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(r)
			case '\b':
				out.WriteString("\\b")
			case '\f':
				out.WriteString("\\f")
			case '\n':
				out.WriteString("\\n")
			case '\r':
				out.WriteString("\\r")
			case '\t':
				out.WriteString("\\t")
			default:
				if r < 32 {
					fmt.Fprintf(&out, "\\u%04x", r)
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
		return nil
	}
	encode = func(v any) error {
		switch x := v.(type) {
		case nil:
			out.WriteString("null")
		case string:
			return quote(x)
		case bool:
			out.WriteString(strconv.FormatBool(x))
		case json.Number:
			if strings.ContainsAny(string(x), ".eE") {
				f, e := x.Float64()
				if e != nil {
					return e
				}
				return encode(f)
			}
			if !regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`).MatchString(string(x)) {
				return errors.New("invalid_integer")
			}
			out.WriteString(string(x))
		case float64:
			if math.IsNaN(x) || math.IsInf(x, 0) {
				return errors.New("nonfinite_number")
			}
			s := strconv.FormatFloat(x, 'g', -1, 64)
			if x == 0 && math.Signbit(x) {
				s = "-0.0"
			} else if !strings.ContainsAny(s, ".e") {
				s += ".0"
			}
			abs := math.Abs(x)
			if abs >= 1e-4 && abs < 1e16 {
				s = strconv.FormatFloat(x, 'f', -1, 64)
				if !strings.Contains(s, ".") {
					s += ".0"
				}
			}
			out.WriteString(s)
		case Map:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					out.WriteString(comma)
				}
				if e := quote(k); e != nil {
					return e
				}
				out.WriteString(colon)
				if e := encode(x[k]); e != nil {
					return e
				}
			}
			out.WriteByte('}')
		default:
			r := reflect.ValueOf(v)
			switch r.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				out.WriteString(strconv.FormatInt(r.Int(), 10))
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				out.WriteString(strconv.FormatUint(r.Uint(), 10))
			case reflect.Slice, reflect.Array:
				out.WriteByte('[')
				for i := 0; i < r.Len(); i++ {
					if i > 0 {
						out.WriteString(comma)
					}
					if e := encode(r.Index(i).Interface()); e != nil {
						return e
					}
				}
				out.WriteByte(']')
			default:
				return errors.New("unsupported_json_type")
			}
		}
		return nil
	}
	e := encode(v)
	return out.Bytes(), e
}
