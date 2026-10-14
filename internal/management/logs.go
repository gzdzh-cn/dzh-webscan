package management

import (
	"bytes"
	"sync"
)

// Redaction runs on complete lines, including secrets split across subprocess writes.
type lineWriter struct {
	mu     sync.Mutex
	buffer []byte
	writer logWriter
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buffer = append(w.buffer, p...)
	for {
		i := bytes.IndexByte(w.buffer, '\n')
		if i < 0 {
			break
		}
		if _, e := w.writer.Write(w.buffer[:i+1]); e != nil {
			return 0, e
		}
		w.buffer = w.buffer[i+1:]
	}
	if len(w.buffer) > 64<<10 {
		w.buffer = nil
		_, e := w.writer.Write([]byte("[过长日志行已省略]\n"))
		if e != nil {
			return 0, e
		}
	}
	return len(p), nil
}
func (w *lineWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buffer) > 0 {
		w.writer.Write(w.buffer)
		w.buffer = nil
	}
}
