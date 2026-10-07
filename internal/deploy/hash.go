package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
)

type shaReader struct {
	r io.Reader
	h hash.Hash
}

func newSHAReader(r io.Reader) *shaReader       { return &shaReader{r, sha256.New()} }
func (r *shaReader) Read(p []byte) (int, error) { n, e := r.r.Read(p); r.h.Write(p[:n]); return n, e }
func (r *shaReader) Sum() string                { return hex.EncodeToString(r.h.Sum(nil)) }
