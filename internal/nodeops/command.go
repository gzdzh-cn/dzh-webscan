package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// Command accepts one bounded JSON request on stdin. Paths and commands cannot
// be supplied by the caller. Once a request has been read, SSH hangup must not
// turn a completed phase into an unrecorded success. Hard crashes are reconciled
// from the durable running row on the next invocation.
func Command(_ context.Context, in io.Reader, out io.Writer) error {
	return command(in, out, false)
}

// CommandLifecycle enables the fixed native/Docker service phases. The default
// preparation command remains read-only with respect to running services. Only
// the trusted central executor emits the static --lifecycle switch.
func CommandLifecycle(_ context.Context, in io.Reader, out io.Writer) error {
	return command(in, out, true)
}

func command(in io.Reader, out io.Writer, lifecycle bool) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return errors.New("node-v3-requires-root-linux-amd64")
	}
	r, err := decodeRequest(in)
	if err != nil {
		return err
	}
	signal.Ignore(syscall.SIGHUP)
	defer signal.Reset(syscall.SIGHUP)
	handler := Handler(NewLocalRuntime())
	if lifecycle {
		handler, err = lifecycleHandler(r)
		if err != nil {
			return err
		}
	}
	j, err := Open(Root, handler)
	if err != nil {
		return errors.New("node-v3-journal-unavailable")
	}
	res := j.Handle(r)
	if err = json.NewEncoder(out).Encode(res); err != nil {
		return errors.New("node-v3-response-unavailable")
	}
	if res.Code != "ok" {
		return errors.New("node-v3-operation-failed")
	}
	return nil
}

func lifecycleHandler(r Request) (Handler, error) {
	if r.Validate() != nil || !r.Spec.configurationValid() || r.Spec.Mode == "docker" && !ValidAgentImage(r.Spec.AgentImage) {
		return nil, errors.New("node-v3-lifecycle-requires-bound-runtime")
	}
	var h Handler = newDockerLifecycle()
	if r.Spec.Mode == "native" {
		h = newNativeLifecycle()
	}
	if r.Uninstall != nil {
		return withUninstall(h), nil
	}
	if r.Recovery != nil {
		return withRecovery(h), nil
	}
	return h, nil
}

func decodeRequest(in io.Reader) (Request, error) {
	var r Request
	raw, err := io.ReadAll(io.LimitReader(in, MaxRequestBytes+1))
	if err != nil || len(raw) > MaxRequestBytes {
		return r, errors.New("invalid-node-v3-request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Validate() != nil {
		return Request{}, errors.New("invalid-node-v3-request")
	}
	return r, nil
}
