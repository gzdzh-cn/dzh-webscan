package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"webscan/internal/common"
)

const composeSHA = "7af95166a730b87e172d4fc9aefea8725d3c6c7327d59149267b452114ddb7d4"

func (d *Deploy) installComposeFallback(ctx context.Context, r *Remote) error {
	path := filepath.Join(StateRoot, "helpers", "docker-compose-v2.39.4")
	b, e := os.ReadFile(path)
	if e != nil || common.Hash(b) != composeSHA {
		if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			return e
		}
		tmp := path + ".new"
		defer os.Remove(tmp)
		if _, e = RunCommand(ctx, nil, "curl", "-fsSL", "--connect-timeout", "15", "--max-time", "180", "--retry", "2", "https://github.com/docker/compose/releases/download/v2.39.4/docker-compose-linux-x86_64", "-o", tmp); e != nil {
			return errors.New("compose_verified_download_failed")
		}
		b, e = os.ReadFile(tmp)
		if e != nil || common.Hash(b) != composeSHA {
			return errors.New("compose_checksum_mismatch")
		}
		if e = common.Atomic(path, b, 0700); e != nil {
			return e
		}
	}
	if e = r.Write(ctx, "/usr/local/lib/docker/cli-plugins/docker-compose", b, 0755); e != nil {
		return e
	}
	_, e = r.Run(ctx, "test \"$(sha256sum /usr/local/lib/docker/cli-plugins/docker-compose | cut -d ' ' -f1)\" = "+Q(composeSHA)+" && docker compose version >/dev/null")
	if e != nil {
		return errors.New("compose_plugin_verification_failed")
	}
	return nil
}
