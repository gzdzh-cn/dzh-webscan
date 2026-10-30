#!/usr/bin/env bash
# Isolated validation only. Never attach the host socket or business paths to
# DinD. No image push, production SSH, global Docker cleanup or Git changes.
set -euo pipefail
cd "$(dirname "$0")/.."
task_root="$(pwd)"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/docker-lifecycle.XXXXXX")"
chmod 700 "$task_run"
task_dind_id=""
task_source_id=""
cleanup() {
  if [[ -n "$task_source_id" ]]; then docker rm -v "$task_source_id" >/dev/null 2>&1 || true; fi
  if [[ -n "$task_dind_id" ]]; then
    docker logs "$task_dind_id" > "$task_run/daemon.log" 2>&1 || true
    docker rm -fv "$task_dind_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
for task_command in docker go python3; do command -v "$task_command" >/dev/null; done
task_arch="$(docker info --format '{{.Architecture}}')"
case "$task_arch" in
  amd64|x86_64) task_arch=amd64 ;;
  arm64|aarch64) task_arch=arm64 ;;
  *) printf 'Unsupported isolated daemon architecture: %s\n' "$task_arch" >&2; exit 1 ;;
esac
task_image="${WEBSCAN_V3_AGENT_TEST_IMAGE:-gzdzh/webscan-agent:v2.0.46}"
docker image inspect "$task_image" > "$task_run/image-inspect.json"
# Pin a multiarchitecture manifest; no change to the user's cached Agent tags.
task_dind_image="${WEBSCAN_V3_DIND_IMAGE:-docker:27-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce}"
# An explicit digest prevents a mutable tag from silently changing the test
# engine between runs; allow Docker 29 to be tested with the same harness.
if [[ ! "$task_dind_image" =~ @sha256:[0-9a-f]{64}$ ]]; then
  printf 'WEBSCAN_V3_DIND_IMAGE must be pinned by sha256 digest\n' >&2
  exit 1
fi
docker pull --platform "linux/$task_arch" "$task_dind_image" > "$task_run/pull.log" 2>&1
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags '-X webscan/internal/deploy.Release=v3.0.0-local-test' \
  -o "$task_run/webscan-linux-amd64" ./cmd/webscan
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodeops.test" ./internal/nodeops
task_source_id="$(docker create --platform linux/amd64 "$task_image")"
docker cp "$task_source_id:/usr/local/lib/webscan/agent-native.tar.gz" "$task_run/tools.tar.gz"
docker rm -v "$task_source_id" >/dev/null
task_source_id=""
docker image save --output "$task_run/agent-image.tar" "$task_image"
chmod 600 "$task_run/agent-image.tar"
python3 - "$task_run" <<'PY'
import hashlib, io, json, pathlib, sys, tarfile
from scripts.v3_saved_image_config import saved_image_config
root = pathlib.Path(sys.argv[1])
with tarfile.open(root / 'tools.tar.gz', 'r:gz') as archive:
    files = {entry.name.removeprefix('./'): (archive.extractfile(entry).read(), entry.mode)
             for entry in archive.getmembers() if entry.isfile()}
files['webscan'] = ((root / 'webscan-linux-amd64').read_bytes(), 0o755)
files['VERSION'] = (b'v3.0.0-local-test\n', 0o644)
files['SHA256SUMS'] = (''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
    for name, (data, mode) in sorted(files.items()) if name != 'SHA256SUMS').encode(), 0o644)
with tarfile.open(root / 'agent-native.tar.gz', 'w:gz') as archive:
    for name, (data, mode) in sorted(files.items()):
        entry = tarfile.TarInfo(name)
        entry.size, entry.mode = len(data), mode
        archive.addfile(entry, io.BytesIO(data))
image = json.loads((root / 'image-inspect.json').read_text())[0]
if image['Os'] != 'linux' or image['Architecture'] != 'amd64' or not image.get('RepoDigests'):
    raise SystemExit('A cached immutable Linux amd64 Agent fixture is required')
archive = root / 'agent-image.tar'
hasher = hashlib.sha256()
with archive.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        hasher.update(chunk)
proof = {'mode': 'docker', 'metrics_port': 19100, 'monitor_directories': ['/'],
         'artifact_bytes': 0, 'clamav': False, 'agent_image': image['RepoDigests'][0],
         'image_archive_sha256': hasher.hexdigest(), 'image_archive_bytes': archive.stat().st_size,
         'image_config_sha256': saved_image_config(archive)}
(root / 'image-proof.json').write_text(json.dumps(proof))
(root / 'isolated-engine').write_text('webscan-v3-disposable-dind\n')
(root / 'isolated-engine').chmod(0o600)
PY
# No bind mounts, exposed ports or host namespaces. The only privileged service
# is this short-lived isolated daemon. Its data volume is removed by exact ID.
task_dind_id="$(docker run -d --rm --platform "linux/$task_arch" --privileged --network none \
  -e DOCKER_TLS_CERTDIR= "$task_dind_image" dockerd \
  --host unix:///var/run/docker.sock --bridge=none --iptables=false --ip6tables=false --storage-driver=vfs)"
printf '%s\n' "$task_dind_id" > "$task_run/daemon.id"
for task_attempt in {1..60}; do
  if docker exec "$task_dind_id" docker info --format '{{.ServerVersion}} {{.Architecture}} {{.Driver}}' > "$task_run/engine.txt" 2>/dev/null; then break; fi
  if [[ "$task_attempt" == 60 ]]; then printf 'Isolated daemon did not start\n' >&2; exit 1; fi
  sleep 1
done
docker exec "$task_dind_id" mkdir -m 700 /v3-tests
for task_file in nodeops.test agent-native.tar.gz agent-image.tar image-proof.json isolated-engine; do
  docker cp "$task_run/$task_file" "$task_dind_id:/v3-tests/$task_file"
done
docker exec "$task_dind_id" docker load --input /v3-tests/agent-image.tar > "$task_run/load.log" 2>&1
docker exec -e WEBSCAN_V3_TEST_DIND=1 "$task_dind_id" /v3-tests/nodeops.test \
  -test.run '^TestDockerLifecycleOnDisposableNestedEngine$' -test.v -test.timeout 6m | tee "$task_run/lifecycle.log"
printf 'Evidence: %s\n' "$task_run"
printf 'Engine switching tested; successful native amd64 kernel verification and finalization are not certified.\n'
