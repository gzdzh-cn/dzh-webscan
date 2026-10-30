#!/usr/bin/env bash
# Real vendor objects in a disposable, network-isolated DinD daemon. No host
# socket, production paths, real service manager, push destination or Git writes.
set -euo pipefail
cd "$(dirname "$0")/.."
task_root="$(pwd)"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/wrapper-objects.XXXXXX")"
chmod 700 "$task_run"
task_dind_id=""
cleanup() {
  if [[ -n "$task_dind_id" ]]; then
    docker logs "$task_dind_id" > "$task_run/daemon.log" 2>&1 || true
    docker rm -fv "$task_dind_id" > "$task_run/cleanup.log" 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
task_arch="$(docker info --format '{{.Architecture}}')"
case "$task_arch" in
  amd64|x86_64) task_arch=amd64 ;;
  arm64|aarch64) task_arch=arm64 ;;
  *) echo 'Unsupported disposable daemon architecture' >&2; exit 1 ;;
esac
task_dind_image='docker:27-dind@sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce'
task_vector_image='timberio/vector@sha256:385f534a0bad5bb58a06c3a261ad7b5a2b170ce2f1f035d32019503c23e8fc07'
task_exporter_image='prom/node-exporter@sha256:d00a542e409ee618a4edc67da14dd48c5da66726bbd5537ab2af9c1dfc442c8a'
docker image inspect "$task_vector_image" "$task_exporter_image" > "$task_run/images.json"
docker image inspect "$task_dind_image" > "$task_run/daemon-image.json"
python3 - "$task_run" <<'PY'
import json,pathlib,re,sys
root=pathlib.Path(sys.argv[1])
images=json.loads((root/'images.json').read_text())
if len(images)!=2:
    raise SystemExit('Both vendor image records are required')
for role,image in zip(['vector','exporter'],images):
    if image['Os']!='linux' or image['Architecture']!='amd64' or not re.fullmatch(r'sha256:[a-f0-9]{64}',image['Id']):
        raise SystemExit('Cached Linux amd64 vendor image required; pull by the pinned digest first')
    (root/(role+'.id')).write_text(image['Id']+'\n')
(root/'isolated-engine').write_text('webscan-v3-disposable-dind\n')
PY
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodeops.test" ./internal/nodeops
docker image save --output "$task_run/sidecars.tar" "$(cat "$task_run/vector.id")" "$(cat "$task_run/exporter.id")"
chmod 600 "$task_run/sidecars.tar"
task_dind_id="$(docker run -d --rm --platform "linux/$task_arch" --privileged --network none \
  -e DOCKER_TLS_CERTDIR= "$task_dind_image" dockerd \
  --host unix:///var/run/docker.sock --bridge=none --iptables=false --ip6tables=false --storage-driver=vfs)"
printf '%s\n' "$task_dind_id" > "$task_run/daemon.id"
for task_attempt in {1..60}; do
  if docker exec "$task_dind_id" docker info --format '{{.ServerVersion}} {{.Architecture}} {{.Driver}}' > "$task_run/engine.txt" 2>/dev/null; then break; fi
  if [[ "$task_attempt" == 60 ]]; then echo 'Disposable daemon did not start' >&2; exit 1; fi
  sleep 1
done
docker exec "$task_dind_id" mkdir -m 700 /v3-tests
for task_file in nodeops.test sidecars.tar isolated-engine; do
  docker cp "$task_run/$task_file" "$task_dind_id:/v3-tests/$task_file"
done
docker cp internal/nodeops/testdata "$task_dind_id:/v3-tests/testdata"
docker exec "$task_dind_id" docker load --input /v3-tests/sidecars.tar > "$task_run/load.log" 2>&1
docker exec "$task_dind_id" docker image tag "$(cat "$task_run/vector.id")" docker.io/timberio/vector:0.45.0-alpine
docker exec "$task_dind_id" docker image tag "$(cat "$task_run/exporter.id")" docker.io/prom/node-exporter:v1.9.1
docker exec -w /v3-tests -e WEBSCAN_V3_TEST_WRAPPER_DIND=1 "$task_dind_id" /v3-tests/nodeops.test \
  -test.run '^TestLegacyWrapperObjectsOnDisposableNestedEngine$' -test.v -test.timeout 3m | tee "$task_run/objects.log"
printf 'Evidence: %s\n' "$task_run"
printf 'Real objects tested; systemd manager and active-wrapper migration are not certified.\n'
