#!/usr/bin/env bash
# Actual single-stack CLI/container acceptance. systemd is explicitly simulated
# inside the runner; no production YAML, network destination or credentials.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${WEBSCAN_V3_TEST_SINGLE_PG_IMAGE:?Provide a cached immutable docker.io/library/postgres@sha256 reference for PostgreSQL 17 linux/amd64}"
: "${WEBSCAN_V3_TEST_SINGLE_VM_IMAGE:?Provide a cached immutable docker.io/victoriametrics/victoria-metrics@sha256 reference for linux/amd64}"
: "${WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE:?Provide the freshly built v3 central image with tag and digest}"
: "${WEBSCAN_V3_TEST_SINGLE_AGENT_IMAGE:?Provide the matching freshly built v3 agent image with tag and digest}"
# Fail before creating resources if the local fixtures have the wrong platform.
for task_fixture in "$WEBSCAN_V3_TEST_SINGLE_PG_IMAGE" "$WEBSCAN_V3_TEST_SINGLE_VM_IMAGE" "$WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE" "$WEBSCAN_V3_TEST_SINGLE_AGENT_IMAGE"; do
  task_platform="$(docker image inspect --platform linux/amd64 "$task_fixture" --format '{{.Os}}/{{.Architecture}}')"
  if [[ "$task_platform" != linux/amd64 ]]; then printf 'An immutable Linux amd64 fixture is required.\n' >&2; exit 2; fi
done
task_root="$(pwd)"
task_run="$(mktemp -d "$task_root/.cache/verification/v3/single-install.XXXXXX")"
task_suffix="$(basename "$task_run")"
task_volume="webscan-v3-single-test-$task_suffix"
task_runner="webscan-v3-single-runner-$task_suffix"
task_extract="webscan-v3-single-extract-$task_suffix"
task_project=""
task_bind=""
cleanup() {
  if [[ -n "${task_mount:-}" ]]; then
    for task_evidence in journal.json install.json; do
      docker cp "$task_runner:$task_mount/installation/$task_evidence" "$task_run/$task_evidence" >> "$task_run/cleanup.log" 2>&1 || true
    done
    docker cp "$task_runner:$task_mount/executor.log" "$task_run/executor.log" >> "$task_run/cleanup.log" 2>&1 || true
  fi
  if [[ -n "$task_project" ]]; then
    docker ps -aq --filter "label=com.docker.compose.project=$task_project" > "$task_run/owned-containers.txt" || true
    while IFS= read -r task_id; do
      if [[ "$task_id" =~ ^[a-f0-9]{12,64}$ ]]; then
        docker logs --tail 150 "$task_id" > "$task_run/container-$task_id.log" 2>&1 || true
        docker rm -fv "$task_id" >> "$task_run/cleanup.log" 2>&1 || true
      fi
    done < "$task_run/owned-containers.txt"
  fi
  docker rm -fv "$task_runner" "$task_extract" >> "$task_run/cleanup.log" 2>&1 || true
  docker volume rm "$task_volume" >> "$task_run/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags '-X webscan/internal/deploy.Release=v3.0.0-local-test' \
  -o "$task_run/webscan" ./cmd/webscan
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/controlplane.test" ./internal/controlplane
docker create --name "$task_extract" --platform linux/amd64 --network none --entrypoint /bin/true "$WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE" > "$task_run/extract.id"
docker cp "$task_extract:/usr/local/lib/webscan/agent-native.tar.gz" "$task_run/agent-native.tar.gz"
docker rm "$task_extract" > "$task_run/extract-cleanup.txt"
task_mount_source=""
task_is_bind=0
task_test='^TestSingleInstallDisposableDockerStack$'
task_existing=""
if [[ -n "${WEBSCAN_V3_SINGLE_EXISTING:-}" ]]; then
  task_bind="$WEBSCAN_V3_SINGLE_EXISTING"
  [[ "$task_bind" == /Users/*/webscan-v3-single-test.* && -d "$task_bind" && ! -L "$task_bind" ]] || { echo 'An explicitly retained disposable test directory is required.' >&2; exit 2; }
  task_mount="/host_mnt$task_bind"
  task_mount_source="$task_bind"
  task_is_bind=1
  task_existing="$task_mount"
  task_test='^TestSingleUpgradeExistingDisposableDockerStack$'
elif [[ -n "${WEBSCAN_V3_SINGLE_BIND_PARENT:-}" ]]; then
  [[ "$WEBSCAN_V3_SINGLE_BIND_PARENT" == /Users/* && -d "$WEBSCAN_V3_SINGLE_BIND_PARENT" && ! -L "$WEBSCAN_V3_SINGLE_BIND_PARENT" ]] || { echo 'A private existing /Users/ test parent is required.' >&2; exit 2; }
  task_bind="$(mktemp -d "$WEBSCAN_V3_SINGLE_BIND_PARENT/webscan-v3-single-test.XXXXXX")"
  chmod 700 "$task_bind"
  task_mount="/host_mnt$task_bind"
  task_mount_source="$task_bind"
  task_is_bind=1
else
  docker volume create "$task_volume" > "$task_run/volume.txt"
  task_mount="$(docker volume inspect "$task_volume" --format '{{.Mountpoint}}')"
  task_mount_source="$task_volume"
fi
task_project="$(python3 - "$task_mount/installation" <<'PY'
import hashlib,sys
print('webscan-v3-single-'+hashlib.sha256(sys.argv[1].encode()).hexdigest()[:12])
PY
)"
# Match the runner CLI to the Docker 29/containerd engine. Docker 27's image
# inspect cannot select an architecture from a multi-platform Desktop cache.
task_image="$(docker image inspect "${WEBSCAN_V3_SINGLE_RUNNER_IMAGE:-webscan-v3-docker29-kernel-guest:local}" --format '{{.Id}}')"
docker create --name "$task_runner" --platform linux/amd64 --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$task_mount_source:$task_mount" -v "$task_run:/evidence:ro" \
  -e WEBSCAN_V3_TEST_SINGLE_STACK=1 -e "WEBSCAN_V3_TEST_SINGLE_ROOT=$task_mount" \
  -e "WEBSCAN_V3_TEST_SINGLE_BIND=$task_is_bind" \
  -e "WEBSCAN_V3_TEST_SINGLE_EXISTING=$task_existing" \
  -e WEBSCAN_V3_TEST_SINGLE_BINARY=/evidence/webscan \
  -e "WEBSCAN_V3_TEST_SINGLE_PG_IMAGE=$WEBSCAN_V3_TEST_SINGLE_PG_IMAGE" \
  -e "WEBSCAN_V3_TEST_SINGLE_VM_IMAGE=$WEBSCAN_V3_TEST_SINGLE_VM_IMAGE" \
  -e "WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE=$WEBSCAN_V3_TEST_SINGLE_CENTRAL_IMAGE" \
  -e "WEBSCAN_V3_TEST_SINGLE_AGENT_IMAGE=$WEBSCAN_V3_TEST_SINGLE_AGENT_IMAGE" \
  --entrypoint /evidence/controlplane.test "$task_image" \
  -test.run "$task_test" -test.v -test.timeout 15m > "$task_run/runner.id"
docker start -a "$task_runner" | tee "$task_run/integration.log"
task_exit="$(docker inspect "$task_runner" --format '{{.State.ExitCode}}')"
docker cp "$task_runner:$task_mount/installation/journal.json" "$task_run/journal.json" || true
docker cp "$task_runner:$task_mount/installation/install.json" "$task_run/install.json" || true
docker cp "$task_runner:$task_mount/executor.log" "$task_run/executor.log" || true
if [[ "$task_exit" != 0 ]]; then exit "$task_exit"; fi
printf 'Disposable single-stack verification passed; systemd was simulated. Evidence: %s\n' "$task_run"
