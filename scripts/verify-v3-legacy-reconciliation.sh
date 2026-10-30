#!/usr/bin/env bash
# Disposable data handoff tests. No host socket, SSH, production config,
# network, service manager, notification workers, image publication or Git writes.
set -euo pipefail
cd "$(dirname "$0")/.."
task_root="$(pwd)"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/legacy-reconciliation.XXXXXX")"
chmod 700 "$task_run"
task_container="webscan-v3-legacy-$(basename "$task_run")"
task_image="${WEBSCAN_V3_AGENT_TEST_IMAGE:-sha256:c7b76b7061936ada0706593e3edc3ff94fa8dad1b1bc82d2e4f5094f69afcf3f}"
cleanup() {
  docker rm -fv "$task_container" > "$task_run/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker image inspect "$task_image" > "$task_run/image.json"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodeops.test" ./internal/nodeops
docker run --rm --name "$task_container" --platform linux/amd64 \
  --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,size=256m,mode=1777 \
  --tmpfs /var/tmp:rw,exec,nosuid,size=128m,mode=1777 \
  --tmpfs /var/lib:rw,nosuid,size=128m,mode=755 \
  --tmpfs /var/log:rw,nosuid,size=64m,mode=755 \
  -e WEBSCAN_V3_TEST_LEGACY_IMPORT=1 \
  -v "$task_run:/validation:ro" --entrypoint /validation/nodeops.test "$task_image" \
  -test.run '^TestLegacyReconciliation' -test.v -test.timeout 5m | tee "$task_run/integration.log"
printf 'Isolated legacy reconciliation evidence: %s\n' "$task_run"
