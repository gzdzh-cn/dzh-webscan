#!/usr/bin/env bash
# Wrapper inventory and private backup coordination in a disposable Linux container. No host socket,
# SSH, production configuration, live systemd manager, network or notification.
set -euo pipefail
cd "$(dirname "$0")/.."
task_root="$(pwd)"
mkdir -p .cache/verification/v3
task_run="$(mktemp -d "$task_root/.cache/verification/v3/legacy-wrappers.XXXXXX")"
chmod 700 "$task_run"
task_container="webscan-v3-wrappers-$(basename "$task_run")"
task_parser="webscan-v3-wrapper-parser-$(basename "$task_run")"
task_image="${WEBSCAN_V3_AGENT_TEST_IMAGE:-sha256:c7b76b7061936ada0706593e3edc3ff94fa8dad1b1bc82d2e4f5094f69afcf3f}"
task_parser_image="${WEBSCAN_V3_SYSTEMD_TEST_IMAGE:-sha256:7f15a88821bd3ca458e3d668fe7f399404d15756e3162d20fa221c187ff3582f}"
cleanup() {
  docker rm -fv "$task_container" "$task_parser" > "$task_run/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker image inspect "$task_image" > "$task_run/image.json"
docker image inspect "$task_parser_image" > "$task_run/parser-image.json"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodeops.test" ./internal/nodeops
mkdir "$task_run/testdata"
cp internal/nodeops/testdata/legacy-*.service "$task_run/testdata/"
docker run --rm --name "$task_container" --platform linux/amd64 \
  --network none --read-only --workdir /validation \
  --tmpfs /tmp:rw,exec,nosuid,size=128m,mode=1777 \
  --tmpfs /var/tmp:rw,exec,nosuid,size=128m,mode=1777 \
  -v "$task_run:/validation:ro" --entrypoint /validation/nodeops.test "$task_image" \
  -test.run '^Test(LegacyWrapper(Exact|Rejects|Reader|Inventory|Transition|ObjectProof|Group)|RetainedWrapper|InstallationRejectsActiveLegacyWrapper)' \
  -test.v -test.timeout 5m | tee "$task_run/integration.log"
docker run --rm --name "$task_parser" --platform linux/amd64 \
  --network none --read-only --workdir /validation \
  --tmpfs /tmp:rw,exec,nosuid,size=128m,mode=1777 \
  --tmpfs /var/tmp:rw,exec,nosuid,size=128m,mode=1777 \
  -e WEBSCAN_V3_TEST_SYSTEMD_ANALYZE=1 \
  -v "$task_run:/validation:ro" --entrypoint /validation/nodeops.test "$task_parser_image" \
  -test.run '^TestLegacyWrapperTemplatesPassSystemdAnalyze$' \
  -test.v -test.timeout 5m | tee "$task_run/systemd-parser.log"
printf 'Isolated legacy wrapper evidence: %s\n' "$task_run"
