#!/usr/bin/env bash
# Full x86_64 kernel/systemd acceptance on an ARM Docker Desktop host. The guest
# has no NIC, shared host filesystem, SSH, public ports or production credentials.
set -euo pipefail
# Parse the complete run before starting long-lived guests. Local edits to
# this script during acceptance must not shift Bash's later file reads.
main() {
cd "$(dirname "$0")/.."
task_mode="${1:-native}"
case "$task_mode" in native|docker|web-native|web-docker|transition|sidecars|legacy-group|pure-compose|recovery|docker-recovery|name-change|docker-name-change|backup-timer|single-boot) ;; *) printf 'Usage: %s [native|docker|web-native|web-docker|transition|sidecars|legacy-group|pure-compose|recovery|docker-recovery|name-change|docker-name-change|backup-timer|single-boot]\n' "$0" >&2; exit 2 ;; esac
task_release="${WEBSCAN_V3_KERNEL_RELEASE:-v3.0.0-local-test}"
if [[ ! "$task_release" =~ ^v[0-9][A-Za-z0-9._-]{1,80}$ ]]; then echo 'Invalid explicit acceptance release.' >&2; exit 2; fi
task_helper="${WEBSCAN_V3_KERNEL_HELPER:-}"
task_native="${WEBSCAN_V3_KERNEL_NATIVE_BUNDLE:-}"
if [[ -n "$task_helper" || -n "$task_native" || "$task_release" != v3.0.0-local-test ]]; then
  [[ "$task_mode" == web-native || "$task_mode" == web-docker || "$task_mode" == single-boot ]] || { echo 'Exact release artifact acceptance requires a web lifecycle or single boot mode.' >&2; exit 2; }
  for task_artifact in "$task_helper" "$task_native"; do
    [[ "$task_artifact" == /* && -f "$task_artifact" && ! -L "$task_artifact" ]] || { echo 'Explicit regular helper and native artifacts required.' >&2; exit 2; }
  done
fi
task_root="$(pwd)"
mkdir -p .cache/verification/v3
task_output_root="${WEBSCAN_V3_KERNEL_OUTPUT_ROOT:-$task_root/.cache/verification/v3}"
if [[ "$task_output_root" != /* || ! -d "$task_output_root" || -L "$task_output_root" ]]; then
  printf 'Kernel output root must be an existing absolute directory, without a symlink leaf.\n' >&2
  exit 2
fi
# Preparation temporarily holds the exported tar, extracted tree and populated
# sparse guest disk together. Sparse logical size is not a free-space check;
# running out can also make Docker Desktop's backing filesystem read-only.
# Leave headroom for the engine and unrelated local projects before any build
# or container operation, rather than attempting a global cleanup or restart.
task_required_gib=4
if [[ "$task_mode" != native && "$task_mode" != recovery && "$task_mode" != name-change ]]; then task_required_gib=6; fi
task_available_kib="$(df -Pk "$task_output_root" | awk 'END {print $4}')"
if [[ ! "$task_available_kib" =~ ^[0-9]+$ ]] || (( task_available_kib < task_required_gib * 1024 * 1024 )); then
  printf '内核验证临时目录至少需要 %s GiB 可用空间（含解包及引擎预留）；请选择空间充足的 WEBSCAN_V3_KERNEL_OUTPUT_ROOT。未开始构建或创建容器。\n' "$task_required_gib" >&2
  exit 2
fi
task_run="$(mktemp -d "$task_output_root/kernel-lifecycle.XXXXXX")"
chmod 700 "$task_run"
task_suffix="$(basename "$task_run")"
task_export="webscan-v3-guest-export-$task_suffix"
task_prepare="webscan-v3-guest-prepare-$task_suffix"
task_vm="webscan-v3-kernel-$task_suffix"
cleanup() {
  docker rm -fv "$task_export" "$task_prepare" "$task_vm" > "$task_run/cleanup.log" 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
task_guest_name=webscan-v3-kernel-guest:local
if [[ "$task_mode" != native && "$task_mode" != recovery && "$task_mode" != name-change ]]; then task_guest_name="${WEBSCAN_V3_DOCKER_KERNEL_IMAGE:-webscan-v3-docker-kernel-guest:local}"; fi
task_guest="$(docker image inspect "$task_guest_name" --format '{{.Id}}')"
task_tools="$(docker image inspect webscan-v3-kernel-tools:local --format '{{.Id}}')"
docker image inspect "$task_guest" "$task_tools" > "$task_run/images.json"
if [[ -n "$task_helper" ]]; then
  cp "$task_helper" "$task_run/webscan"
else
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags '-X webscan/internal/deploy.Release=v3.0.0-local-test' \
    -o "$task_run/webscan" ./cmd/webscan
fi
printf '%s\n' "$task_release" > "$task_run/release"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$task_run/nodeops.test" ./internal/nodeops
if [[ "$task_mode" == web-native || "$task_mode" == web-docker || "$task_mode" == backup-timer || "$task_mode" == single-boot ]]; then
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -ldflags "-X webscan/internal/deploy.Release=$task_release" -o "$task_run/controlplane.test" ./internal/controlplane
  cp webscan-v3.example.yaml "$task_run/webscan-v3.example.yaml"
  task_pg="${WEBSCAN_V3_WEB_KERNEL_PG_IMAGE:?explicit immutable PostgreSQL 17 image required}"
  if [[ ! "$task_pg" =~ @sha256:[a-f0-9]{64}$ ]]; then printf 'Immutable PostgreSQL image required.\n' >&2; exit 2; fi
  docker image inspect --platform linux/amd64 "$task_pg" > "$task_run/postgres-image.json"
  python3 - "$task_run" <<'PGPROOF'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); image=json.loads((root/'postgres-image.json').read_text())[0]
if image['Os']!='linux' or image['Architecture']!='amd64':
    raise SystemExit('Linux amd64 PostgreSQL required')
PGPROOF
  docker image save --platform linux/amd64 --output "$task_run/postgres-image.tar" "$task_pg"
  python3 - "$task_run" <<'PGCONFIG'
import pathlib,sys
from scripts.v3_saved_image_config import saved_image_runtime_id
import os
root=pathlib.Path(sys.argv[1])
(root/'postgres-image-id').write_text(saved_image_runtime_id(root/'postgres-image.tar',os.environ.get('WEBSCAN_V3_DOCKER_CONTAINERD')=='1')+'\n')
PGCONFIG
  if [[ "$task_mode" == backup-timer ]]; then
    task_vm_image="${WEBSCAN_V3_BACKUP_TIMER_VM_IMAGE:?explicit cached immutable VictoriaMetrics image required}"
    [[ "$task_vm_image" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Cached immutable VM image ID required.' >&2; exit 2; }
    docker create --name "$task_export" --platform linux/amd64 --network none --entrypoint /bin/true "$task_vm_image" > "$task_run/vm-export.txt"
    docker cp "$task_export:/victoria-metrics-prod" "$task_run/victoria-metrics-prod"
    docker rm "$task_export" > "$task_run/vm-export-cleanup.txt"
    sha256sum "$task_run/victoria-metrics-prod" > "$task_run/vm-binary.sha256"
  else
  task_central="${WEBSCAN_V3_WEB_KERNEL_CENTRAL_IMAGE:?explicit immutable current central image required}"
  if [[ ! "$task_central" =~ @sha256:[a-f0-9]{64}$ ]]; then printf 'Immutable central image required.\n' >&2; exit 2; fi
  docker image inspect --platform linux/amd64 "$task_central" > "$task_run/central-image.json"
  WEBSCAN_V3_TEST_RELEASE="$task_release" python3 - "$task_run" <<'CENTRALPROOF'
import json,os,pathlib,sys
root=pathlib.Path(sys.argv[1]); image=json.loads((root/'central-image.json').read_text())[0]
if image['Os']!='linux' or image['Architecture']!='amd64' or image.get('Config',{}).get('Labels',{}).get('org.opencontainers.image.version')!=os.environ['WEBSCAN_V3_TEST_RELEASE']:
    raise SystemExit('Current built-in Linux amd64 central test image required')
CENTRALPROOF
  docker image save --platform linux/amd64 --output "$task_run/central-image.tar" "$task_central"
  python3 - "$task_run" <<'CENTRALCONFIG'
import pathlib,sys
from scripts.v3_saved_image_config import saved_image_runtime_id
import os
root=pathlib.Path(sys.argv[1])
(root/'central-image-id').write_text(saved_image_runtime_id(root/'central-image.tar',os.environ.get('WEBSCAN_V3_DOCKER_CONTAINERD')=='1')+'\n')
CENTRALCONFIG
  fi
fi
if [[ "$task_mode" == single-boot ]]; then
  task_metrics="${WEBSCAN_V3_SINGLE_KERNEL_VM_IMAGE:?explicit immutable VictoriaMetrics image required}"
  [[ "$task_metrics" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'Immutable VM image required.' >&2; exit 2; }
  docker image inspect --platform linux/amd64 "$task_metrics" > "$task_run/metrics-image.json"
  docker image save --platform linux/amd64 --output "$task_run/metrics-image.tar" "$task_metrics"
fi
docker create --name "$task_export" --platform linux/amd64 --network none \
  --entrypoint /bin/true "$task_guest" > "$task_run/export-container.txt"
docker export "$task_export" > "$task_run/rootfs.tar"
docker cp "$task_export:/boot/vmlinuz-6.1.0-54-amd64" "$task_run/vmlinuz"
docker cp "$task_export:/boot/initrd.img-6.1.0-54-amd64" "$task_run/initrd.img"
docker cp "$task_export:/kernel-guest-packages.txt" "$task_run/guest-packages.txt"
if [[ "$task_mode" != native && "$task_mode" != recovery && "$task_mode" != name-change && "$task_mode" != backup-timer ]]; then
  docker cp "$task_export:/usr/local/lib/webscan/agent-native.tar.gz" "$task_run/tools.tar.gz"
fi
docker rm -v "$task_export" > "$task_run/export-cleanup.txt"
printf '%s\n' "$task_mode" > "$task_run/mode"
if [[ "$task_mode" != native && "$task_mode" != recovery && "$task_mode" != name-change && "$task_mode" != backup-timer ]]; then
  task_agent="${WEBSCAN_V3_AGENT_KERNEL_IMAGE:-docker.io/gzdzh/webscan-agent@sha256:0b47dd5c6c5fa84cdb9b30c6ecd8998ff1c81f05dd106cba4be3b6c0e4a8c078}"
  docker image inspect --platform linux/amd64 "$task_agent" > "$task_run/agent-image.json"
  docker image save --platform linux/amd64 --output "$task_run/agent-image.tar" "$task_agent"
  WEBSCAN_V3_TEST_RELEASE="$task_release" WEBSCAN_V3_TEST_NATIVE="$task_native" python3 - "$task_run" <<'PY'
import hashlib, io, json, os, pathlib, shutil, sys, tarfile
from scripts.v3_saved_image_config import saved_image_config
root = pathlib.Path(sys.argv[1])
with tarfile.open(root / 'tools.tar.gz', 'r:gz') as archive:
    files = {entry.name.removeprefix('./'): (archive.extractfile(entry).read(), entry.mode)
             for entry in archive.getmembers() if entry.isfile()}
files['webscan'] = ((root / 'webscan').read_bytes(), 0o755)
files['VERSION'] = (b'v3.0.0-local-test\n', 0o644)
files['SHA256SUMS'] = (''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
    for name, (data, mode) in sorted(files.items()) if name != 'SHA256SUMS').encode(), 0o644)
if os.environ['WEBSCAN_V3_TEST_NATIVE']:
    # Preserve the signed release bytes. Never rebuild or relabel a pilot bundle.
    shutil.copyfile(os.environ['WEBSCAN_V3_TEST_NATIVE'], root / 'agent-native.tar.gz')
else:
    with tarfile.open(root / 'agent-native.tar.gz', 'w:gz') as archive:
        for name, (data, mode) in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), mode
            archive.addfile(entry, io.BytesIO(data))
image = json.loads((root / 'agent-image.json').read_text())[0]
if image['Os'] != 'linux' or image['Architecture'] != 'amd64' or not image.get('RepoDigests'):
    raise SystemExit('immutable amd64 Agent fixture required')
archive = root / 'agent-image.tar'
digest = hashlib.sha256()
with archive.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
reference = ('docker.io/library/' + image['RepoDigests'][0] if '/' not in image['RepoDigests'][0].split('@')[0] else image['RepoDigests'][0])
# Current-source fixtures must also exercise the readable version alias through
# Docker load, launch, restart and rollback. Old pilot fixtures stay untagged;
# they cannot be presented as the new test release.
release = os.environ['WEBSCAN_V3_TEST_RELEASE']
if image.get('Config', {}).get('Labels', {}).get('org.opencontainers.image.version') == release:
    repository, digest_value = reference.split('@')
    reference = repository + ':' + release + '@' + digest_value
proof = {'mode': 'docker', 'metrics_port': 19100, 'monitor_directories': ['/'],
         'artifact_bytes': 0, 'clamav': False, 'agent_image': reference,
         'image_archive_sha256': digest.hexdigest(), 'image_archive_bytes': archive.stat().st_size,
         'image_config_sha256': saved_image_config(archive)}
(root / 'image-proof.json').write_text(json.dumps(proof))
PY
fi
if [[ "$task_mode" == single-boot ]]; then
  python3 - "$task_run" <<'SINGLEPROOF'
import json,pathlib,sys
from scripts.v3_saved_image_config import saved_image_runtime_id
root=pathlib.Path(sys.argv[1])
repositories={'central':'docker.io/gzdzh/webscan-central','agent':'docker.io/gzdzh/webscan-agent','postgres':'docker.io/library/postgres','metrics':'docker.io/victoriametrics/victoria-metrics'}
images={key:repo+'@'+saved_image_runtime_id(root/(key+'-image.tar'),True) for key,repo in repositories.items()}
(root/'single-images.json').write_text(json.dumps(images))
(root/'single-images.txt').write_text(''.join(value+'\n' for value in images.values()))
SINGLEPROOF
fi
if [[ "$task_mode" == sidecars || "$task_mode" == legacy-group || "$task_mode" == pure-compose ]]; then
  task_vector='timberio/vector@sha256:385f534a0bad5bb58a06c3a261ad7b5a2b170ce2f1f035d32019503c23e8fc07'
  task_exporter='prom/node-exporter@sha256:d00a542e409ee618a4edc67da14dd48c5da66726bbd5537ab2af9c1dfc442c8a'
  docker image inspect "$task_vector" "$task_exporter" > "$task_run/sidecar-images.json"
  python3 - "$task_run" <<'PY'
import json, pathlib, re, sys
root=pathlib.Path(sys.argv[1])
images=json.loads((root/'sidecar-images.json').read_text())
if len(images)!=2 or any(i['Os']!='linux' or i['Architecture']!='amd64' or not re.fullmatch(r'sha256:[a-f0-9]{64}',i['Id']) for i in images):
    raise SystemExit('Two pinned Linux amd64 vendor images required')
(root/'sidecar-proof.json').write_text(json.dumps(dict(zip(['vector','exporter'],[i['Id'] for i in images]))))
PY
  docker image save --output "$task_run/sidecars.tar" "$task_vector" "$task_exporter"
  chmod 600 "$task_run/sidecars.tar" "$task_run/sidecar-proof.json"
fi
if [[ "$task_mode" == legacy-group || "$task_mode" == pure-compose ]]; then
  task_legacy='gzdzh/webscan-agent@sha256:453ec55733ec73457e4ddf3ea6a6d23b2d6e4e55c044ec77cd2194aac5c6ee27'
  docker image inspect "$task_legacy" > "$task_run/legacy-image.json"
  docker run --rm --name "$task_prepare" --platform linux/amd64 --network none --read-only --entrypoint /usr/local/bin/webscan "$task_legacy" version > "$task_run/legacy-version.txt"
  python3 - "$task_run" <<'PYPROOF'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); image=json.loads((root/'legacy-image.json').read_text())[0]
release=(root/'legacy-version.txt').read_text().strip()
digest='sha256:453ec55733ec73457e4ddf3ea6a6d23b2d6e4e55c044ec77cd2194aac5c6ee27'
if release!='v2.0.34' or image['Os']!='linux' or image['Architecture']!='amd64' or not any(i.endswith('@'+digest) for i in image['RepoDigests']):
    raise SystemExit('Actual published v2.0.34 Agent required')
(root/'legacy-group-proof.json').write_text(json.dumps({'release':release,'digest':digest,'id':image['Id']}))
PYPROOF
  docker image save --output "$task_run/legacy-agent.tar" "$task_legacy"
  chmod 600 "$task_run/legacy-agent.tar" "$task_run/legacy-group-proof.json"
fi
cat > "$task_run/prepare.sh" <<'PREPARE'
set -eu
cd /validation
mkdir rootfs
tar -xf rootfs.tar -C rootfs
# Exported container markers must not make PID 1 enter container mode inside
# the full virtual machine. The guest owns its kernel and writable cgroups.
rm -f rootfs/.dockerenv rootfs/run/.containerenv
mkdir -p rootfs/v3-tests rootfs/etc/systemd/system/multi-user.target.wants
cp webscan nodeops.test rootfs/v3-tests/
cp mode rootfs/v3-tests/mode
cp release rootfs/v3-tests/release
printf '%s\n' "${WEBSCAN_V3_DOCKER_CONTAINERD:-0}" > rootfs/v3-tests/containerd-store
if [ "$WEBSCAN_V3_KERNEL_MODE" != native ] && [ "$WEBSCAN_V3_KERNEL_MODE" != recovery ] && [ "$WEBSCAN_V3_KERNEL_MODE" != name-change ] && [ "$WEBSCAN_V3_KERNEL_MODE" != backup-timer ]; then
  cp agent-native.tar.gz agent-image.tar image-proof.json rootfs/v3-tests/
  printf 'webscan-v3-disposable-dind\n' > rootfs/v3-tests/isolated-engine
  chmod 600 rootfs/v3-tests/isolated-engine rootfs/v3-tests/*.tar* rootfs/v3-tests/image-proof.json
fi
if [ "$WEBSCAN_V3_KERNEL_MODE" = sidecars ] || [ "$WEBSCAN_V3_KERNEL_MODE" = legacy-group ] || [ "$WEBSCAN_V3_KERNEL_MODE" = pure-compose ]; then
  cp sidecars.tar sidecar-proof.json rootfs/v3-tests/
  # Legacy units use this exact real executable path. Do not substitute a
  # symlink or relax /proc executable ownership in the product.
  cp rootfs/usr/local/bin/docker rootfs/usr/bin/docker
  cat > rootfs/etc/systemd/system/docker.service <<'ENGINE'
[Unit]
Description=Disposable independent Docker engine for kernel acceptance
After=basic.target
[Service]
Type=exec
ExecStart=/usr/local/bin/dockerd --host unix:///var/run/docker.sock --bridge=none --iptables=false --ip6tables=false --storage-driver=vfs --exec-opt native.cgroupdriver=systemd
StandardOutput=append:/v3-tests/dockerd.log
StandardError=append:/v3-tests/dockerd.log
TimeoutStopSec=60
ENGINE
fi
if [ "$WEBSCAN_V3_KERNEL_MODE" = legacy-group ] || [ "$WEBSCAN_V3_KERNEL_MODE" = pure-compose ]; then
  cp legacy-agent.tar legacy-group-proof.json rootfs/v3-tests/
  chmod 600 rootfs/v3-tests/legacy-agent.tar rootfs/v3-tests/legacy-group-proof.json
fi
chmod 755 rootfs/v3-tests/webscan rootfs/v3-tests/nodeops.test
printf 'webscan-v3-networkless-kernel-guest\n' > rootfs/v3-tests/kernel-guest
chmod 700 rootfs/v3-tests
chmod 600 rootfs/v3-tests/kernel-guest
if [ "$WEBSCAN_V3_KERNEL_MODE" = web-native ] || [ "$WEBSCAN_V3_KERNEL_MODE" = web-docker ] || [ "$WEBSCAN_V3_KERNEL_MODE" = backup-timer ] || [ "$WEBSCAN_V3_KERNEL_MODE" = single-boot ]; then
  cp controlplane.test postgres-image.tar postgres-image.json postgres-image-id rootfs/v3-tests/
  if [ "$WEBSCAN_V3_KERNEL_MODE" = backup-timer ]; then
    cp victoria-metrics-prod rootfs/v3-tests/
    chmod 700 rootfs/v3-tests/victoria-metrics-prod
  else
    cp central-image.tar central-image.json central-image-id rootfs/v3-tests/
  fi
  chmod 600 rootfs/v3-tests/postgres-image.tar rootfs/v3-tests/postgres-image.json
  chmod 700 rootfs/v3-tests/controlplane.test
  mkdir -p rootfs/workspace/internal/controlplane
  cp webscan-v3.example.yaml rootfs/workspace/webscan-v3.example.yaml
fi
if [ "$WEBSCAN_V3_KERNEL_MODE" = single-boot ]; then
  cp metrics-image.tar single-images.json single-images.txt rootfs/v3-tests/
  chmod 600 rootfs/v3-tests/metrics-image.tar rootfs/v3-tests/single-images.json
  # Real enabled engine: the second boot must recover it without test startup.
  task_engine_feature=''
  if [ "$WEBSCAN_V3_DOCKER_CONTAINERD" = 1 ]; then task_engine_feature='--feature=containerd-snapshotter=true'; fi
  cat > rootfs/etc/systemd/system/docker.service <<ENGINE
[Unit]
Description=Disposable independent Docker29 boot acceptance
After=basic.target
[Service]
Type=exec
ExecStart=/usr/local/bin/dockerd $task_engine_feature --host unix:///var/run/docker.sock --bridge=none --iptables=false --ip6tables=false --storage-driver=overlayfs --exec-opt native.cgroupdriver=systemd
StandardOutput=append:/v3-tests/dockerd.log
StandardError=append:/v3-tests/dockerd.log
TimeoutStopSec=90
[Install]
WantedBy=multi-user.target
ENGINE
  ln -s ../docker.service rootfs/etc/systemd/system/multi-user.target.wants/docker.service
fi
rm -f rootfs/etc/machine-id rootfs/etc/hostname
: > rootfs/etc/machine-id
printf 'webscan-v3-kernel-guest\n' > rootfs/etc/hostname
cat > rootfs/v3-tests/run.sh <<'GUEST'
#!/bin/bash
set -o pipefail
exec >>/v3-tests/test.log 2>&1
printf '\nWEBSCAN_V3_GUEST_TEST_BEGIN\n'
uname -a
systemctl --version
cat /sys/fs/cgroup/cgroup.controllers
export WEBSCAN_V3_TEST_SYSTEMD_GUEST=1
export WEBSCAN_V3_TEST_NODE_BINARY=/v3-tests/webscan
export WEBSCAN_V3_TEST_BUNDLE=1
export WEBSCAN_V3_TEST_RELEASE="$(cat /v3-tests/release)"
if [ "$(cat /v3-tests/mode)" = single-boot ]; then
  task_status=1
  task_phase=before
  if [ -f /v3-tests/first-boot-passed ]; then task_phase=after; fi
  task_ready=0
  for task_attempt in $(seq 1 120); do
    if docker info >/v3-tests/engine.txt 2>&1; then task_ready=1; break; fi
    sleep 1
  done
  if [ "$task_ready" = 1 ] && [ "$task_phase" = before ]; then
    for task_image in agent postgres central metrics; do
      if ! docker load --input "/v3-tests/$task_image-image.tar" >>/v3-tests/image-load.log 2>&1; then task_ready=0; break; fi
    done
    # Name only the actual authenticated platform manifest in this disposable
    # store. No remote registry, digest substitution or installer shim exists.
    if [ "$task_ready" = 1 ]; then
      while IFS= read -r task_reference; do
        task_repository="${task_reference%@*}"
        task_identity="${task_reference#*@}"
        if ! docker tag "$task_identity" "$task_repository:kernel-offline" >>/v3-tests/image-load.log 2>&1 || ! docker image inspect "$task_reference" >>/v3-tests/image-load.log 2>&1; then task_ready=0; break; fi
      done < /v3-tests/single-images.txt
    fi
  fi
  if [ "$task_ready" = 1 ]; then
    export WEBSCAN_V3_SINGLE_KERNEL_PHASE="$task_phase"
    cd /workspace/internal/controlplane
    /v3-tests/controlplane.test -test.run '^TestSingleInstallActualKernelBootRecovery$' -test.v -test.timeout 15m 2>&1 | tee /dev/ttyS0
    task_status=$?
  else
    cat /v3-tests/image-load.log /v3-tests/engine.txt /v3-tests/dockerd.log
  fi
  printf '\nWEBSCAN_V3_SINGLE_BOOT_%s_EXIT=%s\n' "$task_phase" "$task_status"
  if [ "$task_status" = 0 ] && [ "$task_phase" = before ]; then
    touch /v3-tests/first-boot-passed
    sync
    systemctl reboot
    exit 0
  fi
  printf '\nWEBSCAN_V3_GUEST_TEST_EXIT=%s\n' "$task_status"
  cat /v3-tests/test.log >/dev/ttyS0
  sync
  systemctl poweroff
  exit "$task_status"
fi
if [ "$(cat /v3-tests/mode)" != native ] && [ "$(cat /v3-tests/mode)" != recovery ] && [ "$(cat /v3-tests/mode)" != name-change ]; then
  # This is an independent engine inside the full networkless guest. It has
  # no external socket, bridge, iptables mutations or registry access.
  task_daemon=''
  if [ "$(cat /v3-tests/mode)" = sidecars ] || [ "$(cat /v3-tests/mode)" = legacy-group ] || [ "$(cat /v3-tests/mode)" = pure-compose ]; then
    systemctl start docker.service
  else
    task_driver=vfs; task_engine_flags=()
    if [ "$(cat /v3-tests/containerd-store)" = 1 ]; then task_driver=overlayfs; task_engine_flags=(--feature=containerd-snapshotter=true); fi
    dockerd "${task_engine_flags[@]}" --host unix:///var/run/docker.sock --bridge=none --iptables=false --ip6tables=false --storage-driver="$task_driver" --exec-opt native.cgroupdriver=systemd >/v3-tests/dockerd.log 2>&1 &
    task_daemon=$!
  fi
  task_ready=0
  for task_attempt in $(seq 1 60); do
    if docker info --format '{{.ServerVersion}} {{.Architecture}} {{.Driver}} {{.CgroupDriver}} {{.CgroupVersion}}' > /v3-tests/engine.txt 2>&1; then task_ready=1; break; fi
    if [ -n "$task_daemon" ]; then kill -0 "$task_daemon" 2>/dev/null || break; fi
    sleep 1
  done
  task_images=0
  if [ "$task_ready" = 1 ] && [ "$(cat /v3-tests/mode)" = backup-timer ]; then
    task_images=1
  elif [ "$task_ready" = 1 ] && docker load --input /v3-tests/agent-image.tar > /v3-tests/image-load.log 2>&1; then
    task_images=1
    if [ "$(cat /v3-tests/mode)" = sidecars ] || [ "$(cat /v3-tests/mode)" = legacy-group ] || [ "$(cat /v3-tests/mode)" = pure-compose ]; then
      docker load --input /v3-tests/sidecars.tar >> /v3-tests/image-load.log 2>&1 || task_images=0
    fi
  fi
  if [ "$task_images" = 1 ] && { [ "$(cat /v3-tests/mode)" = legacy-group ] || [ "$(cat /v3-tests/mode)" = pure-compose ]; }; then
    docker load --input /v3-tests/legacy-agent.tar >> /v3-tests/image-load.log 2>&1 || task_images=0
  fi
  if [ "$task_images" = 1 ] && { [ "$(cat /v3-tests/mode)" = web-native ] || [ "$(cat /v3-tests/mode)" = web-docker ] || [ "$(cat /v3-tests/mode)" = backup-timer ]; }; then
    task_images=0
    if docker load --input /v3-tests/postgres-image.tar >>/v3-tests/image-load.log 2>&1 && { [ "$(cat /v3-tests/mode)" = backup-timer ] || docker load --input /v3-tests/central-image.tar >>/v3-tests/image-load.log 2>&1; }; then
      task_pg_id="$(cat /v3-tests/postgres-image-id)"
      if docker run -d --name webscan-web-kernel-postgres --network host --restart no \
        -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=webscan -e PGPORT=55432 \
        "$task_pg_id" postgres -c max_wal_size=128MB -c min_wal_size=32MB > /v3-tests/postgres-container.txt 2>&1; then
        for task_attempt in $(seq 1 90); do
          if docker exec webscan-web-kernel-postgres pg_isready -h 127.0.0.1 -p 55432 -U postgres -d webscan >/dev/null 2>&1; then task_images=1; break; fi
          sleep 1
        done
      fi
    fi
  fi
  if [ "$task_images" = 1 ] && [ "$(cat /v3-tests/mode)" = backup-timer ]; then
    export WEBSCAN_V3_TEST_DSN='postgres://postgres@127.0.0.1:55432/webscan?sslmode=disable'
    export WEBSCAN_V3_TEST_BACKUP_SYSTEMD=1 WEBSCAN_V3_TEST_BACKUP_HELPER=/v3-tests/webscan
    export WEBSCAN_V3_TEST_VM_EXECUTABLE=/v3-tests/victoria-metrics-prod
    cd /workspace/internal/controlplane
    /v3-tests/controlplane.test -test.run '^TestSingleBackupActualSignedHelperAndEnginesLinux$' -test.v -test.timeout 12m 2>&1 | tee /dev/ttyS0
    task_status=$?
    docker logs webscan-web-kernel-postgres > /v3-tests/postgres.log 2>&1
    docker rm -fv webscan-web-kernel-postgres >/dev/null 2>&1
  elif [ "$task_images" = 1 ] && { [ "$(cat /v3-tests/mode)" = web-native ] || [ "$(cat /v3-tests/mode)" = web-docker ]; }; then
    export WEBSCAN_V3_WEB_KERNEL_MODE="$(cat /v3-tests/mode | sed 's/^web-//')"
    export WEBSCAN_V3_TEST_DSN='postgres://postgres@127.0.0.1:55432/webscan?sslmode=disable'
    cd /workspace/internal/controlplane
    /v3-tests/controlplane.test -test.run '^TestWebDeploymentKernelPublicAPIAndActualServices$' -test.v -test.timeout 30m 2>&1 | tee /dev/ttyS0
    task_status=$?
    docker logs webscan-web-kernel-postgres > /v3-tests/postgres.log 2>&1
    docker rm -fv webscan-web-kernel-postgres >/dev/null 2>&1
  elif [ "$task_images" = 1 ]; then
    cat /v3-tests/engine.txt
    export WEBSCAN_V3_TEST_DIND=1 WEBSCAN_V3_TEST_DOCKER_KERNEL_GUEST=1
    task_test='^TestDockerKernelLifecycleFinalizesAndRetainsEvents$'
    if [ "$(cat /v3-tests/mode)" = docker-name-change ]; then task_test='^TestDockerKernelNameChangeApplicationAndRollback$'; fi
    if [ "$(cat /v3-tests/mode)" = docker-recovery ]; then task_test='^TestDockerKernelIdentityRecoveryRetainsEvents$'; fi
    if [ "$(cat /v3-tests/mode)" = transition ]; then task_test='^TestKernelNativeDockerTransitionsRetainCurrentData$'; fi
    if [ "$(cat /v3-tests/mode)" = sidecars ] || [ "$(cat /v3-tests/mode)" = legacy-group ] || [ "$(cat /v3-tests/mode)" = pure-compose ]; then task_test='^TestKernelActiveLegacyWrappersRetainOriginalContainers$'; fi
    if [ "$(cat /v3-tests/mode)" = legacy-group ] || [ "$(cat /v3-tests/mode)" = pure-compose ]; then task_test='^TestKernelLegacyAgentAndWrappersMigrateAndRollback$'; fi
    if [ "$(cat /v3-tests/mode)" = pure-compose ]; then task_test='^TestKernelPureComposeGroupMigrateAndRollback$'; fi
    /v3-tests/nodeops.test -test.run "$task_test" -test.v -test.timeout 22m 2>&1 | tee /dev/ttyS0
    task_status=$?
  else
    cat /v3-tests/dockerd.log /v3-tests/engine.txt
    task_status=1
  fi
  if [ -n "$task_daemon" ]; then
    kill "$task_daemon" 2>/dev/null || true
    wait "$task_daemon"
  else
    systemctl stop docker.service
  fi
else
  task_test='^TestNativeSystemdKernel(LifecycleRetainsUnconfirmedEvents|UpgradeRestoresOriginalAndRetainsEvents)$'
  if [ "$(cat /v3-tests/mode)" = recovery ]; then task_test='^TestNativeSystemdKernelIdentityRecoveryRetainsEvents$'; fi
  if [ "$(cat /v3-tests/mode)" = name-change ]; then task_test='^TestNativeSystemdKernelNameChangeApplicationAndRollback$'; fi
  /v3-tests/nodeops.test -test.run "$task_test" -test.v -test.timeout 12m 2>&1 | tee /dev/ttyS0
  task_status=$?
fi
printf '\nWEBSCAN_V3_GUEST_TEST_EXIT=%s\n' "$task_status"
cat /v3-tests/test.log >/dev/ttyS0
sync
systemctl poweroff
GUEST
chmod 700 rootfs/v3-tests/run.sh
cat > rootfs/etc/systemd/system/v3-kernel-validation.service <<'UNIT'
[Unit]
Description=Disposable Webscan kernel acceptance
After=basic.target
OnFailure=poweroff.target
[Service]
Type=oneshot
ExecStart=/bin/bash /v3-tests/run.sh
TimeoutStartSec=30min
[Install]
WantedBy=multi-user.target
UNIT
ln -s ../v3-kernel-validation.service rootfs/etc/systemd/system/multi-user.target.wants/v3-kernel-validation.service
# Root disk lives only in this private test directory. No loop device or mount.
task_disk_size=4G
if [ "$WEBSCAN_V3_KERNEL_MODE" != native ] && [ "$WEBSCAN_V3_KERNEL_MODE" != recovery ] && [ "$WEBSCAN_V3_KERNEL_MODE" != name-change ]; then task_disk_size=8G; fi
if [ "$WEBSCAN_V3_KERNEL_MODE" = web-native ] || [ "$WEBSCAN_V3_KERNEL_MODE" = web-docker ] || [ "$WEBSCAN_V3_KERNEL_MODE" = single-boot ]; then task_disk_size=10G; fi
truncate -s "$task_disk_size" guest.ext4
mkfs.ext4 -q -F -d rootfs guest.ext4
sha256sum vmlinuz initrd.img webscan nodeops.test rootfs.tar > inputs.sha256
if [ "$WEBSCAN_V3_KERNEL_MODE" = sidecars ] || [ "$WEBSCAN_V3_KERNEL_MODE" = legacy-group ] || [ "$WEBSCAN_V3_KERNEL_MODE" = pure-compose ]; then sha256sum sidecars.tar sidecar-proof.json >> inputs.sha256; fi
if [ "$WEBSCAN_V3_KERNEL_MODE" = legacy-group ] || [ "$WEBSCAN_V3_KERNEL_MODE" = pure-compose ]; then sha256sum legacy-agent.tar legacy-group-proof.json >> inputs.sha256; fi
cp /kernel-tools-packages.txt tools-packages.txt
# The disk and input hashes are the evidence. Reclaim generated preparation
# copies before boot so repeated local acceptance does not fill the workspace.
# A host file browser can recreate metadata while this generated tree is being
# removed. The disk and its input hashes are already complete; cleanup failure
# must not prevent the actual guest from booting. Keep evidence of leftovers.
if ! rm -rf rootfs; then printf 'Generated rootfs cleanup remains pending.\n' > prepare-cleanup-pending.log; fi
rm rootfs.tar
PREPARE
docker run --rm --name "$task_prepare" --platform linux/arm64 --network none \
  --read-only --tmpfs /tmp:rw,nosuid,size=64m \
  -e WEBSCAN_V3_KERNEL_MODE="$task_mode" -e WEBSCAN_V3_DOCKER_CONTAINERD="${WEBSCAN_V3_DOCKER_CONTAINERD:-0}" \
  -v "$task_run:/validation:rw" --entrypoint /bin/sh "$task_tools" \
  /validation/prepare.sh > "$task_run/prepare.log" 2>&1
task_reboot_flags=(-no-reboot)
if [[ "$task_mode" == single-boot ]]; then task_reboot_flags=(); fi
docker run --rm --name "$task_vm" --platform linux/arm64 --network none \
  --read-only --cpus 3 --memory 4g --tmpfs /tmp:rw,nosuid,size=64m \
  -v "$task_run:/validation:rw" --entrypoint /usr/bin/timeout "$task_tools" \
  2000 qemu-system-x86_64 -accel tcg,thread=multi -cpu max -smp 2 -m 1536 \
  -nodefaults -no-user-config -display none -serial stdio -monitor none \
  -nic none ${task_reboot_flags[@]+"${task_reboot_flags[@]}"} \
  -kernel /validation/vmlinuz -initrd /validation/initrd.img \
  -drive file=/validation/guest.ext4,if=virtio,format=raw \
  -append 'root=/dev/vda rw console=ttyS0 systemd.unified_cgroup_hierarchy=1 systemd.show_status=false systemd.getty_auto=no panic=1' \
  2>&1 | tee "$task_run/serial.log"
docker run --rm --name "$task_prepare" --platform linux/arm64 --network none --read-only \
  -v "$task_run:/validation:ro" --entrypoint /usr/sbin/debugfs "$task_tools" \
  -R 'cat /v3-tests/test.log' /validation/guest.ext4 \
  > "$task_run/guest-test.log" 2> "$task_run/guest-log-extraction.log"
if [[ "$task_mode" != native && "$task_mode" != recovery && "$task_mode" != name-change ]]; then
  docker run --rm --name "$task_prepare" --platform linux/arm64 --network none --read-only \
    -v "$task_run:/validation:rw" --entrypoint /bin/sh "$task_tools" -c \
    'for task_file in dockerd.log engine.txt image-load.log; do debugfs -R "cat /v3-tests/$task_file" /validation/guest.ext4 > "/validation/guest-$task_file" 2>>/validation/guest-log-extraction.log; done'
fi
rg -q '^WEBSCAN_V3_GUEST_TEST_EXIT=0$' "$task_run/guest-test.log"
if [[ "$task_mode" == single-boot ]]; then
  rg -q '^WEBSCAN_V3_SINGLE_BOOT_before_EXIT=0$' "$task_run/guest-test.log"
  rg -q '^WEBSCAN_V3_SINGLE_BOOT_after_EXIT=0$' "$task_run/guest-test.log"
  [[ "$(rg -c '^--- PASS: TestSingleInstallActualKernelBootRecovery ' "$task_run/guest-test.log")" = 2 ]]
elif [[ "$task_mode" == backup-timer ]]; then
  rg -q '^--- PASS: TestSingleBackupActualSignedHelperAndEnginesLinux ' "$task_run/guest-test.log"
  rg -q 'actual systemd default daily timer enabled/active' "$task_run/guest-test.log"
elif [[ "$task_mode" == web-native || "$task_mode" == web-docker || "$task_mode" == single-boot ]]; then
  rg -q '^--- PASS: TestWebDeploymentKernelPublicAPIAndActualServices ' "$task_run/guest-test.log"
elif [[ "$task_mode" == pure-compose ]]; then
  rg -q '^--- PASS: TestKernelPureComposeGroupMigrateAndRollback ' "$task_run/guest-test.log"
  rg -q '^    --- PASS: TestKernelPureComposeGroupMigrateAndRollback/to-native ' "$task_run/guest-test.log"
  rg -q '^    --- PASS: TestKernelPureComposeGroupMigrateAndRollback/to-docker ' "$task_run/guest-test.log"
elif [[ "$task_mode" == legacy-group ]]; then
  rg -q '^--- PASS: TestKernelLegacyAgentAndWrappersMigrateAndRollback ' "$task_run/guest-test.log"
  rg -q '^    --- PASS: TestKernelLegacyAgentAndWrappersMigrateAndRollback/to-native ' "$task_run/guest-test.log"
  rg -q '^    --- PASS: TestKernelLegacyAgentAndWrappersMigrateAndRollback/to-docker ' "$task_run/guest-test.log"
elif [[ "$task_mode" == sidecars ]]; then
  rg -q '^--- PASS: TestKernelActiveLegacyWrappersRetainOriginalContainers ' "$task_run/guest-test.log"
  rg -q '^    --- PASS: TestKernelActiveLegacyWrappersRetainOriginalContainers/vector ' "$task_run/guest-test.log"
  rg -q '^    --- PASS: TestKernelActiveLegacyWrappersRetainOriginalContainers/exporter ' "$task_run/guest-test.log"
elif [[ "$task_mode" == transition ]]; then
  rg -q '^--- PASS: TestKernelNativeDockerTransitionsRetainCurrentData ' "$task_run/guest-test.log"
  rg -q '^    --- PASS: TestKernelNativeDockerTransitionsRetainCurrentData/from-native ' "$task_run/guest-test.log"
  rg -q '^    --- PASS: TestKernelNativeDockerTransitionsRetainCurrentData/from-docker ' "$task_run/guest-test.log"
elif [[ "$task_mode" == recovery ]]; then
  rg -q '^--- PASS: TestNativeSystemdKernelIdentityRecoveryRetainsEvents ' "$task_run/guest-test.log"
elif [[ "$task_mode" == docker-recovery ]]; then
  rg -q '^--- PASS: TestDockerKernelIdentityRecoveryRetainsEvents ' "$task_run/guest-test.log"
elif [[ "$task_mode" == docker ]]; then
  rg -q '^--- PASS: TestDockerKernelLifecycleFinalizesAndRetainsEvents ' "$task_run/guest-test.log"
elif [[ "$task_mode" == name-change ]]; then
  rg -q '^--- PASS: TestNativeSystemdKernelNameChangeApplicationAndRollback ' "$task_run/guest-test.log"
elif [[ "$task_mode" == docker-name-change ]]; then
  rg -q '^--- PASS: TestDockerKernelNameChangeApplicationAndRollback ' "$task_run/guest-test.log"
else
  rg -q '^--- PASS: TestNativeSystemdKernelLifecycleRetainsUnconfirmedEvents ' "$task_run/guest-test.log"
  rg -q '^--- PASS: TestNativeSystemdKernelUpgradeRestoresOriginalAndRetainsEvents ' "$task_run/guest-test.log"
fi
printf 'Real x86_64 kernel evidence: %s\n' "$task_run"
# Exit inside the already parsed function; Bash must not resume reading a
# changed source file after returning from this long-lived invocation.
exit 0
}
main "$@"
