#!/bin/bash
# Fresh standalone native package. Existing nodes must use the central manager.
set -euo pipefail
[[ $EUID == 0 && $(uname -m) == x86_64 && -d /run/systemd/system ]] || { echo '需要 root、Linux amd64 和 systemd' >&2; exit 1; }
TASK_SYSTEMD_VERSION=$(systemctl --version | awk 'NR==1 {print $2}')
[[ $TASK_SYSTEMD_VERSION -ge 231 ]] || { echo '需要 systemd 231 或更高版本' >&2; exit 1; }
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  grep -qw memory /sys/fs/cgroup/cgroup.controllers && grep -qw cpu /sys/fs/cgroup/cgroup.controllers || { echo '缺少 CPU/内存 cgroup 能力' >&2; exit 1; }
else
  [[ -d /sys/fs/cgroup/memory && -d /sys/fs/cgroup/cpu ]] || { echo '缺少 CPU/内存 cgroup 能力' >&2; exit 1; }
fi
[[ ! -e /etc/systemd/system/webscan-agent-native.service ]] || { echo '已有服务，请从主服务器升级' >&2; exit 1; }
[[ $# == 2 && $2 =~ ^[a-f0-9]{64}$ ]] || { echo '用法：bash install-native.sh agent-native.tar.gz <发布清单中的 SHA256>' >&2; exit 1; }
TASK_BASE=$(cd -- "$(dirname -- "$0")" && pwd)
[[ ! -e /etc/webscan-v1/runtime.json && ! -L /etc/webscan-v1 && ! -e /opt/webscan-go/standalone && ! -L /opt/webscan-go ]] || { echo '发现已有配置，请通过主服务器升级，未覆盖原文件' >&2; exit 1; }
[[ $(sha256sum "$1" | cut -d ' ' -f1) == "$2" ]] || { echo '工具包校验失败' >&2; exit 1; }
umask 077
mkdir -p /opt/webscan-go /etc/webscan-v1 /var/lib/webscan-v1/textfile /var/log/webscan-v1
TASK_STAGE=$(mktemp -d /opt/webscan-go/.native-XXXXXX)
trap 'rm -rf -- "$TASK_STAGE"' EXIT
tar -xzf "$1" -C "$TASK_STAGE"
(cd "$TASK_STAGE" && sha256sum -c SHA256SUMS >/dev/null && test "$(./webscan version)" = "$(cat VERSION)" && ./tools/bin/yara --version >/dev/null)
"$TASK_STAGE/tools/bin/yara" -w "$TASK_BASE/config/php-webshell.yar" /dev/null
if [ "${TASK_CLAMAV:-false}" = true ]; then
  : > "$TASK_STAGE/scan-probe"
  test -S /run/clamav/clamd.ctl && "$TASK_STAGE/tools/bin/clamdscan" --fdpass --config-file="$TASK_BASE/config/clamd.conf" --no-summary "$TASK_STAGE/scan-probe" || { echo 'ClamAV 扫描服务不可用' >&2; exit 1; }
  rm -f "$TASK_STAGE/scan-probe"
fi
cp -a "$TASK_BASE/config/." /etc/webscan-v1/
chmod 700 /etc/webscan-v1 /var/lib/webscan-v1 /var/log/webscan-v1
find /etc/webscan-v1 -type f -exec chmod 600 '{}' \;
mv "$TASK_STAGE" /opt/webscan-go/standalone
cp "$TASK_BASE/webscan-agent-native.service" /etc/systemd/system/webscan-agent-native.service
bash "$TASK_BASE/prepare-directories.sh"
systemctl daemon-reload
systemctl enable --now webscan-agent-native
if ! /opt/webscan-go/standalone/webscan tool --action validate-native-service; then
  systemctl disable --now webscan-agent-native
  echo '实际资源限制未生效，已停止新服务；配置及数据保留，请修复后通过主服务器管理' >&2
  exit 1
fi
echo '服务已启动。请在主服务器核对目录覆盖、扫描、指标和事件投递；端口默认 19100。'
