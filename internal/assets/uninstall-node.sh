set -euo pipefail
umask 077
mkdir -p -- "$TASK_BACKUP"
chmod 700 "$TASK_BACKUP"
if [ -f "$TASK_BACKUP/node-uninstalled" ]; then
  echo '此节点已完成卸载，继续主服务器收尾。'
  exit 0
fi
units=()
running=()
for name in webscan-agent-native webscan-agent-v1 webscan-vector-v1 webscan-exporter-v1 webscan-firewall-v1; do
  if systemctl is-active --quiet "$name.service"; then units+=("$name.service"); fi
done
TASK_DOCKER_AVAILABLE=0
if command -v docker >/dev/null && { [ "${TASK_MODE:-docker}" = docker ] || [ -f /etc/webscan-v1/compose.yml ]; }; then
  docker info >/dev/null 2>&1 || { echo "Docker 服务不可用，无法核对旧监控容器是否停止，请先恢复后卸载" >&2; exit 1; }
  TASK_DOCKER_AVAILABLE=1
  for name in webscan-agent-go webscan-vector-v1 webscan-exporter-v1; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" = true ]; then running+=("$name"); fi
  done
fi
removed=0
recover() {
  rc=$?
  if [ "$rc" -ne 0 ] && [ "$removed" = 0 ]; then
    for name in "${running[@]+"${running[@]}"}"; do docker start "$name" >/dev/null 2>&1 || true; done
    for name in "${units[@]+"${units[@]}"}"; do systemctl start "$name" || true; done
  fi
  exit "$rc"
}
trap recover EXIT
for name in "${units[@]+"${units[@]}"}"; do systemctl stop "$name"; done
for name in "${running[@]+"${running[@]}"}"; do
  if docker inspect "$name" >/dev/null 2>&1; then docker stop "$name" >/dev/null; fi
done
paths=()
for path in /etc/webscan-v1 /opt/webscan-go /opt/webscan-agent-v1 /var/lib/webscan-v1/agent.sqlite3 /var/lib/webscan-v1/agent.sqlite3-wal /var/lib/webscan-v1/agent.sqlite3-shm; do
  if [ -e "$path" ] || [ -L "$path" ]; then paths+=("${path#/}"); fi
done
for name in webscan-agent-native webscan-agent-v1 webscan-vector-v1 webscan-exporter-v1 webscan-firewall-v1; do
  for path in "/etc/systemd/system/$name.service" "/etc/systemd/system/$name.service.d"; do
    if [ -e "$path" ] || [ -L "$path" ]; then paths+=("${path#/}"); fi
  done
done
if [ ! -f "$TASK_BACKUP/node-runtime-and-database.tar.gz" ]; then
  if [ "${#paths[@]}" -gt 0 ]; then
    tar -C / -czf "$TASK_BACKUP/node-runtime-and-database.tar.gz.tmp" -- "${paths[@]+"${paths[@]}"}"
  else
    tar -czf "$TASK_BACKUP/node-runtime-and-database.tar.gz.tmp" --files-from /dev/null
  fi
  tar -tzf "$TASK_BACKUP/node-runtime-and-database.tar.gz.tmp" >/dev/null
  mv -- "$TASK_BACKUP/node-runtime-and-database.tar.gz.tmp" "$TASK_BACKUP/node-runtime-and-database.tar.gz"
fi
tar -tzf "$TASK_BACKUP/node-runtime-and-database.tar.gz" >/dev/null
removed=1
for name in webscan-agent-native webscan-agent-v1 webscan-vector-v1 webscan-exporter-v1 webscan-firewall-v1; do
  if [ -e "/etc/systemd/system/$name.service" ]; then systemctl disable "$name.service"; fi
done
if [ "$TASK_DOCKER_AVAILABLE" = 1 ]; then
  for name in webscan-agent-go webscan-vector-v1 webscan-exporter-v1; do
    if docker inspect "$name" >/dev/null 2>&1; then docker rm "$name" >/dev/null; fi
  done
fi
for tool in iptables ip6tables; do
  if command -v "$tool" >/dev/null && "$tool" -S WEBSCAN_V1 >/dev/null 2>&1; then
    while IFS= read -r rule; do
      read -ra args <<< "$rule"
      args[0]=-D
      "$tool" "${args[@]}"
    done < <("$tool" -S INPUT | awk '$NF == "WEBSCAN_V1"')
    "$tool" -F WEBSCAN_V1
    "$tool" -X WEBSCAN_V1
  fi
done
for name in webscan-agent-native webscan-agent-v1 webscan-vector-v1 webscan-exporter-v1 webscan-firewall-v1; do
  rm -rf -- "/etc/systemd/system/$name.service" "/etc/systemd/system/$name.service.d" "/etc/systemd/system/multi-user.target.wants/$name.service"
done
rm -rf -- /etc/webscan-v1 /opt/webscan-go /opt/webscan-agent-v1
systemctl daemon-reload
for name in webscan-agent-native webscan-agent-v1 webscan-vector-v1 webscan-exporter-v1; do
  if systemctl is-active --quiet "$name.service"; then echo "监控服务仍在运行，卸载未通过验收" >&2; exit 1; fi
done
if [ "$TASK_DOCKER_AVAILABLE" = 1 ]; then
  for name in webscan-agent-go webscan-vector-v1 webscan-exporter-v1; do
    if docker inspect "$name" >/dev/null 2>&1; then echo "监控容器仍存在，卸载未通过验收" >&2; exit 1; fi
  done
fi
echo '节点监控已卸载，数据库、队列、网站文件与备份保留。'
printf 'complete\n' > "$TASK_BACKUP/node-uninstalled.tmp"
mv -- "$TASK_BACKUP/node-uninstalled.tmp" "$TASK_BACKUP/node-uninstalled"
