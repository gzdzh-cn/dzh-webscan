set -euo pipefail
umask 077
TASK_UNITS=${TASK_UNITS:-/etc/systemd/system}
mkdir -p -- "$TASK_BACKUP"
chmod 700 "$TASK_BACKUP"
ids=()
running=()
legacy=0
if systemctl is-active --quiet webscan-central-v1.service; then legacy=1; fi
if command -v docker >/dev/null; then
  docker info >/dev/null
  container_ids=$(docker ps -aq --filter "label=com.docker.compose.project=$TASK_PROJECT")
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ids+=("$id")
    if [ "$(docker inspect -f '{{.State.Running}}' "$id")" = true ]; then running+=("$id"); fi
  done <<< "$container_ids"
fi
removed=0
recover() {
  rc=$?
  if [ "$rc" -ne 0 ] && [ "$removed" = 0 ]; then
    for id in "${running[@]+"${running[@]}"}"; do docker start "$id" >/dev/null 2>&1 || true; done
    if [ "$legacy" = 1 ]; then systemctl start webscan-central-v1.service || true; fi
  fi
  exit "$rc"
}
trap recover EXIT
if [ "$legacy" = 1 ]; then systemctl stop webscan-central-v1.service; fi
for id in "${running[@]+"${running[@]}"}"; do docker stop "$id" >/dev/null; done
paths=()
for path in "$TASK_RUNTIME" "$TASK_DATA/events-v1.sqlite3" "$TASK_DATA/events-v1.sqlite3-wal" "$TASK_DATA/events-v1.sqlite3-shm" "$TASK_UNITS/webscan-central-v1.service" "$TASK_UNITS/webscan-central-v1.service.d"; do
  if [ -e "$path" ] || [ -L "$path" ]; then paths+=("${path#/}"); fi
done
if [ "${#paths[@]}" -gt 0 ]; then
  tar -C / -czf "$TASK_BACKUP/central-runtime-and-database.tar.gz" -- "${paths[@]+"${paths[@]}"}"
else
  tar -czf "$TASK_BACKUP/central-runtime-and-database.tar.gz" --files-from /dev/null
fi
tar -tzf "$TASK_BACKUP/central-runtime-and-database.tar.gz" >/dev/null
removed=1
for id in "${ids[@]+"${ids[@]}"}"; do docker rm "$id" >/dev/null; done
if [ -e "$TASK_UNITS/webscan-central-v1.service" ]; then systemctl disable webscan-central-v1.service; fi
if [ -z "$TASK_EXTERNAL_NETWORK" ] && command -v docker >/dev/null; then
  network="${TASK_PROJECT}-monitor"
  if [ "$(docker network inspect -f '{{len .Containers}}' "$network" 2>/dev/null || true)" = 0 ]; then docker network rm "$network" >/dev/null; fi
fi
rm -rf -- "$TASK_RUNTIME" "$TASK_UNITS/webscan-central-v1.service" "$TASK_UNITS/webscan-central-v1.service.d" "$TASK_UNITS/multi-user.target.wants/webscan-central-v1.service"
systemctl daemon-reload
echo '主服务器监控已卸载，数据、账号、部署包与备份保留。'
