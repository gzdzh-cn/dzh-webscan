#!/usr/bin/env bash
# Only used for fresh Debian/Ubuntu installations; existing Docker is kept.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'root required' >&2; exit 1; }
if docker info >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then exit 0; fi
  install -m 0755 -d /usr/local/lib/docker/cli-plugins
  if command -v docker-compose >/dev/null 2>&1 && [[ $(docker-compose version --short) == 2.* || $(docker-compose version --short) == v2.* ]]; then
    ln -sf -- "$(command -v docker-compose)" /usr/local/lib/docker/cli-plugins/docker-compose
  else
    [[ $(uname -m) == x86_64 ]] || { echo 'linux amd64 required' >&2; exit 1; }
    TASK_PLUGIN=$(mktemp)
    trap 'rm -f -- "$TASK_PLUGIN"' EXIT
    curl -fsSL --connect-timeout 15 --max-time 180 --retry 2 https://github.com/docker/compose/releases/download/v2.39.4/docker-compose-linux-x86_64 -o "$TASK_PLUGIN"
    [[ $(sha256sum "$TASK_PLUGIN" | cut -d ' ' -f1) == 7af95166a730b87e172d4fc9aefea8725d3c6c7327d59149267b452114ddb7d4 ]] || { echo 'Compose checksum mismatch' >&2; exit 1; }
    install -m 0755 "$TASK_PLUGIN" /usr/local/lib/docker/cli-plugins/docker-compose
  fi
  docker compose version
  exit 0
fi
source /etc/os-release
case "$ID" in debian|ubuntu) ;; *) echo 'Fresh Docker bootstrap supports Debian and Ubuntu' >&2; exit 1;; esac
[[ $(uname -m) == x86_64 ]] || { echo 'linux amd64 required' >&2; exit 1; }
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
TASK_KEY=$(mktemp)
trap 'rm -f -- "$TASK_KEY"' EXIT
curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o "$TASK_KEY"
[[ $(gpg --show-keys --with-colons "$TASK_KEY" | awk -F: '$1=="fpr" {print $10; exit}') == 9DC858229FC7DD38854AE2D88D81803C0EBFCD88 ]] || { echo 'Docker repository key mismatch' >&2; exit 1; }
install -m 0644 "$TASK_KEY" /etc/apt/keyrings/docker.asc
printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' "$ID" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
TASK_ENGINE="5:29.1.3-1~$ID.$VERSION_ID~$VERSION_CODENAME"
apt-get install -y --no-install-recommends "docker-ce=$TASK_ENGINE" "docker-ce-cli=$TASK_ENGINE" containerd.io "docker-compose-plugin=2.39.4-1~$ID.$VERSION_ID~$VERSION_CODENAME"
systemctl enable --now docker
docker info >/dev/null
docker compose version
