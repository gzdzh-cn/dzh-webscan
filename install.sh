#!/usr/bin/env bash
# Public DZH Webscan installer. Keep main as the final statement for pipe use.
set -euo pipefail
umask 077
webscan_install_main() {
  [[ ${EUID:-$(id -u)} == 0 ]] || { echo '请使用 root 在主服务器执行安装命令。' >&2; return 1; }
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo '目前仅支持 Linux amd64（x86_64）主服务器。' >&2; return 1; }
  for TASK_TOOL in curl sha256sum mktemp bash flock cut; do command -v "$TASK_TOOL" >/dev/null || { echo "缺少工具 $TASK_TOOL，请安装后重试。" >&2; return 1; }; done
  [[ -r /dev/tty && -w /dev/tty ]] && ( : </dev/tty ) 2>/dev/null || { echo '需要交互终端，请在主服务器 SSH 终端执行安装命令。' >&2; return 1; }
  # Refuse unsafe ancestors before creating the state directory or lock.
  for TASK_PATH in /var /var/lib /var/lib/webscan-deploy; do
    [[ ! -L "$TASK_PATH" && ( ! -e "$TASK_PATH" || -d "$TASK_PATH" ) ]] || { echo "目录不安全：$TASK_PATH" >&2; return 1; }
  done
  mkdir -p /var/lib/webscan-deploy
  chmod 700 /var/lib/webscan-deploy
  [[ ! -L /var/lib/webscan-deploy/download.lock ]] || { echo '下载锁路径不安全。' >&2; return 1; }
  exec 9>/var/lib/webscan-deploy/download.lock
  flock -n 9 || { echo '另一个安装入口正在执行，请稍后重试。' >&2; return 1; }
  TASK_STAGE=$(mktemp -d /tmp/webscan-install.XXXXXXXX)
  trap 'rm -rf -- "$TASK_STAGE"' EXIT
  TASK_BASE=https://github.com/gzdzh-cn/dzh-webscan/releases
  TASK_FETCH() {
    if ! curl --proto '=https' --proto-redir '=https' -fSL --connect-timeout 15 --max-time 180 --retry 2 "$1" -o "$2"; then
      echo '下载失败，未启动部署。已有部署可直接输入 webscan 管理，或执行 bash /root/webscan-deploy/deploy-webscan.sh。' >&2
      return 1
    fi
  }
  TASK_FETCH "$TASK_BASE/latest/download/install-manifest.txt" "$TASK_STAGE/install-manifest.txt"
  TASK_RELEASE= TASK_COMMIT= TASK_SCRIPT_SHA= TASK_EXAMPLE_SHA=
  while IFS='=' read -r TASK_KEY TASK_VALUE; do
    case "$TASK_KEY" in
      release) [[ -z "$TASK_RELEASE" ]] || return 1; TASK_RELEASE=$TASK_VALUE ;;
      source_commit) [[ -z "$TASK_COMMIT" ]] || return 1; TASK_COMMIT=$TASK_VALUE ;;
      script_sha256) [[ -z "$TASK_SCRIPT_SHA" ]] || return 1; TASK_SCRIPT_SHA=$TASK_VALUE ;;
      example_sha256) [[ -z "$TASK_EXAMPLE_SHA" ]] || return 1; TASK_EXAMPLE_SHA=$TASK_VALUE ;;
      *) echo '发布清单包含不支持的字段。' >&2; return 1 ;;
    esac
  done < "$TASK_STAGE/install-manifest.txt"
  [[ $TASK_RELEASE =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && $TASK_COMMIT =~ ^[a-f0-9]{40}$ && $TASK_SCRIPT_SHA =~ ^[a-f0-9]{64}$ && $TASK_EXAMPLE_SHA =~ ^[a-f0-9]{64}$ ]] || { echo '发布清单格式不正确。' >&2; return 1; }
  if [[ -f /root/webscan-deploy/deploy-webscan.sh && ! -L /root/webscan-deploy/deploy-webscan.sh ]] && [[ $(sha256sum /root/webscan-deploy/deploy-webscan.sh | cut -d ' ' -f1) == "$TASK_SCRIPT_SHA" ]]; then
    cp /root/webscan-deploy/deploy-webscan.sh "$TASK_STAGE/deploy-webscan.sh"
    echo '本地脚本已是最新发布版本，跳过重复下载。'
  else
    TASK_FETCH "$TASK_BASE/download/$TASK_RELEASE/deploy-webscan.sh" "$TASK_STAGE/deploy-webscan.sh"
  fi
  if [[ ! -e /root/webscan-deploy/webscan.yaml && ! -L /root/webscan-deploy/webscan.yaml ]]; then
    TASK_FETCH "https://raw.githubusercontent.com/gzdzh-cn/dzh-webscan/$TASK_COMMIT/webscan.example.yaml" "$TASK_STAGE/webscan.example.yaml"
    [[ $(sha256sum "$TASK_STAGE/webscan.example.yaml" | cut -d ' ' -f1) == "$TASK_EXAMPLE_SHA" ]] || { echo '示例 YAML 校验失败，未初始化配置。' >&2; return 1; }
  fi
  [[ $(sha256sum "$TASK_STAGE/deploy-webscan.sh" | cut -d ' ' -f1) == "$TASK_SCRIPT_SHA" ]] || { echo '脚本 SHA256 校验失败，未安装或覆盖本地文件。' >&2; return 1; }
  bash -n "$TASK_STAGE/deploy-webscan.sh"
  bash "$TASK_STAGE/deploy-webscan.sh" --prepare-package "$TASK_STAGE"
  # Use the controlling terminal, not the curl pipeline, for the wizard/menu.
  bash /root/webscan-deploy/deploy-webscan.sh </dev/tty
}
webscan_install_main "$@"
