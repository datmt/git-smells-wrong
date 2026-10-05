#!/usr/bin/env bash
# Install git-smells-wrong on this machine.
#   curl -fsSL https://raw.githubusercontent.com/datmt/git-smells-wrong/main/install.sh | bash
#
# Env overrides:
#   INSTALL_DIR  destination directory (default /usr/local/bin)
set -euo pipefail

REPO="datmt/git-smells-wrong"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="git-smells-wrong"

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux) os="linux" ;;
  Darwin) os="darwin" ;;
  *) echo "error: unsupported os $os (only linux/darwin binaries are published)" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "error: unsupported arch $arch (only amd64/arm64 are published)" >&2; exit 1 ;;
esac

asset="${BIN_NAME}-${os}-${arch}"

dest="${INSTALL_DIR}/${BIN_NAME}"
log() { echo "[install] $*" >&2; }
CURL="curl -fsSL --connect-timeout 10 --max-time 300"
log "os=$os arch=$arch dest=$dest"

log "fetching latest release tag"
latest=$($CURL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

log "latest=${latest:-<none>}"

if [ -x "$dest" ]; then
  log "existing binary found, checking version"
  # binaries predating the `version` subcommand exit non-zero here,
  # which the fallback below treats as "unknown" and reinstalls.
  current=$(timeout 3 "$dest" version 2>/dev/null </dev/null || echo "")
  log "current=${current:-<unknown>}"
  if [ -n "$latest" ] && [ "$current" = "$latest" ]; then
    echo "$dest already at $current, skipping"
    exit 0
  fi
fi

url="https://github.com/${REPO}/releases/latest/download/${asset}"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

echo "downloading $url"
$CURL "$url" -o "$tmp"
chmod +x "$tmp"

if [ -w "$INSTALL_DIR" ]; then
  log "moving to $dest"
  mv "$tmp" "$dest"
else
  log "$INSTALL_DIR not writable, using sudo (may prompt for password)"
  sudo mv "$tmp" "$dest"
fi

echo "installed $dest ($("$dest" version))"
