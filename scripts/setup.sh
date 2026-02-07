#!/usr/bin/env bash
set -euo pipefail

LEFTHOOK_VERSION="2.1.0"
INSTALL_DIR="${HOME}/.local/bin"

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "${OS}" in
  Linux)  OS_NAME="Linux" ;;
  Darwin) OS_NAME="macOS" ;;
  *)      echo "Unsupported OS: ${OS}" >&2; exit 1 ;;
esac

case "${ARCH}" in
  x86_64)  ARCH_NAME="x86_64" ;;
  aarch64|arm64) ARCH_NAME="arm64" ;;
  *)       echo "Unsupported architecture: ${ARCH}" >&2; exit 1 ;;
esac

BINARY_NAME="lefthook_${LEFTHOOK_VERSION}_${OS_NAME}_${ARCH_NAME}"
URL="https://github.com/evilmartians/lefthook/releases/download/v${LEFTHOOK_VERSION}/${BINARY_NAME}"

# Skip download if already installed at correct version
if command -v lefthook &>/dev/null && lefthook version 2>/dev/null | grep -q "${LEFTHOOK_VERSION}"; then
  echo "lefthook ${LEFTHOOK_VERSION} already installed"
else
  echo "Downloading lefthook ${LEFTHOOK_VERSION}..."
  mkdir -p "${INSTALL_DIR}"
  curl -fsSL -o "${INSTALL_DIR}/lefthook" "${URL}"
  chmod +x "${INSTALL_DIR}/lefthook"
  echo "Installed lefthook to ${INSTALL_DIR}/lefthook"
fi

# Install git hooks (idempotent — safe in worktrees too)
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"
lefthook install
echo "Git hooks installed."
