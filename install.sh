#!/usr/bin/env sh
set -e

REPO="alfa-reza/cvss-calculator-mcp"
BINARY="cvss-calculator-mcp"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux*) OS="linux" ;;
  darwin*) OS="darwin" ;;
  *)
    echo "Error: Unsupported operating system: $OS" >&2
    echo "Supported operating systems: Linux, macOS (Darwin)" >&2
    exit 1
    ;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Error: Unsupported architecture: $ARCH" >&2
    echo "Supported architectures: amd64 (x86_64), arm64 (aarch64)" >&2
    exit 1
    ;;
esac

# Determine installation directory
INSTALL_DIR="${INSTALL_DIR:-}"
if [ -z "$INSTALL_DIR" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
  elif [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="$HOME/.local/bin"
  fi
fi

# Determine version to install
VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  echo "Checking latest release..."
  LATEST_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)"
  if [ -n "$LATEST_JSON" ]; then
    VERSION="$(echo "$LATEST_JSON" | grep '"tag_name":' | head -n 1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
  fi
fi

if [ -z "$VERSION" ]; then
  VERSION="v1.0.0"
fi

VERSION_NUM="${VERSION#v}"
TARBALL="${BINARY}_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"

echo "Installing ${BINARY} ${VERSION} (${OS}/${ARCH}) into ${INSTALL_DIR}..."

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'cvss_install')"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading ${TARBALL}..."
curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${TARBALL}"
curl -fsSL "$CHECKSUMS_URL" -o "${TMP_DIR}/SHA256SUMS"

echo "Verifying SHA256 checksum..."
(
  cd "$TMP_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    grep "${TARBALL}" SHA256SUMS | sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    grep "${TARBALL}" SHA256SUMS | shasum -a 256 -c -
  else
    echo "Warning: sha256sum or shasum not found, skipping checksum verification." >&2
  fi
)

echo "Extracting..."
tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"

mkdir -p "$INSTALL_DIR"
cp "${TMP_DIR}/${BINARY}_${VERSION_NUM}_${OS}_${ARCH}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
chmod 755 "${INSTALL_DIR}/${BINARY}"

echo "Successfully installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  echo ""
  echo "Notice: ${INSTALL_DIR} is not in your PATH."
  echo "You can add it by running:"
  echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
fi
