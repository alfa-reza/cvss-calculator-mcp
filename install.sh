#!/usr/bin/env sh
set -e

REPO="alfa-reza/cvss-calculator-mcp"
BINARY="cvss-calculator-mcp"

# Keep output readable when redirected or when color is disabled.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
  BOLD="$(printf '\033[1m')"
  CYAN="$(printf '\033[36m')"
  GREEN="$(printf '\033[32m')"
  RESET="$(printf '\033[0m')"
else
  BOLD="" CYAN="" GREEN="" RESET=""
fi

step() {
  printf '%s  →%s %s\n' "$CYAN" "$RESET" "$1"
}

printf '\n%s  CVSS Calculator MCP%s\n' "$BOLD" "$RESET"
printf '  Install the latest release on your system\n\n'

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
  step "Checking latest release"
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

printf '  Version   %s\n' "$VERSION"
printf '  Platform  %s/%s\n' "$OS" "$ARCH"
printf '  Location  %s\n\n' "$INSTALL_DIR"

TMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t 'cvss_install')"
trap 'rm -rf "$TMP_DIR"' EXIT

step "Downloading release"
curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${TARBALL}"
curl -fsSL "$CHECKSUMS_URL" -o "${TMP_DIR}/SHA256SUMS"

step "Verifying SHA256 checksum"
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

step "Installing binary"
tar -xzf "${TMP_DIR}/${TARBALL}" -C "$TMP_DIR"

mkdir -p "$INSTALL_DIR"
cp "${TMP_DIR}/${BINARY}_${VERSION_NUM}_${OS}_${ARCH}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
chmod 755 "${INSTALL_DIR}/${BINARY}"

printf '\n%s  ✓ Installation complete%s\n' "$GREEN" "$RESET"
printf '  Binary: %s/%s\n' "$INSTALL_DIR" "$BINARY"

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
  echo ""
  echo "Notice: ${INSTALL_DIR} is not in your PATH."
  echo "You can add it by running:"
  echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
fi

printf '\n%s  Next steps%s\n' "$BOLD" "$RESET"
printf '  Add this MCP server to your agent using stdio:\n'
printf '    Command: %s/%s\n' "$INSTALL_DIR" "$BINARY"
printf '    Arguments: --transport stdio\n\n'
printf '  Or start the Streamable HTTP server in your terminal:\n'
printf '    "%s/%s" --transport http\n' "$INSTALL_DIR" "$BINARY"
printf '    Endpoint: http://127.0.0.1:43871/mcp (stop with Ctrl+C)\n\n'
printf '  Ask your agent to use calculate_cvss with a version and base vector.\n'
printf '  Setup guide: https://github.com/%s#usage\n' "$REPO"
