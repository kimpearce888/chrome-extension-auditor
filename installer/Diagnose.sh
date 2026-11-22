#!/usr/bin/env bash
# Local Chrome Extension Auditor - Diagnostics (Linux)
# Runs the scanner's built-in local diagnostics: toolchain, Chrome profile
# discovery, native host registration and data directories.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$(uname -m)" in
  x86_64|amd64) SCAN_ARCH=amd64 ;;
  aarch64|arm64) SCAN_ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
esac
SCANNER="$PKG_DIR/native/scanner-linux-$SCAN_ARCH"
[ -x "$SCANNER" ] || { echo "Scanner binary missing: $SCANNER (run installer/install.sh)"; exit 1; }
exec "$SCANNER" --diagnose
