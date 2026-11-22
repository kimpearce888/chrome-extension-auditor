#!/usr/bin/env bash
# Local Chrome Extension Auditor - Uninstaller (Linux)
# Removes ONLY this product's artifacts. Chrome itself, other extensions and
# unrelated settings are never touched. Reports are kept unless --purge.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_NAME="com.local.extensionauditor.scanner"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/LocalExtensionAuditor"
G=\033[32m; Y=\033[33m; N=\033[0m

echo -e "${G}[1/4] Removing native messaging host registrations${N}"
for nmd in "$HOME/.config/google-chrome/NativeMessagingHosts" "$HOME/.config/chromium/NativeMessagingHosts"; do
  f="$nmd/$HOST_NAME.json"
  if [ -f "$f" ]; then rm -f "$f" && echo "  removed $f"; fi
done

echo -e "${G}[2/4] Removing generated host manifest from package${N}"
rm -f "$PKG_DIR/native/$HOST_NAME.json" && echo "  removed $PKG_DIR/native/$HOST_NAME.json"

echo -e "${G}[3/4] Removing desktop entry${N}"
rm -f "$HOME/.local/share/applications/local-extension-auditor.desktop" && echo "  removed desktop entry (if present)"

echo -e "${G}[4/4] Data directory${N}"
case "${1:-}" in
  --purge)
    rm -rf "$DATA_DIR" && echo "  purged $DATA_DIR (reports included)" ;;
  *)
    echo "  keeping $DATA_DIR (your reports). Re-run with --purge to delete them."
    # The extension itself stays loaded in Chrome; remove it from
    # chrome://extensions if you want it gone.
    ;;
esac
echo -e "\n${G}=== Uninstall completed ===${N}"
echo "Remove the extension itself (if desired): chrome://extensions -> Remove."
