#!/usr/bin/env bash
# Local Chrome Extension Auditor - Installer (Linux)
# Per-user install: registers the native messaging host under ~/.config.
# No root, no system-wide changes, no unrelated settings touched.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_NAME="com.local.extensionauditor.scanner"
EXTENSION_ID="dmcdpgifoohggggokgglbhhfgaicnahd"   # pinned via manifest key
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/LocalExtensionAuditor"

G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; C=$'\033[36m'; N=$'\033[0m'
step() { printf "[%s/8] %s" "$1" "$2"; }
ok()   { echo -e "${G} OK${N}"; }
warn() { echo -e "${Y} WARNING${N}"; }
fail() { echo -e "${R} FAILED${N}"; }

# 1. Detect architecture + pick the scanner binary
step 1 "Detecting architecture"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  SCAN_ARCH=amd64 ;;
  aarch64|arm64) SCAN_ARCH=arm64 ;;
  *) fail; echo " Unsupported architecture: $arch (need x86-64 or arm64)."; exit 1 ;;
esac
ok; echo "  CPU: $arch -> scanner-linux-$SCAN_ARCH"

# 2. Detect Chrome / Chromium (Linux user data dirs)
step 2 "Detecting Google Chrome"
CHROME_BIN=""; CHROME_UD=""
for cand in google-chrome google-chrome-stable chromium-browser chromium; do
  p=$(command -v "$cand" 2>/dev/null || true)
  [ -n "$p" ] && CHROME_BIN="$p" && break
done
for ud in "$HOME/.config/google-chrome" "$HOME/.config/chromium"; do
  [ -d "$ud" ] && CHROME_UD="$ud" && break
done
if [ -n "$CHROME_UD" ]; then ok; echo "  Profile dir: $CHROME_UD"
else warn; echo "  No Chrome/Chromium profile found yet. Install still works; first launch of the browser creates it."; fi
[ -n "$CHROME_BIN" ] && echo "  Binary: $CHROME_BIN"

# 3. Verify native scanner exists (portable install, lives in the package)
step 3 "Verifying native scanner"
SCANNER="$PKG_DIR/native/scanner-linux-$SCAN_ARCH"
# Self-heal in case the archive extractor stripped execute bits
[ -f "$SCANNER" ] && chmod +x "$SCANNER" 2>/dev/null || true
if [ ! -x "$SCANNER" ]; then
  if command -v go >/dev/null 2>&1; then
    echo "  Binary missing — building from source with Go …"
    ( cd "$PKG_DIR/native" && go build -o "scanner-linux-$SCAN_ARCH" . )
  else
    fail; echo "  $SCANNER not found and Go is not installed to build it."; exit 1
  fi
fi
[ -x "$SCANNER" ] || { fail; echo "  Scanner still missing after build attempt."; exit 1; }
ok; echo "  $SCANNER"

# 4. Write the native messaging host manifest with real values (portable)
step 4 "Writing native host manifest"
HOST_MANIFEST="$PKG_DIR/native/$HOST_NAME.json"
cat > "$HOST_MANIFEST" <<EOF
{
  "name": "$HOST_NAME",
  "description": "Local Chrome Extension Auditor scanner",
  "path": "$SCANNER",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXTENSION_ID/"]
}
EOF
ok; echo "  $HOST_MANIFEST"
echo "  allowed_origins: chrome-extension://$EXTENSION_ID/"

# 5. Register native messaging host (per-browser dir, all profiles of that browser)
step 5 "Registering native messaging host"
REGISTERED=0
for nmd in "$HOME/.config/google-chrome/NativeMessagingHosts" "$HOME/.config/chromium/NativeMessagingHosts"; do
  mkdir -p "$nmd"
  cp "$HOST_MANIFEST" "$nmd/$HOST_NAME.json"
  REGISTERED=1
done
if [ "$REGISTERED" = 1 ]; then ok; else warn; echo "  No browser config dirs existed; created ~/.config paths anyway."; fi

# 6. Extension installation - honest about Chrome's restrictions
step 6 "Chrome extension install (one manual step, required by Chrome)"
echo ""
echo -e "${Y}  Chrome does not permit silent installation of self-hosted extensions outside${N}"
echo -e "${Y}  enterprise policy, and this package will never bypass Chrome's security.${N}"
echo ""
echo -e "${C}  Do this once:${N}"
echo "    1. Open chrome://extensions"
echo "    2. Enable 'Developer mode' (top right)"
echo "    3. Click 'Load unpacked'"
echo "    4. Select:  $PKG_DIR/extension/dist"
echo ""
if [ -t 0 ] && [ -n "$CHROME_BIN" ]; then
  read -r -p "  Open chrome://extensions now? (y/N) " ans
  case "$ans" in y|Y) "$CHROME_BIN" --new-window "chrome://extensions" >/dev/null 2>&1 & echo -e "${C}  Opening…${N}";; esac
fi

# 7. Create data directories (matches native/store.go DataDir)
step 7 "Creating data directories"
mkdir -p "$DATA_DIR/reports" "$DATA_DIR/logs"
ok; echo "  $DATA_DIR"

# 8. Verify installation
step 8 "Verifying installation"
VERDICT=0
chmod +x "$PKG_DIR/installer/Diagnose.sh" "$PKG_DIR/installer/uninstall.sh" 2>/dev/null || true
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['name']=='$HOST_NAME' and d['path'].startswith('/')" "$HOME/.config/google-chrome/NativeMessagingHosts/$HOST_NAME.json" 2>/dev/null || VERDICT=1
if [ "$VERDICT" = 0 ]; then ok; else warn; echo "  Host manifest JSON could not be validated (python3 missing?) — file was still written."; fi
if V=$("$SCANNER" --version 2>/dev/null); then echo "  Scanner: $V"; else warn; echo "  Scanner did not run; check architecture/dependencies."; fi

# Optional desktop shortcut to the dashboard
DESKTOP="$HOME/.local/share/applications/local-extension-auditor.desktop"
if [ -n "$CHROME_BIN" ] && [ -d "$HOME/.local/share/applications" ]; then
  cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=Local Extension Auditor
Exec=$CHROME_BIN --app=chrome-extension://$EXTENSION_ID/dashboard.html
Terminal=false
Comment=Dashboard of the Local Chrome Extension Auditor
EOF
  echo "  Desktop entry: $DESKTOP (works once the extension is loaded)"
fi

echo ""
echo -e "${G}=== Install completed ===${N}"
echo "Next: load the extension (step 6), open it, and run your first scan."
echo "Diagnostics: installer/Diagnose.sh   |   Uninstall: installer/uninstall.sh"
