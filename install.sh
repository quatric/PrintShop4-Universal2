#!/bin/zsh
# Merge the original x86_64 binary with out/PrintShop.arm64 and install the
# Universal 2 executable into an existing copy of the app, keeping a backup.
#   ./install.sh "/Applications/The Print Shop 4.app"
set -e
cd "${0:A:h}"
DEST="${1:?usage: install.sh <path to The Print Shop 4.app>}"
X86="${APP_BIN:-orig/The Print Shop 4.app/Contents/MacOS/The Print Shop 4}"
E="$DEST/Contents/MacOS/The Print Shop 4"
[[ -f "$E" ]] || { echo "no executable at $E" >&2; exit 1; }
[[ -f out/PrintShop.arm64 ]] || { echo "build first: ./build.sh" >&2; exit 1; }
cp -p "$E" "out/The Print Shop 4.backup-$(date +%Y%m%d-%H%M%S)"
lipo -create "$X86" out/PrintShop.arm64 -output out/universal.tmp
rm -f "$E" && mv out/universal.tmp "$E" && chmod 755 "$E"
codesign --force --deep --sign - "$DEST"
lipo -info "$E"
codesign --verify --deep --strict "$DEST" && echo "installed and verified: $DEST"
