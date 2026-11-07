#!/bin/zsh
# Build a Universal 2 disk image from MacKiev's The_Print_Shop_4_for_Mac.dmg.
#   ./make-dmg.sh <The_Print_Shop_4_for_Mac.dmg> <The_Print_Shop_4_User_Guide.pdf> [version]
# The template is never modified: changes go to a shadow file, then the
# template plus shadow are compressed into out/The_Print_Shop_4_for_Mac_<version>.dmg.
# Keeps the template's volume name, background, window and icon layout, adds the
# user guide bottom-left with Registration bottom-right (as on the KID PIX 5 image).
set -e
cd "${0:A:h}"
TEMPLATE="${1:?usage: make-dmg.sh <template.dmg> <user guide.pdf> [version]}"
GUIDE="${2:?usage: make-dmg.sh <template.dmg> <user guide.pdf> [version]}"
VER="${3:-4.1-U2B}"
PY="${PY:-.venv/bin/python}"
[[ -f out/PrintShop.arm64 ]] || { echo "build first: ./build.sh" >&2; exit 1; }
$PY -c "import ds_store" 2>/dev/null || { echo "$PY needs ds_store: $PY -m pip install -r requirements.txt" >&2; exit 1; }

W="$PWD/out/dmg-work"
OUT="$PWD/out/The_Print_Shop_4_for_Mac_${VER}.dmg"
rm -rf "$W" "$OUT"
mkdir -p "$W/mnt"
hdiutil attach -nobrowse -noautoopen -noverify -shadow "$W/shadow" -mountpoint "$W/mnt" "$TEMPLATE" >/dev/null
trap 'hdiutil detach "$W/mnt" -quiet 2>/dev/null || true' EXIT

A="$W/mnt/The Print Shop 4.app"
E="$A/Contents/MacOS/The Print Shop 4"
lipo -info "$E" | grep -q "architecture: x86_64" || { echo "template app is not the original x86_64 build" >&2; exit 1; }

# Universal 2 executable: the template's own x86_64 code plus the recompiled arm64 slice.
lipo -create "$E" out/PrintShop.arm64 -output "$W/universal"
rm -f "$E" && cp "$W/universal" "$E" && chmod 755 "$E" && rm -f "$W/universal"
$PY tools/set_version.py "$A" "$VER"
codesign --force --deep --sign - "$A"
codesign --verify --deep --strict "$A"

ditto "$GUIDE" "$W/mnt/The Print Shop 4 User Guide.pdf"
$PY tools/dmg_layout.py "$W/mnt/.DS_Store" \
  "The Print Shop 4 User Guide.pdf=128,519" \
  "Registration=363,519"

sync
hdiutil detach "$W/mnt" -quiet
trap - EXIT
hdiutil convert "$TEMPLATE" -shadow "$W/shadow" -format UDZO -o "$OUT"
rm -rf "$W"
hdiutil verify "$OUT" >/dev/null
echo "built $OUT"
