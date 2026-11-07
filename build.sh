#!/bin/zsh
# Build the arm64 slice of The Print Shop 4 from its x86_64 binary.
#   ./build.sh           lift, relink and compile everything
#   ./build.sh --nolift  reuse gen/lift_*.c (runtime or relink changes only)
set -e
cd "${0:A:h}"
APP_BIN="${APP_BIN:-orig/The Print Shop 4.app/Contents/MacOS/The Print Shop 4}"
PY="${PY:-.venv/bin/python}"
OPT="${OPT:--O1}"
if [[ ! -f "$APP_BIN" ]]; then
  echo "missing $APP_BIN: copy the original x86_64 The Print Shop 4.app into orig/ (or set APP_BIN)" >&2
  exit 1
fi
if ! lipo -info "$APP_BIN" | grep -q "architecture: x86_64"; then
  echo "$APP_BIN must be the original x86_64-only binary, not a universal build" >&2
  exit 1
fi
mkdir -p gen obj out
if [[ "$1" != "--nolift" && "$1" != "--link" ]]; then
  $PY tools/lift.py "$APP_BIN" gen
fi
$PY tools/relink.py "$APP_BIN" gen
$PY tools/gensigs.py gen
CF=(-arch arm64 -mmacosx-version-min=11.0 -Iruntime -Igen -g0)
ls gen/lift_*.c | xargs -P "$(sysctl -n hw.ncpu)" -I{} sh -c 'f={}; o=obj/$(basename $f .c).o; [ "$o" -nt "$f" ] || clang '"$OPT ${CF[*]}"' -c $f -o $o'
clang $OPT $CF -c gen/table.c -o obj/table.o
clang $OPT $CF -c gen/image.c -o obj/image_c.o
clang $CF -c gen/image.s -o obj/image.o
clang $CF -c gen/tramp.s -o obj/tramp.o
clang $CF -c runtime/stubs.s -o obj/stubs.o
clang $OPT $CF -c runtime/abi.c -o obj/abi.o
clang $OPT $CF -c runtime/eh.c -o obj/eh.o
clang $OPT $CF -fno-objc-arc -c runtime/rt.m -o obj/rt.o
clang++ $CF -std=c++17 -O0 gen/sigs.mm $(cat fw.txt) -o gen/dumpsigs
gen/dumpsigs | $PY tools/sigtable.py gen
clang $OPT $CF -c gen/sigs_table.c -o obj/sigs.o
clang++ $CF obj/*.o $(cat fw.txt) -Wl,-no_objc_category_merging -Wl,-platform_version,macos,11.0,10.15 -o out/PrintShop.arm64
echo built out/PrintShop.arm64
