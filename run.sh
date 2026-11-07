#!/bin/zsh
# Launch out/PrintShop.arm64 inside a copy of the original bundle (test/), logging to out/run.log.
# Set X86RT_TRACE=1 to log every bridged call.
cd "${0:A:h}"
B="test/The Print Shop 4.app"
D="$B/Contents/MacOS"
if [[ ! -d "$B" ]]; then
  mkdir -p test && cp -cR "orig/The Print Shop 4.app" test/
fi
for p in $(pgrep -x PS4.arm64); do kill $p; done
# rm first: overwriting in place breaks the binary's signature.
rm -f "$D/PS4.arm64" && cp out/PrintShop.arm64 "$D/PS4.arm64"
LOG="${LOG:-$PWD/out/run.log}"
cd "$D" && (./PS4.arm64 -ApplePersistenceIgnoreState YES > "$LOG" 2>&1 &)
