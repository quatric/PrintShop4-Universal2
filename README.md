# The Print Shop 4 — Universal 2

Runs The Print Shop 4 (4.1, build 900) natively on Apple silicon by statically
recompiling its x86_64 executable to arm64 and shipping both slices in one
Universal 2 binary. No Rosetta needed.

You can download the compiled DMG on MacSerialJunkie or MacBB.

## How it works

- `tools/lift.py` disassembles every x86_64 function (with capstone) and emits
  C that runs it against an emulated register file (`gen/lift_*.c`, functions
  named `F_<x86 address>`).
- `tools/relink.py` reproduces the original data segments and pointers
  (`gen/image.s`, `gen/image.c`, `gen/table.c`), and `tools/eh.py` translates
  the C++ exception tables.
- `tools/gensigs.py` and `tools/sigtable.py` derive a native type signature
  for each imported function from the SDK headers.
- `runtime/` is the bridge between the recompiled code and macOS:
  - `abi.c` converts arguments and return values between x86-64 SysV and arm64.
  - `rt.m` handles imports, `objc_msgSend`, printf-style variadics, `va_list`
    imports, blocks and callbacks into recompiled code.
  - `eh.c` runs the C++ exceptions thrown by the recompiled code.

## Build

```sh
mkdir -p orig && cp -cR "/path/to/original/The Print Shop 4.app" orig/   # x86_64-only copy
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./build.sh            # full lift + build -> out/PrintShop.arm64
./build.sh --nolift   # after runtime/ or relink changes only
```

## Test and install

```sh
./run.sh                                         # runs inside test/ (a copy of orig/), log in out/run.log
X86RT_TRACE=1 ./run.sh                           # log every bridged call
python3 tools/crash.py                           # summarize the newest PS4.arm64 crash report
./install.sh "/Applications/The Print Shop 4.app" # lipo x86_64 + arm64, ad-hoc sign, back up the old binary to out/
```

## Disk image

`make-dmg.sh` builds `out/The_Print_Shop_4_for_Mac_4.1-U2B.dmg` from MacKiev's
own image, keeping its volume name, background and window layout. It:

- adds the arm64 slice to the template's app and re-signs it (ad hoc);
- stamps 4.1-U2B into the display version strings. `CFBundleVersion` stays
  900 because the in-app updater compares it as a number;
- adds the user guide bottom-left, with Registration bottom-right.

```sh
./make-dmg.sh The_Print_Shop_4_for_Mac.dmg The_Print_Shop_4_User_Guide.pdf 4.1-U2B
```

The template is never modified. Changes go to a shadow file, so it needs about
5 GB free for the compressed output.

## Known issues

- Edit > Select All with text on the page reports "Correct Spell: Unknown
  error encountered" when `Contents/Resources/Dictionaries/` (`Iens9522.dat`,
  `Henis321.dat`) is missing from the app. The original x86_64 app does the
  same. MacKiev's DMG includes the folder, so apps built with `make-dmg.sh`
  have it.
