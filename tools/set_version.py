"""Stamp a display version into The Print Shop 4 bundle.

usage: set_version.py <path/The Print Shop 4.app> <version>

Replaces the "4.1 (900)" display strings in Info.plist and the localized
InfoPlist.strings. CFBundleVersion stays 900: the in-app updater reads it
with CFStringGetIntValue and compares it against MacKiev's update list.
"""
import glob
import os
import plistlib
import sys

OLD = "4.1 (900)"


def main():
    app, ver = sys.argv[1], sys.argv[2]
    info = os.path.join(app, "Contents", "Info.plist")
    with open(info, "rb") as fh:
        fmt = plistlib.FMT_BINARY if fh.read(6) == b"bplist" else plistlib.FMT_XML
        fh.seek(0)
        p = plistlib.load(fh)
    p["CFBundleShortVersionString"] = ver
    for key in ("CFBundleGetInfoString", "PSShortVersionString"):
        if key in p:
            p[key] = p[key].replace(OLD, ver)
    with open(info, "wb") as fh:
        plistlib.dump(p, fh, fmt=fmt)
    print(info, "->", p["CFBundleShortVersionString"], "|", p.get("PSShortVersionString"))

    for path in glob.glob(os.path.join(app, "Contents", "Resources", "*.lproj", "InfoPlist.strings")):
        raw = open(path, "rb").read()
        enc = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
        text = raw.decode(enc)
        if OLD not in text:
            continue
        new = text.replace(OLD, ver)
        # Python's utf-16 codec writes a BOM and native (little-endian) order, as the original.
        open(path, "wb").write(new.encode(enc))
        print(path, "updated")


if __name__ == "__main__":
    main()
