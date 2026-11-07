"""Generate gen/sigs.mm: native address + type encoding for every imported function.

Usage: gensigs.py <gendir>

Encodings come from the SDK declarations via @encode, so the ABI marshaller
sees the real argument and return types.  A trailing '.' marks a variadic
function.  Functions with no usable declaration are listed in tools/manual_sigs.txt
as "<symbol> <encoding>" and bound by assembly name.
"""
import json
import os
import sys

HEADERS = """
#import <Cocoa/Cocoa.h>
#import <Carbon/Carbon.h>
#import <Quartz/Quartz.h>
#import <QuartzCore/QuartzCore.h>
#import <WebKit/WebKit.h>
#import <Contacts/Contacts.h>
#import <AddressBook/AddressBook.h>
#import <MapKit/MapKit.h>
#import <EventKit/EventKit.h>
#import <CoreLocation/CoreLocation.h>
#import <MediaLibrary/MediaLibrary.h>
#import <Security/Security.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CoreImage/CoreImage.h>
#import <ImageIO/ImageIO.h>
#import <CoreText/CoreText.h>
#import <CFNetwork/CFNetwork.h>
#include <CommonCrypto/CommonCrypto.h>
#include <zlib.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <dispatch/dispatch.h>
#include <libkern/OSAtomic.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <copyfile.h>
#include <execinfo.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <xlocale.h>
#include <Block.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <string>
"""

PRELUDE = """
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <string>
template <typename T> struct E { static std::string s() { return @encode(T); } };
template <> struct E<void> { static std::string s() { return "v"; } };
template <typename R, typename... A> static const char *sigof(R (*)(A...))
{
    static std::string s = E<R>::s() + (std::string() + ... + E<A>::s());
    return s.c_str();
}
template <typename R, typename... A> static const char *sigof(R (*)(A..., ...))
{
    static std::string s = E<R>::s() + (std::string() + ... + E<A>::s()) + ".";
    return s.c_str();
}
struct ImportSig { void *addr; const char *sig; };
"""


def cname(sym):
    n = sym[1:] if sym.startswith("_") else sym
    return n.split("$", 1)[0]


def main():
    gen = sys.argv[1]
    here = os.path.dirname(__file__)
    meta = json.load(open(os.path.join(gen, "meta.json")))
    imports = meta["imports"]
    manual = {}
    mp = os.path.join(here, "manual_sigs.txt")
    if os.path.exists(mp):
        for line in open(mp):
            line = line.strip()
            if line and not line.startswith("#"):
                f = line.split()
                manual[f[0]] = (f[1], f[2] if len(f) > 2 else f[0])
    out = [HEADERS, PRELUDE]
    for i, sym in enumerate(imports):
        if sym in manual:
            out.append(f'extern "C" void m_{i}(void) __asm("{manual[sym][1]}");')
    out.append('extern "C" const ImportSig x86_import_sigs[];')
    out.append("const ImportSig x86_import_sigs[] = {")
    for i, sym in enumerate(imports):
        if sym in manual:
            out.append(f' {{(void *)&m_{i}, "{manual[sym][0]}"}}, /* {sym} */')
        else:
            out.append(f" {{(void *)&::{cname(sym)}, sigof(&::{cname(sym)})}}, /* {sym} */")
    out.append("};")
    out.append("#include <stdio.h>")
    out.append(f"int main(void) {{ for (int i = 0; i < {len(imports)}; i++) printf(\"%s\\n\", x86_import_sigs[i].sig); }}")
    with open(os.path.join(gen, "sigs.mm"), "w") as fh:
        fh.write("\n".join(out) + "\n")
    # Native symbol each import binds to (for the constant table built from the dump).
    with open(os.path.join(gen, "sigsyms.txt"), "w") as fh:
        for sym in imports:
            fh.write((manual[sym][1] if sym in manual else "_" + cname(sym)) + "\n")


if __name__ == "__main__":
    main()
