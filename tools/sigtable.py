"""Write gen/sigs_table.c: constant import table (address, encoding) from the dumped encodings.

Usage: sigtable.py <gendir> < dumped-encodings
Constant so it is usable before C++ static initializers run (guest +load methods).
"""
import os
import sys

gen = sys.argv[1]
syms = open(os.path.join(gen, "sigsyms.txt")).read().split()
sigs = sys.stdin.read().split("\n")[:len(syms)]
out = ['#include "rt.h"']
for i, s in enumerate(syms):
    out.append(f'extern char imp_{i}[] __asm("{s}");')
out.append("const ImportSig x86_import_sigs[] = {")
for i, sig in enumerate(sigs):
    out.append(f' {{imp_{i}, "{sig}"}},')
out.append("};")
open(os.path.join(gen, "sigs_table.c"), "w").write("\n".join(out) + "\n")
