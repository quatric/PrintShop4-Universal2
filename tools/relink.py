"""Re-emit the guest image's sections as native assembly so ld/dyld do its fixups.

Usage: relink.py <x86_64 binary> <gendir>

Writes <gendir>/image.s (all guest sections; pointer slots as relocations),
<gendir>/image.c (section table, entry point, ObjC method signatures per function)
and <gendir>/binds.txt (external symbols the image references).
"""
import bisect
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
from macho import MachO
from atoms import atom_labels, CSTRING_SECTS

# Sections the native ObjC runtime looks up by name keep their names.
OBJC_KEEP = {"__objc_classlist", "__objc_nlclslist", "__objc_catlist", "__objc_nlcatlist",
             "__objc_protolist", "__objc_selrefs", "__objc_superrefs",
             "__objc_protorefs", "__objc_const", "__objc_data"}
ZEROFILL = {"__bss", "__common"}


def sym(name):
    return '"' + name + '"' if any(ch in name for ch in "$.<> ") else name


def main():
    path, gen = sys.argv[1], sys.argv[2]
    m = MachO(path)
    meta = json.load(open(os.path.join(gen, "meta.json")))
    starts = meta["starts"]
    fidx = {a: i for i, a in enumerate(starts)}
    secs = sorted((s for s in m.sections if s.size and s.segname != "__PAGEZERO"), key=lambda s: s.addr)
    sec_starts = [s.addr for s in secs]

    import bisect

    def sect_of(addr):
        k = max(bisect.bisect_right(sec_starts, addr) - 1, 0)
        return k, addr - secs[k].addr

    atoms = atom_labels(m, secs)
    atom_sets = {k: set(v) for k, v in atoms.items()}
    # Method names: assembler-local labels (section-relative relocations, as clang emits).
    local_strs = {}
    for k, s_ in enumerate(secs):
        if s_.sectname == "__objc_methname":
            data = m.read(s_.addr, s_.size)
            offs, i = [], 0
            while i < len(data):
                offs.append(i)
                e = data.find(b"\0", i)
                i = len(data) if e < 0 else e + 1
            local_strs[k] = offs

    def ptr_expr(v):
        if v in fidx:
            return f"_x86t_{fidx[v]}"
        k, d = sect_of(v)
        if k in atom_sets and d in atom_sets[k]:
            return f"_x86a_{k}_{d:x}"
        if k in local_strs:
            offs = local_strs[k]
            j = bisect.bisect_right(offs, d) - 1
            return f"Lx86m_{offs[j]:x}" + (f"+{d - offs[j]}" if d != offs[j] else "")
        return f"_x86s_{k}{d:+d}" if d else f"_x86s_{k}"

    rebases = set(m.rebases())
    binds = {}
    for addr, name, ordinal, addend, flags in m.binds():
        binds[addr] = (name, addend)
    lazy = set(a for a, *_ in m.lazy_binds())
    externs = set()

    out = []
    for k, s in enumerate(secs):
        name = s.sectname
        if name in CSTRING_SECTS:
            seg, nm = "__TEXT", name + ",cstring_literals"
        elif s.segname == "__TEXT":
            seg, nm = "__TEXT", "__x" + name[2:][:13]
        elif name in OBJC_KEEP:
            seg, nm = "__DATA", name
        else:
            seg, nm = "__DATA", "__x" + name[2:][:13]
        align = s.align
        if name in ZEROFILL or s.type == 1:
            out.append(f".zerofill __DATA,{nm},_x86s_{k},{s.size},{align}")
            out.append(f".private_extern _x86s_{k}")
            continue
        flags = ",regular,no_dead_strip" if name in OBJC_KEEP else ""
        out.append(f".section {seg},{nm}{flags}")
        out.append(f".p2align {align}")
        out.append(f".private_extern _x86s_{k}")
        out.append(f"_x86s_{k}:")
        data = m.read(s.addr, s.size)
        i = 0
        run = []

        def flush_run():
            if run:
                for j in range(0, len(run), 64):
                    out.append(" .byte " + ",".join(str(b) for b in run[j:j + 64]))
                run.clear()

        local_set = set(local_strs.get(k, ()))
        slotted = name in OBJC_KEEP and name not in ("__objc_const", "__objc_data")
        while i < s.size:
            a = s.addr + i
            if k in local_strs and i in local_set:
                flush_run()
                out.append(f"Lx86m_{i:x}:")
            if k in atom_sets and i in atom_sets[k]:
                flush_run()
                out.append(f".private_extern _x86a_{k}_{i:x}")
                out.append(f"_x86a_{k}_{i:x}:")
            if slotted and i % 8 == 0:
                flush_run()
                out.append(f".private_extern _x86s_{k}_{i:x}")
                out.append(f"_x86s_{k}_{i:x}:")
            if a in binds and i + 8 <= s.size:
                flush_run()
                nm_, add = binds[a]
                externs.add(nm_)
                out.append(f" .quad {sym(nm_)}{add:+d}" if add else f" .quad {sym(nm_)}")
                i += 8
            elif a in rebases and i + 8 <= s.size:
                flush_run()
                v = struct.unpack_from("<Q", data, i)[0]
                out.append(f" .quad {ptr_expr(v)}")
                i += 8
            elif a in lazy and i + 8 <= s.size:
                flush_run()
                out.append(" .quad 0")
                i += 8
            else:
                run.append(data[i])
                i += 1
        flush_run()
    with open(os.path.join(gen, "image.s"), "w") as fh:
        fh.write("\n".join(out) + "\n")
    with open(os.path.join(gen, "binds.txt"), "w") as fh:
        fh.write("\n".join(sorted(externs)) + "\n")

    # ObjC method type encodings per IMP, for native->guest marshalling.
    sigs = {}
    base = m.base

    def u64(a):
        return m.u64(a)

    def methods(ml):
        if not ml:
            return
        ent, cnt = struct.unpack("<II", m.read(ml, 8))
        ent &= 0xFFFC
        for j in range(cnt):
            e = ml + 8 + j * ent
            nm_, ty, imp = u64(e), u64(e + 8), u64(e + 16)
            if imp in fidx:
                sigs.setdefault(fidx[imp], (m.cstr(ty), m.cstr(nm_)))

    def cls(c):
        for kls in (c, u64(c)):
            ro = u64(kls + 32) & ~7
            methods(u64(ro + 32))

    for sname, fn in (("__objc_classlist", cls),):
        s = next((x for x in secs if x.sectname == sname), None)
        if s:
            for j in range(s.size // 8):
                fn(u64(s.addr + j * 8))
    for sname in ("__objc_catlist", "__objc_nlcatlist"):
        s = next((x for x in secs if x.sectname == sname), None)
        if s:
            for j in range(s.size // 8):
                cat = u64(s.addr + j * 8)
                methods(u64(cat + 16))
                methods(u64(cat + 24))

    inits = []
    s = next((x for x in secs if x.sectname == "__mod_init_func"), None)
    if s:
        inits = [secs.index(s), s.size // 8]
    main_addr = base + m.entryoff
    with open(os.path.join(gen, "image.c"), "w") as fh:
        fh.write('#include "x86.h"\n#include "funcs.h"\n')
        fh.write(f"const unsigned x86_nsecs = {len(secs)};\n")
        def secsym(k):
            if secs[k].sectname in ("__objc_classlist", "__objc_catlist", "__objc_nlcatlist", "__objc_nlclslist"):
                return "0"
            sl = secs[k].sectname in OBJC_KEEP and secs[k].sectname not in ("__objc_const", "__objc_data")
            return f"x86s_{k}_0" if sl else f"x86s_{k}"
        for k in range(len(secs)):
            if secsym(k) != "0":
                fh.write(f"extern u8 {secsym(k)}[];\n")
        fh.write("u8 *const x86_sec_ptr[] = {" + ",".join(secsym(k) for k in range(len(secs))) + "};\n")
        fh.write("const u64 x86_sec_addr[] = {" + ",".join(f"0x{s.addr:x}ULL" for s in secs) + "};\n")
        fh.write("const u64 x86_sec_size[] = {" + ",".join(f"0x{s.size:x}ULL" for s in secs) + "};\n")
        fh.write("const char *const x86_sec_name[] = {" + ",".join(f'"{s.sectname}"' for s in secs) + "};\n")
        fh.write(f"const int x86_main_index = {fidx[main_addr]};\n")
        if inits:
            fh.write(f"u64 *const x86_modinit = (u64 *)x86s_{inits[0]};\nconst unsigned x86_nmodinit = {inits[1]};\n")
        else:
            fh.write("u64 *const x86_modinit = 0;\nconst unsigned x86_nmodinit = 0;\n")
        syms = m.defined_symbols()
        fh.write("const u8 x86_fn_isblock[] = {")
        fh.write(",".join("1" if "_block_invoke" in syms.get(a, "") else "0" for a in starts))
        fh.write("};\n")
        fh.write("const char *const x86_fn_sig[] = {\n")
        for i in range(len(starts)):
            t = sigs.get(i)
            fh.write(f' "{t[0]}",\n' if t else " 0,\n")
        fh.write("};\n")
    print(f"{len(secs)} sections, {len(externs)} external symbols, {len(sigs)} method signatures, "
          f"main=F_{main_addr:x}", file=sys.stderr)


if __name__ == "__main__":
    main()
