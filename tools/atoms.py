"""Atom labels for relinked guest data.

ld splits ObjC metadata (and other data) into atoms and expects every pointer
to target the start of one, so each rebase target in these sections gets its
own label _x86a_<k>_<offset>.  Lifter and relinker share this table.
"""
import bisect

# Emitted as real cstring_literals sections (ld's ObjC analysis expects them); one label per string.
CSTRING_SECTS = {"__cstring", "__objc_methname", "__objc_classname", "__objc_methtype"}
# ld crashes on labels inside __objc_methname; code only reaches it through selrefs.
NO_ATOMS = {"__objc_methname", "__text", "__stubs", "__stub_helper", "__bss", "__common"}


def atom_labels(m, secs):
    """{section index: sorted offsets} for every labelled guest section."""
    starts = [s.addr for s in secs]
    out = {k: {0} for k, s in enumerate(secs) if s.sectname not in NO_ATOMS and s.type != 1}
    for k, s in enumerate(secs):
        if s.sectname in CSTRING_SECTS and k in out:
            data = m.read(s.addr, s.size)
            i = 0
            while i < len(data):
                out[k].add(i)
                e = data.find(b"\0", i)
                i = len(data) if e < 0 else e + 1
    def mark(v):
        k = bisect.bisect_right(starts, v) - 1
        if k in out and v < secs[k].addr + secs[k].size:
            out[k].add(v - secs[k].addr)

    for a in m.rebases():
        mark(m.u64(a))
    for end in objc_struct_ends(m, secs):
        mark(end)
    return {k: sorted(v) for k, v in out.items()}


def objc_struct_ends(m, secs):
    """End addresses of ObjC metadata structures, so each is a separate atom."""
    import struct
    ends = set()

    def sect(name):
        return next((s for s in secs if s.sectname == name), None)

    def lst(p, fixed_ent=None):
        if not p:
            return 0
        ent, cnt = struct.unpack("<II", m.read(p, 8))
        ent = fixed_ent or (ent & 0xFFFC)
        ends.add(p + 8 + cnt * ent)
        return cnt

    def protolist(p):
        if not p:
            return
        cnt = m.u64(p)
        ends.add(p + 8 + cnt * 8)

    def ro(r):
        ends.add(r + 72)
        lst(m.u64(r + 32))
        protolist(m.u64(r + 40))
        lst(m.u64(r + 48))
        lst(m.u64(r + 64))

    s = sect("__objc_classlist")
    for j in range(s.size // 8 if s else 0):
        c = m.u64(s.addr + j * 8)
        for kls in (c, m.u64(c)):
            ends.add(kls + 40)
            ro(m.u64(kls + 32) & ~7)
    for name in ("__objc_catlist", "__objc_nlcatlist"):
        s = sect(name)
        for j in range(s.size // 8 if s else 0):
            cat = m.u64(s.addr + j * 8)
            lst(m.u64(cat + 16))
            lst(m.u64(cat + 24))
            protolist(m.u64(cat + 32))
            lst(m.u64(cat + 40))
    s = sect("__objc_protolist")
    for j in range(s.size // 8 if s else 0):
        p = m.u64(s.addr + j * 8)
        size = struct.unpack("<I", m.read(p + 64, 4))[0]
        ends.add(p + size)
        protolist(m.u64(p + 16))
        total = sum(lst(m.u64(p + off)) for off in (24, 32, 40, 48))
        lst(m.u64(p + 56))
        if size >= 80:
            emt = m.u64(p + 72)
            if emt:
                ends.add(emt + 8 * total)
    return ends


def label_for(labels, k, d):
    """(label name, delta) addressing offset d of section k."""
    offs = labels[k]
    i = bisect.bisect_right(offs, d) - 1
    if i < 0:
        i = 0
    return f"x86a_{k}_{offs[i]:x}", d - offs[i]
