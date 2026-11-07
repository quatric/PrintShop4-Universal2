"""Exception tables of the guest: function -> LSDA call sites, for setjmp-based landing pads.

Each call site: (start, length, landing pad address or None, [(filter, type_ref)])
where type_ref is None (catch-all/cleanup) or (address, indirect).
"""
import struct

from macho import read_uleb, read_sleb


def lsda_map(m):
    """function start -> (lsda address, personality index) from __unwind_info and __eh_frame."""
    out = {}
    ui = m.section("__TEXT", "__unwind_info")
    if ui:
        d = m.read(ui.addr, ui.size)
        _, ceo, cec, po, pc, io, ic = struct.unpack_from("<7I", d, 0)
        idx = [struct.unpack_from("<III", d, io + 12 * i) for i in range(ic)]
        lo, hi = idx[0][2], idx[-1][2]
        for i in range((hi - lo) // 8):
            fo, lso = struct.unpack_from("<II", d, lo + 8 * i)
            out[m.base + fo] = m.base + lso
    eh = m.section("__TEXT", "__eh_frame")
    if eh:
        out.update(_eh_frame_lsdas(m, eh))
    return out


def _read_enc(m, d, i, enc, addr_of_i):
    if enc == 0xFF:
        return None, i
    fmt = enc & 0x0F
    if fmt == 0x00:
        v, i2 = struct.unpack_from("<Q", d, i)[0], i + 8
    elif fmt == 0x01:
        v, i2 = read_uleb(d, i)
    elif fmt == 0x02:
        v, i2 = struct.unpack_from("<H", d, i)[0], i + 2
    elif fmt == 0x03:
        v, i2 = struct.unpack_from("<I", d, i)[0], i + 4
    elif fmt == 0x04:
        v, i2 = struct.unpack_from("<Q", d, i)[0], i + 8
    elif fmt == 0x09:
        v, i2 = read_sleb(d, i)
    elif fmt == 0x0A:
        v, i2 = struct.unpack_from("<h", d, i)[0], i + 2
    elif fmt == 0x0B:
        v, i2 = struct.unpack_from("<i", d, i)[0], i + 4
    elif fmt == 0x0C:
        v, i2 = struct.unpack_from("<q", d, i)[0], i + 8
    else:
        raise ValueError(f"encoding {enc:#x}")
    if (enc & 0x70) == 0x10 and v:
        v += addr_of_i
    return v & 0xFFFFFFFFFFFFFFFF, i2


def _eh_frame_lsdas(m, eh):
    d = m.read(eh.addr, eh.size)
    cies = {}
    out = {}
    i = 0
    while i < len(d):
        length = struct.unpack_from("<I", d, i)[0]
        if length == 0:
            break
        start = i + 4
        cid = struct.unpack_from("<I", d, start)[0]
        if cid == 0:
            j = start + 5
            aug = d[j:d.index(b"\0", j)].decode()
            j += len(aug) + 1
            _, j = read_uleb(d, j)
            _, j = read_sleb(d, j)
            _, j = read_uleb(d, j)
            info = {"lsda": 0xFF, "fde": 0}
            if aug.startswith("z"):
                _, j = read_uleb(d, j)
                for ch in aug[1:]:
                    if ch == "P":
                        penc = d[j]
                        _, j = _read_enc(m, d, j + 1, penc, eh.addr + j + 1)
                    elif ch == "L":
                        info["lsda"] = d[j]
                        j += 1
                    elif ch == "R":
                        info["fde"] = d[j]
                        j += 1
            cies[i] = info
        else:
            cie = cies.get(start - cid)
            if cie:
                j = start + 4
                pc, j = _read_enc(m, d, j, cie["fde"], eh.addr + j)
                _, j = _read_enc(m, d, j, cie["fde"] & 0x0F, eh.addr + j)
                _, j = read_uleb(d, j)
                if cie["lsda"] != 0xFF:
                    lsda, j = _read_enc(m, d, j, cie["lsda"], eh.addr + j)
                    if lsda:
                        out[pc] = lsda
        i = start + length
    return out


def parse_lsda(m, lsda, fstart):
    """Call sites of one LSDA."""
    sec = next(s for s in m.sections if s.addr <= lsda < s.addr + s.size)
    d = m.read(sec.addr, sec.size)
    i = lsda - sec.addr
    lpstart_enc = d[i]
    i += 1
    lpstart = fstart
    if lpstart_enc != 0xFF:
        lpstart, i = _read_enc(m, d, i, lpstart_enc, sec.addr + i)
    ttype_enc = d[i]
    i += 1
    ttbase = None
    if ttype_enc != 0xFF:
        off, i = read_uleb(d, i)
        ttbase = i + off
    cs_enc = d[i]
    i += 1
    cs_len, i = read_uleb(d, i)
    cs_end = i + cs_len
    action_base = cs_end
    tsize = {0x00: 8, 0x03: 4, 0x0B: 4, 0x04: 8, 0x0C: 8, 0x02: 2, 0x0A: 2}.get(ttype_enc & 0x0F, 4)
    sites = []
    while i < cs_end:
        st, i = _read_enc(m, d, i, cs_enc & 0x0F, 0)
        ln, i = _read_enc(m, d, i, cs_enc & 0x0F, 0)
        lp, i = _read_enc(m, d, i, cs_enc & 0x0F, 0)
        act, i = read_uleb(d, i)
        actions = []
        if act:
            a = action_base + act - 1
            for _ in range(64):
                filt, a2 = read_sleb(d, a)
                nxt, _ = read_sleb(d, a2)
                tref = None
                if filt > 0 and ttbase is not None:
                    e = ttbase - filt * tsize
                    v, _ = _read_enc(m, d, e, ttype_enc & 0x7F, sec.addr + e)
                    if v:
                        tref = (v, bool(ttype_enc & 0x80))
                actions.append((filt, tref))
                if nxt == 0:
                    break
                a = a2 + nxt
        sites.append((fstart + st, ln, (lpstart + lp) if lp else None, actions))
    return sites
