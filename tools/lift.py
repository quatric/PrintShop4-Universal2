"""Static recompiler: x86_64 Mach-O __text -> C for arm64.

Usage: lift.py <x86_64 binary> <outdir>
"""
import os
import sys
import struct
import collections
import json

sys.path.insert(0, os.path.dirname(__file__))
from macho import MachO
from atoms import atom_labels, label_for
import eh
import capstone
from capstone import x86 as X

OP_REG, OP_IMM, OP_MEM = X.X86_OP_REG, X.X86_OP_IMM, X.X86_OP_MEM

GPR64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
REGS = {}
for i, r in enumerate(GPR64):
    REGS[r] = (r, 8, 0)
for r, a, b, c in [("rax", "eax", "ax", "al"), ("rcx", "ecx", "cx", "cl"), ("rdx", "edx", "dx", "dl"),
                   ("rbx", "ebx", "bx", "bl"), ("rsp", "esp", "sp", "spl"), ("rbp", "ebp", "bp", "bpl"),
                   ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil")]:
    REGS[a] = (r, 4, 0)
    REGS[b] = (r, 2, 0)
    REGS[c] = (r, 1, 0)
for r, h in [("rax", "ah"), ("rcx", "ch"), ("rdx", "dh"), ("rbx", "bh")]:
    REGS[h] = (r, 1, 8)
for n in range(8, 16):
    REGS[f"r{n}d"] = (f"r{n}", 4, 0)
    REGS[f"r{n}w"] = (f"r{n}", 2, 0)
    REGS[f"r{n}b"] = (f"r{n}", 1, 0)

UT = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}
ST = {1: "s8", 2: "s16", 4: "s32", 8: "s64"}
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}

CC = {"e": "e", "z": "e", "ne": "ne", "nz": "ne", "b": "b", "c": "b", "nae": "b", "ae": "ae", "nb": "ae", "nc": "ae",
      "be": "be", "na": "be", "a": "a", "nbe": "a", "l": "l", "nge": "l", "ge": "ge", "nl": "ge", "le": "le",
      "ng": "le", "g": "g", "nle": "g", "s": "s", "ns": "ns", "p": "p", "pe": "p", "np": "np", "po": "np",
      "o": "o", "no": "no"}

EAGER = {
    "e": "ZF", "ne": "!ZF", "b": "CF", "ae": "!CF", "be": "(CF|ZF)", "a": "(!CF&&!ZF)",
    "l": "(SF!=OF)", "ge": "(SF==OF)", "le": "(ZF||SF!=OF)", "g": "(!ZF&&SF==OF)",
    "s": "SF", "ns": "!SF", "p": "PF", "np": "!PF", "o": "OF", "no": "!OF",
}

FCMP_PRED = {"eq": 0, "lt": 1, "le": 2, "unord": 3, "neq": 4, "nlt": 5, "nle": 6, "ord": 7}


# ObjC pointer-list sections ld splits into per-entry atoms: referenced per slot.
SLOT_SECTS = {"__objc_classlist", "__objc_nlclslist", "__objc_catlist", "__objc_nlcatlist",
              "__objc_protolist", "__objc_selrefs", "__objc_superrefs",
              "__objc_protorefs"}


class Unhandled(Exception):
    pass


class Program:
    def __init__(self, path):
        self.m = m = MachO(path)
        self.base = m.base
        self.text = m.section("__TEXT", "__text")
        self.tlo, self.thi = self.text.addr, self.text.addr + self.text.size
        self.code = m.read(self.text.addr, self.text.size)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.dic = {a: (l, k) for a, l, k in m.data_in_code()}
        # stubs and pointer slots -> import names
        self.stub_name = {}
        self.slot_name = {}
        for s, addr, name in m.indirect_symbols():
            if s.type == 8:
                self.stub_name[addr] = name
            else:
                self.slot_name[addr] = name
        # Lazy pointer slots for stubs: the indirect table gives names directly.
        self.imports = []
        self.import_index = {}
        self.syms = m.defined_symbols()
        # Guest sections are relinked as separate native symbols x86s_<k>.
        self.secs = [s for s in m.sections if s.size and s.segname != "__PAGEZERO"]
        self.secs.sort(key=lambda s: s.addr)
        self.sec_starts = [s.addr for s in self.secs]
        self.text_k = self.secs.index(self.text)
        self.slot_syms = set()
        self.atoms = atom_labels(m, self.secs)
        self.eh = {}
        for f, l in eh.lsda_map(m).items():
            sites = eh.parse_lsda(m, l, f)
            if any(lp for _, _, lp, _ in sites):
                self.eh[f] = sites

    def sect_of(self, addr):
        """(section index, delta) for a guest address; an exact end address binds to its section."""
        import bisect
        k = bisect.bisect_right(self.sec_starts, addr) - 1
        if k < 0:
            k = 0
        return k, addr - self.secs[k].addr

    def sym_of(self, addr):
        """(symbol, delta) addressing a guest address in the relinked image."""
        k, d = self.sect_of(addr)
        if self.secs[k].sectname in SLOT_SECTS and 0 <= d < self.secs[k].size and d % 8 == 0:
            name = f"x86s_{k}_{d:x}"
            self.slot_syms.add(name)
            return name, 0
        if k in self.atoms and 0 <= d < self.secs[k].size:
            name, dd = label_for(self.atoms, k, d)
            self.slot_syms.add(name)
            return name, dd
        return f"x86s_{k}", d

    def img(self, addr):
        name, d = self.sym_of(addr)
        if d == 0:
            return f"((u64)(uintptr_t){name})"
        return f"((u64)(uintptr_t){name}+0x{d:x})" if d > 0 else f"((u64)(uintptr_t){name}-0x{-d:x})"

    def img_ptr(self, addr):
        name, d = self.sym_of(addr)
        return f"((const u8 *){name}{d:+d})" if d else f"((const u8 *){name})"

    def import_id(self, name):
        if name not in self.import_index:
            self.import_index[name] = len(self.imports)
            self.imports.append(name)
        return self.import_index[name]

    def decode(self, a):
        o = a - self.tlo
        ins = next(self.md.disasm(self.code[o:o + 16], a), None)
        return ins

    def analyze(self):
        starts = set(a for a in self.m.function_starts() if self.tlo <= a < self.thi)
        self.orig_starts = set(starts)
        self.insns = {}  # addr -> capstone insn
        decoded_ranges = {}
        changed = True
        rounds = 0
        while changed:
            rounds += 1
            changed = False
            ss = sorted(starts)
            ends = ss[1:] + [self.thi]
            new = set()
            for f, e in zip(ss, ends):
                a = f
                while a < e:
                    if a in self.dic:
                        a += self.dic[a][0]
                        continue
                    ins = self.insns.get(a)
                    if ins is None:
                        ins = self.decode(a)
                        if ins is None:
                            a += 1
                            continue
                        self.insns[a] = ins
                    mn = ins.mnemonic
                    if mn == "call" or mn == "jmp" or (mn.startswith("j") and mn != "jmp"):
                        op = ins.operands[0] if ins.operands else None
                        if op is not None and op.type == OP_IMM:
                            t = op.imm
                            if self.tlo <= t < self.thi:
                                if mn == "call":
                                    if t not in starts:
                                        new.add(t)
                                elif not (f <= t < e) and t not in starts:
                                    new.add(t)
                    a += ins.size
            if new:
                starts |= new
                changed = True
        self.starts = sorted(starts)
        self.ends = dict(zip(self.starts, self.starts[1:] + [self.thi]))
        self.index = {a: i for i, a in enumerate(self.starts)}
        print(f"analysis: {rounds} rounds, {len(self.starts)} functions "
              f"({len(self.starts) - len(self.orig_starts)} synthetic)", file=sys.stderr)

    def jump_tables(self, f, e):
        """Targets reachable through 32-bit relative jump tables inside [f, e)."""
        targets = set()
        for a, (l, k) in self.dic.items():
            if f <= a < e and k in (2, 3, 4):
                sz = {2: 1, 3: 2, 4: 4}[k]
                fmt = {1: "<b", 2: "<h", 4: "<i"}[sz]
                for j in range(l // sz):
                    off = struct.unpack_from(fmt, self.code, a - self.tlo + j * sz)[0]
                    targets.add(a + off)
        return targets


class FuncLifter:
    def __init__(self, prog, start):
        self.p = prog
        self.start = start
        self.end = prog.ends[start]
        self.out = []
        self.unhandled = []
        self.fl = None  # last flag-setting op knowledge within current block
        self.sites = prog.eh.get(start)
        self.ex = "x86_eh_pop(c,&xf); " if self.sites else ""

    # ---- operand helpers ------------------------------------------------
    def reg(self, ins, r):
        return ins.reg_name(r)

    def img(self, addr):
        return self.p.img(addr)

    def ea(self, ins, op):
        mem = op.mem
        parts = []
        base = self.reg(ins, mem.base) if mem.base else None
        index = self.reg(ins, mem.index) if mem.index else None
        if base == "rip":
            absaddr = (ins.address + ins.size + mem.disp) & MASK[8]
            if index:
                raise Unhandled("rip+index")
            return self.code_or_data_addr(absaddr)
        if base:
            b = REGS[base]
            if b[1] != 8:
                parts.append(f"(u64)({UT[b[1]]}){b[0]}")
            else:
                parts.append(b[0])
        if index:
            ix = REGS[index]
            s = ix[0] if ix[1] == 8 else f"(u64)({UT[ix[1]]}){ix[0]}"
            parts.append(f"{s}*{mem.scale}" if mem.scale != 1 else s)
        if mem.disp:
            d = mem.disp
            parts.append(f"0x{d & MASK[8]:x}ULL" if d >= 0 else f"(u64)(s64){d}")
        e = "(" + "+".join(parts) + ")" if parts else "0"
        seg = self.reg(ins, mem.segment) if mem.segment else None
        if seg in ("gs", "fs"):
            e = f"(c->{seg}_base+{e})"
        return e

    def code_or_data_addr(self, absaddr):
        if absaddr in self.p.index:
            return f"TRAMP({self.p.index[absaddr]})"
        return self.img(absaddr)

    def rd(self, ins, op, size=None):
        size = size or op.size
        if op.type == OP_REG:
            name = self.reg(ins, op.reg)
            r, w, sh = REGS[name]
            if w == 8 and size == 8:
                return r
            if sh:
                return f"(u8)({r}>>8)"
            return f"({UT[min(w, size)]}){r}"
        if op.type == OP_IMM:
            v = op.imm & MASK[size]
            return f"0x{v:x}ULL" if size == 8 else f"({UT[size]})0x{v:x}"
        if op.type == OP_MEM:
            return f"LD{size * 8}({self.ea(ins, op)})"
        raise Unhandled("operand")

    def rds(self, ins, op, size=None):
        """Read signed-extended immediate/operand as signed type."""
        size = size or op.size
        return f"({ST[size]}){self.rd(ins, op, size)}"

    def wr(self, ins, op, val, size=None):
        size = size or op.size
        if op.type == OP_REG:
            name = self.reg(ins, op.reg)
            r, w, sh = REGS[name]
            if w == 8:
                return f"{r}=(u64)({val});"
            if w == 4:
                return f"{r}=(u32)({val});"
            if w == 2:
                return f"{r}=({r}&~0xffffULL)|(u16)({val});"
            if sh:
                return f"{r}=({r}&~0xff00ULL)|((u64)(u8)({val})<<8);"
            return f"{r}=({r}&~0xffULL)|(u8)({val});"
        if op.type == OP_MEM:
            return f"ST{size * 8}({self.ea(ins, op)},{val});"
        raise Unhandled("write operand")

    def xr(self, ins, op):
        """xmm register name or 128-bit memory load."""
        if op.type == OP_REG:
            n = self.reg(ins, op.reg)
            if not n.startswith("xmm"):
                raise Unhandled("expected xmm")
            return "x" + n[3:]
        if op.type == OP_MEM:
            return f"LDV({self.ea(ins, op)})"
        raise Unhandled("xmm operand")

    def xname(self, ins, op):
        n = self.reg(ins, op.reg)
        if not n.startswith("xmm"):
            raise Unhandled("expected xmm dst")
        return "x" + n[3:]

    def is_xmm(self, ins, op):
        return op.type == OP_REG and self.reg(ins, op.reg).startswith("xmm")

    def sf(self, ins, op):
        """scalar float operand (low lane of xmm or m32)."""
        if op.type == OP_REG:
            return f"vf({self.xr(ins, op)},0)"
        return f"u2f(LD32({self.ea(ins, op)}))"

    def sd(self, ins, op):
        if op.type == OP_REG:
            return f"vd({self.xr(ins, op)},0)"
        return f"u2d(LD64({self.ea(ins, op)}))"

    # ---- flags ------------------------------------------------------------
    def flags_logic(self, r, w):
        b = w * 8
        self.fl = ("logic", w)
        return (f"CF=0;OF=0;ZF=({UT[w]})({r})==0;SF=(({UT[w]})({r})>>{b - 1})&1;PF=parity8({r});"
                f"FR=({UT[w]})({r});")

    def flags_add(self, a, b_, r, w):
        b = w * 8
        self.fl = None
        return (f"CF=({UT[w]})({r})<({UT[w]})({a});OF=(((({a})^({r}))&(({b_})^({r})))>>{b - 1})&1;"
                f"ZF=({UT[w]})({r})==0;SF=(({UT[w]})({r})>>{b - 1})&1;PF=parity8({r});")

    def flags_sub(self, a, b_, r, w):
        b = w * 8
        self.fl = ("sub", w)
        return (f"CF=({UT[w]})({a})<({UT[w]})({b_});OF=(((({a})^({b_}))&(({a})^({r})))>>{b - 1})&1;"
                f"ZF=({UT[w]})({r})==0;SF=(({UT[w]})({r})>>{b - 1})&1;PF=parity8({r});FA=({a});FB=({b_});")

    def cond(self, cc):
        cc = CC[cc]
        fl = self.fl
        if fl:
            kind, w = fl
            u, s = UT.get(w), ST.get(w)
            if kind == "sub":
                m = {"e": f"({u})FA==({u})FB", "ne": f"({u})FA!=({u})FB", "b": f"({u})FA<({u})FB",
                     "ae": f"({u})FA>=({u})FB", "be": f"({u})FA<=({u})FB", "a": f"({u})FA>({u})FB",
                     "l": f"({s})FA<({s})FB", "ge": f"({s})FA>=({s})FB", "le": f"({s})FA<=({s})FB",
                     "g": f"({s})FA>({s})FB"}
                if cc in m:
                    return "(" + m[cc] + ")"
            elif kind == "logic":
                m = {"e": f"({u})FR==0", "ne": f"({u})FR!=0", "s": f"({s})FR<0", "ns": f"({s})FR>=0",
                     "l": f"({s})FR<0", "ge": f"({s})FR>=0", "le": f"({s})FR<=0", "g": f"({s})FR>0",
                     "be": f"({u})FR==0", "a": f"({u})FR!=0", "b": "0", "ae": "1"}
                if cc in m:
                    return "(" + m[cc] + ")"
            elif kind == "fcmp":
                m = {"a": "(FDA>FDB)", "ae": "(FDA>=FDB)", "b": "(!(FDA>=FDB))", "be": "(!(FDA>FDB))",
                     "e": "(!(FDA<FDB||FDA>FDB))", "ne": "(FDA<FDB||FDA>FDB)",
                     "p": "(FDA!=FDA||FDB!=FDB)", "np": "(FDA==FDA&&FDB==FDB)"}
                if cc in m:
                    return m[cc]
        return EAGER[cc]

    def fcmp(self, a, b):
        self.fl = ("fcmp", 0)
        return (f"FDA={a};FDB={b};{{int un=FDA!=FDA||FDB!=FDB;ZF=un||FDA==FDB;PF=un;CF=un||FDA<FDB;OF=0;SF=0;}}")

    # ---- control flow helpers ------------------------------------------------
    def emit_call_target(self, ins, t):
        """Code to invoke target t (absolute address) as callee (return address already pushed)."""
        p = self.p
        if t in p.index:
            return f"F_{t:x}(c);"
        if t in p.stub_name:
            name = p.stub_name[t]
            if name == "___chkstk_darwin":
                return None
            return f"x86_bridge(c,{p.import_id(name)});"
        raise Unhandled(f"call target {t:#x}")

    def push_ret(self, ins):
        return f"rsp-=8;ST64(rsp,{self.img(ins.address + ins.size)});"

    # ---- main ----------------------------------------------------------------
    def lift(self):
        p = self.p
        f, e = self.start, self.end
        insns = []
        a = f
        while a < e:
            if a in p.dic:
                a += p.dic[a][0]
                continue
            ins = p.insns.get(a)
            if ins is None:
                a += 1
                continue
            insns.append(ins)
            a += ins.size
        addrs = set(i.address for i in insns)
        labels = set()
        for ins in insns:
            mn = ins.mnemonic
            if (mn == "jmp" or (mn.startswith("j"))) and ins.operands and ins.operands[0].type == OP_IMM:
                t = ins.operands[0].imm
                if f <= t < e:
                    labels.add(t)
        jt = sorted(t for t in (p.jump_tables(f, e) | self.scan_tables(insns, f, e, addrs)) if t in addrs)
        labels |= set(jt)
        self.jt = jt
        o = self.out
        fname = f"F_{f:x}"
        lps = []
        if self.sites:
            lps = sorted(set(lp for _, _, lp, _ in self.sites if lp and lp in addrs))
            labels |= set(lps)
            lpi = {a: i for i, a in enumerate(lps)}
            acts, rows = [], []
            for st, ln, lp, al in self.sites:
                a0 = len(acts)
                for filt, tref in al:
                    if tref:
                        acts.append(f"{{{filt},{int(tref[1])},{p.img_ptr(tref[0])}}}")
                    else:
                        acts.append(f"{{{filt},0,0}}")
                rows.append(f"{{{lpi.get(lp, -1)},{a0},{len(acts) - a0}}}")
            if acts:
                o.append(f"static const EHAct eha_{f:x}[] = {{{','.join(acts)}}};")
            o.append(f"static const EHSite ehs_{f:x}[] = {{{','.join(rows)}}};")
            o.append(f"static const EHFunc ehf_{f:x} = {{ehs_{f:x},{'eha_%x' % f if acts else '0'},{len(rows)},0x{f:x}ULL}};")
        sym = p.syms.get(f)
        if sym:
            o.append(f"/* {sym[:200].replace('*/', '* /')} */")
        o.append(f"void {fname}(CPU *c) {{")
        o.append(" u64 " + ",".join(f"{r}=c->r[{i}]" for i, r in enumerate(GPR64)) + ";")
        o.append(" V " + ",".join(f"x{i}=c->x[{i}]" for i in range(16)) + ";")
        o.append(" u8 CF=c->CF,ZF=c->ZF,SF=c->SF,OF=c->OF,PF=c->PF; u64 FA=0,FB=0,FR=0; double FDA=0,FDB=0;")
        o.append(" (void)FA;(void)FB;(void)FR;(void)FDA;(void)FDB;")
        if self.sites:
            o.append(f" XF xf; x86_eh_push(c,&xf,&ehf_{f:x});")
            cases = "".join(f"case {i}: goto L_{a:x};" for i, a in enumerate(lps))
            o.append(" if(_setjmp(xf.jb)){ rbx=xf.r[0];rbp=xf.r[1];r12=xf.r[2];r13=xf.r[3];r14=xf.r[4];"
                     f"r15=xf.r[5];rsp=xf.rsp;rax=xf.exc;rdx=xf.sel; switch(xf.lp){{{cases} default: "
                     f"x86_trap(c,0x{f:x}ULL,\"bad landing pad\");}} }}")
        last_terminal = False
        for ins in insns:
            if ins.address in labels:
                o.append(f"L_{ins.address:x}:;")
                self.fl = None
            try:
                code, terminal = self.lift_insn(ins)
            except Unhandled as ex:
                self.unhandled.append((ins.address, ins.mnemonic, ins.op_str, str(ex)))
                code, terminal = f"x86_trap(c,0x{ins.address:x}ULL,\"unhandled {ins.mnemonic} {ins.op_str}\");", True
            except Exception as ex:
                self.unhandled.append((ins.address, ins.mnemonic, ins.op_str, "EXC " + repr(ex)))
                code, terminal = f"x86_trap(c,0x{ins.address:x}ULL,\"lift error {ins.mnemonic}\");", True
            o.append(f" /*{ins.address:x}: {ins.mnemonic} {ins.op_str}*/ {code}")
            last_terminal = terminal
        if not last_terminal:
            nxt = e
            if nxt in p.index:
                o.append(f" {self.ex}{self.so_all()} MUSTTAIL return F_{nxt:x}(c);")
            else:
                o.append(f" x86_trap(c,0x{nxt:x}ULL,\"fell off function\");")
        o.append("}")
        return "\n".join(o)

    SO = ("c->r[0]=rax;c->r[1]=rcx;c->r[2]=rdx;c->r[3]=rbx;c->r[4]=rsp;c->r[5]=rbp;c->r[6]=rsi;c->r[7]=rdi;"
          "c->r[8]=r8;c->r[9]=r9;c->r[10]=r10;c->r[11]=r11;c->r[12]=r12;c->r[13]=r13;c->r[14]=r14;c->r[15]=r15;"
          "c->x[0]=x0;c->x[1]=x1;c->x[2]=x2;c->x[3]=x3;c->x[4]=x4;c->x[5]=x5;c->x[6]=x6;c->x[7]=x7;")
    SI = "rax=c->r[0];rdx=c->r[2];rsp=c->r[4];x0=c->x[0];x1=c->x[1];"
    RET = ("c->r[0]=rax;c->r[2]=rdx;c->r[4]=rsp;c->x[0]=x0;c->x[1]=x1;"
           "c->r[3]=rbx;c->r[5]=rbp;c->r[12]=r12;c->r[13]=r13;c->r[14]=r14;c->r[15]=r15;")

    def so_all(self):
        return ("SOALL();")

    def tail_to(self, t):
        p = self.p
        if t in p.index:
            return f"{self.ex}SOALL(); MUSTTAIL return F_{t:x}(c);"
        if t in p.stub_name:
            name = p.stub_name[t]
            return f"{self.ex}SO(); x86_bridge(c,{p.import_id(name)}); return;"
        return f"{self.ex}c->jt={self.img(t)}; SOALL(); MUSTTAIL return x86_jump_indirect(c);"

    def lift_insn(self, ins):
        mn = ins.mnemonic
        ops = ins.operands
        p = self.p
        # ---- control flow ----------------------------------------------------
        if mn == "call":
            pre = self.eh_pre(ins)
            code, term = self.lift_call(ins, ops)
            return pre + code, term
        return self.lift_other(ins, mn, ops)

    def scan_tables(self, insns, f, e, addrs):
        """Targets of rel32 jump tables found by pattern (lea base / movsxd [base+i*4] / add / jmp)."""
        p = self.p
        out = set()
        for j, ins in enumerate(insns):
            if ins.mnemonic != "lea" or len(ins.operands) != 2:
                continue
            src = ins.operands[1]
            if src.type != OP_MEM or not src.mem.base or self.reg(ins, src.mem.base) != "rip":
                continue
            base_reg = ins.operands[0].reg
            for k in insns[j + 1:j + 40]:
                if k.mnemonic == "movsxd" and k.operands[1].type == OP_MEM and k.operands[1].mem.base == base_reg \
                        and k.operands[1].mem.scale == 4:
                    tbl = (ins.address + ins.size + src.mem.disp) & MASK[8]
                    if not (p.tlo <= tbl < p.thi):
                        break
                    for n in range(4096):
                        o = tbl - p.tlo + 4 * n
                        if o + 4 > len(p.code):
                            break
                        t = tbl + struct.unpack_from("<i", p.code, o)[0]
                        if not (f <= t < e) or t not in addrs:
                            break
                        out.add(t)
                    break
        return out

    def eh_pre(self, ins):
        if not self.sites:
            return ""
        ip = ins.address + ins.size - 1
        cs = -1
        for i, (st, ln, lp, al) in enumerate(self.sites):
            if st <= ip < st + ln:
                cs = i
                break
        return f"xf.cs={cs};xf.r[0]=rbx;xf.r[1]=rbp;xf.r[2]=r12;xf.r[3]=r13;xf.r[4]=r14;xf.r[5]=r15;xf.rsp=rsp; "

    def lift_call(self, ins, ops):
        p = self.p
        mn = ins.mnemonic
        if True:
            op = ops[0]
            if op.type == OP_IMM:
                t = op.imm
                if t in p.stub_name and p.stub_name[t] == "___chkstk_darwin":
                    return "", False
                tgt = self.emit_call_target(ins, t)
                self.fl = None
                return f"{self.push_ret(ins)} SO(); {tgt} SI();", False
            if op.type == OP_MEM and op.mem.base and self.reg(ins, op.mem.base) == "rip":
                slot = (ins.address + ins.size + op.mem.disp) & MASK[8]
                if slot in p.slot_name:
                    name = p.slot_name[slot]
                    self.fl = None
                    return f"{self.push_ret(ins)} SO(); x86_bridge(c,{p.import_id(name)}); SI();", False
            t = self.rd(ins, op, 8)
            self.fl = None
            return f"{{u64 t={t}; {self.push_ret(ins)} SO(); x86_call_indirect(c,t); SI();}}", False

    def lift_other(self, ins, mn, ops):
        p = self.p
        if mn == "jmp":
            op = ops[0]
            if op.type == OP_IMM:
                t = op.imm
                if self.start <= t < self.end:
                    return f"goto L_{t:x};", True
                return self.tail_to(t), True
            if op.type == OP_MEM and op.mem.base and self.reg(ins, op.mem.base) == "rip":
                slot = (ins.address + ins.size + op.mem.disp) & MASK[8]
                if slot in p.slot_name:
                    return f"{self.ex}SO(); x86_bridge(c,{p.import_id(p.slot_name[slot])}); return;", True
            t = self.rd(ins, op, 8)
            cases = "".join(f"case 0x{a - p.tlo:x}: goto L_{a:x};" for a in self.jt)
            return (f"{{u64 t={t}; switch(t-S({p.text_k},0)){{{cases} default: {self.ex}c->jt=t; SOALL(); "
                    f"MUSTTAIL return x86_jump_indirect(c);}}}}"), True
        if mn.startswith("j") and mn[1:] in CC:
            t = ops[0].imm
            cnd = self.cond(mn[1:])
            if self.start <= t < self.end:
                return f"if({cnd}) goto L_{t:x};", False
            return f"if({cnd}) {{ {self.tail_to(t)} }}", False
        if mn == "ret":
            n = 8 + (ops[0].imm if ops else 0)
            return f"rsp+={n}; {self.ex}{self.RET} return;", True
        if mn in ("ud2", "hlt", "int3"):
            return f"x86_trap(c,0x{ins.address:x}ULL,\"{mn}\");", True
        if mn == "nop":
            return "", False

        h = getattr(self, "i_" + mn, None)
        if h is None:
            if mn.startswith("set") and mn[3:] in CC:
                return self.wr(ins, ops[0], self.cond(mn[3:]), 1), False
            if mn.startswith("cmov") and mn[4:] in CC:
                d, s = ops
                w = d.size
                v = self.rd(ins, s, w)
                if w == 4:  # 32-bit cmov always zero-extends dst
                    r = REGS[self.reg(ins, d.reg)][0]
                    return f"{r}=(u32)(({self.cond(mn[4:])})?{v}:(u32){r});", False
                return f"if({self.cond(mn[4:])}) {self.wr(ins, d, v)}", False
            if mn.startswith("rep") or mn.startswith("stos") or mn.startswith("movs") and len(ops) == 2 and ops[0].type == OP_MEM and ops[1].type == OP_MEM:
                return self.string_op(ins), False
            if mn.startswith("cmp") and (mn.endswith("ss") or mn.endswith("sd") or mn.endswith("ps") or mn.endswith("pd")) and len(mn) > 5:
                return self.sse_cmp(ins), False
            raise Unhandled("no handler")
        r = h(ins, ops)
        if isinstance(r, tuple):
            return r
        return r, False

    # ---- integer ops ------------------------------------------------------
    def i_mov(self, ins, ops):
        d, s = ops
        if self.is_xmm(ins, d) or self.is_xmm(ins, s):
            raise Unhandled("mov xmm")
        return self.wr(ins, d, self.rd(ins, s, d.size))

    i_movabs = i_mov

    def i_movzx(self, ins, ops):
        d, s = ops
        return self.wr(ins, d, f"(u64){self.rd(ins, s)}")

    def i_movsx(self, ins, ops):
        d, s = ops
        return self.wr(ins, d, f"({ST[d.size]}){self.rds(ins, s)}")

    i_movsxd = i_movsx

    def i_lea(self, ins, ops):
        d, s = ops
        return self.wr(ins, d, self.ea(ins, s))

    def i_push(self, ins, ops):
        s = ops[0]
        if s.type == OP_IMM:
            v = f"0x{s.imm & MASK[8]:x}ULL"
        else:
            v = self.rd(ins, s, 8)
        return f"{{u64 v={v}; rsp-=8; ST64(rsp,v);}}"

    def i_pop(self, ins, ops):
        d = ops[0]
        return f"{{u64 v=LD64(rsp); rsp+=8; {self.wr(ins, d, 'v', 8)}}}"

    def arith(self, ins, ops, kind):
        d, s = ops
        w = d.size
        u = UT[w]
        a = self.rd(ins, d, w)
        b = self.rd(ins, s, w)
        if kind == "add":
            return f"{{{u} a={a},b={b},r=a+b; {self.flags_add('a', 'b', 'r', w)} {self.wr(ins, d, 'r')}}}"
        if kind == "sub":
            return f"{{{u} a={a},b={b},r=a-b; {self.flags_sub('a', 'b', 'r', w)} {self.wr(ins, d, 'r')}}}"
        if kind == "cmp":
            return f"{{{u} a={a},b={b},r=a-b; {self.flags_sub('a', 'b', 'r', w)}}}"
        if kind == "adc":
            bits = w * 8
            self.fl = None
            return (f"{{{u} a={a},b={b},ci=CF,r=a+b+ci; CF=ci?(r<=a):(r<a);"
                    f"OF=(((a^r)&(b^r))>>{bits - 1})&1;ZF=r==0;SF=(r>>{bits - 1})&1;PF=parity8(r); {self.wr(ins, d, 'r')}}}")
        if kind == "sbb":
            bits = w * 8
            self.fl = None
            return (f"{{{u} a={a},b={b},ci=CF,r=a-b-ci; CF=ci?(a<=b):(a<b);"
                    f"OF=(((a^b)&(a^r))>>{bits - 1})&1;ZF=r==0;SF=(r>>{bits - 1})&1;PF=parity8(r); {self.wr(ins, d, 'r')}}}")
        op = {"and": "&", "or": "|", "xor": "^"}[kind]
        if kind == "xor" and s.type == OP_REG and d.type == OP_REG and s.reg == d.reg:
            return f"{self.flags_logic('0', w)} {self.wr(ins, d, '0')}"
        if kind == "test":
            return f"{{{u} r={a}&{b}; {self.flags_logic('r', w)}}}"
        return f"{{{u} r={a}{op}{b}; {self.flags_logic('r', w)} {self.wr(ins, d, 'r')}}}"

    def i_add(self, ins, ops): return self.arith(ins, ops, "add")
    def i_sub(self, ins, ops): return self.arith(ins, ops, "sub")
    def i_cmp(self, ins, ops): return self.arith(ins, ops, "cmp")
    def i_adc(self, ins, ops): return self.arith(ins, ops, "adc")
    def i_sbb(self, ins, ops): return self.arith(ins, ops, "sbb")
    def i_and(self, ins, ops): return self.arith(ins, ops, "and")
    def i_or(self, ins, ops): return self.arith(ins, ops, "or")
    def i_xor(self, ins, ops): return self.arith(ins, ops, "xor")

    def i_test(self, ins, ops):
        d, s = ops
        w = d.size
        a = self.rd(ins, d, w)
        b = self.rd(ins, s, w)
        if s.type == OP_REG and d.type == OP_REG and s.reg == d.reg:
            return f"{{{UT[w]} r={a}; {self.flags_logic('r', w)}}}"
        return f"{{{UT[w]} r={a}&{b}; {self.flags_logic('r', w)}}}"

    def incdec(self, ins, ops, delta):
        d = ops[0]
        w = d.size
        u = UT[w]
        bits = w * 8
        a = self.rd(ins, d, w)
        if delta > 0:
            of = f"OF=r==({u})(1ULL<<{bits - 1});"
            r = "a+1"
        else:
            of = f"OF=a==({u})(1ULL<<{bits - 1});"
            r = "a-1"
        self.fl = None
        return f"{{{u} a={a},r={r}; {of}ZF=r==0;SF=(r>>{bits - 1})&1;PF=parity8(r); {self.wr(ins, d, 'r')}}}"

    def i_inc(self, ins, ops): return self.incdec(ins, ops, 1)
    def i_dec(self, ins, ops): return self.incdec(ins, ops, -1)

    def i_neg(self, ins, ops):
        d = ops[0]
        w = d.size
        u = UT[w]
        bits = w * 8
        self.fl = None
        return (f"{{{u} a={self.rd(ins, d, w)},r=({u})(0-a); CF=a!=0;OF=a==({u})(1ULL<<{bits - 1});"
                f"ZF=r==0;SF=(r>>{bits - 1})&1;PF=parity8(r); {self.wr(ins, d, 'r')}}}")

    def i_not(self, ins, ops):
        d = ops[0]
        return self.wr(ins, d, f"~{self.rd(ins, d)}")

    def shift(self, ins, ops, kind):
        d = ops[0]
        w = d.size
        u, s_ = UT[w], ST[w]
        bits = w * 8
        m = 63 if w == 8 else 31
        if len(ops) == 1:
            cnt = "1"
        else:
            cnt = self.rd(ins, ops[1], 1)
        a = self.rd(ins, d, w)
        self.fl = None
        if kind == "shl":
            body = (f"r=({u})(a<<n); CF=(a>>({bits}-n))&1; OF=((r>>{bits - 1})&1)^CF;")
        elif kind == "shr":
            body = f"r=({u})(a>>n); CF=(a>>(n-1))&1; OF=(a>>{bits - 1})&1;"
        elif kind == "sar":
            body = f"r=({u})(({s_})a>>(n>{bits - 1}?{bits - 1}:n)); CF=(({s_})a>>(n-1>{bits - 1}?{bits - 1}:n-1))&1; OF=0;"
        elif kind == "rol":
            body = (f"unsigned k=n%{bits}; r=k?({u})((a<<k)|(a>>({bits}-k))):a; CF=r&1; OF=((r>>{bits - 1})&1)^CF;")
            return (f"{{{u} a={a},r; unsigned n=({cnt})&{m}; if(n){{ {body} {self.wr(ins, d, 'r')} }}}}")
        elif kind == "ror":
            body = (f"unsigned k=n%{bits}; r=k?({u})((a>>k)|(a<<({bits}-k))):a; CF=(r>>{bits - 1})&1; "
                    f"OF=((r>>{bits - 1})^(r>>{bits - 2}))&1;")
            return (f"{{{u} a={a},r; unsigned n=({cnt})&{m}; if(n){{ {body} {self.wr(ins, d, 'r')} }}}}")
        if kind == "shl" and w < 4:
            body = f"r=({u})((u32)a<<n); CF=n<={bits}?((u32)a>>({bits}-n))&1:0; OF=((r>>{bits - 1})&1)^CF;"
        if kind == "shr" and w < 4:
            body = f"r=n<{bits}?({u})(a>>n):0; CF=n<={bits}?(a>>(n-1))&1:0; OF=(a>>{bits - 1})&1;"
        return (f"{{{u} a={a},r; unsigned n=({cnt})&{m}; if(n){{ {body} ZF=r==0;SF=(r>>{bits - 1})&1;PF=parity8(r); "
                f"{self.wr(ins, d, 'r')} }}}}")

    def i_shl(self, ins, ops): return self.shift(ins, ops, "shl")
    i_sal = i_shl
    def i_shr(self, ins, ops): return self.shift(ins, ops, "shr")
    def i_sar(self, ins, ops): return self.shift(ins, ops, "sar")
    def i_rol(self, ins, ops): return self.shift(ins, ops, "rol")
    def i_ror(self, ins, ops): return self.shift(ins, ops, "ror")

    def i_shrd(self, ins, ops):
        d, s, cn = ops
        w = d.size
        u = UT[w]
        bits = w * 8
        m = 63 if w == 8 else 31
        self.fl = None
        return (f"{{{u} a={self.rd(ins, d)},b={self.rd(ins, s)},r; unsigned n=({self.rd(ins, cn, 1)})&{m}; "
                f"if(n){{ r=({u})((a>>n)|(b<<({bits}-n))); CF=(a>>(n-1))&1; ZF=r==0;SF=(r>>{bits - 1})&1;PF=parity8(r); "
                f"{self.wr(ins, d, 'r')} }}}}")

    def i_shld(self, ins, ops):
        d, s, cn = ops
        w = d.size
        u = UT[w]
        bits = w * 8
        m = 63 if w == 8 else 31
        self.fl = None
        return (f"{{{u} a={self.rd(ins, d)},b={self.rd(ins, s)},r; unsigned n=({self.rd(ins, cn, 1)})&{m}; "
                f"if(n){{ r=({u})((a<<n)|(b>>({bits}-n))); CF=(a>>({bits}-n))&1; ZF=r==0;SF=(r>>{bits - 1})&1;PF=parity8(r); "
                f"{self.wr(ins, d, 'r')} }}}}")

    def i_imul(self, ins, ops):
        self.fl = None
        if len(ops) == 1:
            s = ops[0]
            w = s.size
            if w == 8:
                return (f"{{s128 r=(s128)(s64)rax*(s128)(s64){self.rd(ins, s)}; rax=(u64)r; rdx=(u64)(r>>64); "
                        f"CF=OF=(r!=(s128)(s64)rax);}}")
            if w == 4:
                return (f"{{s64 r=(s64)(s32)rax*(s64)(s32){self.rd(ins, s)}; rax=(u32)r; rdx=(u32)(r>>32); "
                        f"CF=OF=(r!=(s64)(s32)r);}}")
            if w == 2:
                return (f"{{s32 r=(s32)(s16)rax*(s32)(s16){self.rd(ins, s)}; rax=(rax&~0xffffULL)|(u16)r; "
                        f"rdx=(rdx&~0xffffULL)|(u16)(r>>16); CF=OF=(r!=(s32)(s16)r);}}")
            return (f"{{s16 r=(s16)(s8)rax*(s16)(s8){self.rd(ins, s)}; rax=(rax&~0xffffULL)|(u16)r; "
                    f"CF=OF=(r!=(s16)(s8)r);}}")
        if len(ops) == 2:
            d, s = ops
            a, b = self.rds(ins, d), self.rds(ins, s, d.size)
        else:
            d, s, im = ops
            a, b = self.rds(ins, s, d.size), self.rds(ins, im, d.size)
        w = d.size
        big = "s128" if w == 8 else "s64"
        return (f"{{{big} r=({big}){a}*({big}){b}; CF=OF=(r!=({big})({ST[w]})r); "
                f"{self.wr(ins, d, 'r')}}}")

    def i_mul(self, ins, ops):
        s = ops[0]
        w = s.size
        self.fl = None
        if w == 8:
            return f"{{u128 r=(u128)rax*(u128){self.rd(ins, s)}; rax=(u64)r; rdx=(u64)(r>>64); CF=OF=rdx!=0;}}"
        if w == 4:
            return f"{{u64 r=(u64)(u32)rax*(u64){self.rd(ins, s)}; rax=(u32)r; rdx=(u32)(r>>32); CF=OF=(r>>32)!=0;}}"
        raise Unhandled("mul width")

    def i_div(self, ins, ops):
        s = ops[0]
        w = s.size
        if w == 8:
            return (f"{{u64 d={self.rd(ins, s)}; u128 n=((u128)rdx<<64)|rax; if(!d) x86_trap(c,0x{ins.address:x}ULL,\"div0\"); "
                    f"rax=(u64)(n/d); rdx=(u64)(n%d);}}")
        if w == 4:
            return (f"{{u32 d={self.rd(ins, s)}; u64 n=((u64)(u32)rdx<<32)|(u32)rax; if(!d) x86_trap(c,0x{ins.address:x}ULL,\"div0\"); "
                    f"rax=(u32)(n/d); rdx=(u32)(n%d);}}")
        if w == 2:
            return (f"{{u16 d={self.rd(ins, s)}; u32 n=((u32)(u16)rdx<<16)|(u16)rax; if(!d) x86_trap(c,0x{ins.address:x}ULL,\"div0\"); "
                    f"rax=(rax&~0xffffULL)|(u16)(n/d); rdx=(rdx&~0xffffULL)|(u16)(n%d);}}")
        if w == 1:
            return (f"{{u8 d={self.rd(ins, s)}; u16 n=(u16)rax; if(!d) x86_trap(c,0x{ins.address:x}ULL,\"div0\"); "
                    f"rax=(rax&~0xffffULL)|(u8)(n/d)|((u64)(u8)(n%d)<<8);}}")
        raise Unhandled("div width")

    def i_idiv(self, ins, ops):
        s = ops[0]
        w = s.size
        if w == 8:
            return (f"{{s64 d={self.rds(ins, s)}; s128 n=(s128)(((u128)rdx<<64)|rax); if(!d) x86_trap(c,0x{ins.address:x}ULL,\"div0\"); "
                    f"rax=(u64)(s64)(n/d); rdx=(u64)(s64)(n%d);}}")
        if w == 4:
            return (f"{{s32 d={self.rds(ins, s)}; s64 n=(s64)(((u64)(u32)rdx<<32)|(u32)rax); if(!d) x86_trap(c,0x{ins.address:x}ULL,\"div0\"); "
                    f"rax=(u32)(s32)(n/d); rdx=(u32)(s32)(n%d);}}")
        raise Unhandled("idiv width")

    def i_cdq(self, ins, ops): return "rdx=(u32)((s32)rax>>31);"
    def i_cqo(self, ins, ops): return "rdx=(u64)((s64)rax>>63);"
    def i_cdqe(self, ins, ops): return "rax=(u64)(s64)(s32)rax;"
    def i_cwde(self, ins, ops): return "rax=(u32)(s32)(s16)rax;"

    def i_bswap(self, ins, ops):
        d = ops[0]
        if d.size == 8:
            return self.wr(ins, d, f"__builtin_bswap64({self.rd(ins, d)})")
        return self.wr(ins, d, f"__builtin_bswap32({self.rd(ins, d)})")

    def bitop(self, ins, ops, kind):
        d, s = ops
        w = d.size
        bits = w * 8
        self.fl = None
        if d.type == OP_MEM and s.type == OP_REG:
            ea = self.ea(ins, d)
            off = f"(s64)({ST[w]}){self.rd(ins, s, w)}"
            addr = f"({ea}+(u64)(({off})>>3))"
            setup = f"u64 ad={addr}; unsigned n=(unsigned)(({off})&7); u8 v=LD8(ad); CF=(v>>n)&1;"
            upd = {"bt": "", "bts": "ST8(ad,v|(1u<<n));", "btr": "ST8(ad,v&~(1u<<n));",
                   "btc": "ST8(ad,v^(1u<<n));"}[kind]
            return f"{{{setup} {upd}}}"
        n = f"(({self.rd(ins, s, 1) if s.type == OP_IMM else self.rd(ins, s)})&{bits - 1})"
        u = UT[w]
        a = self.rd(ins, d, w)
        setup = f"{u} v={a}; unsigned n={n}; CF=(v>>n)&1;"
        if kind == "bt":
            return f"{{{setup}}}"
        expr = {"bts": f"v|(({u})1<<n)", "btr": f"v&~(({u})1<<n)", "btc": f"v^(({u})1<<n)"}[kind]
        return f"{{{setup} {self.wr(ins, d, expr)}}}"

    def i_bt(self, ins, ops): return self.bitop(ins, ops, "bt")
    def i_bts(self, ins, ops): return self.bitop(ins, ops, "bts")
    def i_btr(self, ins, ops): return self.bitop(ins, ops, "btr")
    def i_btc(self, ins, ops): return self.bitop(ins, ops, "btc")

    def i_bsr(self, ins, ops):
        d, s = ops
        w = d.size
        self.fl = None
        clz = "__builtin_clzll" if w == 8 else "__builtin_clz"
        return f"{{{UT[w]} v={self.rd(ins, s)}; ZF=v==0; if(v) {{ {self.wr(ins, d, f'{w * 8 - 1}-{clz}(v)')} }}}}"

    def i_bsf(self, ins, ops):
        d, s = ops
        w = d.size
        self.fl = None
        ctz = "__builtin_ctzll" if w == 8 else "__builtin_ctz"
        return f"{{{UT[w]} v={self.rd(ins, s)}; ZF=v==0; if(v) {{ {self.wr(ins, d, f'{ctz}(v)')} }}}}"

    def i_xchg(self, ins, ops):
        d, s = ops
        w = d.size
        return f"{{{UT[w]} a={self.rd(ins, d)},b={self.rd(ins, s)}; {self.wr(ins, d, 'b')} {self.wr(ins, s, 'a')}}}"

    def string_op(self, ins):
        mn = ins.mnemonic
        rep = mn.startswith("rep")
        base = mn.split()[-1]
        size = {"b": 1, "w": 2, "d": 4, "q": 8}[base[-1]]
        kind = base[:-1]
        if kind == "stos":
            one = f"ST{size * 8}(rdi,({UT[size]})rax); rdi+={size};"
        elif kind == "movs":
            one = f"ST{size * 8}(rdi,LD{size * 8}(rsi)); rdi+={size}; rsi+={size};"
        else:
            raise Unhandled("string op " + mn)
        if rep:
            if kind == "stos" and size == 1:
                return "{ memset((void*)(uintptr_t)rdi,(u8)rax,rcx); rdi+=rcx; rcx=0; }"
            if kind == "movs":
                return (f"{{ u64 n=rcx*{size}; memmove((void*)(uintptr_t)rdi,(void*)(uintptr_t)rsi,n); "
                        f"rdi+=n; rsi+=n; rcx=0; }}")
            return f"while(rcx){{ {one} rcx--; }}"
        return "{" + one + "}"

    # ---- SSE --------------------------------------------------------------
    def i_movss(self, ins, ops):
        d, s = ops
        if d.type == OP_MEM:
            return f"ST32({self.ea(ins, d)},vu32({self.xr(ins, s)},0));"
        x = self.xname(ins, d)
        if s.type == OP_MEM:
            return f"{x}=fromu32(LD32({self.ea(ins, s)}));"
        return f"{x}=setu32({x},0,vu32({self.xr(ins, s)},0));"

    def i_movsd(self, ins, ops):
        d, s = ops
        if d.type == OP_MEM and s.type == OP_MEM:
            return self.string_op(ins)
        if d.type == OP_MEM:
            return f"ST64({self.ea(ins, d)},vu64({self.xr(ins, s)},0));"
        x = self.xname(ins, d)
        if s.type == OP_MEM:
            return f"{x}=fromu64(LD64({self.ea(ins, s)}));"
        return f"{x}=setu64({x},0,vu64({self.xr(ins, s)},0));"

    def mov128(self, ins, ops):
        d, s = ops
        if d.type == OP_MEM:
            return f"STV({self.ea(ins, d)},{self.xr(ins, s)});"
        return f"{self.xname(ins, d)}={self.xr(ins, s)};"

    i_movaps = i_movapd = i_movups = i_movupd = i_movdqa = i_movdqu = mov128

    def i_movd(self, ins, ops):
        d, s = ops
        if self.is_xmm(ins, d):
            return f"{self.xname(ins, d)}=fromu32({self.rd(ins, s, 4)});"
        return self.wr(ins, d, f"vu32({self.xr(ins, s)},0)", 4)

    def i_movq(self, ins, ops):
        d, s = ops
        if self.is_xmm(ins, d):
            if self.is_xmm(ins, s):
                return f"{self.xname(ins, d)}=fromu64(vu64({self.xr(ins, s)},0));"
            return f"{self.xname(ins, d)}=fromu64({self.rd(ins, s, 8)});"
        return self.wr(ins, d, f"vu64({self.xr(ins, s)},0)", 8)

    def i_movhpd(self, ins, ops):
        d, s = ops
        if d.type == OP_MEM:
            return f"ST64({self.ea(ins, d)},vu64({self.xr(ins, s)},1));"
        x = self.xname(ins, d)
        return f"{x}=setu64({x},1,LD64({self.ea(ins, s)}));"

    i_movhps = i_movhpd

    def i_movlpd(self, ins, ops):
        d, s = ops
        if d.type == OP_MEM:
            return f"ST64({self.ea(ins, d)},vu64({self.xr(ins, s)},0));"
        x = self.xname(ins, d)
        return f"{x}=setu64({x},0,LD64({self.ea(ins, s)}));"

    i_movlps = i_movlpd

    def i_movhlps(self, ins, ops):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=movhlps({x},{self.xr(ins, s)});"

    def i_movlhps(self, ins, ops):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=movlhps({x},{self.xr(ins, s)});"

    def i_movddup(self, ins, ops):
        d, s = ops
        v = f"vu64({self.xr(ins, s)},0)" if s.type == OP_REG else f"LD64({self.ea(ins, s)})"
        return f"{{u64 t={v}; {self.xname(ins, d)}=(V){{t,t}};}}"

    def i_movshdup(self, ins, ops):
        d, s = ops
        return f"{self.xname(ins, d)}=movshdup({self.xr(ins, s)});"

    def i_movsldup(self, ins, ops):
        d, s = ops
        return f"{self.xname(ins, d)}=movsldup({self.xr(ins, s)});"

    def logic128(self, ins, ops, op):
        d, s = ops
        x = self.xname(ins, d)
        if op == "andn":
            return f"{x}=(~{x})&{self.xr(ins, s)};"
        if op == "^" and s.type == OP_REG and s.reg == d.reg:
            return f"{x}=vzero();"
        return f"{x}={x}{op}{self.xr(ins, s)};"

    def i_xorps(self, ins, ops): return self.logic128(ins, ops, "^")
    i_xorpd = i_pxor = i_xorps
    def i_andps(self, ins, ops): return self.logic128(ins, ops, "&")
    i_andpd = i_pand = i_andps
    def i_orps(self, ins, ops): return self.logic128(ins, ops, "|")
    i_orpd = i_por = i_orps
    def i_andnps(self, ins, ops): return self.logic128(ins, ops, "andn")
    i_andnpd = i_pandn = i_andnps

    def scalar_ss(self, ins, ops, expr):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=setf({x},0,{expr.format(a=f'vf({x},0)', b=self.sf(ins, s))});"

    def scalar_sd(self, ins, ops, expr):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=setd({x},0,{expr.format(a=f'vd({x},0)', b=self.sd(ins, s))});"

    def i_addss(self, ins, ops): return self.scalar_ss(ins, ops, "{a}+{b}")
    def i_subss(self, ins, ops): return self.scalar_ss(ins, ops, "{a}-{b}")
    def i_mulss(self, ins, ops): return self.scalar_ss(ins, ops, "{a}*{b}")
    def i_divss(self, ins, ops): return self.scalar_ss(ins, ops, "{a}/{b}")
    def i_minss(self, ins, ops): return self.scalar_ss(ins, ops, "minssf({a},{b})")
    def i_maxss(self, ins, ops): return self.scalar_ss(ins, ops, "maxssf({a},{b})")
    def i_sqrtss(self, ins, ops): return self.scalar_ss(ins, ops, "sqrtf({b})")
    def i_addsd(self, ins, ops): return self.scalar_sd(ins, ops, "{a}+{b}")
    def i_subsd(self, ins, ops): return self.scalar_sd(ins, ops, "{a}-{b}")
    def i_mulsd(self, ins, ops): return self.scalar_sd(ins, ops, "{a}*{b}")
    def i_divsd(self, ins, ops): return self.scalar_sd(ins, ops, "{a}/{b}")
    def i_minsd(self, ins, ops): return self.scalar_sd(ins, ops, "minsdf({a},{b})")
    def i_maxsd(self, ins, ops): return self.scalar_sd(ins, ops, "maxsdf({a},{b})")
    def i_sqrtsd(self, ins, ops): return self.scalar_sd(ins, ops, "sqrt({b})")

    def packed(self, ins, ops, ty, expr):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=(V)({expr.format(a=f'(({ty}){x})', b=f'(({ty}){self.xr(ins, s)})')});"

    def i_addps(self, ins, ops): return self.packed(ins, ops, "f32x4", "{a}+{b}")
    def i_subps(self, ins, ops): return self.packed(ins, ops, "f32x4", "{a}-{b}")
    def i_mulps(self, ins, ops): return self.packed(ins, ops, "f32x4", "{a}*{b}")
    def i_divps(self, ins, ops): return self.packed(ins, ops, "f32x4", "{a}/{b}")
    def i_addpd(self, ins, ops): return self.packed(ins, ops, "f64x2", "{a}+{b}")
    def i_subpd(self, ins, ops): return self.packed(ins, ops, "f64x2", "{a}-{b}")
    def i_mulpd(self, ins, ops): return self.packed(ins, ops, "f64x2", "{a}*{b}")
    def i_divpd(self, ins, ops): return self.packed(ins, ops, "f64x2", "{a}/{b}")
    def i_paddd(self, ins, ops): return self.packed(ins, ops, "u32x4", "{a}+{b}")
    def i_psubd(self, ins, ops): return self.packed(ins, ops, "u32x4", "{a}-{b}")
    def i_paddq(self, ins, ops): return self.packed(ins, ops, "u64x2", "{a}+{b}")
    def i_psubq(self, ins, ops): return self.packed(ins, ops, "u64x2", "{a}-{b}")
    def i_pcmpgtd(self, ins, ops): return self.packed(ins, ops, "i32x4", "{a}>{b}")
    def i_pcmpeqd(self, ins, ops): return self.packed(ins, ops, "i32x4", "{a}=={b}")
    def i_pcmpeqb(self, ins, ops): return self.packed(ins, ops, "i8x16", "{a}=={b}")
    def i_pmaxsd(self, ins, ops): return self.minmaxp(ins, ops, "i32x4", 4, ">")
    def i_pminsd(self, ins, ops): return self.minmaxp(ins, ops, "i32x4", 4, "<")

    def minmaxp(self, ins, ops, ty, n, cmp):
        d, s = ops
        x = self.xname(ins, d)
        return (f"{{{ty} a=({ty}){x},b=({ty}){self.xr(ins, s)}; for(int i=0;i<{n};i++) a[i]=(a[i]{cmp}b[i])?a[i]:b[i]; "
                f"{x}=(V)a;}}")

    def i_maxps(self, ins, ops): return self.minmaxp(ins, ops, "f32x4", 4, ">")
    def i_maxpd(self, ins, ops): return self.minmaxp(ins, ops, "f64x2", 2, ">")
    def i_minpd(self, ins, ops): return self.minmaxp(ins, ops, "f64x2", 2, "<")
    def i_minps(self, ins, ops): return self.minmaxp(ins, ops, "f32x4", 4, "<")

    def i_sqrtps(self, ins, ops):
        d, s = ops
        return (f"{{f32x4 a=(f32x4){self.xr(ins, s)}; for(int i=0;i<4;i++) a[i]=sqrtf(a[i]); "
                f"{self.xname(ins, d)}=(V)a;}}")

    def i_ucomiss(self, ins, ops):
        d, s = ops
        return self.fcmp(f"(double){self.sf(ins, d)}", f"(double){self.sf(ins, s)}")

    i_comiss = i_ucomiss

    def i_ucomisd(self, ins, ops):
        d, s = ops
        return self.fcmp(self.sd(ins, d), self.sd(ins, s))

    i_comisd = i_ucomisd

    def i_cvtss2sd(self, ins, ops):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=setd({x},0,(double){self.sf(ins, s)});"

    def i_cvtsd2ss(self, ins, ops):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=setf({x},0,(float){self.sd(ins, s)});"

    def i_cvtsi2ss(self, ins, ops):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=setf({x},0,(float){self.rds(ins, s)});"

    def i_cvtsi2sd(self, ins, ops):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=setd({x},0,(double){self.rds(ins, s)});"

    def i_cvttss2si(self, ins, ops):
        d, s = ops
        fn = "cvtt_f2i64" if d.size == 8 else "cvtt_f2i32"
        return self.wr(ins, d, f"{fn}((double){self.sf(ins, s)})")

    def i_cvttsd2si(self, ins, ops):
        d, s = ops
        fn = "cvtt_f2i64" if d.size == 8 else "cvtt_f2i32"
        return self.wr(ins, d, f"{fn}({self.sd(ins, s)})")

    def i_cvtss2si(self, ins, ops):
        d, s = ops
        fn = "cvt_f2i64" if d.size == 8 else "cvt_f2i32"
        return self.wr(ins, d, f"{fn}((double){self.sf(ins, s)})")

    def i_cvtsd2si(self, ins, ops):
        d, s = ops
        fn = "cvt_f2i64" if d.size == 8 else "cvt_f2i32"
        return self.wr(ins, d, f"{fn}({self.sd(ins, s)})")

    def low64(self, ins, s):
        if s.type == OP_REG:
            return f"vu64({self.xr(ins, s)},0)"
        return f"LD64({self.ea(ins, s)})"

    def i_cvtps2pd(self, ins, ops):
        d, s = ops
        return (f"{{V t=fromu64({self.low64(ins, s)}); {self.xname(ins, d)}=(V)(f64x2){{(double)vf(t,0),(double)vf(t,1)}};}}")

    def i_cvtpd2ps(self, ins, ops):
        d, s = ops
        return (f"{{V t={self.xr(ins, s)}; {self.xname(ins, d)}=(V)(f32x4){{(float)vd(t,0),(float)vd(t,1),0,0}};}}")

    def i_cvttpd2dq(self, ins, ops):
        d, s = ops
        return (f"{{V t={self.xr(ins, s)}; {self.xname(ins, d)}=(V)(i32x4){{cvtt_f2i32(vd(t,0)),cvtt_f2i32(vd(t,1)),0,0}};}}")

    def i_cvtdq2ps(self, ins, ops):
        d, s = ops
        return f"{{i32x4 t=(i32x4){self.xr(ins, s)}; {self.xname(ins, d)}=(V)(f32x4){{(float)t[0],(float)t[1],(float)t[2],(float)t[3]}};}}"

    def i_cvtdq2pd(self, ins, ops):
        d, s = ops
        return f"{{i32x4 t=(i32x4)fromu64({self.low64(ins, s)}); {self.xname(ins, d)}=(V)(f64x2){{(double)t[0],(double)t[1]}};}}"

    def i_cvttps2dq(self, ins, ops):
        d, s = ops
        return (f"{{f32x4 t=(f32x4){self.xr(ins, s)}; {self.xname(ins, d)}=(V)(i32x4){{cvtt_f2i32(t[0]),cvtt_f2i32(t[1]),"
                f"cvtt_f2i32(t[2]),cvtt_f2i32(t[3])}};}}")

    def bin_helper(self, ins, ops, fn):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}={fn}({x},{self.xr(ins, s)});"

    def i_unpcklpd(self, ins, ops): return self.bin_helper(ins, ops, "unpcklpd")
    def i_unpckhpd(self, ins, ops): return self.bin_helper(ins, ops, "unpckhpd")
    def i_unpcklps(self, ins, ops): return self.bin_helper(ins, ops, "unpcklps")
    def i_unpckhps(self, ins, ops): return self.bin_helper(ins, ops, "unpckhps")
    def i_punpcklqdq(self, ins, ops): return self.bin_helper(ins, ops, "unpcklpd")
    def i_punpckhqdq(self, ins, ops): return self.bin_helper(ins, ops, "unpckhpd")
    def i_punpckldq(self, ins, ops): return self.bin_helper(ins, ops, "unpcklps")
    def i_punpcklbw(self, ins, ops): return self.bin_helper(ins, ops, "punpcklbw")
    def i_punpcklwd(self, ins, ops): return self.bin_helper(ins, ops, "punpcklwd")
    def i_haddpd(self, ins, ops): return self.bin_helper(ins, ops, "haddpd")
    def i_addsubpd(self, ins, ops): return self.bin_helper(ins, ops, "addsubpd")
    def i_phaddd(self, ins, ops): return self.bin_helper(ins, ops, "phaddd")
    def i_pshufb(self, ins, ops): return self.bin_helper(ins, ops, "pshufb")

    def imm_helper(self, ins, ops, fn, two=True):
        d, s, im = ops
        x = self.xname(ins, d)
        if two:
            return f"{x}={fn}({x},{self.xr(ins, s)},{im.imm & 0xff});"
        return f"{x}={fn}({self.xr(ins, s)},{im.imm & 0xff});"

    def i_shufps(self, ins, ops): return self.imm_helper(ins, ops, "shufps")
    def i_shufpd(self, ins, ops): return self.imm_helper(ins, ops, "shufpd")
    def i_blendps(self, ins, ops): return self.imm_helper(ins, ops, "blendps")
    def i_blendpd(self, ins, ops): return self.imm_helper(ins, ops, "blendpd")
    def i_pblendw(self, ins, ops): return self.imm_helper(ins, ops, "pblendw")
    def i_pshufd(self, ins, ops): return self.imm_helper(ins, ops, "pshufd", False)
    def i_pshuflw(self, ins, ops): return self.imm_helper(ins, ops, "pshuflw", False)

    def i_insertps(self, ins, ops):
        d, s, im = ops
        x = self.xname(ins, d)
        if s.type == OP_MEM:
            src = f"fromu32(LD32({self.ea(ins, s)}))"
            imm = im.imm & 0x3F  # memory form: count_s ignored
        else:
            src = self.xr(ins, s)
            imm = im.imm & 0xFF
        return f"{x}=insertps({x},{src},{imm});"

    def i_blendvps(self, ins, ops):
        d, s = ops[0], ops[1]
        x = self.xname(ins, d)
        return f"{x}=blendvps({x},{self.xr(ins, s)},x0);"

    def i_blendvpd(self, ins, ops):
        d, s = ops[0], ops[1]
        x = self.xname(ins, d)
        return f"{x}=blendvpd({x},{self.xr(ins, s)},x0);"

    def i_extractps(self, ins, ops):
        d, s, im = ops
        return self.wr(ins, d, f"vu32({self.xr(ins, s)},{im.imm & 3})", 4)

    def i_pextrd(self, ins, ops):
        d, s, im = ops
        return self.wr(ins, d, f"vu32({self.xr(ins, s)},{im.imm & 3})", 4)

    def i_pextrq(self, ins, ops):
        d, s, im = ops
        return self.wr(ins, d, f"vu64({self.xr(ins, s)},{im.imm & 1})", 8)

    def i_pextrb(self, ins, ops):
        d, s, im = ops
        v = f"((u8x16){self.xr(ins, s)})[{im.imm & 15}]"
        if d.type == OP_MEM:
            return self.wr(ins, d, v, 1)
        return self.wr(ins, d, f"(u32){v}", 4)

    def i_pinsrd(self, ins, ops):
        d, s, im = ops
        x = self.xname(ins, d)
        return f"{x}=setu32({x},{im.imm & 3},{self.rd(ins, s, 4)});"

    def i_pinsrq(self, ins, ops):
        d, s, im = ops
        x = self.xname(ins, d)
        return f"{x}=setu64({x},{im.imm & 1},{self.rd(ins, s, 8)});"

    def i_pinsrb(self, ins, ops):
        d, s, im = ops
        x = self.xname(ins, d)
        return f"{{u8x16 t=(u8x16){x}; t[{im.imm & 15}]={self.rd(ins, s, 1)}; {x}=(V)t;}}"

    def i_pinsrw(self, ins, ops):
        d, s, im = ops
        x = self.xname(ins, d)
        return f"{{u16x8 t=(u16x8){x}; t[{im.imm & 7}]={self.rd(ins, s, 2)}; {x}=(V)t;}}"

    def pmov(self, ins, ops, srct, n, dstt, nbytes):
        d, s = ops
        if s.type == OP_MEM:
            src = f"fromu64(LD{nbytes * 8}({self.ea(ins, s)}))" if nbytes == 8 else f"fromu64((u64)LD{nbytes * 8}({self.ea(ins, s)}))"
        else:
            src = self.xr(ins, s)
        elems = ",".join(f"t[{i}]" for i in range(n))
        return f"{{{srct} t=({srct}){src}; {self.xname(ins, d)}=(V)({dstt}){{{elems}}};}}"

    def i_pmovsxdq(self, ins, ops): return self.pmov(ins, ops, "i32x4", 2, "i64x2", 8)
    def i_pmovzxdq(self, ins, ops): return self.pmov(ins, ops, "u32x4", 2, "u64x2", 8)
    def i_pmovsxwd(self, ins, ops): return self.pmov(ins, ops, "i16x8", 4, "i32x4", 8)
    def i_pmovzxwd(self, ins, ops): return self.pmov(ins, ops, "u16x8", 4, "u32x4", 8)
    def i_pmovsxbq(self, ins, ops): return self.pmov(ins, ops, "i8x16", 2, "i64x2", 2)
    def i_pmovzxbq(self, ins, ops): return self.pmov(ins, ops, "u8x16", 2, "u64x2", 2)
    def i_pmovzxbd(self, ins, ops): return self.pmov(ins, ops, "u8x16", 4, "u32x4", 4)
    def i_pmovsxbd(self, ins, ops): return self.pmov(ins, ops, "i8x16", 4, "i32x4", 4)

    def i_pmovmskb(self, ins, ops):
        d, s = ops
        return self.wr(ins, d, f"pmovmskb({self.xr(ins, s)})", 4)

    def i_movmskps(self, ins, ops):
        d, s = ops
        return self.wr(ins, d, f"movmskps({self.xr(ins, s)})", 4)

    def i_movmskpd(self, ins, ops):
        d, s = ops
        return self.wr(ins, d, f"movmskpd({self.xr(ins, s)})", 4)

    def pshift(self, ins, ops, ty, bits, op):
        d, s = ops
        x = self.xname(ins, d)
        if s.type == OP_IMM:
            n = f"{s.imm & 0xff}"
        else:
            n = f"vu64({self.xr(ins, s)},0)"
        if op == ">>a":
            return f"{{u64 n={n}; if(n>{bits - 1}) n={bits - 1}; {x}=(V)((({ty}){x})>>(int)n);}}"
        return f"{{u64 n={n}; if(n>{bits - 1}) {x}=vzero(); else {x}=(V)((({ty}){x}){op}(int)n);}}"

    def i_pslld(self, ins, ops): return self.pshift(ins, ops, "u32x4", 32, "<<")
    def i_psllq(self, ins, ops): return self.pshift(ins, ops, "u64x2", 64, "<<")
    def i_psrld(self, ins, ops): return self.pshift(ins, ops, "u32x4", 32, ">>")
    def i_psrlq(self, ins, ops): return self.pshift(ins, ops, "u64x2", 64, ">>")
    def i_psrad(self, ins, ops): return self.pshift(ins, ops, "i32x4", 32, ">>a")

    def i_pslldq(self, ins, ops):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=pslldq({x},{s.imm & 0xff});"

    def i_psrldq(self, ins, ops):
        d, s = ops
        x = self.xname(ins, d)
        return f"{x}=psrldq({x},{s.imm & 0xff});"

    def rnd(self, ins, ops, kind):
        d, s, im = ops
        x = self.xname(ins, d)
        imm = im.imm & 0xff
        mode = 0 if imm & 4 else imm & 3
        if kind == "ss":
            return f"{x}=setf({x},0,round_modef({self.sf(ins, s)},{mode}));"
        if kind == "sd":
            return f"{x}=setd({x},0,round_mode({self.sd(ins, s)},{mode}));"
        if kind == "ps":
            return f"{{f32x4 t=(f32x4){self.xr(ins, s)}; for(int i=0;i<4;i++) t[i]=round_modef(t[i],{mode}); {x}=(V)t;}}"
        return f"{{f64x2 t=(f64x2){self.xr(ins, s)}; for(int i=0;i<2;i++) t[i]=round_mode(t[i],{mode}); {x}=(V)t;}}"

    def i_roundss(self, ins, ops): return self.rnd(ins, ops, "ss")
    def i_roundsd(self, ins, ops): return self.rnd(ins, ops, "sd")
    def i_roundps(self, ins, ops): return self.rnd(ins, ops, "ps")
    def i_roundpd(self, ins, ops): return self.rnd(ins, ops, "pd")

    def sse_cmp(self, ins):
        mn = ins.mnemonic
        suf = mn[-2:]
        pred = mn[3:-2]
        if pred not in FCMP_PRED:
            raise Unhandled("cmp pred")
        pv = FCMP_PRED[pred]
        ops = ins.operands
        d, s = ops[0], ops[1]
        x = self.xname(ins, d)
        if suf == "ss":
            return f"{x}=setu32({x},0,fcmp_pred(vf({x},0),{self.sf(ins, s)},{pv})?0xffffffffu:0);"
        if suf == "sd":
            return f"{x}=setu64({x},0,fcmp_pred(vd({x},0),{self.sd(ins, s)},{pv})?~0ULL:0);"
        if suf == "ps":
            return (f"{{f32x4 a=(f32x4){x},b=(f32x4){self.xr(ins, s)}; u32x4 r; for(int i=0;i<4;i++) "
                    f"r[i]=fcmp_pred(a[i],b[i],{pv})?0xffffffffu:0; {x}=(V)r;}}")
        return (f"{{f64x2 a=(f64x2){x},b=(f64x2){self.xr(ins, s)}; u64x2 r; for(int i=0;i<2;i++) "
                f"r[i]=fcmp_pred(a[i],b[i],{pv})?~0ULL:0; {x}=(V)r;}}")

    # ---- x87 --------------------------------------------------------------
    def st_index(self, ins, op):
        n = self.reg(ins, op.reg)
        if n.startswith("st(") and n.endswith(")"):
            return int(n[3:-1])
        if n == "st":
            return 0
        raise Unhandled("x87 reg " + n)

    def fmem(self, ins, op):
        ea = self.ea(ins, op)
        if op.size == 4:
            return f"(double)u2f(LD32({ea}))"
        if op.size == 8:
            return f"u2d(LD64({ea}))"
        if op.size == 10:
            return f"ld80({ea})"
        raise Unhandled("x87 mem size")

    def i_fld(self, ins, ops):
        s = ops[0]
        if s.type == OP_MEM:
            return f"fpush(c,{self.fmem(ins, s)});"
        return f"{{double v=FST({self.st_index(ins, s)}); fpush(c,v);}}"

    def i_fild(self, ins, ops):
        s = ops[0]
        return f"fpush(c,(double){self.rds(ins, s)});"

    def i_fldz(self, ins, ops): return "fpush(c,0.0);"
    def i_fld1(self, ins, ops): return "fpush(c,1.0);"
    def i_fchs(self, ins, ops): return "FST(0)=-FST(0);"

    def fstore(self, ins, ops, pop):
        d = ops[0]
        tail = "fpop(c);" if pop else ""
        if d.type == OP_MEM:
            ea = self.ea(ins, d)
            if d.size == 4:
                return f"ST32({ea},f2u((float)FST(0))); {tail}"
            if d.size == 8:
                return f"ST64({ea},d2u(FST(0))); {tail}"
            if d.size == 10:
                return f"st80({ea},FST(0)); {tail}"
            raise Unhandled("fst size")
        i = self.st_index(ins, d)
        return f"FST({i})=FST(0); {tail}"

    def i_fstp(self, ins, ops): return self.fstore(ins, ops, True)
    def i_fst(self, ins, ops): return self.fstore(ins, ops, False)

    def i_fisttp(self, ins, ops):
        d = ops[0]
        w = d.size
        fn = "cvtt_f2i64" if w == 8 else "cvtt_f2i32"
        return f"{self.wr(ins, d, f'{fn}(FST(0))')} fpop(c);"

    def i_fistp(self, ins, ops):
        d = ops[0]
        w = d.size
        fn = "cvt_f2i64" if w == 8 else "cvt_f2i32"
        return f"{self.wr(ins, d, f'{fn}(FST(0))')} fpop(c);"

    def farith(self, ins, ops, op, pop=False, rev=False, intmem=False):
        if len(ops) == 1 and ops[0].type == OP_MEM:
            v = self.rds(ins, ops[0]) if intmem else self.fmem(ins, ops[0])
            v = f"(double){v}"
            if rev:
                return f"FST(0)={v}{op}FST(0);"
            return f"FST(0)=FST(0){op}{v};"
        if len(ops) == 2:
            di, si = self.st_index(ins, ops[0]), self.st_index(ins, ops[1])
        elif len(ops) == 1:
            di, si = 0, self.st_index(ins, ops[0])
        else:
            di, si = 1, 0
        expr = f"FST({si}){op}FST({di})" if rev else f"FST({di}){op}FST({si})"
        return f"FST({di})={expr}; {'fpop(c);' if pop else ''}"

    def i_fadd(self, ins, ops): return self.farith(ins, ops, "+")
    def i_faddp(self, ins, ops): return self.farith(ins, ops, "+", pop=True)
    def i_fmul(self, ins, ops): return self.farith(ins, ops, "*")
    def i_fmulp(self, ins, ops): return self.farith(ins, ops, "*", pop=True)
    def i_fdiv(self, ins, ops): return self.farith(ins, ops, "/")
    def i_fdivp(self, ins, ops): return self.farith(ins, ops, "/", pop=True)
    def i_fsub(self, ins, ops): return self.farith(ins, ops, "-")
    def i_fsubp(self, ins, ops): return self.farith(ins, ops, "-", pop=True)
    def i_fimul(self, ins, ops): return self.farith(ins, ops, "*", intmem=True)
    def i_fidiv(self, ins, ops): return self.farith(ins, ops, "/", intmem=True)
    def i_fidivr(self, ins, ops): return self.farith(ins, ops, "/", intmem=True, rev=True)
    def i_fiadd(self, ins, ops): return self.farith(ins, ops, "+", intmem=True)

    def i_fxch(self, ins, ops):
        i = self.st_index(ins, ops[0]) if ops else 1
        if len(ops) == 2:
            i = self.st_index(ins, ops[1]) or self.st_index(ins, ops[0])
        return f"{{double t=FST(0); FST(0)=FST({i}); FST({i})=t;}}"

    def i_fucomi(self, ins, ops):
        i = self.st_index(ins, ops[-1])
        return self.fcmp("FST(0)", f"FST({i})")

    i_fcomi = i_fucomi

    def i_fucompi(self, ins, ops):
        i = self.st_index(ins, ops[-1])
        return self.fcmp("FST(0)", f"FST({i})") + " fpop(c);"

    i_fcompi = i_fucompi

    def i_fcmovnb(self, ins, ops):
        i = self.st_index(ins, ops[-1])
        return f"if(!CF) FST(0)=FST({i});"

    def i_fcmovnbe(self, ins, ops):
        i = self.st_index(ins, ops[-1])
        return f"if(!CF&&!ZF) FST(0)=FST({i});"

    def i_fcmovb(self, ins, ops):
        i = self.st_index(ins, ops[-1])
        return f"if(CF) FST(0)=FST({i});"

    def i_fcmovbe(self, ins, ops):
        i = self.st_index(ins, ops[-1])
        return f"if(CF||ZF) FST(0)=FST({i});"

    def i_fcmove(self, ins, ops):
        i = self.st_index(ins, ops[-1])
        return f"if(ZF) FST(0)=FST({i});"

    def i_fcmovne(self, ins, ops):
        i = self.st_index(ins, ops[-1])
        return f"if(!ZF) FST(0)=FST({i});"

    def i_fstp_noop(self, ins, ops):
        return ""

    def i_fnstcw(self, ins, ops):
        return f"ST16({self.ea(ins, ops[0])},0x37f);"

    def i_fldcw(self, ins, ops):
        return ""


FILE_HEADER = """#include "x86.h"
#include "funcs.h"
#define SO() ({so})
#define SOALL() ({so},c->CF=CF,c->ZF=ZF,c->SF=SF,c->OF=OF,c->PF=PF,c->x[8]=x8,c->x[9]=x9,c->x[10]=x10,c->x[11]=x11,c->x[12]=x12,c->x[13]=x13,c->x[14]=x14,c->x[15]=x15)
#define SI() ({si})
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wunused-but-set-variable"
#pragma clang diagnostic ignored "-Wparentheses-equality"
#pragma clang diagnostic ignored "-Wconstant-conversion"
#pragma clang diagnostic ignored "-Wshift-count-overflow"
#pragma clang diagnostic ignored "-Wtautological-constant-out-of-range-compare"
"""


def main():
    path, outdir = sys.argv[1], sys.argv[2]
    only = set(int(x, 16) for x in sys.argv[3].split(",")) if len(sys.argv) > 3 else None
    os.makedirs(outdir, exist_ok=True)
    prog = Program(path)
    prog.analyze()
    hdr = FILE_HEADER.format(so=FuncLifter.SO.rstrip(";").replace(";", ","),
                             si=FuncLifter.SI.rstrip(";").replace(";", ","))
    unhandled = []
    files = []
    chunk, chunk_ins, fileno = [], 0, 0

    def flush():
        nonlocal chunk, chunk_ins, fileno
        if not chunk:
            return
        fn = os.path.join(outdir, f"lift_{fileno:03d}.c")
        with open(fn, "w") as fh:
            fh.write(hdr)
            fh.write("\n\n".join(chunk))
            fh.write("\n")
        files.append(fn)
        fileno += 1
        chunk, chunk_ins = [], 0

    for i, f in enumerate(prog.starts):
        if only and f not in only:
            continue
        fl = FuncLifter(prog, f)
        src = fl.lift()
        unhandled += fl.unhandled
        chunk.append(src)
        chunk_ins += src.count("\n")
        if chunk_ins > 60000:
            flush()
    flush()
    with open(os.path.join(outdir, "funcs.h"), "w") as fh:
        fh.write("#pragma once\n")
        for k in range(len(prog.secs)):
            fh.write(f"extern u8 x86s_{k}[];\n")
        for n in sorted(prog.slot_syms):
            fh.write(f"extern u8 {n}[];\n")
        for f in prog.starts:
            fh.write(f"void F_{f:x}(CPU *c);\n")
    with open(os.path.join(outdir, "table.c"), "w") as fh:
        fh.write('#include "x86.h"\n#include "funcs.h"\n')
        fh.write(f"const unsigned x86_nfuncs = {len(prog.starts)};\n")
        fh.write("const xfn x86_fn_table[] = {\n")
        for f in prog.starts:
            fh.write(f" F_{f:x},\n")
        fh.write("};\nconst u64 x86_fn_addr[] = {\n")
        for f in prog.starts:
            fh.write(f" 0x{f:x}ULL,\n")
        fh.write("};\n")
        fh.write(f"const unsigned x86_nimports = {len(prog.imports)};\n")
        fh.write("const char *const x86_import_names[] = {\n")
        for n in prog.imports:
            fh.write(f' "{n}",\n')
        fh.write("};\n")
    # trampolines: one per function, 8 bytes each
    with open(os.path.join(outdir, "tramp.s"), "w") as fh:
        fh.write(".text\n.p2align 4\n.globl _x86tramp\n_x86tramp:\n")
        for i in range(len(prog.starts)):
            fh.write(f".private_extern _x86t_{i}\n_x86t_{i}:\n movz x16, #{i & 0xffff}\n")
            if i >= 0x10000:
                raise SystemExit("too many functions for trampoline encoding")
            fh.write(" b _x86_tramp_common\n")
        fh.write(".globl _x86tramp_end\n_x86tramp_end:\n")
    with open(os.path.join(outdir, "meta.json"), "w") as fh:
        json.dump({"imports": prog.imports, "nfuncs": len(prog.starts),
                   "starts": prog.starts}, fh)
    with open(os.path.join(outdir, "unhandled.txt"), "w") as fh:
        c = collections.Counter((m, why) for a, m, o, why in unhandled)
        for (m, why), n in c.most_common():
            fh.write(f"{n:6d} {m} {why}\n")
        for a, m, o, why in unhandled[:3000]:
            fh.write(f"{a:#x} {m} {o} : {why}\n")
    print(f"lifted {len(prog.starts)} functions into {len(files)} files; {len(unhandled)} unhandled insns",
          file=sys.stderr)


if __name__ == "__main__":
    main()
