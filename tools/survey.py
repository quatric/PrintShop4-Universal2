import sys, collections
sys.path.insert(0, 'tools')
from macho import MachO
import capstone
APP = sys.argv[1]
m = MachO(APP)
text = m.section('__TEXT', '__text')
fs = sorted(set(m.function_starts()))
print('functions', len(fs), 'binds', len(m.binds()), 'lazy', len(m.lazy_binds()), 'weak', len(m.weak_binds()), 'rebases', len(m.rebases()))
dic = m.data_in_code(); print('data_in_code', len(dic), collections.Counter(k for _,_,k in dic))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
code = m.read(text.addr, text.size)
mn = collections.Counter(); bad = 0; n = 0
ends = fs[1:] + [text.addr + text.size]
dicset = {a: l for a, l, k in dic}
for f, e in zip(fs, ends):
    if not (text.addr <= f < text.addr + text.size): continue
    a = f
    while a < e:
        if a in dicset: a += dicset[a]; continue
        ins = next(md.disasm_lite(code[a - text.addr: a - text.addr + 16], a), None)
        if ins is None: bad += 1; a += 1; continue
        n += 1; mn[ins[2]] += 1; a += ins[1]
print('instructions', n, 'undecodable bytes', bad, 'distinct mnemonics', len(mn))
for k, v in mn.most_common(): print(f'{v:8d} {k}')
