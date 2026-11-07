import sys, collections
sys.path.insert(0, 'tools')
from macho import MachO
m = MachO(sys.argv[1])
names = collections.Counter()
for kind, lst in (('bind', m.binds()), ('lazy', m.lazy_binds()), ('weak', m.weak_binds())):
    for a, n, o, add, fl in lst: names[(kind, n, o)] += 1
print('dylibs:', *enumerate(m.dylibs, 1), sep='\n ')
imp = sorted(set((n, o) for (k, n, o) in names if k != 'weak'))
print('unique non-weak imports', len(imp))
byd = collections.Counter(o for n, o in imp); print(byd)
for n, o in imp: print(o, n)
