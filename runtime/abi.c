/* Type-encoding driven argument marshalling between x86-64 SysV and arm64 Apple ABIs. */
#include "rt.h"
#include <stdlib.h>
#include <string.h>

/* ---- encoding parser ------------------------------------------------------ */

static void add_leaf(TI *t, u32 off, u32 size, char cls)
{
    if (t->nleaf >= MAX_LEAF) {
        t->bad = 1;
        return;
    }
    t->leaf[t->nleaf].off = (u16)off;
    t->leaf[t->nleaf].size = (u8)size;
    t->leaf[t->nleaf].cls = (u8)cls;
    t->nleaf++;
}

static const char *skip_quals(const char *p)
{
    while (*p && strchr("rnNoORVA", *p)) p++;
    return p;
}

/* Parse one type at p into t (leaves relative to off); returns the end of the type. */
static const char *ptype(const char *p, TI *t, u32 off, u32 *size, u32 *align)
{
    p = skip_quals(p);
    char ch = *p++;
    *size = *align = 1;
    switch (ch) {
    case 'c': case 'C': case 'B':
        *size = *align = 1; add_leaf(t, off, 1, 'i'); t->sgn = ch == 'c'; break;
    case 's': case 'S':
        *size = *align = 2; add_leaf(t, off, 2, 'i'); t->sgn = ch == 's'; break;
    case 'i': case 'I': case 'l': case 'L':
        *size = *align = 4; add_leaf(t, off, 4, 'i'); t->sgn = ch == 'i' || ch == 'l'; break;
    case 'q': case 'Q':
        *size = *align = 8; add_leaf(t, off, 8, 'i'); break;
    case 'f':
        *size = *align = 4; add_leaf(t, off, 4, 'f'); break;
    case 'd':
        *size = *align = 8; add_leaf(t, off, 8, 'd'); break;
    case 'D':
        *size = *align = 8; add_leaf(t, off, 8, 'd'); t->bad = 2; break;
    case 'v':
        *size = 0; break;
    case '*': case '#': case ':': case '?':
        *size = *align = 8; add_leaf(t, off, 8, 'i'); break;
    case '@':
        *size = *align = 8; add_leaf(t, off, 8, 'i');
        if (*p == '?') p++;
        else if (*p == '"') { const char *q = strchr(p + 1, '"'); p = q ? q + 1 : p + strlen(p); }
        break;
    case '^': {
        TI scratch = {0};
        u32 s2, a2;
        *size = *align = 8; add_leaf(t, off, 8, 'i');
        if (*p == '?') p++;
        else if (*p) p = ptype(p, &scratch, 0, &s2, &a2);
        break;
    }
    case 'b':
        while (*p >= '0' && *p <= '9') p++;
        *size = *align = 4; add_leaf(t, off, 4, 'i'); t->bad = 1; break;
    case '[': {
        long n = strtol(p, (char **)&p, 10);
        u32 es = 0, ea = 1;
        u8 first = t->nleaf;
        p = ptype(p, t, off, &es, &ea);
        u8 last = t->nleaf;
        for (long i = 1; i < n; i++)
            for (u8 j = first; j < last; j++)
                add_leaf(t, t->leaf[j].off + (u32)(i * es), t->leaf[j].size, t->leaf[j].cls);
        if (*p == ']') p++;
        *size = (u32)(es * n);
        *align = ea;
        break;
    }
    case '{': case '(': {
        char close = ch == '{' ? '}' : ')';
        while (*p && *p != '=' && *p != close) p++;
        u32 cur = 0, maxa = 1, maxs = 0;
        if (*p == '=') {
            p++;
            while (*p && *p != close) {
                if (*p == '"') { const char *q = strchr(p + 1, '"'); p = q ? q + 1 : p + strlen(p); continue; }
                u32 fs, fa;
                u32 at = ch == '{' ? (cur + 0) : 0;
                /* field alignment: parse into scratch first to learn alignment */
                TI tmp = {0};
                ptype(p, &tmp, 0, &fs, &fa);
                if (ch == '{') at = (cur + fa - 1) & ~(fa - 1);
                p = ptype(p, t, off + at, &fs, &fa);
                if (fa > maxa) maxa = fa;
                if (ch == '{') cur = at + fs;
                else if (fs > maxs) maxs = fs;
            }
        } else {
            t->bad = 1; /* opaque */
        }
        if (*p == close) p++;
        u32 sz = ch == '{' ? cur : maxs;
        *size = (sz + maxa - 1) & ~(maxa - 1);
        *align = maxa;
        if (ch == '(') t->bad = 1;
        break;
    }
    default:
        t->bad = 1;
        *size = *align = 8;
        add_leaf(t, off, 8, 'i');
        break;
    }
    return p;
}

const char *type_parse(const char *p, TI *t)
{
    memset(t, 0, sizeof *t);
    u32 sz, al;
    const char *q = skip_quals(p);
    char ch = *q;
    p = ptype(p, t, 0, &sz, &al);
    t->size = sz;
    t->align = al;
    if (ch == 'v') t->kind = 'v';
    else if (ch == '{' || ch == '(' || ch == '[') t->kind = 's';
    else if (ch == 'f') t->kind = 'f';
    else if (ch == 'd') t->kind = 'd';
    else if (ch == 'D') t->kind = 'D';
    else t->kind = 'i';
    return p;
}

int sig_parse(const char *enc, Sig *s)
{
    memset(s, 0, sizeof *s);
    s->vstart = -1;
    const char *p = enc;
    if (*p == '!') {
        s->special = 1;
        return 0;
    }
    p = type_parse(p, &s->ret);
    while (*p == '-' || (*p >= '0' && *p <= '9')) p++;
    while (*p) {
        if (*p == '.') {
            s->vstart = s->nargs;
            p++;
            continue;
        }
        if (s->nargs >= MAX_ARGS) return -1;
        p = type_parse(p, &s->args[s->nargs++]);
        while (*p == '-' || (*p >= '0' && *p <= '9')) p++;
    }
    if (s->vstart < 0) s->vstart = s->nargs;
    return 0;
}

void sig_add_arg(Sig *s, char kind)
{
    if (s->nargs >= MAX_ARGS) return;
    TI *t = &s->args[s->nargs++];
    memset(t, 0, sizeof *t);
    if (kind == 'd') {
        t->kind = 'd'; t->size = t->align = 8; add_leaf(t, 0, 8, 'd');
    } else {
        t->kind = 'i'; t->size = t->align = 8; add_leaf(t, 0, 8, 'i');
    }
}

/* ---- x86-64 SysV ---------------------------------------------------------- */

static const int GPR[6] = {RDI, RSI, RDX, RCX, R8, R9};

/* Classify a value into eightbytes; returns count, 0 for MEMORY, -1 for void. */
static int x86_classify(const TI *t, char cls[2])
{
    if (t->kind == 'v' || t->size == 0) return -1;
    if (t->kind == 'D') return 0;
    if (t->kind == 'i') { cls[0] = 'I'; return 1; }
    if (t->kind == 'f' || t->kind == 'd') { cls[0] = 'S'; return 1; }
    if (t->size > 16) return 0;
    int n = (int)((t->size + 7) / 8);
    cls[0] = cls[1] = 0;
    for (int i = 0; i < t->nleaf; i++) {
        const Leaf *l = &t->leaf[i];
        int e = l->off / 8;
        if ((l->off % l->size) != 0 || (l->off + l->size - 1) / 8 != e) return 0;
        if (l->cls == 'i') cls[e] = 'I';
        else if (cls[e] != 'I') cls[e] = 'S';
    }
    for (int e = 0; e < n; e++)
        if (!cls[e]) cls[e] = 'S';
    return n;
}

int x86_ret_in_memory(const TI *t)
{
    char cls[2];
    return x86_classify(t, cls) == 0;
}

void x86_read_args(CPU *c, const Sig *s, int first_gpr, u64 stack, u8 (*vals)[VAL_MAX])
{
    int gi = first_gpr, xi = 0;
    u64 sp = stack;
    for (int a = 0; a < s->nargs; a++) {
        const TI *t = &s->args[a];
        u8 *v = vals[a];
        memset(v, 0, 16);
        char cls[2];
        int n = x86_classify(t, cls);
        if (n > 0) {
            int ni = 0, ns = 0;
            for (int e = 0; e < n; e++) cls[e] == 'I' ? ni++ : ns++;
            if (gi + ni <= 6 && xi + ns <= 8) {
                for (int e = 0; e < n; e++) {
                    u32 len = t->size - 8 * e < 8 ? t->size - 8 * e : 8;
                    if (cls[e] == 'I') memcpy(v + 8 * e, &c->r[GPR[gi++]], len);
                    else memcpy(v + 8 * e, &c->x[xi++], len);
                }
                continue;
            }
        }
        if (n < 0) continue;
        if (t->align > 8) sp = (sp + 15) & ~15ull;
        u32 len = t->size < VAL_MAX ? t->size : VAL_MAX;
        memcpy(v, (void *)(uintptr_t)sp, len);
        sp += (t->size + 7) & ~7u;
    }
}

/* Place args for a call into guest code; returns the new rsp (pointing at the return slot). */
u64 x86_write_args(CPU *c, const Sig *s, int first_gpr, u64 sp, u8 (*vals)[VAL_MAX])
{
    int gi = first_gpr, xi = 0;
    struct { int a; u32 off; } st[MAX_ARGS];
    int nst = 0;
    u32 soff = 0;
    for (int a = 0; a < s->nargs; a++) {
        const TI *t = &s->args[a];
        char cls[2];
        int n = x86_classify(t, cls);
        if (n < 0) continue;
        if (n > 0) {
            int ni = 0, ns = 0;
            for (int e = 0; e < n; e++) cls[e] == 'I' ? ni++ : ns++;
            if (gi + ni <= 6 && xi + ns <= 8) {
                for (int e = 0; e < n; e++) {
                    u32 len = t->size - 8 * e < 8 ? t->size - 8 * e : 8;
                    u64 w = 0;
                    memcpy(&w, vals[a] + 8 * e, len);
                    if (t->kind == 'i' && t->sgn && t->size < 8) {
                        if (t->size == 1) w = (u64)(s64)(s8)w;
                        else if (t->size == 2) w = (u64)(s64)(s16)w;
                        else w = (u64)(s64)(s32)w;
                    }
                    if (cls[e] == 'I') c->r[GPR[gi++]] = w;
                    else c->x[xi++] = (V){w, 0};
                }
                continue;
            }
        }
        if (t->align > 8) soff = (soff + 15) & ~15u;
        st[nst].a = a;
        st[nst].off = soff;
        nst++;
        soff += (t->size + 7) & ~7u;
    }
    soff = (soff + 15) & ~15u;
    sp = (sp - soff) & ~15ull;
    for (int i = 0; i < nst; i++) {
        const TI *t = &s->args[st[i].a];
        memset((void *)(uintptr_t)(sp + st[i].off), 0, (t->size + 7) & ~7u);
        memcpy((void *)(uintptr_t)(sp + st[i].off), vals[st[i].a], t->size < VAL_MAX ? t->size : VAL_MAX);
    }
    c->r[RAX] = (u64)xi; /* vector count for variadic callees */
    return sp - 8;
}

void x86_write_ret(CPU *c, const TI *t, const u8 *val, u64 sret)
{
    char cls[2];
    int n = x86_classify(t, cls);
    if (n < 0) return;
    if (n == 0) {
        memcpy((void *)(uintptr_t)sret, val, t->size);
        c->r[RAX] = sret;
        return;
    }
    int gi = 0, xi = 0;
    static const int RR[2] = {RAX, RDX};
    for (int e = 0; e < n; e++) {
        u32 len = t->size - 8 * e < 8 ? t->size - 8 * e : 8;
        u64 w = 0;
        memcpy(&w, val + 8 * e, len);
        if (t->kind == 'i' && t->size < 8) {
            if (t->sgn) w = t->size == 1 ? (u64)(s64)(s8)w : t->size == 2 ? (u64)(s64)(s16)w : (u64)(s64)(s32)w;
        }
        if (cls[e] == 'I') c->r[RR[gi++]] = w;
        else c->x[xi++] = (V){w, 0};
    }
}

void x86_read_ret(CPU *c, const TI *t, u8 *val, u64 sret)
{
    char cls[2];
    int n = x86_classify(t, cls);
    if (n < 0) return;
    if (n == 0) {
        memcpy(val, (void *)(uintptr_t)sret, t->size < VAL_MAX ? t->size : VAL_MAX);
        return;
    }
    int gi = 0, xi = 0;
    static const int RR[2] = {RAX, RDX};
    for (int e = 0; e < n; e++) {
        u32 len = t->size - 8 * e < 8 ? t->size - 8 * e : 8;
        if (cls[e] == 'I') memcpy(val + 8 * e, &c->r[RR[gi++]], len);
        else memcpy(val + 8 * e, &c->x[xi++], len);
    }
}

/* ---- arm64 Apple ------------------------------------------------------------ */

/* Homogeneous floating-point aggregate: element count (1-4) or 0. */
static int a64_hfa(const TI *t, char *k)
{
    if (t->kind != 's' || t->nleaf == 0 || t->nleaf > 4) return 0;
    char c0 = t->leaf[0].cls;
    if (c0 != 'f' && c0 != 'd') return 0;
    for (int i = 1; i < t->nleaf; i++)
        if (t->leaf[i].cls != c0) return 0;
    if (t->size != (u32)t->nleaf * t->leaf[0].size) return 0;
    *k = c0;
    return t->nleaf;
}

int a64_ret_in_memory(const TI *t)
{
    char k;
    if (t->kind != 's') return 0;
    if (a64_hfa(t, &k)) return 0;
    return t->size > 16;
}

static u64 extend(const TI *t, const u8 *v)
{
    u64 w = 0;
    memcpy(&w, v, t->size < 8 ? t->size : 8);
    if (t->kind == 'i' && t->size < 8) {
        if (t->sgn) w = t->size == 1 ? (u64)(s64)(s8)w : t->size == 2 ? (u64)(s64)(s16)w : (u64)(s64)(s32)w;
    }
    return w;
}

/* spill: scratch memory for >16 byte aggregates passed by reference (MAX_ARGS*VAL_MAX). */
void a64_write_args(NC *nc, const Sig *s, u8 (*vals)[VAL_MAX], u8 *stackbuf, u8 *spill)
{
    int ngrn = 0, nsrn = 0;
    u32 nsaa = 0;
    for (int a = 0; a < s->nargs; a++) {
        const TI *t = &s->args[a];
        const u8 *v = vals[a];
        char k;
        int h;
        if (t->kind == 'v') continue;
        if (a >= s->vstart) {
            /* Apple: variadic arguments go on the stack in 8-byte slots. */
            if (t->kind == 's' && !a64_hfa(t, &k) && t->size > 16) {
                memcpy(spill + a * VAL_MAX, v, t->size);
                u64 p = (u64)(uintptr_t)(spill + a * VAL_MAX);
                memcpy(stackbuf + nsaa, &p, 8);
                nsaa += 8;
            } else if (t->kind == 'i') {
                u64 w = extend(t, v);
                memcpy(stackbuf + nsaa, &w, 8);
                nsaa += 8;
            } else {
                if (t->align > 8) nsaa = (nsaa + 15) & ~15u;
                memcpy(stackbuf + nsaa, v, t->size);
                nsaa += (t->size + 7) & ~7u;
            }
            continue;
        }
        if (t->kind == 'i') {
            if (ngrn < 8) nc->x[ngrn++] = extend(t, v);
            else {
                u32 sz = t->size < 4 ? 4 : t->size;
                nsaa = (nsaa + sz - 1) & ~(sz - 1);
                u64 w = extend(t, v);
                memcpy(stackbuf + nsaa, &w, sz);
                nsaa += sz;
            }
        } else if (t->kind == 'f' || t->kind == 'd' || t->kind == 'D') {
            if (nsrn < 8) {
                u64 w = 0;
                memcpy(&w, v, t->kind == 'f' ? 4 : 8);
                nc->v[nsrn++] = (V){w, 0};
            } else {
                u32 sz = t->kind == 'f' ? 4 : 8;
                nsaa = (nsaa + sz - 1) & ~(sz - 1);
                memcpy(stackbuf + nsaa, v, sz);
                nsaa += sz;
            }
        } else if ((h = a64_hfa(t, &k))) {
            u32 es = k == 'f' ? 4 : 8;
            if (nsrn + h <= 8) {
                for (int i = 0; i < h; i++) {
                    u64 w = 0;
                    memcpy(&w, v + i * es, es);
                    nc->v[nsrn++] = (V){w, 0};
                }
            } else {
                nsrn = 8;
                u32 al = t->align < 8 ? 8 : t->align;
                nsaa = (nsaa + al - 1) & ~(al - 1);
                memcpy(stackbuf + nsaa, v, t->size);
                nsaa += (t->size + 7) & ~7u;
            }
        } else if (t->size > 16) {
            memcpy(spill + a * VAL_MAX, v, t->size);
            u64 p = (u64)(uintptr_t)(spill + a * VAL_MAX);
            if (ngrn < 8) nc->x[ngrn++] = p;
            else {
                nsaa = (nsaa + 7) & ~7u;
                memcpy(stackbuf + nsaa, &p, 8);
                nsaa += 8;
            }
        } else {
            int n = (int)((t->size + 7) / 8);
            if (t->align == 16) ngrn = (ngrn + 1) & ~1;
            if (ngrn + n <= 8) {
                for (int i = 0; i < n; i++) {
                    u64 w = 0;
                    u32 len = t->size - 8 * i < 8 ? t->size - 8 * i : 8;
                    memcpy(&w, v + 8 * i, len);
                    nc->x[ngrn++] = w;
                }
            } else {
                ngrn = 8;
                u32 al = t->align < 8 ? 8 : t->align;
                nsaa = (nsaa + al - 1) & ~(al - 1);
                memcpy(stackbuf + nsaa, v, t->size);
                nsaa += (t->size + 7) & ~7u;
            }
        }
    }
    nc->stack = (u64)(uintptr_t)stackbuf;
    nc->stack_size = (nsaa + 15) & ~15u;
}

void a64_read_args(const NC *nc, const Sig *s, u8 (*vals)[VAL_MAX])
{
    int ngrn = 0, nsrn = 0;
    u32 nsaa = 0;
    const u8 *stk = (const u8 *)(uintptr_t)nc->stack;
    for (int a = 0; a < s->nargs; a++) {
        const TI *t = &s->args[a];
        u8 *v = vals[a];
        char k;
        int h;
        memset(v, 0, 16);
        if (t->kind == 'v') continue;
        if (t->kind == 'i') {
            if (ngrn < 8) memcpy(v, &nc->x[ngrn++], t->size);
            else {
                u32 sz = t->size < 4 ? 4 : t->size;
                nsaa = (nsaa + sz - 1) & ~(sz - 1);
                memcpy(v, stk + nsaa, t->size);
                nsaa += sz;
            }
        } else if (t->kind == 'f' || t->kind == 'd' || t->kind == 'D') {
            u32 sz = t->kind == 'f' ? 4 : 8;
            if (nsrn < 8) memcpy(v, &nc->v[nsrn++], sz);
            else {
                nsaa = (nsaa + sz - 1) & ~(sz - 1);
                memcpy(v, stk + nsaa, sz);
                nsaa += sz;
            }
        } else if ((h = a64_hfa(t, &k))) {
            u32 es = k == 'f' ? 4 : 8;
            if (nsrn + h <= 8) {
                for (int i = 0; i < h; i++) memcpy(v + i * es, &nc->v[nsrn++], es);
            } else {
                nsrn = 8;
                u32 al = t->align < 8 ? 8 : t->align;
                nsaa = (nsaa + al - 1) & ~(al - 1);
                memcpy(v, stk + nsaa, t->size);
                nsaa += (t->size + 7) & ~7u;
            }
        } else if (t->size > 16) {
            u64 p;
            if (ngrn < 8) p = nc->x[ngrn++];
            else {
                nsaa = (nsaa + 7) & ~7u;
                memcpy(&p, stk + nsaa, 8);
                nsaa += 8;
            }
            memcpy(v, (void *)(uintptr_t)p, t->size < VAL_MAX ? t->size : VAL_MAX);
        } else {
            int n = (int)((t->size + 7) / 8);
            if (t->align == 16) ngrn = (ngrn + 1) & ~1;
            if (ngrn + n <= 8) {
                for (int i = 0; i < n; i++) {
                    u32 len = t->size - 8 * i < 8 ? t->size - 8 * i : 8;
                    memcpy(v + 8 * i, &nc->x[ngrn++], len);
                }
            } else {
                ngrn = 8;
                u32 al = t->align < 8 ? 8 : t->align;
                nsaa = (nsaa + al - 1) & ~(al - 1);
                memcpy(v, stk + nsaa, t->size);
                nsaa += (t->size + 7) & ~7u;
            }
        }
    }
}

void a64_read_ret(const NC *nc, const TI *t, u8 *val)
{
    char k;
    int h;
    if (t->kind == 'v') return;
    if (t->kind == 'i') memcpy(val, &nc->x[0], t->size);
    else if (t->kind == 'f') memcpy(val, &nc->v[0], 4);
    else if (t->kind == 'd' || t->kind == 'D') memcpy(val, &nc->v[0], 8);
    else if ((h = a64_hfa(t, &k))) {
        u32 es = k == 'f' ? 4 : 8;
        for (int i = 0; i < h; i++) memcpy(val + i * es, &nc->v[i], es);
    } else if (t->size > 16) {
        memcpy(val, (void *)(uintptr_t)nc->x[8], t->size < VAL_MAX ? t->size : VAL_MAX);
    } else {
        memcpy(val, &nc->x[0], t->size < 8 ? t->size : 8);
        if (t->size > 8) memcpy(val + 8, &nc->x[1], t->size - 8);
    }
}

void a64_write_ret(NC *nc, const TI *t, const u8 *val)
{
    char k;
    int h;
    if (t->kind == 'v') return;
    if (t->kind == 'i') nc->x[0] = extend(t, val);
    else if (t->kind == 'f') { u64 w = 0; memcpy(&w, val, 4); nc->v[0] = (V){w, 0}; }
    else if (t->kind == 'd' || t->kind == 'D') { u64 w = 0; memcpy(&w, val, 8); nc->v[0] = (V){w, 0}; }
    else if ((h = a64_hfa(t, &k))) {
        u32 es = k == 'f' ? 4 : 8;
        for (int i = 0; i < h; i++) { u64 w = 0; memcpy(&w, val + i * es, es); nc->v[i] = (V){w, 0}; }
    } else if (t->size > 16) {
        memcpy((void *)(uintptr_t)nc->x[8], val, t->size);
    } else {
        u64 w0 = 0, w1 = 0;
        memcpy(&w0, val, t->size < 8 ? t->size : 8);
        if (t->size > 8) memcpy(&w1, val + 8, t->size - 8);
        nc->x[0] = w0;
        nc->x[1] = w1;
    }
}
