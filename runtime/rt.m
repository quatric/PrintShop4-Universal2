/* Bridge layer: guest CPU per thread, native<->guest calls, ObjC messaging, entry point. */
#import <Foundation/Foundation.h>
#include "rt.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <mach/mach.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <os/lock.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define GUEST_STACK (16u << 20)

static __thread CPU *t_cpu;
static int g_trace;

/* ---- signature caches -------------------------------------------------------- */

static Sig **g_import_sig;
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;

typedef struct SigEnt { const char *key; Sig *sig; } SigEnt;
static SigEnt *g_sigtab;
static size_t g_sigcap, g_sigcount;

/* Parsed signature for an encoding string, cached by pointer then by content. */
static Sig *sig_for(const char *enc)
{
    os_unfair_lock_lock(&g_lock);
    if (g_sigcount * 2 >= g_sigcap) {
        size_t ncap = g_sigcap ? g_sigcap * 2 : 1024;
        SigEnt *nt = calloc(ncap, sizeof *nt);
        for (size_t i = 0; i < g_sigcap; i++)
            if (g_sigtab[i].key) {
                size_t h = ((uintptr_t)g_sigtab[i].key >> 3) & (ncap - 1);
                while (nt[h].key) h = (h + 1) & (ncap - 1);
                nt[h] = g_sigtab[i];
            }
        free(g_sigtab);
        g_sigtab = nt;
        g_sigcap = ncap;
    }
    size_t h = ((uintptr_t)enc >> 3) & (g_sigcap - 1);
    while (g_sigtab[h].key) {
        if (g_sigtab[h].key == enc) {
            Sig *s = g_sigtab[h].sig;
            os_unfair_lock_unlock(&g_lock);
            return s;
        }
        h = (h + 1) & (g_sigcap - 1);
    }
    Sig *s = calloc(1, sizeof *s);
    if (sig_parse(enc, s) < 0) {
        free(s);
        s = NULL;
    }
    g_sigtab[h].key = enc;
    g_sigtab[h].sig = s;
    g_sigcount++;
    os_unfair_lock_unlock(&g_lock);
    return s;
}

/* ---- import address map ------------------------------------------------------- */

typedef struct AddrEnt { u64 addr; int idx; } AddrEnt;
static AddrEnt *g_addrtab;
static size_t g_addrcap;

static int import_by_addr(u64 a)
{
    size_t h = (a >> 2) & (g_addrcap - 1);
    while (g_addrtab[h].addr) {
        if (g_addrtab[h].addr == a) return g_addrtab[h].idx;
        h = (h + 1) & (g_addrcap - 1);
    }
    return -1;
}

static int g_text = 0;
static int g_idx_throw = -1, g_idx_rethrow = -1, g_idx_resume = -1, g_idx_resume_rethrow = -1;
static int g_idx_msgsend = -1, g_idx_msgsend_stret = -1, g_idx_super2 = -1, g_idx_super2_stret = -1;

static void build_tables(void)
{
    for (unsigned k = 0; k < x86_nsecs; k++)
        if (!strcmp(x86_sec_name[k], "__text")) g_text = (int)k;
    g_import_sig = calloc(x86_nimports, sizeof(Sig *));
    g_addrcap = 4096;
    while (g_addrcap < x86_nimports * 4) g_addrcap *= 2;
    g_addrtab = calloc(g_addrcap, sizeof *g_addrtab);
    for (unsigned i = 0; i < x86_nimports; i++) {
        const char *n = x86_import_names[i];
        if (!strcmp(n, "_objc_msgSend")) g_idx_msgsend = (int)i;
        else if (!strcmp(n, "_objc_msgSend_stret")) g_idx_msgsend_stret = (int)i;
        else if (!strcmp(n, "_objc_msgSendSuper2")) g_idx_super2 = (int)i;
        else if (!strcmp(n, "_objc_msgSendSuper2_stret")) g_idx_super2_stret = (int)i;
        else if (!strcmp(n, "___cxa_throw")) g_idx_throw = (int)i;
        else if (!strcmp(n, "___cxa_rethrow")) g_idx_rethrow = (int)i;
        else if (!strcmp(n, "__Unwind_Resume")) g_idx_resume = (int)i;
        else if (!strcmp(n, "__Unwind_Resume_or_Rethrow")) g_idx_resume_rethrow = (int)i;
        Sig *s = calloc(1, sizeof *s);
        if (sig_parse(x86_import_sigs[i].sig, s) < 0) {
            fprintf(stderr, "x86rt: bad import signature %s %s\n", n, x86_import_sigs[i].sig);
            free(s);
            s = NULL;
        }
        g_import_sig[i] = s;
        u64 a = (u64)(uintptr_t)x86_import_sigs[i].addr;
        if (!a || (s && s->special && strcmp(n, "_objc_msgSend") && strcmp(n, "_objc_msgSendSuper2") &&
                   strcmp(n, "___cxa_throw") && strcmp(n, "___cxa_rethrow"))) continue;
        size_t h = (a >> 2) & (g_addrcap - 1);
        while (g_addrtab[h].addr && g_addrtab[h].addr != a) h = (h + 1) & (g_addrcap - 1);
        if (!g_addrtab[h].addr) {
            g_addrtab[h].addr = a;
            g_addrtab[h].idx = (int)i;
        }
    }
}

/* ---- guest CPU ------------------------------------------------------------------ */

static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static void init_once(void)
{
    g_trace = getenv("X86RT_TRACE") != NULL;
    build_tables();
}

void x86_init(void) { pthread_once(&g_once, init_once); }

CPU *x86_cpu(void)
{
    CPU *c = t_cpu;
    if (c) return c;
    x86_init();
    c = calloc(1, sizeof *c);
    void *stk = mmap(NULL, GUEST_STACK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stk == MAP_FAILED) abort();
    mprotect(stk, 4096, PROT_NONE);
    c->stack_lo = (u64)(uintptr_t)stk;
    c->stack_hi = c->stack_lo + GUEST_STACK;
    c->r[RSP] = c->stack_hi - 64;
    c->mxcsr = 0x1f80;
    c->thread = pthread_self();
    t_cpu = c;
    return c;
}

/* ---- diagnostics ------------------------------------------------------------------ */

static void dump_cpu(CPU *c)
{
    static const char *n[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    for (int i = 0; i < 16; i++) fprintf(stderr, "  %-3s %016llx%s", n[i], c->r[i], (i & 3) == 3 ? "\n" : "");
}

void x86_trap(CPU *c, u64 addr, const char *why)
{
    fprintf(stderr, "x86rt: trap at guest 0x%llx: %s\n", addr, why);
    dump_cpu(c);
    void *bt[64];
    int n = backtrace(bt, 64);
    backtrace_symbols_fd(bt, n, 2);
    abort();
}

void x86_bad_jump(CPU *c, u64 from, u64 target)
{
    fprintf(stderr, "x86rt: bad jump from 0x%llx to 0x%llx\n", from, target);
    x86_trap(c, from, "bad jump");
}

void x86_rep_movs(CPU *c, int size) { (void)c; (void)size; abort(); }
void x86_rep_stos(CPU *c, int size) { (void)c; (void)size; abort(); }
u64 x86_rdtsc(void) { return __builtin_readcyclecounter(); }

/* ---- printf-style format scanning ------------------------------------------------ */

/* Append variadic argument kinds ('q' int/pointer, 'd' double) implied by a format. */
static void add_format_args(Sig *s, const char *fmt, int scanf_style)
{
    if (!fmt) return;
    for (const char *p = fmt; *p; p++) {
        if (*p != '%') continue;
        p++;
        if (*p == '%') continue;
        /* positional %n$ */
        const char *q = p;
        while (*q >= '0' && *q <= '9') q++;
        if (*q == '$') p = q + 1;
        if (scanf_style && *p == '*') { p++; }
        while (*p && strchr("-+ #0'", *p)) p++;
        if (*p == '*') { sig_add_arg(s, 'q'); p++; }
        else while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') {
            p++;
            if (*p == '*') { sig_add_arg(s, 'q'); p++; }
            else while (*p >= '0' && *p <= '9') p++;
        }
        while (*p && strchr("hlLqjztv", *p)) p++;
        if (!*p) break;
        if (*p == '[') { /* scanf set */
            p++;
            if (*p == ']') p++;
            while (*p && *p != ']') p++;
            sig_add_arg(s, 'q');
            if (!*p) break;
            continue;
        }
        if (scanf_style) { sig_add_arg(s, 'q'); continue; }
        if (strchr("eEfFgGaA", *p)) sig_add_arg(s, 'd');
        else sig_add_arg(s, 'q');
    }
}

static const char *nsstring_utf8(u64 obj)
{
    if (!obj) return NULL;
    return [(__bridge NSString *)(void *)(uintptr_t)obj UTF8String];
}

/* Variadic C imports: index of the format argument and its flavour. */
static int variadic_format(const char *name, int *fmt_arg, int *kind)
{
    static const struct { const char *n; int arg, kind; } tab[] = {
        {"_NSLog", 0, 1}, {"_CFStringCreateWithFormat", 2, 1}, {"_CFStringAppendFormat", 2, 1},
        {"_NSRunAlertPanel", 1, 1}, {"_NSRunCriticalAlertPanel", 1, 1}, {"_NSBeginAlertSheet", 8, 1},
        {"_sprintf", 1, 0}, {"_snprintf", 2, 0}, {"_fprintf", 1, 0}, {"_printf", 0, 0},
        {"___sprintf_chk", 3, 0}, {"_asprintf", 1, 0}, {"_sscanf", 1, 2}, {"_syslog", 1, 0},
    };
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++)
        if (!strcmp(name, tab[i].n)) {
            *fmt_arg = tab[i].arg;
            *kind = tab[i].kind;
            return 1;
        }
    return 0;
}

/* Imports taking a va_list: format argument, va_list argument, format flavour. */
static int valist_format(const char *name, int *fmt_arg, int *va_arg, int *kind)
{
    static const struct { const char *n; int fmt, va, kind; } tab[] = {
        {"_CFStringCreateWithFormatAndArguments", 2, 3, 1}, {"_CFStringAppendFormatAndArguments", 2, 3, 1},
        {"_NSLogv", 0, 1, 1}, {"_vprintf", 0, 1, 0}, {"_vfprintf", 1, 2, 0}, {"_vsprintf", 1, 2, 0},
        {"_vsnprintf", 2, 3, 0}, {"_vasprintf", 1, 2, 0}, {"___vsprintf_chk", 3, 4, 0},
        {"___vsnprintf_chk", 4, 5, 0}, {"_vsyslog", 1, 2, 0}, {"_vsscanf", 1, 2, 2},
    };
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++)
        if (!strcmp(name, tab[i].n)) {
            *fmt_arg = tab[i].fmt;
            *va_arg = tab[i].va;
            *kind = tab[i].kind;
            return 1;
        }
    return 0;
}

/* x86-64 SysV va_list: a pointer to this; arm64 Apple va_list: a pointer to 8-byte slots. */
typedef struct XVaList { u32 gp_offset, fp_offset; u64 overflow_arg_area, reg_save_area; } XVaList;

/* Copy the arguments a guest va_list holds, as the format describes them, into out[]
 * in the arm64 layout. Returns the number of slots written. */
static int valist_convert(const XVaList *va, const char *fmt, int kind, u64 *out, int max)
{
    Sig *s = alloca(sizeof(Sig));
    memset(s, 0, sizeof *s);
    add_format_args(s, fmt, kind == 2);
    u32 gp = va->gp_offset, fp = va->fp_offset;
    u64 ov = va->overflow_arg_area;
    int n = 0;
    for (int a = 0; a < s->nargs && n < max; a++) {
        u64 w;
        if (s->args[a].kind == 'd') {
            if (fp < 176) { w = LD64(va->reg_save_area + fp); fp += 16; }
            else { w = LD64(ov); ov += 8; }
        } else {
            if (gp < 48) { w = LD64(va->reg_save_area + gp); gp += 8; }
            else { w = LD64(ov); ov += 8; }
        }
        out[n++] = w;
    }
    if (g_trace) fprintf(stderr, "x86rt:   va_list -> %d args\n", n);
    return n;
}

/* ---- guest -> native call with a signature ------------------------------------- */

/* Extend s with the variadic arguments a guest caller passed, judging by format/nil terminator. */
static void add_variadics(CPU *c, Sig *s, int first_gpr, int fmt_arg, int kind)
{
    if (kind == 3) { /* nil-terminated object list */
        while (s->nargs < MAX_ARGS) {
            sig_add_arg(s, 'q');
            u8 (*vals)[VAL_MAX] = alloca((size_t)s->nargs * VAL_MAX);
            x86_read_args(c, s, first_gpr, c->r[RSP] + 8, vals);
            u64 v;
            memcpy(&v, vals[s->nargs - 1], 8);
            if (!v) break;
        }
        if (g_trace) fprintf(stderr, "x86rt:   %d args (nil-terminated list)\n", s->nargs);
        return;
    }
    u8 (*vals)[VAL_MAX] = alloca((size_t)(s->nargs ? s->nargs : 1) * VAL_MAX);
    x86_read_args(c, s, first_gpr, c->r[RSP] + 8, vals);
    u64 f;
    memcpy(&f, vals[fmt_arg], 8);
    const char *fmt = kind == 1 ? nsstring_utf8(f) : (const char *)(uintptr_t)f;
    add_format_args(s, fmt, kind == 2);
}

/* Call native fn whose arguments are in guest registers/stack per s. The guest return
 * address is on top of the guest stack and is popped here. */
static void call_native(CPU *c, void *fn, const Sig *s0, int sret_rdi, int fmt_arg, int fkind,
                        int override0, u64 val0)
{
    Sig *s = (Sig *)s0;
    if (fkind) {
        s = alloca(sizeof(Sig));
        *s = *s0;
        add_variadics(c, s, sret_rdi, fmt_arg, fkind);
    }
    size_t n = s->nargs ? (size_t)s->nargs : 1;
    u8 (*vals)[VAL_MAX] = alloca(n * VAL_MAX);
    u8 *spill = alloca(n * VAL_MAX);
    u8 *stack = alloca(n * 16 + 64);
    u8 ret[VAL_MAX];
    u64 sret = sret_rdi ? c->r[RDI] : 0;
    x86_read_args(c, s, sret_rdi, c->r[RSP] + 8, vals);
    if (override0) memcpy(vals[0], &val0, 8);
    NC nc;
    memset(&nc, 0, sizeof nc);
    a64_write_args(&nc, s, vals, stack, spill);
    if (a64_ret_in_memory(&s->ret)) nc.x[8] = (u64)(uintptr_t)ret;
    x86_a64_call(fn, &nc);
    a64_read_ret(&nc, &s->ret, ret);
    if (x86_ret_in_memory(&s->ret) && !sret) {
        /* Signature says memory return but the guest did not pass a buffer. */
        x86_trap(c, 0, "memory return without sret");
    }
    x86_write_ret(c, &s->ret, ret, sret);
    c->r[RSP] += 8;
}

/* Unknown signature: integer args in rdi..r9 + 8 stack slots, float args in xmm0-7. */
static void call_native_generic(CPU *c, void *fn)
{
    static const int G[6] = {RDI, RSI, RDX, RCX, R8, R9};
    NC nc;
    memset(&nc, 0, sizeof nc);
    for (int i = 0; i < 6; i++) nc.x[i] = c->r[G[i]];
    u64 sp = c->r[RSP] + 8;
    nc.x[6] = LD64(sp);
    nc.x[7] = LD64(sp + 8);
    u64 stk[8];
    for (int i = 0; i < 8; i++) stk[i] = LD64(sp + 16 + 8 * i);
    nc.stack = (u64)(uintptr_t)stk;
    nc.stack_size = sizeof stk;
    for (int i = 0; i < 8; i++) nc.v[i] = c->x[i];
    x86_a64_call(fn, &nc);
    c->r[RAX] = nc.x[0];
    c->r[RDX] = nc.x[1];
    c->x[0] = nc.v[0];
    c->x[1] = nc.v[1];
    c->r[RSP] += 8;
}

static int safe_read(u64 addr, void *out, size_t n)
{
    vm_size_t got = 0;
    if (addr < 0x1000) return 0;
    return vm_read_overwrite(mach_task_self(), (vm_address_t)addr, n, (vm_address_t)out, &got) == KERN_SUCCESS &&
           got == n;
}

struct BlockLit { void *isa; int flags, reserved; void *invoke; void *desc; };
#define BLOCK_HAS_COPY_DISPOSE (1 << 25)
#define BLOCK_HAS_SIGNATURE (1 << 30)

static const char *block_signature(const struct BlockLit *b)
{
    if (!(b->flags & BLOCK_HAS_SIGNATURE)) return NULL;
    const u64 *d = b->desc;
    int i = 2 + ((b->flags & BLOCK_HAS_COPY_DISPOSE) ? 2 : 0);
    return (const char *)(uintptr_t)d[i];
}

/* ---- ObjC messaging ------------------------------------------------------------- */

static const char *types_from_signature(id self, SEL sel)
{
    NSMethodSignature *ms = nil;
    @try {
        ms = [self methodSignatureForSelector:sel];
    } @catch (id e) {
        ms = nil;
    }
    if (!ms) return NULL;
    NSMutableString *t = [NSMutableString stringWithUTF8String:ms.methodReturnType];
    for (NSUInteger i = 0; i < ms.numberOfArguments; i++) [t appendFormat:@"%s", [ms getArgumentTypeAtIndex:i]];
    /* Interned so the signature cache can key on the pointer. */
    return sel_getName(sel_registerName(t.UTF8String));
}

/* Variadic native methods (their encodings do not say so). */
static int selector_variadic(SEL sel, int *kind)
{
    const char *n = sel_getName(sel);
    size_t l = strlen(n);
    if (l >= 7 && !strcmp(n + l - 7, "Format:")) { *kind = 1; return 1; }
    if ((l >= 8 && !strcmp(n + l - 8, "Objects:")) || (l >= 15 && !strcmp(n + l - 15, "ObjectsAndKeys:"))) {
        *kind = 3;
        return 1;
    }
    return 0;
}

/* NSTextAlignment differs by ABI: x86_64 has Right = 1, Center = 2, arm64 uses the iOS
 * values Center = 1, Right = 2.  Returns 1 for a setter whose first argument is one,
 * 2 for a getter returning one, 0 otherwise.  Other classes reuse these selectors
 * for unrelated enums (NSStackView takes an NSLayoutAttribute), so check the receiver. */
static int text_alignment_kind(id self, SEL sel)
{
    static SEL s_set, s_range, s_get;
    static Class k[4];
    if (!s_set) {
        s_set = @selector(setAlignment:);
        s_range = @selector(setAlignment:range:);
        s_get = @selector(alignment);
        k[0] = objc_getClass("NSCell");
        k[1] = objc_getClass("NSControl");
        k[2] = objc_getClass("NSText");
        k[3] = objc_getClass("NSParagraphStyle");
    }
    if (sel != s_set && sel != s_range && sel != s_get) return 0;
    for (int i = 0; i < 4; i++)
        if ([self isKindOfClass:k[i]]) return sel == s_get ? 2 : 1;
    return 0;
}

static u64 swap_text_alignment(u64 v)
{
    return v == 1 ? 2 : v == 2 ? 1 : v;
}

static void zero_ret(CPU *c)
{
    c->r[RAX] = c->r[RDX] = 0;
    c->x[0] = c->x[1] = (V){0, 0};
}

static void bridge_msgsend(CPU *c, int stret, int super)
{
    u64 a0 = c->r[stret ? RSI : RDI];
    SEL sel = (SEL)(uintptr_t)c->r[stret ? RDX : RSI];
    id self;
    Class cls;
    if (super) {
        u64 *os = (u64 *)(uintptr_t)a0;
        self = (__bridge id)(void *)(uintptr_t)os[0];
        cls = class_getSuperclass((__bridge Class)(void *)(uintptr_t)os[1]);
    } else {
        self = (__bridge id)(void *)(uintptr_t)a0;
        if (!self) {
            zero_ret(c);
            c->r[RSP] += 8;
            return;
        }
        cls = object_getClass(self);
    }
    IMP imp = class_getMethodImplementation(cls, sel);
    int idx = tramp_index((u64)(uintptr_t)imp);
    if (g_trace) fprintf(stderr, "x86rt: msg %s[%s %s]%s\n", super ? "super " : "", class_getName(cls), sel_getName(sel), idx >= 0 ? " (guest)" : "");
    if (idx >= 0) {
        if (super) c->r[stret ? RSI : RDI] = (u64)(uintptr_t)self;
        x86_fn_table[idx](c);
        return;
    }
    Method m = class_getInstanceMethod(cls, sel);
    const char *types = m ? method_getTypeEncoding(m) : NULL;
    if (!types) types = types_from_signature(self, sel);
    if (!types) {
        fprintf(stderr, "x86rt: no signature for -[%s %s]\n", class_getName(cls), sel_getName(sel));
        x86_trap(c, 0, "objc_msgSend without signature");
    }
    Sig *s = sig_for(types);
    if (!s) x86_trap(c, 0, "bad method signature");
    int fk = 0, fa = 0;
    if (selector_variadic(sel, &fk)) {
        Sig *v = alloca(sizeof(Sig));
        *v = *s;
        v->vstart = v->nargs;
        fa = v->nargs - 1;
        call_native(c, (void *)imp, v, stret, fa, fk, super, (u64)(uintptr_t)self);
        return;
    }
    int ta = stret ? 0 : text_alignment_kind(self, sel);
    if (ta == 1) c->r[RDX] = swap_text_alignment(c->r[RDX]);
    call_native(c, (void *)imp, s, stret, 0, 0, super, (u64)(uintptr_t)self);
    if (ta == 2) c->r[RAX] = swap_text_alignment(c->r[RAX]);
}

/* ---- entry points used by lifted code --------------------------------------------- */

void x86_bridge(CPU *c, int idx)
{
    Sig *s = g_import_sig[idx];
    if (g_trace) fprintf(stderr, "x86rt: call %s\n", x86_import_names[idx]);
    if (!s) x86_trap(c, 0, x86_import_names[idx]);
    if (s->special) {
        if (idx == g_idx_msgsend) bridge_msgsend(c, 0, 0);
        else if (idx == g_idx_msgsend_stret) bridge_msgsend(c, 1, 0);
        else if (idx == g_idx_super2) bridge_msgsend(c, 0, 1);
        else if (idx == g_idx_super2_stret) bridge_msgsend(c, 1, 1);
        else if (idx == g_idx_throw) x86_eh_throw(c, (void *)(uintptr_t)c->r[RDI], (const u8 *)(uintptr_t)c->r[RSI], (void *)(uintptr_t)c->r[RDX]);
        else if (idx == g_idx_rethrow) x86_eh_rethrow(c);
        else if (idx == g_idx_resume || idx == g_idx_resume_rethrow) x86_eh_resume(c, (u8 *)(uintptr_t)c->r[RDI]);
        else x86_trap(c, 0, x86_import_names[idx]);
        return;
    }
    int fa = 0, fk = 0;
    if (strchr(x86_import_sigs[idx].sig, '.')) {
        if (variadic_format(x86_import_names[idx], &fa, &fk)) {
            call_native(c, x86_import_sigs[idx].addr, s, x86_ret_in_memory(&s->ret), fa, fk, 0, 0);
            return;
        }
        if (!strcmp(x86_import_names[idx], "_open")) {
            Sig v = *s;
            sig_add_arg(&v, 'q');
            call_native(c, x86_import_sigs[idx].addr, &v, 0, 0, 0, 0, 0);
            return;
        }
    }
    int va = 0;
    if (valist_format(x86_import_names[idx], &fa, &va, &fk)) {
        /* Swap the guest's x86 va_list pointer for an arm64 one built from it; the slots
         * stay alive in this frame for the duration of the call. */
        static const int G[6] = {RDI, RSI, RDX, RCX, R8, R9};
        u64 *slots = alloca((MAX_ARGS + 1) * sizeof(u64));
        u64 f = c->r[G[fa]];
        const char *fmt = fk == 1 ? nsstring_utf8(f) : (const char *)(uintptr_t)f;
        const XVaList *xv = (const XVaList *)(uintptr_t)c->r[G[va]];
        if (xv) {
            valist_convert(xv, fmt, fk, slots, MAX_ARGS);
            c->r[G[va]] = (u64)(uintptr_t)slots;
        }
    }
    call_native(c, x86_import_sigs[idx].addr, s, x86_ret_in_memory(&s->ret), 0, 0, 0, 0);
}

void x86_call_indirect(CPU *c, u64 t)
{
    int idx = tramp_index(t);
    if (idx >= 0) {
        x86_fn_table[idx](c);
        return;
    }
    u64 tb = (u64)(uintptr_t)x86_sec_ptr[g_text];
    if (t >= tb && t < tb + x86_sec_size[g_text]) {
        u64 ga = t - tb + x86_sec_addr[g_text];
        unsigned lo = 0, hi = x86_nfuncs;
        while (lo < hi) {
            unsigned mid = (lo + hi) / 2;
            if (x86_fn_addr[mid] < ga) lo = mid + 1;
            else hi = mid;
        }
        if (lo < x86_nfuncs && x86_fn_addr[lo] == ga) {
            x86_fn_table[lo](c);
            return;
        }
        x86_trap(c, ga, "indirect call into the middle of guest code");
    }
    int imp = import_by_addr(t);
    if (imp >= 0) {
        x86_bridge(c, imp);
        return;
    }
    struct BlockLit b;
    if (safe_read(c->r[RDI], &b, sizeof b) && (u64)(uintptr_t)b.invoke == t) {
        const char *sig = block_signature(&b);
        if (sig) {
            Sig *s = sig_for(sig);
            if (s) {
                call_native(c, (void *)(uintptr_t)t, s, x86_ret_in_memory(&s->ret), 0, 0, 0, 0);
                return;
            }
        }
    }
    if (g_trace) {
        Dl_info di;
        fprintf(stderr, "x86rt: generic native call %p %s\n", (void *)(uintptr_t)t,
                dladdr((void *)(uintptr_t)t, &di) && di.dli_sname ? di.dli_sname : "?");
    }
    call_native_generic(c, (void *)(uintptr_t)t);
}

void x86_jump_indirect(CPU *c) { x86_call_indirect(c, c->jt); }

/* ---- native -> guest ------------------------------------------------------------------ */

void x86_native_entry(u64 idx, NC *f)
{
    CPU *c = x86_cpu();
    CPU save = *c;
    const char *sig = x86_fn_sig[idx];
    if (!sig && x86_fn_isblock[idx] && f->x[0]) sig = block_signature((const struct BlockLit *)(uintptr_t)f->x[0]);
    u64 sp = (c->r[RSP] - 256) & ~15ull;
    Sig *s = sig ? sig_for(sig) : NULL;
    if (g_trace) fprintf(stderr, "x86rt: enter F_%llx %s\n", x86_fn_addr[idx], sig ? sig : "(generic)");
    if (s && !s->special) {
        size_t n = s->nargs ? (size_t)s->nargs : 1;
        u8 (*vals)[VAL_MAX] = alloca(n * VAL_MAX);
        u8 ret[VAL_MAX];
        a64_read_args(f, s, vals);
        u64 sret = 0;
        int mem = x86_ret_in_memory(&s->ret);
        if (mem) {
            sp = (sp - ((s->ret.size + 15) & ~15u)) & ~15ull;
            sret = sp;
            c->r[RDI] = sret;
        }
        sp = x86_write_args(c, s, mem, sp, vals);
        ST64(sp, 0);
        c->r[RSP] = sp;
        x86_fn_table[idx](c);
        x86_read_ret(c, &s->ret, ret, sret);
        a64_write_ret(f, &s->ret, ret);
    } else {
        static const int G[6] = {RDI, RSI, RDX, RCX, R8, R9};
        for (int i = 0; i < 6; i++) c->r[G[i]] = f->x[i];
        for (int i = 0; i < 8; i++) c->x[i] = f->v[i];
        u64 nst[8] = {0};
        u64 top = (u64)(uintptr_t)pthread_get_stackaddr_np(pthread_self());
        for (int i = 0; i < 8; i++)
            if (f->stack + 8 * i + 8 <= top) nst[i] = ((const u64 *)(uintptr_t)f->stack)[i];
        sp -= 8 * 10;
        sp &= ~15ull;
        ST64(sp + 0, f->x[6]);
        ST64(sp + 8, f->x[7]);
        for (int i = 0; i < 8; i++) ST64(sp + 16 + 8 * i, nst[i]);
        sp -= 8;
        ST64(sp, 0);
        c->r[RSP] = sp;
        c->r[RAX] = 8;
        x86_fn_table[idx](c);
        f->x[0] = c->r[RAX];
        f->x[1] = c->r[RDX];
        f->v[0] = c->x[0];
        f->v[1] = c->x[1];
    }
    *c = save;
}

/* ---- startup ------------------------------------------------------------------------ */

static void on_fault(int sig, siginfo_t *si, void *uc)
{
    (void)uc;
    fprintf(stderr, "x86rt: signal %d at %p\n", sig, si->si_addr);
    if (t_cpu) dump_cpu(t_cpu);
    void *bt[64];
    int n = backtrace(bt, 64);
    backtrace_symbols_fd(bt, n, 2);
    signal(sig, SIG_DFL);
    raise(sig);
}

int main(int argc, char **argv, char **envp, char **apple)
{
    x86_init();
    if (getenv("X86RT_FAULTS")) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = on_fault;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        sigaction(SIGILL, &sa, NULL);
    }
    x86_cpu();
    const char *dump = getenv("X86RT_DUMPCLASS");
    if (dump) {
        Class k = objc_getClass(dump);
        for (int meta = 0; k && meta < 2; meta++, k = object_getClass((id)k)) {
            unsigned n = 0;
            Method *ms = class_copyMethodList(k, &n);
            for (unsigned i = 0; i < n; i++) {
                IMP imp = method_getImplementation(ms[i]);
                fprintf(stderr, "%c[%s %s] %s imp=%p tramp=%d\n", meta ? '+' : '-', dump, sel_getName(method_getName(ms[i])),
                        method_getTypeEncoding(ms[i]), (void *)imp, tramp_index((u64)(uintptr_t)imp));
            }
            free(ms);
        }
    }
    for (unsigned i = 0; i < x86_nmodinit; i++) {
        void (*init)(int, char **, char **, char **) = (void (*)(int, char **, char **, char **))(uintptr_t)x86_modinit[i];
        init(argc, argv, envp, apple);
    }
    int (*gmain)(int, char **, char **, char **) =
        (int (*)(int, char **, char **, char **))(uintptr_t)TRAMP(x86_main_index);
    return gmain(argc, argv, envp, apple);
}
