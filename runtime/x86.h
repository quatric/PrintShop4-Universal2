/* Support header for statically recompiled x86_64 code. */
#ifndef X86_H
#define X86_H
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <setjmp.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef __uint128_t u128;
typedef __int128_t s128;

typedef u64 V __attribute__((vector_size(16)));
typedef float f32x4 __attribute__((vector_size(16)));
typedef double f64x2 __attribute__((vector_size(16)));
typedef s32 i32x4 __attribute__((vector_size(16)));
typedef u32 u32x4 __attribute__((vector_size(16)));
typedef s64 i64x2 __attribute__((vector_size(16)));
typedef u64 u64x2 __attribute__((vector_size(16)));
typedef s16 i16x8 __attribute__((vector_size(16)));
typedef u16 u16x8 __attribute__((vector_size(16)));
typedef s8 i8x16 __attribute__((vector_size(16)));
typedef u8 u8x16 __attribute__((vector_size(16)));

/* Guest CPU state shared between recompiled functions and bridges. */
typedef struct CPU {
    u64 r[16]; /* rax rcx rdx rbx rsp rbp rsi rdi r8..r15 */
    V x[16];
    u8 CF, ZF, SF, OF, PF, _pad[3];
    /* x87 register stack, kept as doubles. */
    double st[8];
    int ftop;
    u32 mxcsr;
    u64 fs_base, gs_base;
    u64 jt; /* indirect jump/call target */
    /* runtime private */
    void *thread;
    u64 stack_lo, stack_hi;
    int depth;
    struct XF *eh; /* innermost guest frame with landing pads */
} CPU;

/* Guest exception tables (from the LSDA) and per-call frame records. */
typedef struct EHAct { s32 filter; s32 indirect; const u8 *type; } EHAct;
typedef struct EHSite { s32 lp; u32 act; u32 nact; } EHSite;
typedef struct EHFunc { const EHSite *sites; const EHAct *acts; u32 nsites; u64 fstart; } EHFunc;
typedef struct XF {
    jmp_buf jb;
    struct XF *next;
    const EHFunc *f;
    s32 cs, lp;
    u64 r[6]; /* rbx rbp r12 r13 r14 r15 at the call site */
    u64 rsp, exc, sel;
} XF;
static inline void x86_eh_push(struct CPU *c, XF *x, const EHFunc *f) { x->next = c->eh; x->f = f; x->cs = -1; c->eh = x; }
static inline void x86_eh_pop(struct CPU *c, XF *x) { c->eh = x->next; }

enum { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 };

typedef void (*xfn)(CPU *);

/* Guest sections, relinked as native symbols x86s_<k> (declared in funcs.h). */
#define S(k, d) ((u64)(uintptr_t)x86s_##k + (u64)(d))
/* Native trampolines, one per recompiled function (8 bytes each). */
extern u8 x86tramp[];
#define TRAMP(i) ((u64)(uintptr_t)x86tramp + (u64)(i) * 8)

/* Unaligned, alias-safe memory access. */
typedef u16 u16u __attribute__((aligned(1), may_alias));
typedef u32 u32u __attribute__((aligned(1), may_alias));
typedef u64 u64u __attribute__((aligned(1), may_alias));
typedef u8 u8u __attribute__((may_alias));
typedef V Vu __attribute__((aligned(1), may_alias));
typedef float f32u __attribute__((aligned(1), may_alias));
typedef double f64u __attribute__((aligned(1), may_alias));

#define LD8(a) (*(volatile u8u *)(uintptr_t)(a))
#define LD16(a) (*(u16u *)(uintptr_t)(a))
#define LD32(a) (*(u32u *)(uintptr_t)(a))
#define LD64(a) (*(u64u *)(uintptr_t)(a))
#define LDV(a) (*(Vu *)(uintptr_t)(a))
#define ST8(a, v) (*(u8u *)(uintptr_t)(a) = (u8)(v))
#define ST16(a, v) (*(u16u *)(uintptr_t)(a) = (u16)(v))
#define ST32(a, v) (*(u32u *)(uintptr_t)(a) = (u32)(v))
#define ST64(a, v) (*(u64u *)(uintptr_t)(a) = (u64)(v))
#define STV(a, v) (*(Vu *)(uintptr_t)(a) = (v))
#undef LD8
#define LD8(a) (*(u8u *)(uintptr_t)(a))

static inline u8 parity8(u64 v) { return !__builtin_parity((u32)(v & 0xff)); }

/* Vector lane helpers. */
static inline float vf(V v, int i) { return ((f32x4)v)[i]; }
static inline double vd(V v, int i) { return ((f64x2)v)[i]; }
static inline u32 vu32(V v, int i) { return ((u32x4)v)[i]; }
static inline u64 vu64(V v, int i) { return ((u64x2)v)[i]; }
static inline V setf(V v, int i, float f) { f32x4 t = (f32x4)v; t[i] = f; return (V)t; }
static inline V setd(V v, int i, double d) { f64x2 t = (f64x2)v; t[i] = d; return (V)t; }
static inline V setu32(V v, int i, u32 x) { u32x4 t = (u32x4)v; t[i] = x; return (V)t; }
static inline V setu64(V v, int i, u64 x) { u64x2 t = (u64x2)v; t[i] = x; return (V)t; }
static inline V vzero(void) { return (V){0, 0}; }
static inline V fromf(float f) { f32x4 t = {f, 0, 0, 0}; return (V)t; }
static inline V fromd(double d) { f64x2 t = {d, 0}; return (V)t; }
static inline V fromu32(u32 x) { u32x4 t = {x, 0, 0, 0}; return (V)t; }
static inline V fromu64(u64 x) { u64x2 t = {x, 0}; return (V)t; }
static inline float u2f(u32 x) { float f; memcpy(&f, &x, 4); return f; }
static inline double u2d(u64 x) { double f; memcpy(&f, &x, 8); return f; }
static inline u32 f2u(float f) { u32 x; memcpy(&x, &f, 4); return x; }
static inline u64 d2u(double f) { u64 x; memcpy(&x, &f, 8); return x; }

/* x86 float->int conversions return the "integer indefinite" value on overflow/NaN. */
static inline s32 cvtt_f2i32(double d) { return (d >= -2147483648.0 && d < 2147483648.0) ? (s32)d : (s32)0x80000000; }
static inline s64 cvtt_f2i64(double d) { return (d >= -9223372036854775808.0 && d < 9223372036854775808.0) ? (s64)d : (s64)0x8000000000000000LL; }
static inline s32 cvt_f2i32(double d) { return cvtt_f2i32(nearbyint(d)); }
static inline s64 cvt_f2i64(double d) { return cvtt_f2i64(nearbyint(d)); }

/* x86 min/max return the second operand when either is NaN or both are zero. */
static inline float minssf(float a, float b) { return a < b ? a : b; }
static inline float maxssf(float a, float b) { return a > b ? a : b; }
static inline double minsdf(double a, double b) { return a < b ? a : b; }
static inline double maxsdf(double a, double b) { return a > b ? a : b; }

static inline double round_mode(double d, int imm)
{
    switch (imm & 3) {
    case 0: return nearbyint(d);
    case 1: return floor(d);
    case 2: return ceil(d);
    default: return trunc(d);
    }
}
static inline float round_modef(float d, int imm)
{
    switch (imm & 3) {
    case 0: return nearbyintf(d);
    case 1: return floorf(d);
    case 2: return ceilf(d);
    default: return truncf(d);
    }
}

static inline V pshufd(V v, int imm)
{
    u32x4 s = (u32x4)v, r;
    r[0] = s[imm & 3]; r[1] = s[(imm >> 2) & 3]; r[2] = s[(imm >> 4) & 3]; r[3] = s[(imm >> 6) & 3];
    return (V)r;
}
static inline V shufps(V a, V b, int imm)
{
    u32x4 s = (u32x4)a, t = (u32x4)b, r;
    r[0] = s[imm & 3]; r[1] = s[(imm >> 2) & 3]; r[2] = t[(imm >> 4) & 3]; r[3] = t[(imm >> 6) & 3];
    return (V)r;
}
static inline V shufpd(V a, V b, int imm)
{
    u64x2 s = (u64x2)a, t = (u64x2)b, r;
    r[0] = s[imm & 1]; r[1] = t[(imm >> 1) & 1];
    return (V)r;
}
static inline V pshuflw(V v, int imm)
{
    u16x8 s = (u16x8)v, r = s;
    for (int i = 0; i < 4; i++) r[i] = s[(imm >> (2 * i)) & 3];
    return (V)r;
}
static inline V pshufb(V a, V b)
{
    u8x16 s = (u8x16)a, m = (u8x16)b, r;
    for (int i = 0; i < 16; i++) r[i] = (m[i] & 0x80) ? 0 : s[m[i] & 15];
    return (V)r;
}
static inline V insertps(V d, V s, int imm)
{
    u32x4 dd = (u32x4)d, ss = (u32x4)s;
    dd[(imm >> 4) & 3] = ss[(imm >> 6) & 3];
    for (int i = 0; i < 4; i++) if (imm & (1 << i)) dd[i] = 0;
    return (V)dd;
}
static inline V blendps(V a, V b, int imm)
{
    u32x4 x = (u32x4)a, y = (u32x4)b;
    for (int i = 0; i < 4; i++) if (imm & (1 << i)) x[i] = y[i];
    return (V)x;
}
static inline V blendpd(V a, V b, int imm)
{
    u64x2 x = (u64x2)a, y = (u64x2)b;
    for (int i = 0; i < 2; i++) if (imm & (1 << i)) x[i] = y[i];
    return (V)x;
}
static inline V pblendw(V a, V b, int imm)
{
    u16x8 x = (u16x8)a, y = (u16x8)b;
    for (int i = 0; i < 8; i++) if (imm & (1 << i)) x[i] = y[i];
    return (V)x;
}
static inline V blendvps(V a, V b, V m)
{
    i32x4 mm = (i32x4)m;
    u32x4 x = (u32x4)a, y = (u32x4)b;
    for (int i = 0; i < 4; i++) if (mm[i] < 0) x[i] = y[i];
    return (V)x;
}
static inline V blendvpd(V a, V b, V m)
{
    i64x2 mm = (i64x2)m;
    u64x2 x = (u64x2)a, y = (u64x2)b;
    for (int i = 0; i < 2; i++) if (mm[i] < 0) x[i] = y[i];
    return (V)x;
}
static inline V unpcklps(V a, V b) { u32x4 x = (u32x4)a, y = (u32x4)b; return (V)(u32x4){x[0], y[0], x[1], y[1]}; }
static inline V unpckhps(V a, V b) { u32x4 x = (u32x4)a, y = (u32x4)b; return (V)(u32x4){x[2], y[2], x[3], y[3]}; }
static inline V unpcklpd(V a, V b) { return (V){a[0], b[0]}; }
static inline V unpckhpd(V a, V b) { return (V){a[1], b[1]}; }
static inline V punpcklbw(V a, V b)
{
    u8x16 x = (u8x16)a, y = (u8x16)b, r;
    for (int i = 0; i < 8; i++) { r[2 * i] = x[i]; r[2 * i + 1] = y[i]; }
    return (V)r;
}
static inline V punpcklwd(V a, V b)
{
    u16x8 x = (u16x8)a, y = (u16x8)b, r;
    for (int i = 0; i < 4; i++) { r[2 * i] = x[i]; r[2 * i + 1] = y[i]; }
    return (V)r;
}
static inline V movhlps(V a, V b) { return (V){b[1], a[1]}; }
static inline V movlhps(V a, V b) { return (V){a[0], b[0]}; }
static inline V movshdup(V a) { u32x4 x = (u32x4)a; return (V)(u32x4){x[1], x[1], x[3], x[3]}; }
static inline V movsldup(V a) { u32x4 x = (u32x4)a; return (V)(u32x4){x[0], x[0], x[2], x[2]}; }
static inline V haddpd(V a, V b) { f64x2 x = (f64x2)a, y = (f64x2)b; return (V)(f64x2){x[0] + x[1], y[0] + y[1]}; }
static inline V addsubpd(V a, V b) { f64x2 x = (f64x2)a, y = (f64x2)b; return (V)(f64x2){x[0] - y[0], x[1] + y[1]}; }
static inline V phaddd(V a, V b) { u32x4 x = (u32x4)a, y = (u32x4)b; return (V)(u32x4){x[0] + x[1], x[2] + x[3], y[0] + y[1], y[2] + y[3]}; }
static inline V pslldq(V a, int n)
{
    u8x16 x = (u8x16)a, r = {0};
    if (n > 15) return vzero();
    for (int i = n; i < 16; i++) r[i] = x[i - n];
    return (V)r;
}
static inline V psrldq(V a, int n)
{
    u8x16 x = (u8x16)a, r = {0};
    if (n > 15) return vzero();
    for (int i = 0; i + n < 16; i++) r[i] = x[i + n];
    return (V)r;
}
static inline u32 pmovmskb(V a)
{
    u8x16 x = (u8x16)a;
    u32 r = 0;
    for (int i = 0; i < 16; i++) r |= (u32)(x[i] >> 7) << i;
    return r;
}
static inline u32 movmskps(V a)
{
    u32x4 x = (u32x4)a;
    return (x[0] >> 31) | ((x[1] >> 31) << 1) | ((x[2] >> 31) << 2) | ((x[3] >> 31) << 3);
}
static inline u32 movmskpd(V a) { return (u32)(a[0] >> 63) | (u32)((a[1] >> 63) << 1); }

/* SSE compare predicate (cmpps imm / cmpXXss) -> all-ones mask. */
static inline int fcmp_pred(double a, double b, int p)
{
    switch (p & 7) {
    case 0: return a == b;
    case 1: return a < b;
    case 2: return a <= b;
    case 3: return a != a || b != b;
    case 4: return !(a == b);
    case 5: return !(a < b);
    case 6: return !(a <= b);
    default: return a == a && b == b;
    }
}

/* x87 stack helpers (values kept as double). */
#define FST(i) (c->st[(c->ftop + (i)) & 7])
static inline void fpush(CPU *c, double v) { c->ftop = (c->ftop - 1) & 7; c->st[c->ftop] = v; }
static inline double fpop(CPU *c) { double v = c->st[c->ftop]; c->ftop = (c->ftop + 1) & 7; return v; }
static inline double ld80(u64 a)
{
    u64 mant = LD64(a);
    u16 se = LD16(a + 8);
    int sign = se >> 15, exp = se & 0x7fff;
    if (exp == 0 && mant == 0) return sign ? -0.0 : 0.0;
    if (exp == 0x7fff) return (mant << 1) ? NAN : (sign ? -INFINITY : INFINITY);
    double d = ldexp((double)mant, exp - 16383 - 63);
    return sign ? -d : d;
}
static inline void st80(u64 a, double d)
{
    u64 mant = 0;
    u16 se = 0;
    if (d != d) { mant = 0xC000000000000000ULL; se = 0x7fff; }
    else if (isinf(d)) { mant = 0x8000000000000000ULL; se = 0x7fff | (d < 0 ? 0x8000 : 0); }
    else if (d != 0) {
        int e;
        double m = frexp(fabs(d), &e); /* m in [0.5,1) */
        mant = (u64)ldexp(m, 64);
        se = (u16)((e - 1 + 16383) | (d < 0 ? 0x8000 : 0));
    } else if (signbit(d)) se = 0x8000;
    ST64(a, mant);
    ST16(a + 8, se);
}

/* Runtime entry points used by recompiled code. */
void x86_call_indirect(CPU *c, u64 target);
void x86_jump_indirect(CPU *c); /* target in c->jt */
void x86_bridge(CPU *c, int import_index);
void x86_trap(CPU *c, u64 addr, const char *why) __attribute__((noreturn));
void x86_bad_jump(CPU *c, u64 from, u64 target) __attribute__((noreturn));
void x86_rep_movs(CPU *c, int size);
void x86_rep_stos(CPU *c, int size);
u64 x86_rdtsc(void);

#define MUSTTAIL __attribute__((musttail))

#endif
