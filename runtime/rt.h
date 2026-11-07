/* Runtime internals shared by the ABI marshaller and the bridge layer. */
#ifndef RT_H
#define RT_H
#include "x86.h"

/* Native arm64 register/stack image used for both call directions. */
typedef struct NC {
    u64 x[9];   /* x0-x7, x8 (indirect result) */
    u64 stack;  /* native stack args: caller's sp (entry) or buffer (call) */
    V v[8];     /* q0-q7 */
    u64 stack_size;
    u64 _pad;
} NC;

/* One scalar piece of a value: byte offset, size, class ('i' int, 'f' float, 'd' double). */
typedef struct Leaf { u16 off; u8 size; u8 cls; } Leaf;

#define MAX_LEAF 16
#define MAX_ARGS 96
#define VAL_MAX 256

typedef struct TI {
    u32 size, align;
    char kind;   /* 'v' void, 'i' integer/pointer, 'f', 'd', 's' aggregate, 'D' long double */
    u8 sgn;      /* signed small integer */
    u8 nleaf;
    u8 bad;      /* layout could not be determined exactly */
    Leaf leaf[MAX_LEAF];
} TI;

typedef struct Sig {
    TI ret;
    int nargs;
    int vstart;  /* index of first variadic argument, or nargs if none */
    int special; /* '!' imports */
    TI args[MAX_ARGS];
} Sig;

int sig_parse(const char *enc, Sig *s);
const char *type_parse(const char *p, TI *t);
void sig_add_arg(Sig *s, char kind);

/* Guest (x86-64 SysV) side. */
void x86_read_args(CPU *c, const Sig *s, int first_gpr, u64 stack, u8 (*vals)[VAL_MAX]);
u64 x86_write_args(CPU *c, const Sig *s, int first_gpr, u64 sp, u8 (*vals)[VAL_MAX]);
int x86_ret_in_memory(const TI *t);
void x86_write_ret(CPU *c, const TI *t, const u8 *val, u64 sret);
void x86_read_ret(CPU *c, const TI *t, u8 *val, u64 sret);

/* Native (arm64 Apple) side. */
void a64_write_args(NC *nc, const Sig *s, u8 (*vals)[VAL_MAX], u8 *stackbuf, u8 *spill);
void a64_read_args(const NC *nc, const Sig *s, u8 (*vals)[VAL_MAX]);
int a64_ret_in_memory(const TI *t);
void a64_read_ret(const NC *nc, const TI *t, u8 *val);
void a64_write_ret(NC *nc, const TI *t, const u8 *val);

void x86_a64_call(void *fn, NC *nc);

/* Guest C++ exceptions (eh.c). */
void x86_eh_throw(CPU *c, void *obj, const u8 *tinfo, void *dtor) __attribute__((noreturn));
void x86_eh_rethrow(CPU *c) __attribute__((noreturn));
void x86_eh_resume(CPU *c, u8 *ue) __attribute__((noreturn));

/* Bridge layer. */
CPU *x86_cpu(void);
void x86_init(void);
extern const unsigned x86_nfuncs;
extern const xfn x86_fn_table[];
extern const u64 x86_fn_addr[];
extern const char *const x86_fn_sig[];
extern const u8 x86_fn_isblock[];
extern const unsigned x86_nimports;
extern const char *const x86_import_names[];
typedef struct ImportSig { void *addr; const char *sig; } ImportSig;
extern const ImportSig x86_import_sigs[];
extern const unsigned x86_nsecs;
extern u8 *const x86_sec_ptr[];
extern const u64 x86_sec_addr[];
extern const u64 x86_sec_size[];
extern const char *const x86_sec_name[];
extern const int x86_main_index;
extern u64 *const x86_modinit;
extern const unsigned x86_nmodinit;
extern u8 x86tramp_end[];

static inline int tramp_index(u64 a)
{
    u64 lo = (u64)(uintptr_t)x86tramp;
    if (a >= lo && a < lo + 8ull * x86_nfuncs && ((a - lo) & 7) == 0) return (int)((a - lo) >> 3);
    return -1;
}

#endif
