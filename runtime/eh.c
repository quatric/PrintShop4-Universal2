/* Guest C++ exceptions: throw/rethrow/resume dispatched over setjmp frame records.
 *
 * Exceptions are allocated by the native __cxa_allocate_exception; the header is
 * filled the way libc++abi's __cxa_throw would, so native __cxa_begin_catch,
 * __cxa_end_catch and __cxa_current_exception_type keep working. */
#include "rt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Offsets from the _Unwind_Exception header (it sits 32 bytes before the object). */
#define UE_FROM_OBJ(o) ((u8 *)(o) - 32)
#define H_REFCOUNT(ue) (*(u64 *)((ue) - 88))
#define H_TYPE(ue) (*(const u8 **)((ue) - 80))
#define H_DTOR(ue) (*(void **)((ue) - 72))
#define H_UNEXPECTED(ue) (*(void **)((ue) - 64))
#define H_TERMINATE(ue) (*(void **)((ue) - 56))
#define H_HANDLERS(ue) (*(int *)((ue) - 40))
#define H_SWITCH(ue) (*(int *)((ue) - 36))
#define H_ADJUSTED(ue) (*(void **)((ue) - 8))
#define UE_CLASS(ue) (*(u64 *)(ue))
#define UE_CLEANUP(ue) (*(void **)((ue) + 8))
#define CXX_CLASS 0x434C4E47432B2B00ull

extern char ZTV_class[] __asm("__ZTVN10__cxxabiv117__class_type_infoE");
extern char ZTV_si[] __asm("__ZTVN10__cxxabiv120__si_class_type_infoE");
extern char ZTV_vmi[] __asm("__ZTVN10__cxxabiv121__vmi_class_type_infoE");
extern char ZTV_ptr[] __asm("__ZTVN10__cxxabiv119__pointer_type_infoE");
extern void *__cxa_get_globals(void);
extern void *std_get_terminate(void) __asm("__ZSt13get_terminatev");
extern void *std_get_unexpected(void) __asm("__ZSt14get_unexpectedv");
extern void std_terminate(void) __asm("__ZSt9terminatev");

static const char *ti_name(const u8 *ti)
{
    u64 n = *(const u64 *)(ti + 8);
    return (const char *)(uintptr_t)(n & ~(1ull << 63));
}

static int ti_equal(const u8 *a, const u8 *b)
{
    return a == b || strcmp(ti_name(a), ti_name(b)) == 0;
}

static const u8 *ti_vptr(const u8 *ti) { return *(const u8 *const *)ti; }

/* Find catch type `want` among the public bases of `have` for object *obj (adjusting it). */
static int find_base(const u8 *have, const u8 *want, void **obj)
{
    if (ti_equal(have, want)) return 1;
    const u8 *vp = ti_vptr(have);
    if (vp == (const u8 *)ZTV_si + 16) {
        return find_base(*(const u8 *const *)(have + 16), want, obj);
    }
    if (vp == (const u8 *)ZTV_vmi + 16) {
        u32 n = *(const u32 *)(have + 20);
        for (u32 i = 0; i < n; i++) {
            const u8 *bt = *(const u8 *const *)(have + 24 + 16 * i);
            long of = *(const long *)(have + 32 + 16 * i);
            if (!(of & 2)) continue; /* not public */
            long off = of >> 8;
            void *sub = *obj;
            if (sub) {
                if (of & 1) off = *(const long *)(*(const u8 *const *)sub + off);
                sub = (u8 *)sub + off;
            }
            if (find_base(bt, want, &sub)) {
                *obj = sub;
                return 1;
            }
        }
    }
    return 0;
}

/* Does a catch clause of type `ct` catch an exception of type `tt` (object at *adj)? */
static int can_catch(const u8 *ct, const u8 *tt, void **adj)
{
    if (!ct) return 1;
    if (ti_equal(ct, tt)) return 1;
    if (ti_vptr(ct) == (const u8 *)ZTV_ptr + 16 && ti_vptr(tt) == (const u8 *)ZTV_ptr + 16) {
        const u8 *cp = *(const u8 *const *)(ct + 24), *tp = *(const u8 *const *)(tt + 24);
        void *p = *(void **)*adj;
        if (!strcmp(ti_name(cp), "v")) { *adj = p; return 1; }
        if (find_base(tp, cp, &p)) { *adj = p; return 1; }
        return 0;
    }
    void *o = *adj;
    if (find_base(tt, ct, &o)) { *adj = o; return 1; }
    return 0;
}

static const u8 *act_type(const EHAct *a)
{
    if (!a->type) return NULL;
    return a->indirect ? *(const u8 *const *)a->type : a->type;
}

/* Selector of the first matching handler in frame x, 0 for cleanup-only, -1 for none. */
static int frame_action(XF *x, u8 *ue, int want_catch, void **adj_out)
{
    if (x->cs < 0) return -2; /* call site not covered: std::terminate */
    const EHSite *s = &x->f->sites[x->cs];
    if (s->lp < 0) return -1;
    if (s->nact == 0) return want_catch ? -1 : 0;
    int cleanup = 0;
    for (u32 i = 0; i < s->nact; i++) {
        const EHAct *a = &x->f->acts[s->act + i];
        if (a->filter > 0) {
            void *adj = ue + 32;
            const u8 *tt = H_TYPE(ue);
            if (can_catch(act_type(a), tt, &adj)) {
                if (adj_out) *adj_out = adj;
                return a->filter;
            }
        } else if (a->filter == 0) {
            cleanup = 1;
        }
    }
    if (!want_catch && cleanup) return 0;
    return -1;
}

static void uncaught(u8 *ue)
{
    const u8 *tt = H_TYPE(ue);
    fprintf(stderr, "x86rt: uncaught guest C++ exception of type %s\n", tt ? ti_name(tt) : "?");
    std_terminate();
    abort();
}

/* Search from frame `from` and transfer control to the first landing pad that applies. */
static void __attribute__((noreturn)) dispatch(CPU *c, XF *from, u8 *ue)
{
    XF *x;
    int found = 0;
    for (x = from; x; x = x->next) {
        int r = frame_action(x, ue, 1, NULL);
        if (r == -2) break;
        if (r > 0) { found = 1; break; }
    }
    if (!found) uncaught(ue);
    for (x = from; x; x = x->next) {
        void *adj = NULL;
        int r = frame_action(x, ue, 0, &adj);
        if (r < 0) continue;
        if (r > 0) {
            H_SWITCH(ue) = r;
            H_ADJUSTED(ue) = adj;
        }
        x->exc = (u64)(uintptr_t)ue;
        x->sel = (u64)(s64)r;
        x->lp = x->f->sites[x->cs].lp;
        c->eh = x;
        _longjmp(x->jb, 1);
    }
    uncaught(ue);
    __builtin_unreachable();
}

void x86_eh_throw(CPU *c, void *obj, const u8 *tinfo, void *dtor)
{
    if (getenv("X86RT_TRACE")) fprintf(stderr, "x86rt: throw %s\n", tinfo ? ti_name(tinfo) : "?");
    u8 *ue = UE_FROM_OBJ(obj);
    H_REFCOUNT(ue) = 1;
    H_TYPE(ue) = tinfo;
    H_DTOR(ue) = dtor;
    H_UNEXPECTED(ue) = std_get_unexpected();
    H_TERMINATE(ue) = std_get_terminate();
    UE_CLASS(ue) = CXX_CLASS;
    struct { void *caught; unsigned uncaught; } *g = __cxa_get_globals();
    g->uncaught++;
    dispatch(c, c->eh, ue);
}

void x86_eh_rethrow(CPU *c)
{
    struct { u8 *caught; unsigned uncaught; } *g = __cxa_get_globals();
    if (!g->caught) std_terminate();
    u8 *ue = g->caught + 96;
    if (H_HANDLERS(ue) > 0) H_HANDLERS(ue) = -H_HANDLERS(ue);
    g->uncaught++;
    dispatch(c, c->eh, ue);
}

void x86_eh_resume(CPU *c, u8 *ue)
{
    /* The frame that ran the cleanup is innermost; continue past it. */
    XF *x = c->eh;
    dispatch(c, x ? x->next : NULL, ue);
}
