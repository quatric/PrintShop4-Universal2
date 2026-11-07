// Native <-> guest transition stubs.
//
// NC frame layout (see rt.h): x[0..8] at 0, stack pointer/buffer at 72,
// v[0..7] at 80, stack size at 208; 224 bytes reserved.

.text
.p2align 2

// Entered from _x86tramp with x16 = function index, native arm64 arguments live.
.globl _x86_tramp_common
_x86_tramp_common:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    sub sp, sp, #224
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    str x8, [sp, #64]
    add x9, x29, #16
    str x9, [sp, #72]
    stp q0, q1, [sp, #80]
    stp q2, q3, [sp, #112]
    stp q4, q5, [sp, #144]
    stp q6, q7, [sp, #176]
    mov x0, x16
    mov x1, sp
    bl _x86_native_entry
    ldp x0, x1, [sp, #0]
    ldp q0, q1, [sp, #80]
    ldp q2, q3, [sp, #112]
    mov sp, x29
    ldp x29, x30, [sp], #16
    ret

// void x86_a64_call(void *fn, NC *nc): call fn with registers/stack from nc,
// store x0, x1, q0-q3 back into nc.
.globl _x86_a64_call
_x86_a64_call:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    mov x19, x1
    mov x20, x0
    ldr x9, [x19, #208]
    sub sp, sp, x9
    ldr x10, [x19, #72]
    mov x11, #0
1:  cmp x11, x9
    b.hs 2f
    ldr x12, [x10, x11]
    str x12, [sp, x11]
    add x11, x11, #8
    b 1b
2:  ldp q0, q1, [x19, #80]
    ldp q2, q3, [x19, #112]
    ldp q4, q5, [x19, #144]
    ldp q6, q7, [x19, #176]
    ldp x0, x1, [x19, #0]
    ldp x2, x3, [x19, #16]
    ldp x4, x5, [x19, #32]
    ldp x6, x7, [x19, #48]
    ldr x8, [x19, #64]
    blr x20
    stp x0, x1, [x19, #0]
    stp q0, q1, [x19, #80]
    stp q2, q3, [x19, #112]
    mov sp, x29
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
