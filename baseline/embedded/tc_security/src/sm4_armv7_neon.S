/* ARMv7-A/R SM4 round core. The NEON load/store path handles endian
 * conversion while scalar ARM instructions execute the nonlinear rounds.
 * Runtime dispatch in sm4.c calls this file only when NEON is available. */

    .syntax unified
    .arch armv7-a
    .fpu neon
    .arm
    .text
    .align 2
    .extern tcsec_sm4_sbox

    .macro SM4_ROUND
    ldr     r0, [r6], #4
    eor     r0, r0, r8
    eor     r0, r0, r9
    eor     r0, r0, r10

    mov     r1, r0, lsr #24
    ldrb    r1, [r4, r1]
    mov     r1, r1, lsl #24
    ubfx    r2, r0, #16, #8
    ldrb    r2, [r4, r2]
    orr     r1, r1, r2, lsl #16
    ubfx    r3, r0, #8, #8
    ldrb    r3, [r4, r3]
    orr     r1, r1, r3, lsl #8
    uxtb    r12, r0
    ldrb    r12, [r4, r12]
    orr     r0, r1, r12

    eor     r1, r0, r0, ror #30
    eor     r1, r1, r0, ror #22
    eor     r1, r1, r0, ror #14
    eor     r1, r1, r0, ror #8
    eor     r12, r7, r1
    mov     r7, r8
    mov     r8, r9
    mov     r9, r10
    mov     r10, r12
    .endm

    .macro SM4_FUNCTION name, decrypt
    .global \name
    .type \name, %function
\name:
    push    {r4-r11, lr}
    mov     r5, r1
    mov     r6, r2
    ldr     r4, =tcsec_sm4_sbox
    vld1.8  {q0}, [r0]
    vrev32.8 q0, q0
    vmov    r7, r8, d0
    vmov    r9, r10, d1
    .if \decrypt
    add     r6, r6, #124
    .endif
    mov     r11, #32
1:
    .if \decrypt
    SM4_ROUND
    sub     r6, r6, #8
    .else
    SM4_ROUND
    .endif
    subs    r11, r11, #1
    bne     1b
    vmov    d0, r10, r9
    vmov    d1, r8, r7
    vrev32.8 q0, q0
    vst1.8  {q0}, [r5]
    pop     {r4-r11, pc}
    .size \name, .-\name
    .endm

    SM4_FUNCTION tcsec_sm4_armv7_neon_encrypt, 0
    SM4_FUNCTION tcsec_sm4_armv7_neon_decrypt, 1

    .section .note.GNU-stack,"",%progbits
