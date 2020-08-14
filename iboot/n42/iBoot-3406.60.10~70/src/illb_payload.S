	.text

.pool
@ illb offsets for iBoot-3406.60.10 on n42
.set BASE_ADDR, 0xbfe00000
.set PAYLOAD_BASE_ADDR, 0xbfe47900
.set PAYLOAD_PTR, 0x41414141
.set PAYLOAD_SZ, 0x42424242
.set RSA_CHECK, 0x1621a
.set DEBUG_ENABLED, 0x16b62
.set HOOK_PAYLOAD_1, 0x1765c
.set HOOK_PAYLOAD_2, 0x17660
.set BOOTARGS, 0x17aa0
.set BOOT_MODE, 0x1e1b0

.set PATCH_VAL_1, 0xf0304630
.set PATCH_VAL_2, 0x2800f94f
.set NEW_BOOTARGS_PTR, 0xbff479a1

.set INSN2_MOV_R0_0__STR_R0_R3, 0x60182000
.set INSN2_MOV_R0_1__MOV_R0_1, 0x20012001

	.syntax	unified

	.arm
_entry:
	b	_entry

    .org    0x9ba
    .thumb
    .thumb_func
_jump_back:
    bx    lr

	.org	0x13f04
	.thumb
	.thumb_func
_hook_back_orig:
	bx	lr

	.org	0x233a0
	.global	_payload
	.thumb
	.thumb_func

_payload:
    bl  _hook_back_orig
    mov r8, r0

_patch_iboot: @ v1.1
    ldr r2, =BASE_ADDR
    ldr r0, =RSA_CHECK
    ldr r1, =INSN2_MOV_R0_0__STR_R0_R3
    str r1, [r0, r2]

    ldr r0, =DEBUG_ENABLED
    ldr r1, =INSN2_MOV_R0_1__MOV_R0_1
    str r1, [r0, r2]

    ldr r0, =HOOK_PAYLOAD_1
    ldr r1, =PATCH_VAL_1
    str r1, [r0, r2]

    ldr r0, =HOOK_PAYLOAD_2
    ldr r1, =PATCH_VAL_2
    str r1, [r0, r2]

    ldr r0, =BOOTARGS
    ldr r1, =NEW_BOOTARGS_PTR
    str r1, [r0, r2]

_copy_loop_init:
    ldr r1, =PAYLOAD_BASE_ADDR
    ldr r2, =PAYLOAD_PTR
    movs r3, #0
_copy_loop:
    ldr r0, [r2]
    str r0, [r1]
    adds r3, #0x4
    ldr r0, =PAYLOAD_SZ
    adds r1, #4
    adds r2, #4
    cmp r3, r0
    bne.n _copy_loop

_back_to_orig:
    mov r0, r8
    b   _jump_back

	.align	2
