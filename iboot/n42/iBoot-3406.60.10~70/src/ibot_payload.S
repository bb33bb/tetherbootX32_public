	.text

.pool
@ kernel offsets for xnu-3789.70.16~21 on n42
.set addr1, 0x2990c
.set val1, 0xee1de007
.set addr2, 0x101098
.set val2, 0x100f040
.set addr3, 0x1020e0
.set val3, 0xe0400f40
.set addr4, 0x2d7cd4
.set val4, 0xf552bf00
.set addr5, 0x36eb60
.set val5, 0x20012001
.set addr6, 0x3b9ea5
.set val6, 0x64626a2e
.set addr7, 0x7934cc
.set val7, 0xe03a2604
.set addr8, 0x7b210c
.set val8, 0x8001946f
.set addr9, 0xc7b04c
.set val9, 0x80cca195
.set addr10, 0xf6b8da
.set val10, 0xbf00bf00
.set addr11, 0x1025e92
.set val11, 0xbf00e014

	.syntax	unified

	.arm
_entry:
	b	_entry

    .org    0x17cb4
    .thumb
    .thumb_func
_jump_back:
    bx    lr

	.org	0x47900
	.global	_payload
	.thumb
	.thumb_func

_payload:               @ kernel patch
    ldr r1, =addr1      @ convert_port_to_locked_task
    ldr r2, =val1       @ if (task == kernel_task && ..) -> if(0)
    str r2, [r0, r1]

    ldr r1, =addr2      @ nosuid
    ldr r2, =val2       @ orr r1, r0, #0x8 -> orr r1, r0, #0x0
    str r2, [r0, r1]

    ldr r1, =addr3      @ mount_common
    ldr r2, =val3       @ if((flags & MNT_RDONLY) == 0) -> if(0)
    str r2, [r0, r1]

    ldr r1, =addr4      @ task_for_pid(0)
    ldr r2, =val4       @ if (pid == 0) -> if(0)
    str r2, [r0, r1]

    ldr r1, =addr5      @ _PE_i_can_has_debugger
    ldr r2, =val5       @ always return 1
    str r2, [r0, r1]

    ldr r1, =addr6      @ "/sbin/launchd" str
    ldr r2, =val6       @ "/sbin/launchd" -> "/.jbd/launchd"
    str r2, [r0, r1]

    ldr r1, =addr7      @ substrate patch
    ldr r2, =val7       @ movs r6, #0x4 -> movs r6, #0x0
    str r2, [r0, r1]

    ldr r1, =addr8      @ AMFI call to memcmp
    ldr r2, =val8       @ replace with bx lr gadget
    str r2, [r0, r1]

    ldr r1, =addr9      @ _mapForIO lock
    ldr r2, =val9       @ change PE_I_can_has_kernel_configuration call and jumping over partition->isWriteProtected check
    str r2, [r0, r1]

    ldr r1, =addr10     @ mpo_cred_label_update_execve
    ldr r2, =val10      @ NOP out
    str r2, [r0, r1]

    ldr r1, =addr11     @ gasgauge entitlement check
    ldr r2, =val11      
    str r2, [r0, r1]

    b   _jump_back

	.align	2
