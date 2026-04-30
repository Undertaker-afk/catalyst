; syscall_stub.asm — x64 direct syscall gate for the hook system
; Compile with: ml64.exe /c syscall_stub.asm
.CODE
PUBLIC syscall_gate

; uint64_t syscall_gate(
;     uint16_t ssn,        ; rcx = syscall number
;     uint64_t rcx_arg,    ; rdx = kernel arg1
;     uint64_t rdx_arg,    ; r8  = kernel arg2
;     uint64_t r8_arg,     ; r9  = kernel arg3
;     uint64_t r9_arg,     ; [rsp+0x28] = kernel arg4
;     uint64_t r10_arg,    ; [rsp+0x30] = kernel arg5
;     uint64_t r12_arg,    ; [rsp+0x38] = kernel arg6
;     uint64_t r13_arg     ; [rsp+0x40] = kernel arg7
; )
;
; Kernel x64 syscall convention:
;   rax = SSN
;   r10 = rcx (copy of first arg, typically the SSN or handle)
;   rcx = arg1 (often ProcessHandle)
;   rdx = arg2
;   r8  = arg3
;   r9  = arg4
;   stack = arg5..argN at [rsp+0x28], [rsp+0x30], etc.
;
; Our wrapper convention:
;   Caller passes SSN in rcx, args in rdx, r8, r9, and stack
;   We need to:
;     1. Save SSN (rcx) into eax
;     2. Copy original arg1 (rdx) into rcx
;     3. Leave rdx, r8, r9 as-is (they are already arg2, arg3, arg4)
;     4. Stack args 5-7 come from caller's [rsp+0x28..0x40]
;        But wait: after our function's prologue, the caller's stack frame
;        shifted. Args 5-7 from the caller's perspective are:
;        caller's [rsp+0x28] = our [rsp+0x28] (shadow space offset)
;        Actually the caller puts them on their own stack.
;        At our entry: rsp points to our return address.
;        Caller's stack frame: [rsp+8] was caller's top.
;        The 5th arg (kernel r9) = our [rsp+0x28]
;        The 6th arg (kernel stack+0x28) = our [rsp+0x30]
;        The 7th arg (kernel stack+0x30) = our [rsp+0x38]
;        The 8th arg (kernel stack+0x38) = our [rsp+0x40]
;
; Kernel expects after syscall instruction:
;   shadow space at [rsp+0x00..0x27] for the kernel to use
;   args at [rsp+0x28], [rsp+0x30], etc.

syscall_gate PROC
    ; SSN is in rcx (our first param). Save it.
    mov     r10, rcx            ; r10 = SSN
    mov     eax, r10d           ; eax = SSN (low 32 bits)

    ; Move caller's arg1 (rdx) into kernel's rcx
    mov     rcx, rdx            ; rcx = original arg1

    ; rdx stays (already kernel arg2)
    ; r8  stays (already kernel arg3)
    ; r9  stays (already kernel arg4)

    ; Args 5-8 are already on the stack at the right offsets
    ; because the caller placed them at [rsp+0x28], [rsp+0x30], etc.
    ; and we haven't modified the stack.

    syscall
    ret
syscall_gate ENDP

END
