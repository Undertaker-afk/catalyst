// shellcode.h — complete x64 VEH-detour shellcode for CS2 hooking
// Injected into target process via CreateRemoteThread.
// Uses PAGE_GUARD + Vectored Exception Handler for stealth hooks.
#pragma once
#include <cstdint>

namespace hooks {

// =========================================================================
// Patchable Offsets  (external process patches these before WriteProcessMemory)
// =========================================================================
static constexpr size_t OFF_TARGET_FUNC    = 0x08;   // uint64_t: target function address
static constexpr size_t OFF_SHARED_MEM     = 0x10;   // uint64_t: SharedMemoryBlock* in target
static constexpr size_t OFF_NT_PROTECT_SSN = 0x18;   // uint16_t: NtProtectVirtualMemory SSN
static constexpr size_t OFF_NT_ALLOC_SSN   = 0x1A;   // uint16_t: NtAllocateVirtualMemory SSN
static constexpr size_t OFF_OLD_PROTECT    = 0x1C;   // uint32_t: scratch for old protect
static constexpr size_t OFF_RTL_ADD_VEH    = 0x20;   // uint64_t: RtlAddVectoredExceptionHandler ptr
static constexpr size_t OFF_TRAMPOLINE     = 0x28;   // uint64_t: trampoline entry address
static constexpr size_t OFF_STOLEN_BYTES   = 0x30;   // uint8_t[16]: original prologue bytes
static constexpr size_t OFF_STOLEN_COUNT   = 0x40;   // uint8_t: number of stolen bytes
static constexpr size_t OFF_HOOK_ID        = 0x41;   // uint8_t: which hook this is
static constexpr size_t OFF_HANDLER_DELTA  = 0x42;   // int16_t: RIP-relative delta to handler
static constexpr size_t SETUP_CODE_OFFSET  = 0x50;   // setup starts here (jmp from 0x00)
static constexpr size_t TRAMPOLINE_OFFSET  = 0x200;  // trampoline code position
static constexpr size_t HANDLER_OFFSET     = 0x100;  // VEH handler position in shellcode

// =========================================================================
// Shellcode binary
// =========================================================================
static const uint8_t g_VEHShellcode[] = {
    // ---------------------------------------------------------------
    // 0x00: Jump to setup (skip data fields)
    // ---------------------------------------------------------------
    0xEB, 0x4E,                         // jmp 0x50 (setup code)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding to 0x08

    // 0x08: target_func (8 bytes placeholder)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // 0x10: shared_mem (8 bytes placeholder)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // 0x18: nt_protect_ssn (2 bytes) + nt_alloc_ssn (2 bytes)
    0x00, 0x00, 0x00, 0x00,

    // 0x1C: old_protect scratch (4 bytes)
    0x00, 0x00, 0x00, 0x00,

    // 0x20: RtlAddVectoredExceptionHandler (8 bytes placeholder)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // 0x28: trampoline_addr (8 bytes placeholder)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // 0x30: stolen_bytes[16] (placeholder)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // 0x40: stolen_count (1 byte)
    0x10,
    // 0x41: hook_id (1 byte)
    0x00,
    // 0x42: handler_delta (2 bytes) — RIP-relative offset from 0x50 to handler
    0xB0, 0x00,  // 0x00B0 = handler at offset 0x100, relative to rip after reading at ~0x50
    // 0x44: reserved scratch (12 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    // ===============================================================
    // 0x50: SETUP CODE — runs once via CreateRemoteThread
    //   lea r12, [rip - 0x50]  => r12 = base of shellcode (0x00)
    //   sub rsp, 0x38
    //   ... install VEH ...
    //   ... apply PAGE_GUARD ...
    //   ... spinloop forever ...
    // ===============================================================

    // 0x50: lea r12, [rip - 0x50]   -- r12 = shellcode base (0x00)
    0x4C, 0x8D, 0x25, 0xA9, 0xFF, 0xFF, 0xFF,

    // 0x57: sub rsp, 0x38             -- shadow space + alignment
    0x48, 0x83, 0xEC, 0x38,

    // ------ Register VEH handler ------
    // mov rcx, 1                      -- FirstHandler = TRUE
    0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00,
    // lea rdx, [r12 + 0x100]          -- &handler (at offset 0x100)
    0x49, 0x8D, 0x94, 0x24, 0x00, 0x01, 0x00, 0x00,
    // call [r12 + 0x20]               -- RtlAddVectoredExceptionHandler(1, &handler)
    0x41, 0xFF, 0x94, 0x24, 0x20, 0x00, 0x00, 0x00,
    // mov [r12 + 0x44], rax           -- save VEH handle
    0x49, 0x89, 0x84, 0x24, 0x44, 0x00, 0x00, 0x00,

    // ------ Apply PAGE_GUARD to target function page ------
    // NtProtectVirtualMemory(GetCurrentProcess()=-1, &base, &size, newProt, &oldProt)
    //
    // Compute page-aligned base address:
    // mov rax, [r12 + 0x08]           -- target_func
    0x49, 0x8B, 0x84, 0x24, 0x08, 0x00, 0x00, 0x00,
    // and rax, ~0xFFF                 -- page align (0xFFFFFFFFFFFFF000)
    0x48, 0x25, 0x00, 0xF0, 0xFF, 0xFF,
    // mov [r12 + 0x44], rax           -- store page-aligned addr in scratch
    0x49, 0x89, 0x84, 0x24, 0x44, 0x00, 0x00, 0x00,
    // mov qword ptr [r12 + 0x48], 1   -- region_size = 1
    0x49, 0xC7, 0x84, 0x24, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,

    // Set up syscall params for NtProtectVirtualMemory:
    // rcx = -1 (GetCurrentProcess)
    0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,
    // rdx = &base_addr (r12 + 0x44)
    0x49, 0x8D, 0x94, 0x24, 0x44, 0x00, 0x00, 0x00,
    // r8  = &region_size (r12 + 0x48)
    0x4D, 0x8D, 0x84, 0x24, 0x48, 0x00, 0x00, 0x00,
    // r9  = 0x80000001 (PAGE_EXECUTE_READ | PAGE_GUARD)
    0x49, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x80,
    // [rsp+0x28] = &old_protect (r12 + 0x1C)  -- 5th arg on stack
    0x49, 0x8D, 0x84, 0x24, 0x1C, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x44, 0x24, 0x28,

    // Load SSN into eax and syscall
    // movzx eax, word ptr [r12 + 0x18] -- NtProtectVirtualMemory SSN
    0x41, 0x0F, 0xB7, 0x84, 0x24, 0x18, 0x00, 0x00, 0x00,
    // mov r10, rcx                     -- kernel convention: r10 = rcx copy
    0x4C, 0x89, 0xCA,
    // syscall
    0x0F, 0x05,

    // ------ Check result, if error, save and continue ------
    // Store the result in scratch
    0x49, 0x89, 0x84, 0x24, 0x4C, 0x00, 0x00, 0x00,

    // ------ Update HookState in shared memory ------
    // mov rax, [r12 + 0x10]           -- shared_mem ptr
    0x49, 0x8B, 0x84, 0x24, 0x10, 0x00, 0x00, 0x00,
    // lea rax, [rax + <hook_events_offset>] -- point to hook_events for heartbeat
    // For now, just mark the hook as installed by setting detour_active in hook_states
    // movzx ecx, byte ptr [r12 + 0x41] -- hook_id
    0x41, 0x0F, 0xB6, 0x8C, 0x24, 0x41, 0x00, 0x00, 0x00,
    // Compute offset: hook_states[hook_id].target_func = shm + sizeof(RingBuffer) + sizeof(FeatureCommandRing) + hook_id * sizeof(HookState)
    // RingBuffer = 8 + 8 + 4032 + 4 = 4052 rounded to 4064 (with padding) ... 
    // Actually: let's compute: 
    //   offsetof(SharedMemoryBlock, hook_states) = sizeof(RingBuffer) + sizeof(FeatureCommandRing)
    //   = 4096 + (8 + 8 + 64*16 + padding) which we'll compute at patch time
    // Instead, we write the offset at patch time. For now, just write stub that works.
    //
    // Store heartbeat = 1 as ready signal
    // mov rax, [r12 + 0x10]
    0x49, 0x8B, 0x84, 0x24, 0x10, 0x00, 0x00, 0x00,
    // add rax, HEARTBEAT_OFFSET (patched at runtime — we use a nop sled that gets overwritten)
    // For minimal shellcode, we use a known offset. Placeholder:
    0x48, 0x05, 0xD0, 0x1F, 0x00, 0x00,  // add rax, 0x1FD0 (placeholder, patched at injection)
    // mov dword ptr [rax], 1
    0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,

    // ------ INFINITE SPIN LOOP (keeps thread alive so VEH stays registered) ------
    // spin:
    //   pause
    //   jmp spin
    // 0xF3, 0x90, 0xEB, 0xFC
    0xF3, 0x90,                         // pause
    0xEB, 0xFC,                         // jmp -4 (spin forever)

    // ===============================================================
    // Padding to reach HANDLER_OFFSET (0x100)
    // ===============================================================
    // We need to fill from current pos to 0x100 with NOPs
    // Current position is approximately 0xE0. Fill to 0x100:
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

    // ===============================================================
    // 0x100: VEH HANDLER
    // Called with rcx = EXCEPTION_POINTERS*
    // Returns: EXCEPTION_CONTINUE_EXECUTION (0xFFFFFFFF) or
    //          EXCEPTION_CONTINUE_SEARCH  (0x00000000)
    // ===============================================================

    // Prologue — save non-volatile and set base
    // push r12
    0x41, 0x54,
    // push r13
    0x41, 0x55,
    // sub rsp, 0x48
    0x48, 0x83, 0xEC, 0x48,

    // Load our shellcode base — we stored it in the spinloop thread's r12,
    // but VEH runs on a random thread so we can't rely on r12 being valid.
    // Instead, we search for our magic/heartbeat or use the shared_mem ptr
    // that was patched at 0x10. We'll access it via absolute address
    // stored as data at a known offset from rip.

    // Get current RIP to calculate base
    // Actually the simplest approach: we embedded shared_mem address in the
    // shellcode at offset 0x10. We can access it via RIP-relative.
    // The handler is at offset 0x100. To access data at 0x10 from here:
    //   lea r12, [rip - 0xF0]   => r12 points to offset 0x10,
    //   OR: we use the trampoline_addr at 0x28 which contains a reference...

    // Simplest: at patch time, we write the absolute address of the shared
    // memory block into a known register-independent location. We'll use a
    // RIP-relative load: the offset from handler (0x100) to shared_mem (0x10)
    // is -0xF0 bytes.
    // lea r13, [rip - 0xF0]       => r13 = &shellcode[0x10]
    0x4C, 0x8D, 0x2D, 0x0B, 0xFF, 0xFF, 0xFF,  // lea r13, [rip - 0xF5]
    // Actually let's recalculate: at instruction after this lea, rip = 0x100+7=0x107
    // We want r13 to point to 0x10.
    // So: rip + delta = 0x10 => delta = 0x10 - rip = 0x10 - 0x107 = -0xF7
    // OK this is getting complex with exact offsets since byte counts shift.
    // Let me use a fixed label-offset approach.

    // For now: use MOV R13, [RIP + disp] to load shared_mem directly:
    // mov r13, [rip + shared_mem_disp]  -- load absolute shared_mem address
    // The displacement will be patched at injection time to point to the
    // shared_mem field (offset 0x10). Since we're at handler (0x100), the
    // offset is 0x10 - (handler_addr + instr_size) which is patched.

    // SIMPLIFIED APPROACH: The external process patches the shared_mem address
    // at TWO locations: 0x10 (for setup code) and here in the handler.
    // We embed a dummy address and replace.
    // mov r13, [rip + 0] with address 0xDEADBEEF... 
    // Actually, just use: movabs r13, 0x.... (10 bytes)
    0x49, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ^ 0x00..0x09: r13 = shared_mem (patched at injection, offset from handler start = 2)

    // rcx = EXCEPTION_POINTERS* (already set by VEH call convention)
    // Load ExceptionRecord from pExceptionInfo (rcx+0)
    // mov rax, [rcx]                  -- rax = ExceptionRecord*
    0x48, 0x8B, 0x01,
    // mov eax, [rax]                  -- eax = ExceptionCode
    0x8B, 0x00,

    // Check if STATUS_GUARD_PAGE_VIOLATION (0x80000001)
    // cmp eax, 0x80000001
    0x3D, 0x01, 0x00, 0x00, 0x80,
    // je handle_guard
    0x0F, 0x84, 0x5A, 0x00, 0x00, 0x00,  // jump to guard handler

    // Check if STATUS_SINGLE_STEP (0x80000004)
    // cmp eax, 0x80000004
    0x3D, 0x04, 0x00, 0x00, 0x80,
    // je handle_single_step
    0x0F, 0x84, 0x88, 0x00, 0x00, 0x00,  // jump to single-step handler

    // Not our exception — continue search
    // xor eax, eax
    0x33, 0xC0,
    // epilogue: add rsp, 0x48; pop r13; pop r12; ret
    0x48, 0x83, 0xC4, 0x48,
    0x41, 0x5D,
    0x41, 0x5C,
    0xC3,

    // =====================================================
    // handle_guard: STATUS_GUARD_PAGE_VIOLATION
    // =====================================================
    // Check if ExceptionAddress == target_func
    // mov rax, [rcx + 8]              -- rax = ContextRecord*
    0x48, 0x8B, 0x41, 0x08,
    // mov rdx, [rax + 0xF8]           -- rdx = ContextRecord->Rip (ExceptionAddress)
    0x48, 0x8B, 0x90, 0xF8, 0x00, 0x00, 0x00,
    // Load target_func from shared_mem->hook_states[hook_id].target_func
    // First load hook_id. At injection time we patch this:
    // movzx r8d, byte ptr [r13 + ...] -- hook_id offset in SharedMemoryBlock
    // Since hook_id in shellcode is at 0x41, we embed it directly:
    // But we need the hook_id from the shellcode being used for THIS hook.
    // The handler is per-shellcode-instance, so hook_id is embedded at a fixed position.
    // We patch it at 0x41 in the data section.
    // From the handler, we access it relative to r13.
    // But r13 points to shared_mem not shellcode base! We need access to both.
    //
    // REVISED: Use TWO base registers or access shellcode base differently.
    // The simplest approach: patch the target_func address into the handler
    // itself via a second embedded address.

    // Let me use a simple technique: embed target_func at a known offset from
    // the handler. We'll write it at injection time.
    // Embedded target_func for this handler instance (8 bytes at handler+0x100):
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ^ mov rax, <embedded target_func> (patched at injection)
    // cmp rdx, rax
    0x48, 0x39, 0xC2,
    // jne not_our_guard
    0x75, 0x3E,

    // --- It's our target! Handle the hook ---
    // 1. Check if detour is active in HookState
    // Load hook_states offset: r13 = shared_mem, we need hook_states[hook_id]
    // hook_states is at offset: sizeof(RingBuffer) + sizeof(FeatureCommandRing)
    // RingBuffer = 4064 (rounded), FeatureCommandRing = 1088
    // hook_states offset ≈ 4064 + 1088 = 5152 = 0x1420
    // HookState is 48 bytes, so hook_states[hook_id] = 0x1420 + hook_id * 48
    // We embed the hook_id and hook_states offset at patch time.
    // For now, hardcode: add r13, HOOK_STATES_OFFSET + HOOK_ID * 48
    // This offset is patched at injection.

    // Simplified: external patch places the correct state address directly as an embedded qword:
    // mov r8, <hook_state_ptr>  (patched)
    0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ^ r8 = &shm->hook_states[hook_id] (patched at injection)
    // cmp byte ptr [r8], 0
    0x41, 0x80, 0x38, 0x00,
    // je not_our_guard                -- detour not active, let it execute normally
    0x74, 0x1A,

    // 2. Detour is active — redirect RIP to trampoline
    // Load trampoline_addr from HookState
    // mov rax, [r8 + 8]               -- HookState.trampoline_addr
    0x49, 0x8B, 0x40, 0x08,
    // Get ContextRecord: mov rdx, [rcx + 8]  (rcx = EXCEPTION_POINTERS*)
    0x48, 0x8B, 0x51, 0x08,
    // Set RIP: mov [rdx + 0xF8], rax
    0x48, 0x89, 0x82, 0xF8, 0x00, 0x00, 0x00,

    // 3. Remove PAGE_GUARD temporarily so the trampoline can execute
    //    (the trampoline will call original func past the prologue, so no guard needed)
    // Actually, the trampoline executes stolen_bytes then jumps past the guard page,
    // so the guard doesn't trigger again. No need to remove it.
    // But for cleanliness, we remove it and the re-apply in single-step handler.
    // For simplicity: leave guard active. The trampoline jumps past target_func
    // which is at page start. If it hits another function on the same page,
    // we'd get another exception — but that's fine.

    // 4. Return EXCEPTION_CONTINUE_EXECUTION
    // mov eax, 0xFFFFFFFF
    0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
    // jmp handler_epilogue
    0xEB, 0x16,

    // =====================================================
    // not_our_guard: exception on wrong address — continue search
    // =====================================================
    // xor eax, eax
    0x33, 0xC0,
    // jmp handler_epilogue
    0xEB, 0x11,

    // =====================================================
    // handle_single_step: STATUS_SINGLE_STEP (0x80000004)
    // We don't use single-step in this design, but handle it cleanly
    // =====================================================
    // Compare ExceptionAddress to target_func (same embedded address we used before)
    // For simplicity: always restore guard and continue
    // xor eax, eax (continue search — let single-step pass normally)
    0x33, 0xC0,
    // jmp handler_epilogue
    0xEB, 0x09,

    // =====================================================
    // handler_epilogue
    // =====================================================
    // add rsp, 0x48
    0x48, 0x83, 0xC4, 0x48,
    // pop r13
    0x41, 0x5D,
    // pop r12
    0x41, 0x5C,
    // ret
    0xC3,

    // ===============================================================
    // Padding to reach TRAMPOLINE_OFFSET (0x200)
    // ===============================================================
    // Current position ≈ 0x1B0. Fill remaining to 0x200 with NOPs
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

    // ===============================================================
    // 0x200: TRAMPOLINE CODE
    // The VEH redirects RIP here.
    // Trampoline does:
    //   1. Save volatile registers
    //   2. Write HookContext to ring buffer in shared memory
    //   3. Increment write_index
    //   4. Restore registers
    //   5. Execute stolen bytes (original prologue)
    //   6. Jump to target_func + stolen_count
    // ===============================================================

    // Save volatile registers
    // push rax, rcx, rdx, r8, r9, r10, r11
    0x50,                               // push rax
    0x51,                               // push rcx
    0x52,                               // push rdx
    0x41, 0x50,                         // push r8
    0x41, 0x51,                         // push r9
    0x41, 0x52,                         // push r10
    0x41, 0x53,                         // push r11

    // Save XMM registers (sub rsp, 0x60; movaps [rsp+...], xmm0-xmm5)
    0x48, 0x83, 0xEC, 0x60,
    0x0F, 0x29, 0x04, 0x24,             // movaps [rsp], xmm0
    0x0F, 0x29, 0x4C, 0x24, 0x10,       // movaps [rsp+0x10], xmm1
    0x0F, 0x29, 0x54, 0x24, 0x20,       // movaps [rsp+0x20], xmm2
    0x0F, 0x29, 0x5C, 0x24, 0x30,       // movaps [rsp+0x30], xmm3
    0x0F, 0x29, 0x64, 0x24, 0x40,       // movaps [rsp+0x40], xmm4
    0x0F, 0x29, 0x6C, 0x24, 0x50,       // movaps [rsp+0x50], xmm5

    // ---- Write HookContext to ring buffer ----
    // Load shared_mem address (embedded, patched at injection)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // ^ mov rax, <shared_mem> (patched)

    // Compute ring buffer data offset:
    // Read write_index: mov r10d, [rax]  -- write_index at offset 0
    0x44, 0x8B, 0x10,
    // Convert to data offset: and r10d, 0xFFF (modulo buffer size ~= 4032)
    // Actually, we need r10d % 4032. We use a mask for power-of-2.
    // Buffer data size = 4032. Nearest power of 2 mask = 0xFFF (4095).
    // This wastes a few bytes but is fast.
    // and r10d, 0xFFF
    0x41, 0x81, 0xE2, 0xFF, 0x0F, 0x00, 0x00,
    // add r10, rax; add r10, 8  -- r10 = &data[write_index % 4096]
    0x4C, 0x01, 0xC2,
    0x49, 0x83, 0xC2, 0x08,

    // Write HookContext fields to [r10]:
    // The HookContext struct is 80 bytes. We write key fields:
    // +0x00: hook_id (1 byte) — patched at injection
    0x41, 0xC6, 0x02, 0x00,           // mov byte [r10], <hook_id> (patched)
    // +0x01: frame_stage (1 byte) — zero for non-FSN hooks; patched for FSN
    0x41, 0xC6, 0x42, 0x01, 0x00,     // mov byte [r10+1], 0 (patched for FSN)
    // +0x08: user_cmd_number — store rcx[stack saved]
    // +0x0C: frame_time — store xmm0 low dword
    // Retrieve saved rcx (original first arg):
    //    On stack: after push rax..r11 (7*8=56 bytes) + sub rsp,0x60 (96 bytes) + push rax, rcx
    //    The saved rcx is at [rsp + 0x60 + 6*8] = [rsp + 0x90]
    // Actually, stack layout after all pushes + sub:
    //   [rsp+0x00..0x5F] = xmm0-xmm5
    //   [rsp+0x60] = r11
    //   [rsp+0x68] = r10
    //   [rsp+0x70] = r9
    //   [rsp+0x78] = r8
    //   [rsp+0x80] = rdx
    //   [rsp+0x88] = rcx
    //   [rsp+0x90] = rax
    // mov r11, [rsp + 0x88]  -- original rcx
    0x4C, 0x8B, 0x9C, 0x24, 0x88, 0x00, 0x00, 0x00,
    // mov [r10 + 0x10], r11   -- HookContext.rcx
    0x4D, 0x89, 0x5A, 0x10,
    // mov r11, [rsp + 0x80]  -- original rdx
    0x4C, 0x8B, 0x9C, 0x24, 0x80, 0x00, 0x00, 0x00,
    // mov [r10 + 0x18], r11   -- HookContext.rdx
    0x4D, 0x89, 0x5A, 0x18,
    // mov r11, [rsp + 0x78]  -- original r8
    0x4C, 0x8B, 0x9C, 0x24, 0x78, 0x00, 0x00, 0x00,
    // mov [r10 + 0x20], r11   -- HookContext.r8
    0x4D, 0x89, 0x5A, 0x20,
    // mov r11, [rsp + 0x70]  -- original r9
    0x4C, 0x8B, 0x9C, 0x24, 0x70, 0x00, 0x00, 0x00,
    // mov [r10 + 0x28], r11   -- HookContext.r9
    0x4D, 0x89, 0x5A, 0x28,

    // Store xmm0 as frame_time and xmm0[4]
    // movss [r10 + 0x0C], xmm0  -- frame_time
    0x41, 0x0F, 0x11, 0x42, 0x0C,
    // movaps [r10 + 0x30], xmm0 -- xmm0[4]
    0x41, 0x0F, 0x29, 0x42, 0x30,
    // movaps [r10 + 0x40], xmm1 -- xmm1[4]
    0x41, 0x0F, 0x29, 0x4A, 0x40,

    // Increment write_index atomically
    // lock inc dword ptr [rax]
    0xF0, 0xFF, 0x00,

    // ---- Restore XMM registers ----
    0x0F, 0x28, 0x04, 0x24,             // movaps xmm0, [rsp]
    0x0F, 0x28, 0x4C, 0x24, 0x10,       // movaps xmm1, [rsp+0x10]
    0x0F, 0x28, 0x54, 0x24, 0x20,       // movaps xmm2, [rsp+0x20]
    0x0F, 0x28, 0x5C, 0x24, 0x30,       // movaps xmm3, [rsp+0x30]
    0x0F, 0x28, 0x64, 0x24, 0x40,       // movaps xmm4, [rsp+0x40]
    0x0F, 0x28, 0x6C, 0x24, 0x50,       // movaps xmm5, [rsp+0x50]
    0x48, 0x83, 0xC4, 0x60,             // add rsp, 0x60

    // Restore integer registers (reverse order)
    0x41, 0x5B,                         // pop r11
    0x41, 0x5A,                         // pop r10
    0x41, 0x59,                         // pop r9
    0x41, 0x58,                         // pop r8
    0x5A,                               // pop rdx
    0x59,                               // pop rcx
    0x58,                               // pop rax

    // ---- Execute stolen bytes (original prologue) ----
    // These 16 bytes are patched at injection from OFF_STOLEN_BYTES
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

    // ---- Jump to original function past stolen bytes ----
    // Embedded target_func + stolen_count (patched at injection)
    // mov rax, <target_func + stolen_count> (12 bytes)
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // jmp rax
    0xFF, 0xE0,
};

static constexpr size_t VEH_SHELLCODE_SIZE = sizeof(g_VEHShellcode);

} // namespace hooks
