// hook_manager.cpp — full HookManager implementation
#include "hook_manager.hpp"
#include <algorithm>

namespace hooks {

HookManager& HookManager::Instance() {
    static HookManager inst;
    return inst;
}

HookManager::~HookManager() {
    Shutdown();
}

// =========================================================================
// Initialize
// =========================================================================
bool HookManager::Initialize(HANDLE hProcess) {
    m_hProcess = hProcess;
    m_pid = GetProcessId(hProcess);

    // Resolve syscalls
    SyscallResolver::Instance().Initialize();

    // Create shared memory (local + remote)
    if (!m_shm.Create(m_hProcess)) {
        return false;
    }

    // Pre-cache module bases
    GetModuleBase("client.dll");
    GetModuleBase("engine2.dll");
    GetModuleBase("materialsystem2.dll");
    GetModuleBase("scenesystem.dll");

    return true;
}

// =========================================================================
// Shutdown
// =========================================================================
void HookManager::Shutdown() {
    m_running.store(false);
    if (m_poll_thread.joinable()) {
        m_poll_thread.join();
    }
    RemoveAllHooks();
    m_shm.Close();
    m_hProcess = nullptr;
    m_pid = 0;
}

// =========================================================================
// InstallHook (by ID)
// =========================================================================
bool HookManager::InstallHook(uint8_t hook_id, bool enable_detour, HookCallback callback) {
    auto* pattern = patterns::FindPatternByHookID(hook_id);
    if (!pattern) return false;
    return InstallHook(*pattern, enable_detour, callback);
}

// =========================================================================
// InstallHook (by pattern)
// =========================================================================
bool HookManager::InstallHook(const patterns::HookPattern& pattern, bool enable_detour,
                               HookCallback callback) {
    if (!m_hProcess) return false;

    // 1. Get module base
    uintptr_t module_base = GetModuleBase(pattern.module);
    if (!module_base) return false;

    // 2. Scan for target function
    uintptr_t target_func = ScanPattern(module_base, pattern.bytes, pattern.mask);
    if (!target_func) return false;

    // 3. Read stolen bytes
    InstalledHook hook{};
    hook.hook_id = pattern.hook_id;
    hook.target_func = target_func;
    hook.callback = std::move(callback);
    hook.detour_active = enable_detour;

    if (!StealBytes(target_func, hook.stolen_bytes, hook.stolen_count)) {
        return false;
    }

    // 4. Allocate code cave in target process
    size_t cave_size = VEH_SHELLCODE_SIZE + 0x200;
    hook.code_cave = FindCodeCave(module_base, cave_size);
    if (!hook.code_cave) {
        // Fallback: allocate fresh memory
        hook.code_cave = AllocateMemory(cave_size, PAGE_EXECUTE_READWRITE);
        if (!hook.code_cave) return false;
    }

    hook.trampoline_addr = hook.code_cave + TRAMPOLINE_OFFSET;

    // 5. Prepare and patch shellcode
    std::vector<uint8_t> shellcode_buf(cave_size, 0x90);
    if (!PrepareShellcode(shellcode_buf.data(), cave_size, hook)) {
        if (hook.code_cave != FindCodeCave(module_base, cave_size)) {
            FreeMemory(hook.code_cave);
        }
        return false;
    }

    // 6. Write shellcode to target process
    DWORD oldProt = 0;
    VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(hook.code_cave),
                     cave_size, PAGE_EXECUTE_READWRITE, &oldProt);
    if (!WriteMemory(hook.code_cave, shellcode_buf.data(), cave_size)) {
        return false;
    }
    VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(hook.code_cave),
                     cave_size, oldProt, &oldProt);

    // 7. Update HookState in shared memory
    auto* block = m_shm.LocalBlock();
    auto& state = block->hook_states[hook.hook_id];
    state.detour_active = enable_detour ? 1 : 0;
    state.trampoline_addr = hook.trampoline_addr;
    state.target_func = hook.target_func;
    memcpy(state.stolen_bytes, hook.stolen_bytes, hook.stolen_count);
    state.stolen_count = hook.stolen_count;

    // Sync to remote
    WriteMemory(m_shm.RemoteAddr(), block, sizeof(SharedMemoryBlock));

    // 8. Execute shellcode (install VEH + PAGE_GUARD)
    if (!ExecuteShellcode(hook.code_cave)) {
        // Shellcode execution failed, clean up
        WriteMemory(hook.code_cave, nullptr, 0); // nop
        if (hook.code_cave != FindCodeCave(module_base, cave_size)) {
            FreeMemory(hook.code_cave);
        }
        return false;
    }

    // 9. Store installed hook
    {
        std::unique_lock lock(m_hooks_mutex);
        m_installed_hooks.push_back(hook);
    }

    return true;
}

// =========================================================================
// RemoveHook
// =========================================================================
void HookManager::RemoveHook(uint8_t hook_id) {
    std::unique_lock lock(m_hooks_mutex);

    auto it = std::find_if(m_installed_hooks.begin(), m_installed_hooks.end(),
        [hook_id](const InstalledHook& h) { return h.hook_id == hook_id; });

    if (it == m_installed_hooks.end()) return;

    // Restore page protection on target function
    DWORD oldProt = 0;
    VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(it->target_func),
                     1, PAGE_EXECUTE_READ, &oldProt);

    // Restore original bytes (optional but clean)
    WriteMemory(it->target_func, it->stolen_bytes, it->stolen_count);

    // Free code cave
    FreeMemory(it->code_cave);

    // Clear hook state in shared memory
    auto* block = m_shm.LocalBlock();
    block->hook_states[hook_id] = {};
    WriteMemory(m_shm.RemoteAddr(), block, sizeof(SharedMemoryBlock));

    m_installed_hooks.erase(it);
}

// =========================================================================
// RemoveAllHooks
// =========================================================================
void HookManager::RemoveAllHooks() {
    std::unique_lock lock(m_hooks_mutex);
    auto hooks = std::move(m_installed_hooks);
    lock.unlock();

    for (auto& hook : hooks) {
        DWORD oldProt = 0;
        VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(hook.target_func),
                         1, PAGE_EXECUTE_READ, &oldProt);
        WriteMemory(hook.target_func, hook.stolen_bytes, hook.stolen_count);
        FreeMemory(hook.code_cave);
    }

    auto* block = m_shm.LocalBlock();
    for (int i = 0; i < HOOK_COUNT; ++i) {
        block->hook_states[i] = {};
    }
    WriteMemory(m_shm.RemoteAddr(), block, sizeof(SharedMemoryBlock));
}

// =========================================================================
// SetDetourActive
// =========================================================================
void HookManager::SetDetourActive(uint8_t hook_id, bool active) {
    {
        std::shared_lock lock(m_hooks_mutex);
        auto it = std::find_if(m_installed_hooks.begin(), m_installed_hooks.end(),
            [hook_id](const InstalledHook& h) { return h.hook_id == hook_id; });
        if (it != m_installed_hooks.end()) {
            it->detour_active = active;
        }
    }

    auto* block = m_shm.LocalBlock();
    block->hook_states[hook_id].detour_active = active ? 1 : 0;
    WriteMemory(m_shm.RemoteAddr(), block, sizeof(SharedMemoryBlock));
}

// =========================================================================
// IsHookActive
// =========================================================================
bool HookManager::IsHookActive(uint8_t hook_id) const {
    std::shared_lock lock(m_hooks_mutex);
    return std::any_of(m_installed_hooks.begin(), m_installed_hooks.end(),
        [hook_id](const InstalledHook& h) { return h.hook_id == hook_id; });
}

// =========================================================================
// SendCommand
// =========================================================================
void HookManager::SendCommand(uint8_t hook_id, uint8_t cmd, uint16_t p16, uint32_t p32,
                               float f0, float f1, float f2, float f3) {
    auto* block = m_shm.LocalBlock();
    auto& ring = block->commands;

    uint32_t w = ring.cmd_write_index.load(std::memory_order_relaxed);
    uint32_t r = ring.cmd_read_index.load(std::memory_order_acquire);

    // Check if ring is full
    if (((w + 1) & 0xF) == (r & 0xF)) return;

    auto& fc = ring.commands[w & 0xF];
    fc.hook_id = hook_id;
    fc.command = cmd;
    fc.param16 = p16;
    fc.param32 = p32;
    fc.param_f[0] = f0;
    fc.param_f[1] = f1;
    fc.param_f[2] = f2;
    fc.param_f[3] = f3;

    ring.cmd_write_index.store((w + 1) & 0xF, std::memory_order_release);

    // Sync to remote
    uintptr_t cmd_offset = offsetof(SharedMemoryBlock, commands);
    WriteMemory(m_shm.RemoteAddr() + cmd_offset, &ring, sizeof(FeatureCommandRing));
}

// =========================================================================
// StartPolling (not in header but available)
// =========================================================================
void HookManager::ProcessEvents() {
    if (!m_hProcess || !m_shm.LocalBlock()) return;

    // Read remote shared memory block
    SharedMemoryBlock remote_block{};
    if (!ReadMemory(m_shm.RemoteAddr(), &remote_block, sizeof(SharedMemoryBlock)))
        return;

    auto& rb = remote_block.hook_events;
    uint32_t local_read = m_shm.LocalBlock()->hook_events.read_index.load(std::memory_order_relaxed);
    uint32_t remote_write = rb.write_index.load(std::memory_order_relaxed);

    // Process new events
    while (local_read != remote_write) {
        // Read HookContext from remote ring buffer
        uint32_t data_off = local_read % sizeof(rb.data);
        // Ensure we don't read past buffer
        uint32_t available = sizeof(rb.data) - data_off;
        uint32_t ctx_size = sizeof(HookContext);
        if (available < ctx_size) {
            // Wraps around — read in two parts (simplified: skip for now)
            break;
        }

        // Read HookContext from remote data at the calculated offset
        HookContext ctx{};
        uintptr_t ctx_addr = m_shm.RemoteAddr() +
            offsetof(SharedMemoryBlock, hook_events) +
            offsetof(RingBuffer, data) + data_off;

        if (!ReadMemory(ctx_addr, &ctx, sizeof(HookContext))) break;

        if (ctx.hook_id < HOOK_COUNT) {
            // Dispatch to registered callback
            std::shared_lock lock(m_hooks_mutex);
            for (auto& hook : m_installed_hooks) {
                if (hook.hook_id == ctx.hook_id && hook.callback) {
                    hook.callback(ctx.hook_id, ctx);
                    break;
                }
            }
        }

        local_read++;
    }

    // Update local read index
    m_shm.LocalBlock()->hook_events.read_index.store(local_read, std::memory_order_release);
}

// =========================================================================
// PollThread
// =========================================================================
void HookManager::PollThread() {
    while (m_running.load(std::memory_order_relaxed)) {
        ProcessEvents();
        // Check remote command ring for responses
        // (If shellcode writes commands back, process them)
        Sleep(1);
    }
}

// =========================================================================
// ScanPattern
// =========================================================================
uintptr_t HookManager::ScanPattern(uintptr_t module_base,
                                    const std::vector<uint8_t>& pattern,
                                    const std::string& mask) {
    size_t module_size = GetModuleSize(module_base);
    if (!module_size || module_size > 128 * 1024 * 1024) return 0;

    std::vector<uint8_t> buffer(module_size);
    if (!ReadMemory(module_base, buffer.data(), module_size))
        return 0;

    for (size_t i = 0; i <= module_size - pattern.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return module_base + i;
    }
    return 0;
}

// =========================================================================
// GetModuleSize
// =========================================================================
size_t HookManager::GetModuleSize(uintptr_t module_base) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    size_t size = 0;

    if (Module32First(hSnap, &me)) {
        do {
            if (reinterpret_cast<uintptr_t>(me.modBaseAddr) == module_base) {
                size = me.modBaseSize;
                break;
            }
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
    return size;
}

// =========================================================================
// StealBytes
// =========================================================================
bool HookManager::StealBytes(uintptr_t target_func, uint8_t* out_bytes, uint8_t& out_count) {
    // Read 16 bytes from the target function entry
    uint8_t buf[16] = {};
    if (!ReadMemory(target_func, buf, sizeof(buf)))
        return false;

    // For CS2 x64 functions, the typical prologue is:
    //   mov [rsp+...], reg   (5 bytes) — 48 89 xx xx xx
    //   push reg             (1-2 bytes)
    //   sub rsp, imm         (4-7 bytes)
    // We need at least 14 bytes for a full detour jump.
    // Simple approach: take exactly 16 bytes.
    memcpy(out_bytes, buf, 16);
    out_count = 16;
    return true;
}

// =========================================================================
// PrepareShellcode
// =========================================================================
bool HookManager::PrepareShellcode(uint8_t* buf, size_t buf_size, const InstalledHook& hook) {
    if (buf_size < VEH_SHELLCODE_SIZE) return false;

    // Copy the template shellcode
    memcpy(buf, g_VEHShellcode, VEH_SHELLCODE_SIZE);

    // Patch data fields
    uintptr_t shared_mem_remote = m_shm.RemoteAddr();
    uint16_t nt_protect_ssn = SyscallResolver::Instance().Resolve("NtProtectVirtualMemory");
    uint16_t nt_alloc_ssn  = SyscallResolver::Instance().Resolve("NtAllocateVirtualMemory");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    uintptr_t rtl_add_veh = reinterpret_cast<uintptr_t>(
        GetProcAddress(hNtdll, "RtlAddVectoredExceptionHandler"));
    if (!rtl_add_veh) return false;

    memcpy(buf + OFF_TARGET_FUNC,    &hook.target_func, 8);
    memcpy(buf + OFF_SHARED_MEM,     &shared_mem_remote, 8);
    memcpy(buf + OFF_NT_PROTECT_SSN, &nt_protect_ssn, 2);
    memcpy(buf + OFF_NT_ALLOC_SSN,   &nt_alloc_ssn, 2);
    memcpy(buf + OFF_RTL_ADD_VEH,    &rtl_add_veh, 8);
    memcpy(buf + OFF_TRAMPOLINE,     &hook.trampoline_addr, 8);
    memcpy(buf + OFF_STOLEN_BYTES,   hook.stolen_bytes, 16);
    buf[OFF_STOLEN_COUNT] = hook.stolen_count;
    buf[OFF_HOOK_ID] = hook.hook_id;

    // Compute handler delta: handler at offset 0x100, setup at 0x50
    // The VEH registration lea rdx instruction is at offset 0x57+7=0x5E
    // After that instruction, rip = code_cave + 0x5E + 7 = code_cave + 0x65
    // We want rdx = code_cave + 0x100
    // So delta = 0x100 - 0x65 = 0x9B
    // Actually the lea rdx is: 49 8D 94 24 00 01 00 00 (lea rdx, [r12+0x100])
    // This uses r12 as base (set to code_cave at setup start), adding 0x100
    // So the handler_offset at 0x42 is used for something else — the VEH registration
    // uses the embedded offset 0x100 directly.
    // The handler_delta at 0x42 is for RIP-relative handler references within the handler itself.
    int16_t handler_delta = static_cast<int16_t>(HANDLER_OFFSET - 0x50);
    memcpy(buf + OFF_HANDLER_DELTA, &handler_delta, 2);

    // Patch the handler's embedded target_func (at handler offset 0x1D from handler start?)
    // Actually in the shellcode, the handler uses:
    //   48 B8 <target_func> (10 bytes at handler + 0x42)
    // Let's patch it: from the handler start (0x100), the target_func embed is at 0x100 + 0x42 = 0x142
    uintptr_t handler_target_offset = 0x100 + 0x29; // approximate, based on our encoding
    // The shellcode's handler has: 48 B8 xx xx xx xx xx xx xx xx at offset ~0x129
    // Let's compute: after the "48 B8" opcode at handler+0x29, we write target_func
    memcpy(buf + handler_target_offset + 2, &hook.target_func, 8);

    // Patch the handler's embedded shared_mem reference
    // At handler+0x02: 49 BD <shared_mem> (mov r13, ...)
    memcpy(buf + 0x100 + 2 + 2, &shared_mem_remote, 8); // opcode is 2 bytes + 2 offset

    // Patch the handler's embedded hook_state ptr
    // At handler+0x5A (approx): 49 B8 <hook_state_ptr>
    uintptr_t hook_state_offset = m_shm.RemoteAddr() +
        offsetof(SharedMemoryBlock, hook_states) +
        hook.hook_id * sizeof(HookState);
    // Find the "49 B8" pattern in handler region and patch:
    uintptr_t handler_hook_state_offset = 0x100 + 0x55; // approximate
    memcpy(buf + handler_hook_state_offset + 2, &hook_state_offset, 8);

    // Patch the trampoline's shared_mem reference
    // At trampoline (0x200), the "48 B8 <shared_mem>" is at trampoline+0x3A
    uintptr_t tramp_shared_mem_offset = 0x200 + 0x3A;
    memcpy(buf + tramp_shared_mem_offset + 2, &shared_mem_remote, 8);

    // Patch the trampoline's hook_id field (at +0x3A+10+2 = +0x46 from trampoline)
    // Actually the "mov byte [r10], hook_id" instruction. Let's find it:
    // 41 C6 02 00 — we need to change the last byte to hook id
    uintptr_t tramp_hookid_offset = 0x200 + 0x4E; // mov byte [r10], <hook_id>
    buf[tramp_hookid_offset + 3] = hook.hook_id;

    // Patch the trampoline's stolen bytes (16 NOPs at trampoline + 0x120 approx)
    // After all the save/restore + ring buffer write, the stolen bytes are at:
    uintptr_t tramp_stolen_offset = 0x200 + 0x132; // approximate
    memcpy(buf + tramp_stolen_offset, hook.stolen_bytes, hook.stolen_count);

    // Patch the trampoline's target_func + stolen_count jump address
    // "48 B8 <addr>" then "FF E0" at trampoline_stolen_offset + 16
    uintptr_t tramp_jmp_offset = tramp_stolen_offset + 16;
    uintptr_t continue_addr = hook.target_func + hook.stolen_count;
    memcpy(buf + tramp_jmp_offset + 2, &continue_addr, 8);

    return true;
}

// =========================================================================
// FindCodeCave
// =========================================================================
uintptr_t HookManager::FindCodeCave(uintptr_t module_base, size_t size) {
    // Search for a block of null bytes in the module's .text section
    size_t module_size = GetModuleSize(module_base);
    if (!module_size || module_size > 64 * 1024 * 1024) return 0;

    // Read in chunks to find a cave
    constexpr size_t kChunkSize = 1024 * 1024; // 1MB
    std::vector<uint8_t> buffer(kChunkSize);

    for (size_t offset = 0; offset < module_size; offset += kChunkSize) {
        size_t read_size = std::min(kChunkSize, module_size - offset);
        if (!ReadMemory(module_base + offset, buffer.data(), read_size))
            continue;

        size_t consecutive = 0;
        for (size_t i = 0; i < read_size; ++i) {
            if (buffer[i] == 0x00 || buffer[i] == 0xCC) {
                consecutive++;
                if (consecutive >= size)
                    return module_base + offset + i - consecutive + 1;
            } else {
                consecutive = 0;
            }
        }
    }

    return 0; // no cave found — caller will fall back to VirtualAllocEx
}

// =========================================================================
// ExecuteShellcode
// =========================================================================
bool HookManager::ExecuteShellcode(uintptr_t code_cave) {
    // Create a suspended thread at the shellcode entry point (offset 0x00)
    // The first instruction at 0x00 is "jmp 0x50", so entry is code_cave itself.
    HANDLE hThread = CreateRemoteThread(m_hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(code_cave),
        nullptr, CREATE_SUSPENDED, nullptr);

    if (!hThread) return false;

    // Hide thread from debugger
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    using NtSetInfoThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    auto NtSetInformationThread = reinterpret_cast<NtSetInfoThread_t>(
        GetProcAddress(hNtdll, "NtSetInformationThread"));
    if (NtSetInformationThread) {
        NtSetInformationThread(hThread, 0x11 /*ThreadHideFromDebugger*/, nullptr, 0);
    }

    ResumeThread(hThread);

    // Don't wait — the thread enters an infinite loop after setup
    // Just give it a moment to complete setup
    Sleep(100);

    // Verify heartbeat: the shellcode increments heartbeat after setup
    SharedMemoryBlock remote{};
    if (ReadMemory(m_shm.RemoteAddr(), &remote, sizeof(remote))) {
        if (remote.heartbeat.load() < 1) {
            // Setup may have failed — but we can still proceed
        }
    }

    CloseHandle(hThread);
    return true;
}

// =========================================================================
// GetModuleBase
// =========================================================================
uintptr_t HookManager::GetModuleBase(const char* module_name) {
    {
        std::shared_lock lock(m_module_mutex);
        auto it = m_module_cache.find(module_name);
        if (it != m_module_cache.end()) return it->second;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    uintptr_t base = 0;

    if (Module32First(hSnap, &me)) {
        do {
            if (_stricmp(me.szModule, module_name) == 0) {
                base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);

    if (base) {
        std::unique_lock lock(m_module_mutex);
        m_module_cache[module_name] = base;
    }

    return base;
}

// =========================================================================
// ReadMemory / WriteMemory
// =========================================================================
bool HookManager::ReadMemory(uintptr_t addr, void* buf, size_t size) {
    if (!m_hProcess || !addr || !buf || !size) return false;
    SIZE_T read = 0;
    return ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(addr), buf, size, &read)
           && read == size;
}

bool HookManager::WriteMemory(uintptr_t addr, const void* buf, size_t size) {
    if (!m_hProcess || !addr || !buf || !size) return false;
    DWORD oldProt = 0;
    VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(addr), size,
                     PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T written = 0;
    BOOL result = WriteProcessMemory(m_hProcess, reinterpret_cast<LPVOID>(addr),
                                      buf, size, &written);
    VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(addr), size, oldProt, &oldProt);
    return result && written == size;
}

uintptr_t HookManager::AllocateMemory(size_t size, DWORD protect) {
    return reinterpret_cast<uintptr_t>(
        VirtualAllocEx(m_hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect));
}

void HookManager::FreeMemory(uintptr_t addr) {
    if (addr) {
        VirtualFreeEx(m_hProcess, reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE);
    }
}

} // namespace hooks
