// hook_manager.hpp — central orchestrator for VEH hook lifecycle
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <cstring>
#include "shared_memory.hpp"
#include "patterns.hpp"
#include "shellcode.h"
#include "syscall.hpp"

namespace hooks {

class HookManager {
public:
    static HookManager& Instance();

    bool Initialize(HANDLE hProcess);
    void Shutdown();

    // Install/remove hooks
    bool InstallHook(uint8_t hook_id, bool enable_detour, HookCallback callback);
    bool InstallHook(const patterns::HookPattern& pattern, bool enable_detour, HookCallback callback);
    void RemoveHook(uint8_t hook_id);
    void RemoveAllHooks();

    // Control detour state
    void SetDetourActive(uint8_t hook_id, bool active);
    bool IsHookActive(uint8_t hook_id) const;

    // Send command to shellcode
    void SendCommand(uint8_t hook_id, uint8_t cmd, uint16_t p16 = 0, uint32_t p32 = 0,
                     float f0 = 0, float f1 = 0, float f2 = 0, float f3 = 0);

    // Accessors
    HANDLE GetProcessHandle() const { return m_hProcess; }
    SharedMemoryBlock* GetSharedMemory() { return m_shm.LocalBlock(); }
    uintptr_t GetRemoteSharedMemory() const { return m_shm.RemoteAddr(); }
    uintptr_t GetModuleBase(const char* module_name);

    // RPM/WPM helpers
    bool ReadMemory(uintptr_t addr, void* buf, size_t size);
    bool WriteMemory(uintptr_t addr, const void* buf, size_t size);
    uintptr_t AllocateMemory(size_t size, DWORD protect = PAGE_EXECUTE_READWRITE);
    void FreeMemory(uintptr_t addr);

private:
    HookManager() = default;
    ~HookManager();
    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    struct InstalledHook {
        uint8_t  hook_id;
        uintptr_t target_func;
        uintptr_t code_cave;
        uintptr_t trampoline_addr;
        uint8_t  stolen_bytes[16];
        uint8_t  stolen_count;
        HookCallback callback;
        bool     detour_active = false;
    };

    // Pattern scanning
    uintptr_t ScanPattern(uintptr_t module_base, const std::vector<uint8_t>& pattern,
                          const std::string& mask);
    size_t GetModuleSize(uintptr_t module_base);

    // Stolen bytes
    bool StealBytes(uintptr_t target_func, uint8_t* out_bytes, uint8_t& out_count);

    // Shellcode patching
    bool PrepareShellcode(uint8_t* buf, size_t buf_size, const InstalledHook& hook);

    // Code cave
    uintptr_t FindCodeCave(uintptr_t module_base, size_t size);

    // Thread execution
    bool ExecuteShellcode(uintptr_t code_cave);

    // Event polling
    void PollThread();
    void ProcessEvents();

    HANDLE m_hProcess = nullptr;
    DWORD  m_pid = 0;

    SharedMemoryManager m_shm;
    std::vector<InstalledHook> m_installed_hooks;
    mutable std::shared_mutex m_hooks_mutex;

    std::thread m_poll_thread;
    std::atomic<bool> m_running{false};

    std::unordered_map<std::string, uintptr_t> m_module_cache;
    mutable std::shared_mutex m_module_mutex;
};

} // namespace hooks
