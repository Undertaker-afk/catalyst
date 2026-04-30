// Syscall.cpp
#include "Syscall.h"
#include <Windows.h>
#include <winternl.h>
#include <algorithm>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>

// -----------------------------------------------------------------------
//  x64 syscall stub
// -----------------------------------------------------------------------
extern "C" uint64_t syscall(uint16_t ssn,
                            uint64_t rcx, uint64_t rdx,
                            uint64_t r8,  uint64_t r9,
                            uint64_t r10, uint64_t r12, uint64_t r13)
{
    // The actual syscall instruction is in an .asm file.
    // We just need to define the function name here so the linker can find it.
    // If you don't use a separate .asm, place the stub below in a naked function.
    return 0;
}

// -----------------------------------------------------------------------
//  Compile-time FNV‑1a hash for function names (avoids strings in binary)
// -----------------------------------------------------------------------
namespace
{
    constexpr uint64_t fnv1a64(const char* str, size_t len,
                               uint64_t hash = 0xcbf29ce484222325ULL)
    {
        for (size_t i = 0; i < len; ++i)
            hash = (hash ^ static_cast<uint64_t>(str[i])) * 0x100000001b3ULL;
        return hash;
    }
    constexpr uint64_t operator "" _hash64(const char* str, size_t len)
    {
        return fnv1a64(str, len);
    }

    // -------------------------------------------------------------------
    //  PEB walk to find ntdll.dll base (no GetModuleHandle)
    // -------------------------------------------------------------------
    HMODULE GetNtdllBase()
    {
        // The PEB is at GS:[0x60]
        const auto peb = reinterpret_cast<const PEB*>(__readgsqword(0x60));
        if (!peb) return nullptr;

        // Ldr->InMemoryOrderModuleList contains the loaded modules
        const auto ldr = peb->Ldr;
        if (!ldr) return nullptr;

        const auto head = &ldr->InMemoryOrderModuleList;
        for (auto entry = head->Flink; entry != head; entry = entry->Flink)
        {
            const auto mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,
                                                InMemoryOrderLinks);
            if (!mod || !mod->DllBase) continue;

            // Check the module name (hash would be even stealthier, but
            // the string is tiny and VAC doesn't scan for it).
            if (mod->FullDllName.Length >= 14 &&
                _wcsnicmp(wcsrchr(mod->FullDllName.Buffer, L'\\'),
                          L"\\ntdll.dll", 10) == 0)
            {
                return static_cast<HMODULE>(mod->DllBase);
            }
        }
        return nullptr;
    }

    // -------------------------------------------------------------------
    //  Parse the Export Address Table to find an exported function.
    //  Returns the RVA of the function, or 0 if not found.
    // -------------------------------------------------------------------
    uint32_t FindExportRVA(HMODULE mod, uint64_t nameHash)
    {
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        const auto nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        const auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!expDir.VirtualAddress) return 0;

        const auto exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            reinterpret_cast<const uint8_t*>(mod) + expDir.VirtualAddress);

        const auto names = reinterpret_cast<const uint32_t*>(
            reinterpret_cast<const uint8_t*>(mod) + exp->AddressOfNames);
        const auto ordinals = reinterpret_cast<const uint16_t*>(
            reinterpret_cast<const uint8_t*>(mod) + exp->AddressOfNameOrdinals);
        const auto functions = reinterpret_cast<const uint32_t*>(
            reinterpret_cast<const uint8_t*>(mod) + exp->AddressOfFunctions);

        for (uint32_t i = 0; i < exp->NumberOfNames; ++i)
        {
            const auto name = reinterpret_cast<const char*>(mod) + names[i];
            const auto len  = strlen(name);
            if (fnv1a64(name, len) == nameHash)
            {
                return functions[ordinals[i]];
            }
        }
        return 0;
    }

    // -------------------------------------------------------------------
    //  Extract the SSN from a function stub.
    //  The stub on x64 is:
    //    mov r10, rcx
    //    mov eax, <ssn>
    //    syscall
    //  We look for the "mov eax, imm32" pattern (opcode 0xb8).
    // -------------------------------------------------------------------
    bool ExtractSSN(const uint8_t* stub, size_t stubSize, uint16_t& ssn)
    {
        // We scan at most the first 32 bytes.
        const size_t limit = std::min(stubSize, size_t(32));
        for (size_t i = 0; i + 5 <= limit; ++i)
        {
            if (stub[i] == 0xb8)   // mov eax, imm32
            {
                ssn = *reinterpret_cast<const uint16_t*>(stub + i + 1);
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------
    //  Global cache and initialization flag
    // -------------------------------------------------------------------
    std::unordered_map<uint64_t, uint16_t> g_ssnCache;
    std::mutex g_cacheMutex;
    bool g_initialized = false;
}

// -----------------------------------------------------------------------
//  ResolveSyscall – the main API
// -----------------------------------------------------------------------
uint16_t ResolveSyscall(std::string_view name)
{
    const auto hash = fnv1a64(name.data(), name.size());
    {
        std::lock_guard lock(g_cacheMutex);
        if (auto it = g_ssnCache.find(hash); it != g_ssnCache.end())
            return it->second;
    }

    // Find ntdll and parse exports
    HMODULE ntdll = GetNtdllBase();
    if (!ntdll) return 0;

    // Try to find the function as an export
    uint32_t rva = FindExportRVA(ntdll, hash);
    if (!rva)
    {
        // Fallback: try to guess from adjacent exports.
        // (See the advanced halos-gate technique.)
        // For now, we return 0 and the caller must handle the error.
        return 0;
    }

    // Read the stub bytes
    const auto stub = reinterpret_cast<const uint8_t*>(ntdll) + rva;
    uint16_t ssn = 0;
    if (!ExtractSSN(stub, 32, ssn))
        return 0;

    {
        std::lock_guard lock(g_cacheMutex);
        g_ssnCache[hash] = ssn;
    }
    return ssn;
}

// -----------------------------------------------------------------------
//  InitSyscallResolver – optional pre-warm
// -----------------------------------------------------------------------
void InitSyscallResolver()
{
    // Pre-populate the most common syscalls you'll need.
    static constexpr std::pair<std::string_view, uint64_t> kPreWarm[] = {
        {"NtAllocateVirtualMemory",  "NtAllocateVirtualMemory"_hash64},
        {"NtProtectVirtualMemory",   "NtProtectVirtualMemory"_hash64},
        {"NtWriteVirtualMemory",     "NtWriteVirtualMemory"_hash64},
        {"NtCreateThreadEx",         "NtCreateThreadEx"_hash64},
        {"NtClose",                  "NtClose"_hash64},
    };

    for (auto& [name, hash] : kPreWarm)
    {
        ResolveSyscall(name);
    }
}

// -----------------------------------------------------------------------
//  DumpSyscallTable – debugging helper
// -----------------------------------------------------------------------
void DumpSyscallTable()
{
    std::lock_guard lock(g_cacheMutex);
    for (auto& [hash, ssn] : g_ssnCache)
    {
        OutputDebugStringA(("SSN: 0x" +
                            std::to_string(ssn) + "\n").c_str());
    }
}
