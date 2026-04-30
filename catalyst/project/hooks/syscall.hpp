// syscall.hpp — dynamic syscall number resolver + direct syscall gate
#pragma once
#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <string_view>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <cstring>

namespace hooks {

// ---------------------------------------------------------------------
// Direct syscall gate (implemented in syscall_stub.asm)
// ---------------------------------------------------------------------
namespace syscall {
    extern "C" uint64_t syscall_gate(
        uint16_t ssn,
        uint64_t rcx = 0, uint64_t rdx = 0,
        uint64_t r8  = 0, uint64_t r9  = 0,
        uint64_t r10 = 0, uint64_t r12 = 0,
        uint64_t r13 = 0);
}

// ---------------------------------------------------------------------
// Compile-time FNV-1a 64-bit hash
// ---------------------------------------------------------------------
namespace detail {
    constexpr uint64_t fnv1a64(const char* str, size_t len, uint64_t hash = 0xcbf29ce484222325ULL) {
        for (size_t i = 0; i < len; ++i)
            hash = (hash ^ static_cast<uint64_t>(str[i])) * 0x100000001b3ULL;
        return hash;
    }
}
constexpr uint64_t operator "" _hash64(const char* str, size_t len) {
    return detail::fnv1a64(str, len);
}

// ---------------------------------------------------------------------
// SyscallResolver — singleton that resolves SSNs from ntdll at runtime
// ---------------------------------------------------------------------
class SyscallResolver {
public:
    static SyscallResolver& Instance() {
        static SyscallResolver inst;
        return inst;
    }

    void Initialize() {
        std::lock_guard lock(m_mutex);
        if (m_initialized) return;
        m_initialized = true;

        // Pre-warm the most-used syscalls
        ResolveUnsafe("NtProtectVirtualMemory");
        ResolveUnsafe("NtAllocateVirtualMemory");
        ResolveUnsafe("NtWriteVirtualMemory");
        ResolveUnsafe("NtCreateThreadEx");
        ResolveUnsafe("NtClose");
        ResolveUnsafe("NtQueryInformationThread");
    }

    uint16_t Resolve(const char* name) {
        std::lock_guard lock(m_mutex);
        return ResolveUnsafe(name);
    }

    uint16_t Resolve(std::string_view name) {
        char buf[128] = {};
        size_t len = std::min(name.size(), sizeof(buf) - 1);
        memcpy(buf, name.data(), len);
        return Resolve(buf);
    }

    void Dump() {
        std::lock_guard lock(m_mutex);
        for (auto& [hash, ssn] : m_cache) {
            char buf[32];
            snprintf(buf, sizeof(buf), "ssn:0x%04X\n", ssn);
            OutputDebugStringA(buf);
        }
    }

private:
    SyscallResolver() = default;

    uint16_t ResolveUnsafe(const char* name) {
        uint64_t hash = detail::fnv1a64(name, strlen(name));
        if (auto it = m_cache.find(hash); it != m_cache.end())
            return it->second;

        HMODULE ntdll = GetNtdllBase();
        if (!ntdll) return 0;

        uint32_t rva = FindExportRVA(ntdll, hash);
        if (!rva) return 0;

        const auto stub = reinterpret_cast<const uint8_t*>(ntdll) + rva;
        uint16_t ssn = 0;
        if (!ExtractSSN(stub, 32, ssn)) return 0;

        m_cache[hash] = ssn;
        return ssn;
    }

    static HMODULE GetNtdllBase() {
        const auto peb = reinterpret_cast<const PEB*>(__readgsqword(0x60));
        if (!peb) return nullptr;
        const auto ldr = peb->Ldr;
        if (!ldr) return nullptr;
        const auto head = &ldr->InMemoryOrderModuleList;
        for (auto entry = head->Flink; entry != head; entry = entry->Flink) {
            const auto mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (!mod || !mod->DllBase) continue;
            if (mod->FullDllName.Length >= 14 &&
                _wcsnicmp(wcsrchr(mod->FullDllName.Buffer, L'\\'), L"\\ntdll.dll", 10) == 0)
                return static_cast<HMODULE>(mod->DllBase);
        }
        return nullptr;
    }

    static uint32_t FindExportRVA(HMODULE mod, uint64_t nameHash) {
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
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

        for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
            const auto name = reinterpret_cast<const char*>(mod) + names[i];
            if (detail::fnv1a64(name, strlen(name)) == nameHash)
                return functions[ordinals[i]];
        }
        return 0;
    }

    static bool ExtractSSN(const uint8_t* stub, size_t stubSize, uint16_t& ssn) {
        const size_t limit = std::min(stubSize, size_t(32));
        for (size_t i = 0; i + 5 <= limit; ++i) {
            if (stub[i] == 0xB8) {  // mov eax, imm32
                ssn = *reinterpret_cast<const uint16_t*>(stub + i + 1);
                return true;
            }
        }
        return false;
    }

    std::unordered_map<uint64_t, uint16_t> m_cache;
    std::mutex m_mutex;
    bool m_initialized = false;
};

// ---------------------------------------------------------------------
// Typed syscall wrappers
// ---------------------------------------------------------------------
inline NTSTATUS NtProtectVirtualMemory_Syscall(
    HANDLE hProcess, PVOID* pBase, PSIZE_T pSize, ULONG newProt, PULONG pOld)
{
    auto& r = SyscallResolver::Instance();
    uint16_t ssn = r.Resolve("NtProtectVirtualMemory");
    return (NTSTATUS)syscall::syscall_gate(ssn,
        (uint64_t)hProcess, (uint64_t)pBase, (uint64_t)pSize,
        (uint64_t)newProt, (uint64_t)pOld, 0, 0);
}

inline NTSTATUS NtAllocateVirtualMemory_Syscall(
    HANDLE hProcess, PVOID* pBase, ULONG_PTR zeroBits, PSIZE_T pSize,
    ULONG allocType, ULONG protect)
{
    auto& r = SyscallResolver::Instance();
    uint16_t ssn = r.Resolve("NtAllocateVirtualMemory");
    return (NTSTATUS)syscall::syscall_gate(ssn,
        (uint64_t)hProcess, (uint64_t)pBase, (uint64_t)zeroBits,
        (uint64_t)pSize, (uint64_t)allocType, (uint64_t)protect, 0);
}

inline NTSTATUS NtWriteVirtualMemory_Syscall(
    HANDLE hProcess, PVOID pBase, PVOID pBuffer, SIZE_T size, PSIZE_T pWritten)
{
    auto& r = SyscallResolver::Instance();
    uint16_t ssn = r.Resolve("NtWriteVirtualMemory");
    return (NTSTATUS)syscall::syscall_gate(ssn,
        (uint64_t)hProcess, (uint64_t)pBase, (uint64_t)pBuffer,
        (uint64_t)size, (uint64_t)pWritten, 0, 0);
}

inline NTSTATUS NtCreateThreadEx_Syscall(
    PHANDLE hThread, ACCESS_MASK desiredAccess, PVOID objAttr,
    HANDLE hProcess, PVOID startAddr, PVOID param, ULONG flags,
    SIZE_T stackZero, SIZE_T stackSize, SIZE_T maxStack, PVOID attrList)
{
    auto& r = SyscallResolver::Instance();
    uint16_t ssn = r.Resolve("NtCreateThreadEx");
    return (NTSTATUS)syscall::syscall_gate(ssn,
        (uint64_t)hThread, (uint64_t)desiredAccess, (uint64_t)objAttr,
        (uint64_t)hProcess, (uint64_t)startAddr, (uint64_t)param,
        (uint64_t)flags);
}

inline NTSTATUS NtClose_Syscall(HANDLE handle) {
    auto& r = SyscallResolver::Instance();
    uint16_t ssn = r.Resolve("NtClose");
    return (NTSTATUS)syscall::syscall_gate(ssn, (uint64_t)handle, 0, 0, 0, 0, 0, 0);
}

} // namespace hooks
