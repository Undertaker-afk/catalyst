// Syscall.h
#pragma once
#include <cstdint>
#include <string_view>
#include <unordered_map>
#include <array>

// -----------------------------------------------------------------------
// Direct syscall stub - replace with your own if you want a different
// calling convention or a gadget-based approach
// -----------------------------------------------------------------------
extern "C" uint64_t syscall(uint16_t syscall_number,
                            uint64_t rcx = 0, uint64_t rdx = 0,
                            uint64_t r8  = 0, uint64_t r9  = 0,
                            uint64_t r10 = 0, uint64_t r12 = 0,
                            uint64_t r13 = 0);

// -----------------------------------------------------------------------
// Public interface - returns the SSN for a given native API name.
// Example: auto ssn = ResolveSyscall("NtProtectVirtualMemory");
// -----------------------------------------------------------------------
uint16_t ResolveSyscall(std::string_view name);

// -----------------------------------------------------------------------
// Initialize the syscall cache (called once at startup).
// You can call this explicitly, or ResolveSyscall will call it on
// first use.
// -----------------------------------------------------------------------
void InitSyscallResolver();

// -----------------------------------------------------------------------
// Advanced: dump all resolved syscalls to stdout (for debugging)
// -----------------------------------------------------------------------
void DumpSyscallTable();
