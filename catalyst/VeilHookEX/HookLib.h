// HookLib.h
#pragma once
#include <Windows.h>
#include "PatternScanner.h"
#include "SharedMemory.h"
#include "Shellcode.h"

class CS2VeilHook
{
    HANDLE m_hProcess;
    uintptr_t m_targetFunc;
    uintptr_t m_codeCave;
    bool m_installed;

public:
    CS2VeilHook(HANDLE hProcess) : m_hProcess(hProcess), m_targetFunc(0),
                                    m_codeCave(0), m_installed(false) {}

    // Install the hook using the given pattern and shared memory name.
    bool Install(const std::string& shmName, const std::vector<uint8_t>& pattern,
                 const std::string& mask, const std::string& module = "client.dll",
                 RingBuffer* pRingBuffer = nullptr)
    {
        if (m_installed) return false;

        // 1. Locate the target function.
        m_targetFunc = PatternScanner::Scan(m_hProcess, module, pattern, mask);
        if (!m_targetFunc) return false;

        // 2. Open shared memory.
        if (!pRingBuffer)
        {
            // The external caller should already have created it.
            return false;
        }

        // 3. Find a code cave of at least sizeof(g_VehShellcode) + 0x100.
        uintptr_t base = PatternScanner::GetModuleBaseRemote(m_hProcess, module);
        m_codeCave = FindCodeCave(base, sizeof(g_VehShellcode) + 0x100);
        if (!m_codeCave) return false;

        // 4. Prepare the shellcode by patching the placeholder addresses.
        uint8_t shellcode[sizeof(g_VehShellcode) + 0x100];
        memcpy(shellcode, g_VehShellcode, sizeof(g_VehShellcode));
        PatchShellcode(shellcode, m_targetFunc, pRingBuffer);

        // 5. Write the shellcode into the code cave.
        DWORD oldProt;
        if (!VirtualProtectEx(m_hProcess, (LPVOID)m_codeCave, sizeof(shellcode),
                              PAGE_EXECUTE_READWRITE, &oldProt))
            return false;
        WriteProcessMemory(m_hProcess, (LPVOID)m_codeCave, shellcode, sizeof(shellcode), nullptr);
        VirtualProtectEx(m_hProcess, (LPVOID)m_codeCave, sizeof(shellcode), oldProt, &oldProt);

        // 6. Execute the shellcode to install the VEH and set PAGE_GUARD.
        //    We use a hijacked thread (or a tiny suspended thread) to call the shellcode entry.
        if (!ExecuteShellcode(m_codeCave)) return false;

        m_installed = true;
        return true;
    }

    // Restore the original page protection and free the code cave.
    void Remove()
    {
        if (!m_installed) return;
        // 1. Remove the VEH handler. (The shellcode could have an uninstall routine.)
        // 2. Restore PAGE_EXECUTE_READ on the target function page.
        DWORD oldProt;
        VirtualProtectEx(m_hProcess, (LPVOID)m_targetFunc, 1, PAGE_EXECUTE_READ, &oldProt);
        // 3. Zero the code cave.
        // 4. Free the memory.
        VirtualFreeEx(m_hProcess, (LPVOID)m_codeCave, 0, MEM_RELEASE);
        m_installed = false;
    }

private:
    // Find a region of null bytes inside the module's code section.
    uintptr_t FindCodeCave(uintptr_t moduleBase, size_t size);
    void PatchShellcode(uint8_t* shellcode, uintptr_t targetFunc, RingBuffer* ringBuffer);
    bool ExecuteShellcode(uintptr_t entryPoint);
};
