// PatternScanner.h
#pragma once
#include <Windows.h>
#include <vector>
#include <string>

class PatternScanner
{
public:
    // Find a pattern inside a given module.
    static uintptr_t Scan(HANDLE hProcess, const std::string& moduleName,
                          const std::vector<uint8_t>& pattern, const std::string& mask)
    {
        uintptr_t base = GetModuleBaseRemote(hProcess, moduleName);
        if (!base) return 0;

        MODULEENTRY32 me;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
        me.dwSize = sizeof(me);
        uint32_t size = 0;
        if (Module32First(hSnap, &me))
        {
            do
            {
                if (_stricmp(me.szModule, moduleName.c_str()) == 0)
                {
                    size = me.modBaseSize;
                    break;
                }
            } while (Module32Next(hSnap, &me));
        }
        CloseHandle(hSnap);
        if (!size) return 0;

        std::vector<uint8_t> buffer(size);
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, (LPCVOID)base, buffer.data(), size, &bytesRead))
            return 0;

        for (size_t i = 0; i <= size - pattern.size(); ++i)
        {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); ++j)
            {
                if (mask[j] == 'x' && buffer[i + j] != pattern[j])
                {
                    found = false;
                    break;
                }
            }
            if (found) return base + i;
        }
        return 0;
    }

private:
    static uintptr_t GetModuleBaseRemote(HANDLE hProcess, const std::string& moduleName)
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
        if (hSnap == INVALID_HANDLE_VALUE) return 0;
        MODULEENTRY32 me;
        me.dwSize = sizeof(me);
        uintptr_t base = 0;
        if (Module32First(hSnap, &me))
        {
            do
            {
                if (_stricmp(me.szModule, moduleName.c_str()) == 0)
                {
                    base = (uintptr_t)me.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &me));
        }
        CloseHandle(hSnap);
        return base;
    }
};
