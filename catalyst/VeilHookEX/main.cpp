#include <Windows.h>
#include <iostream>
#include "Patterns.h"
#include "HookLib.h"
#include "SharedMemory.h"

int main()
{
    // 1. Attach to CS2
    HWND hw = FindWindowA(nullptr, "Counter-Strike 2");
    DWORD pid;
    GetWindowThreadProcessId(hw, &pid);
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                                  PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
                                  FALSE, pid);
    if (!hProcess) { std::cerr << "OpenProcess failed.\n"; return 1; }

    // 2. Create shared memory (name must match inside shellcode)
    SharedMemoryLogger shm;
    if (!shm.Create("Local\\CS2HookSHM")) { std::cerr << "SHM failed.\n"; return 1; }

    // 3. Hook a function (example: CreateMove)
    CS2VeilHook hook(hProcess);
    auto& pattern = AllPatterns[0]; // CreateMove
    if (!hook.Install("Local\\CS2HookSHM", pattern.bytes, pattern.mask, pattern.module, shm.GetBuffer()))
    {
        std::cerr << "Hook install failed.\n";
        return 1;
    }

    // 4. Monitor log
    std::cout << "Hooked CreateMove. Watching ring buffer...\n";
    RingBuffer* rb = shm.GetBuffer();
    uint32_t lastRead = rb->read_index.load();
    while (true)
    {
        if (rb->write_index.load() != lastRead)
        {
            // In a real implementation, copy the buffer entries out and process them.
            std::cout << "CreateMove called!\n";
            lastRead = rb->write_index.load();
        }
        Sleep(50);
    }

    // 5. Cleanup (unreachable in this demo)
    hook.Remove();
    shm.Close();
    CloseHandle(hProcess);
    return 0;
}
