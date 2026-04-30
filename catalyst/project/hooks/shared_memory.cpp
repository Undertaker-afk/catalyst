// shared_memory.cpp — SharedMemoryManager implementation
#include <Windows.h>
#include <cstring>
#include "shared_memory.hpp"

namespace hooks {

bool SharedMemoryManager::Create(HANDLE hProcess) {
    m_hProcess = hProcess;

    // Allocate local block
    m_local = static_cast<SharedMemoryBlock*>(
        VirtualAlloc(nullptr, sizeof(SharedMemoryBlock), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!m_local) return false;

    // Initialize block
    memset(m_local, 0, sizeof(SharedMemoryBlock));
    m_local->magic[0] = 'V';
    m_local->magic[1] = 'H';
    m_local->magic[2] = 'E';
    m_local->magic[3] = 'X';
    m_local->version = 1;
    m_local->heartbeat.store(0);

    // Initialize HookState for all hooks
    for (int i = 0; i < HOOK_COUNT; ++i) {
        m_local->hook_states[i] = {};
    }

    // Allocate remote block in target process
    LPVOID remote = VirtualAllocEx(m_hProcess, nullptr, sizeof(SharedMemoryBlock),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        VirtualFree(m_local, 0, MEM_RELEASE);
        m_local = nullptr;
        return false;
    }
    m_remote_addr = reinterpret_cast<uintptr_t>(remote);

    // Write initial block to target process
    SIZE_T written = 0;
    if (!WriteProcessMemory(m_hProcess, remote, m_local, sizeof(SharedMemoryBlock), &written)) {
        VirtualFreeEx(m_hProcess, remote, 0, MEM_RELEASE);
        VirtualFree(m_local, 0, MEM_RELEASE);
        m_local = nullptr;
        m_remote_addr = 0;
        return false;
    }

    return true;
}

void SharedMemoryManager::Close() {
    if (m_remote_addr && m_hProcess) {
        VirtualFreeEx(m_hProcess, reinterpret_cast<LPVOID>(m_remote_addr), 0, MEM_RELEASE);
        m_remote_addr = 0;
    }
    if (m_local) {
        VirtualFree(m_local, 0, MEM_RELEASE);
        m_local = nullptr;
    }
    m_hProcess = nullptr;
}

bool SharedMemoryManager::IsValid() const {
    if (!m_local) return false;
    return (m_local->magic[0] == 'V' &&
            m_local->magic[1] == 'H' &&
            m_local->magic[2] == 'E' &&
            m_local->magic[3] == 'X' &&
            m_local->version == 1);
}

} // namespace hooks
