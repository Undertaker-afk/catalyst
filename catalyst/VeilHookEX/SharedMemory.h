// SharedMemory.h
#pragma once
#include <Windows.h>
#include <atomic>
#include <cstring>

struct RingBuffer
{
    std::atomic<uint32_t> write_index;
    std::atomic<uint32_t> read_index;
    // Reserve space for 128 entries of 16 bytes each.
    static constexpr size_t BUFFER_SIZE = 2048;
    uint8_t buffer[BUFFER_SIZE - sizeof(write_index) - sizeof(read_index)];
};

class SharedMemoryLogger
{
    HANDLE m_hMapFile;
    RingBuffer* m_ring;
public:
    bool Create(const std::string& name)
    {
        m_hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                        0, sizeof(RingBuffer), name.c_str());
        if (!m_hMapFile) return false;
        m_ring = (RingBuffer*)MapViewOfFile(m_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(RingBuffer));
        m_ring->write_index = 0;
        m_ring->read_index = 0;
        return true;
    }

    bool Open(const std::string& name)
    {
        m_hMapFile = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name.c_str());
        if (!m_hMapFile) return false;
        m_ring = (RingBuffer*)MapViewOfFile(m_hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(RingBuffer));
        return m_ring != nullptr;
    }

    RingBuffer* GetBuffer() { return m_ring; }
    void Close()
    {
        if (m_ring) UnmapViewOfFile(m_ring);
        if (m_hMapFile) CloseHandle(m_hMapFile);
    }
};
