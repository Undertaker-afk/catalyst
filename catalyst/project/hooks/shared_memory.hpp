// shared_memory.hpp — IPC protocol between external catalyst and injected shellcode
#pragma once
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <functional>

namespace hooks {

// ===================================================================
// Hook IDs
// ===================================================================
enum HookID : uint8_t {
    HOOK_CREATEMOVE        = 0,
    HOOK_FRAMESTAGENOTIFY  = 1,
    HOOK_OVERRIDEVIEW      = 2,
    HOOK_DRAWSMOKEVERTEX   = 3,
    HOOK_FLASHOVERLAY      = 4,
    HOOK_CALCVIEWMODEL     = 5,
    HOOK_DRAWSCOPEOVERLAY  = 6,
    HOOK_DRAWLEGS          = 7,
    HOOK_COUNT             = 8
};

// ===================================================================
// HookContext — written by shellcode to ring buffer per hook invocation
// ===================================================================
#pragma pack(push, 1)
struct HookContext {
    uint8_t  hook_id;           // which hook
    uint8_t  frame_stage;       // only meaningful for FrameStageNotify
    uint8_t  _pad[6];           // align to 8
    int32_t  user_cmd_number;   // from CUserCmd (CreateMove)
    float    frame_time;        // from CreateMove
    uint64_t rcx;               // first integer arg
    uint64_t rdx;               // second integer arg
    uint64_t r8;                // third integer arg
    uint64_t r9;                // fourth integer arg
    float    xmm0[4];           // first xmm arg (4 floats)
    float    xmm1[4];           // second xmm arg (4 floats)
    uint64_t return_addr;       // caller return address
};
static_assert(sizeof(HookContext) == 80, "HookContext must be 80 bytes");
#pragma pack(pop)

// ===================================================================
// FeatureCommand — written by external process to command ring
// ===================================================================
#pragma pack(push, 1)
struct alignas(64) FeatureCommand {
    uint8_t  hook_id;
    uint8_t  command;           // 0=none, 1=enable_detour, 2=disable_detour, 3=set_params
    uint16_t param16;
    uint32_t param32;
    float    param_f[4];        // generic float params (view angles, colors, etc.)
    uint8_t  _pad[36];          // pad to 64 bytes
};
static_assert(sizeof(FeatureCommand) == 64, "FeatureCommand must be 64 bytes");
#pragma pack(pop)

// ===================================================================
// HookState — per-hook mutable state
// ===================================================================
#pragma pack(push, 1)
struct HookState {
    uint8_t  detour_active;     // whether VEH redirects to trampoline
    uint8_t  _pad1[7];          // align
    uint64_t trampoline_addr;   // trampoline entry in code cave
    uint64_t target_func;       // hooked function address
    uint8_t  stolen_bytes[16];  // original prologue bytes
    uint8_t  stolen_count;      // number of stolen bytes
    uint8_t  _pad2[7];          // align to 48
};
static_assert(sizeof(HookState) == 48, "HookState must be 48 bytes");
#pragma pack(pop)

// ===================================================================
// FeatureCommandRing — command ring from external -> shellcode
// ===================================================================
struct FeatureCommandRing {
    std::atomic<uint32_t> cmd_write_index{0};
    std::atomic<uint32_t> cmd_read_index{0};
    alignas(64) FeatureCommand commands[16]{};
    uint8_t _pad[64 - 8 - 16*64]; // pad sector to cache line
};

// ===================================================================
// RingBuffer — lock-free SPSC ring buffer (shellcode writes, external reads)
// ===================================================================
struct RingBuffer {
    std::atomic<uint32_t> write_index{0};
    std::atomic<uint32_t> read_index{0};
    uint8_t  data[4032];          // 4096 - 8 (indices) - 56 (other fields in block)
    uint32_t _padding;
};

// ===================================================================
// SharedMemoryBlock — root structure mapped in target process
// ===================================================================
struct SharedMemoryBlock {
    RingBuffer          hook_events;
    FeatureCommandRing  commands;
    HookState           hook_states[HOOK_COUNT];
    std::atomic<uint32_t> heartbeat{0};
    uint8_t             magic[4];     // "VHEX"
    uint32_t            version;      // protocol version = 1
};

static_assert(sizeof(SharedMemoryBlock) <= 8192, "SharedMemoryBlock must fit in 8KB");

// ===================================================================
// SharedMemoryManager — manages the remote shared memory allocation
// ===================================================================
class SharedMemoryManager {
public:
    SharedMemoryManager() = default;

    bool Create(HANDLE hProcess);
    void Close();

    [[nodiscard]] SharedMemoryBlock* LocalBlock()  const { return m_local; }
    [[nodiscard]] uintptr_t          RemoteAddr()  const { return m_remote_addr; }
    [[nodiscard]] bool               IsValid()     const;

private:
    HANDLE              m_hProcess    = nullptr;
    SharedMemoryBlock*  m_local       = nullptr;   // local view (our process)
    uintptr_t           m_remote_addr = 0;          // address in target process
};

// ===================================================================
// HookCallback — called when a hook event fires
// ===================================================================
using HookCallback = std::function<void(uint8_t hook_id, const HookContext& ctx)>;

} // namespace hooks
