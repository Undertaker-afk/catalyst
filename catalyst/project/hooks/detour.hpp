// detour.hpp — feature detour handlers for hook-based features
#pragma once
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <shared_mutex>
#include "shared_memory.hpp"

namespace hooks {

// ===================================================================
// Hook feature settings (mirrored by settings.hpp later)
// ===================================================================
namespace detour_settings {
    struct Bhop {
        bool  enabled   = false;
        int   hit_chance = 100;
        int   min_hops   = 0;
        int   max_hops   = 0;
    };
    struct AntiAim {
        bool  enabled      = false;
        float pitch        = 0.0f;
        float yaw_offset   = 0.0f;
        float yaw_jitter   = 0.0f;
        bool  desync       = false;
        float desync_amt   = 58.0f;
    };
    struct SilentAim {
        bool  enabled   = false;
        float fov       = 5.0f;
        bool  autowall  = false;
        float min_damage = 10.0f;
    };
    struct DoubleTap {
        bool  enabled     = false;
        int   shift_ticks = 13;
    };
    struct Chams {
        bool  enabled       = false;
        bool  visible_only   = true;
        bool  wireframe      = false;
        bool  flat           = false;
        float color_r = 1.0f, color_g = 0.3f, color_b = 0.3f, color_a = 1.0f;
        float color_hidden_r = 0.3f, color_hidden_g = 0.3f, color_hidden_b = 1.0f, color_hidden_a = 0.5f;
    };
    struct WorldMod {
        bool  no_smoke   = false;
        bool  no_flash   = false;
        bool  no_scope   = false;
        bool  night_mode = false;
        float ambient_r = 0.0f, ambient_g = 0.0f, ambient_b = 0.0f;
    };
    struct ViewMod {
        bool  fov_override  = false;
        float fov           = 90.0f;
        bool  third_person  = false;
        float tp_distance   = 150.0f;
    };
    struct ViewModelMod {
        bool  override_fov = false;
        float fov          = 68.0f;
        float offset_x = 0.0f, offset_y = 0.0f, offset_z = 0.0f;
    };

    inline Bhop         bhop{};
    inline AntiAim      antiaim{};
    inline SilentAim    silent_aim{};
    inline DoubleTap    double_tap{};
    inline Chams        chams{};
    inline WorldMod     world_mod{};
    inline ViewMod      view{};
    inline ViewModelMod viewmodel{};
}

// ===================================================================
// DetourHandler type
// ===================================================================
using DetourHandler = std::function<void(uint8_t hook_id, const HookContext& ctx)>;

// ===================================================================
// DetourEngine — manages per-hook feature handlers
// ===================================================================
class DetourEngine {
public:
    static DetourEngine& Instance() {
        static DetourEngine inst;
        return inst;
    }

    void RegisterHandler(uint8_t hook_id, DetourHandler handler) {
        std::unique_lock lock(m_mutex);
        m_handlers[hook_id] = std::move(handler);
    }

    void UnregisterHandler(uint8_t hook_id) {
        std::unique_lock lock(m_mutex);
        m_handlers.erase(hook_id);
    }

    void ProcessEvent(uint8_t hook_id, const HookContext& ctx) {
        std::shared_lock lock(m_mutex);
        auto it = m_handlers.find(hook_id);
        if (it != m_handlers.end() && it->second) {
            it->second(hook_id, ctx);
        }
    }

private:
    DetourEngine() = default;
    std::unordered_map<uint8_t, DetourHandler> m_handlers;
    std::shared_mutex m_mutex;
};

// ===================================================================
// Feature handler registration functions
// ===================================================================

// CreateMove handler: bhop, anti-aim, silent aim, double tap
inline void RegisterCreateMoveHandler() {
    DetourEngine::Instance().RegisterHandler(HOOK_CREATEMOVE,
        [](uint8_t /*hook_id*/, const HookContext& ctx) {
            // ctx.rcx = CUserCmd* (user command pointer)
            // ctx.rdx = CCSPlayerInput* (input interface)
            // ctx.xmm0[0] = frame_time

            // The actual CUserCmd is pointed to by rcx (r8 in hook context)
            // In CS2, CreateMove is: void __fastcall CreateMove(CCSGOInput* input, int slot, CUserCmd* cmd, ...)
            // The args vary by CS2 version. Common signature:
            //   rcx = this (CCSGOInput*)
            //   rdx = slot (int)
            //   r8  = CUserCmd*
            // We access the user command via ctx.r8

            uintptr_t cmd_ptr = static_cast<uintptr_t>(ctx.r8);
            if (!cmd_ptr) return;

            // For now, this is a placeholder — the real implementation
            // reads CUserCmd fields from the target process via RPM
            // and modifies them via WPM through the HookManager.
            //
            // CUserCmd layout (simplified, CS2):
            //   +0x00: vtable
            //   +0x08: command_number (int32)
            //   +0x0C: tick_count (int32)
            //   +0x10: view_angles (QAngle: float[3])
            //   +0x1C: aim_direction (Vector: float[3])
            //   +0x28: forward_move (float)
            //   +0x2C: side_move (float)
            //   +0x30: up_move (float)
            //   +0x34: buttons (int32)   — IN_JUMP=2, IN_DUCK=4, etc.
            //   +0x38: impulse (int32)
            //   +0x3C: weapon_select (int32)
            //   +0x40: weapon_subtype (int32)
            //   +0x44: random_seed (int32)
            //   +0x48: mouse_dx (int16)
            //   +0x4A: mouse_dy (int16)
            //   ...

            auto& s = detour_settings;

            // --- Bhop ---
            if (s.bhop.enabled) {
                // Read buttons from CUserCmd+0x34
                // Read local player flags (FL_ONGROUND = 1 << 0 from m_fFlags at pawn+0x3C8)
                // If holding jump and on ground, force jump
                // (Implementation reads from process memory — placeholder here)
            }

            // --- Anti-Aim ---
            if (s.antiaim.enabled) {
                // Read current view angles from cmd+0x10
                // Modify yaw by yaw_offset + jitter
                // Set desync if enabled
                // Write back to cmd+0x10
            }

            // --- Silent Aim ---
            if (s.silent_aim.enabled) {
                // Override view angles in cmd to aim at best target
                // Read target positions from shared memory or memory
                // Compute aim angle, write to cmd+0x10
            }

            // --- Double Tap ---
            if (s.double_tap.enabled) {
                // Override tick_count to shift back
                // Set buttons |= IN_ATTACK
            }
        });
}

// FrameStageNotify handler: chams, world modulation, no flash
inline void RegisterFrameStageNotifyHandler() {
    DetourEngine::Instance().RegisterHandler(HOOK_FRAMESTAGENOTIFY,
        [](uint8_t /*hook_id*/, const HookContext& ctx) {
            // ctx.rcx = this (CClientState*)
            // ctx.rdx = frame_stage (int)
            // Frame stages:
            //   FRAME_UNDEFINED       = -1
            //   FRAME_START           = 0
            //   FRAME_NET_UPDATE_START = 1
            //   FRAME_NET_UPDATE_POSTDATAUPDATE = 2
            //   FRAME_NET_UPDATE_END  = 3
            //   FRAME_RENDER_START    = 4
            //   FRAME_RENDER_END      = 5
            //   FRAME_NET_FULL_FRAME_UPDATE_ON_REMOVE = 6

            int frame_stage = static_cast<int>(ctx.rdx);
            auto& s = detour_settings;

            if (frame_stage == 4) { // FRAME_RENDER_START
                // --- Chams ---
                if (s.chams.enabled) {
                    // Iterate entity list
                    // For each player entity:
                    //   - Read entity+0x28 (m_bIsVisible) or check spotted mask
                    //   - If visible_only and not visible/occluded, skip
                    //   - Override material at entity renderable
                    // Material override technique:
                    //   - Find "m_pMaterial" or "m_nRenderFX" in the entity
                    //   - Override IMatRenderContext::ForcedMaterialOverride
                    //   - Set color modulation
                    //   - Set alpha modulation
                }

                // --- No Flash ---
                if (s.world_mod.no_flash) {
                    // Override flash alpha: write 0.0f to local player's
                    // m_flFlashMaxAlpha, m_flFlashDuration
                }
            }

            if (frame_stage == 5) { // FRAME_RENDER_END
                // Restore materials
                // Reset IMatRenderContext::ForcedMaterialOverride to nullptr
            }

            if (frame_stage == 2) { // FRAME_NET_UPDATE_POSTDATAUPDATE
                // World modulation: night mode, ambient lighting
                if (s.world_mod.night_mode) {
                    // Set sv_skyname convar (via memory write to cvar value)
                    // Override CViewRender ambient light values
                }
            }
        });
}

// OverrideView handler: FOV, third person
inline void RegisterOverrideViewHandler() {
    DetourEngine::Instance().RegisterHandler(HOOK_OVERRIDEVIEW,
        [](uint8_t /*hook_id*/, const HookContext& ctx) {
            // ctx.rcx = this (CClientState*)
            // ctx.rdx = CViewSetup* (view setup struct)
            //
            // CViewSetup layout (simplified, CS2):
            //   +0x00: x, y (int[2])
            //   +0x08: width, height (int[2])
            //   +0x18: fov (float)
            //   +0x1C: fovViewmodel (float)
            //   +0x20: origin (Vector: float[3])
            //   +0x2C: angles (QAngle: float[3])
            //   +0x38: zNear (float)
            //   +0x3C: zFar (float)

            uintptr_t view_setup = static_cast<uintptr_t>(ctx.rdx);
            if (!view_setup) return;

            auto& s = detour_settings;

            // Override FOV
            if (s.view.fov_override) {
                // Write s.view.fov to view_setup+0x18
            }

            // Third person
            if (s.view.third_person) {
                // Set camera origin behind player
                // Compute: eye_origin - forward * tp_distance
                // Write to view_setup+0x20
            }
        });
}

// DrawSmokeVertex handler: no smoke
inline void RegisterDrawSmokeVertexHandler() {
    DetourEngine::Instance().RegisterHandler(HOOK_DRAWSMOKEVERTEX,
        [](uint8_t /*hook_id*/, const HookContext& ctx) {
            if (detour_settings::world_mod.no_smoke) {
                // The VEH handler sets RIP to trampoline when detour is active
                // The trampoline executes stolen bytes then jumps to original
                // To block smoke, we need to skip rendering
                // This is done by NOT calling original function:
                // The VEH handler should just return without redirecting
                // OR the trampoline should do an early ret

                // Since we can't easily skip execution from the external side,
                // the approach is: the external process writes a "block" flag
                // to the HookState in shared memory, and the shellcode's VEH
                // handler checks this flag. If block is set, the handler
                // sets ContextRecord->Rip to a simple "ret" gadget instead
                // of the trampoline.

                // Simplest approach: enable detour -> trampoline runs stolen
                // bytes + calls original function BUT we override the function's
                // behavior by writing to its data. For DrawSmokeVertex, we
                // can nop the function body entirely.
            }
        });
}

// FlashOverlay handler: no flash (alternative approach)
inline void RegisterFlashOverlayHandler() {
    DetourEngine::Instance().RegisterHandler(HOOK_FLASHOVERLAY,
        [](uint8_t /*hook_id*/, const HookContext& ctx) {
            if (detour_settings::world_mod.no_flash) {
                // Skip flash overlay rendering
                // Modify the flash alpha in CFlashBangEffect
            }
        });
}

// CalcViewModel handler: viewmodel FOV/position
inline void RegisterCalcViewModelHandler() {
    DetourEngine::Instance().RegisterHandler(HOOK_CALCVIEWMODEL,
        [](uint8_t /*hook_id*/, const HookContext& ctx) {
            auto& s = detour_settings;

            if (s.viewmodel.override_fov) {
                // Modify viewmodel FOV via the CViewSetup or model matrix
            }

            // Viewmodel position offset
            if (s.viewmodel.offset_x != 0.0f || s.viewmodel.offset_y != 0.0f || s.viewmodel.offset_z != 0.0f) {
                // Override viewmodel origin
                // This requires writing to the entity's origin before CalcViewModel runs
            }
        });
}

// DrawScopeOverlay handler: no scope overlay
inline void RegisterDrawScopeOverlayHandler() {
    DetourEngine::Instance().RegisterHandler(HOOK_DRAWSCOPEOVERLAY,
        [](uint8_t /*hook_id*/, const HookContext& ctx) {
            if (detour_settings::world_mod.no_scope) {
                // Block scope rendering — similar approach to no smoke
                // Either skip via VEH (set RIP to ret)
                // or nop the function body via WPM
            }
        });
}

// DrawLegs handler: for third person leg rendering
inline void RegisterDrawLegsHandler() {
    DetourEngine::Instance().RegisterHandler(HOOK_DRAWLEGS,
        [](uint8_t /*hook_id*/, const HookContext& ctx) {
            if (detour_settings::view.third_person) {
                // Force leg rendering in third person
                // The game normally hides legs in first person
                // We override the check that determines visibility
            }
        });
}

// ===================================================================
// Register all handlers
// ===================================================================
inline void RegisterAllDetourHandlers() {
    RegisterCreateMoveHandler();
    RegisterFrameStageNotifyHandler();
    RegisterOverrideViewHandler();
    RegisterDrawSmokeVertexHandler();
    RegisterFlashOverlayHandler();
    RegisterCalcViewModelHandler();
    RegisterDrawScopeOverlayHandler();
    RegisterDrawLegsHandler();
}

} // namespace hooks
