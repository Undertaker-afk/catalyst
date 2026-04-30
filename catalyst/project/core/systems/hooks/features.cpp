#include <stdafx.hpp>
#include "hooks.hpp"
#include "shm.hpp"

namespace systems {

	void hooks::update_features( )
	{
		if ( !this->m_shared_data ) return;

		shm::shared_data current{};

		// Global combat settings (Group 0)
		const auto& global_combat = settings::g_combat.groups[0];

		current.features.silent_aim = global_combat.aimbot.enabled;
		current.features.bhop_enabled = settings::g_misc.bhop;
		current.features.anti_aim = false; // Placeholder for future expansion
		current.features.double_tap = false; // Placeholder for future expansion

		current.features.chams_enabled = settings::g_esp.m_player.enabled;

		// Map visual colors to normalized floats for internal renderer
		const auto& col = settings::g_esp.m_player.m_box.visible_color;
		current.features.chams_color[0] = col.r / 255.0f;
		current.features.chams_color[1] = col.g / 255.0f;
		current.features.chams_color[2] = col.b / 255.0f;
		current.features.chams_color[3] = col.a / 255.0f;

		// Synchronize local player context
		current.data.local_pawn = systems::g_local.pawn();

		// Update the internal shared memory buffer in the target process
		std::uintptr_t remote_shm_ptr = 0;
		if ( g::memory.read( this->m_remote_shellcode_base + 0x80, &remote_shm_ptr, 8 ) ) {
			::WriteProcessMemory( g::memory.handle(), reinterpret_cast<void*>( remote_shm_ptr ), &current, sizeof(shm::shared_data), nullptr );
		}
	}

} // namespace systems
