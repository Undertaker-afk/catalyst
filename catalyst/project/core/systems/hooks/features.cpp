#include <stdafx.hpp>
#include "hooks.hpp"
#include "shm.hpp"

namespace systems {

	void hooks::update_features( )
	{
		if ( !this->m_shared_data ) return;

		shm::shared_data current{};

		// Global settings from combat group 0
		const auto& global_combat = settings::g_combat.groups[0];

		// Map feature settings to shared data
		current.features.silent_aim = global_combat.aimbot.enabled;
		current.features.bhop_enabled = settings::g_misc.bhop;
		current.features.anti_aim = false; // Internal AA logic is currently a stub in assembly
		current.features.double_tap = false; // Internal DT logic is currently a stub in assembly
		current.features.chams_enabled = settings::g_esp.m_player.enabled;
		current.features.world_modulation = false;

		// Map visual colors for internal use
		const auto& col = settings::g_esp.m_player.m_box.visible_color;
		current.features.chams_color[0] = col.r / 255.0f;
		current.features.chams_color[1] = col.g / 255.0f;
		current.features.chams_color[2] = col.b / 255.0f;
		current.features.chams_color[3] = col.a / 255.0f;

		// Sync game data for internal logic
		current.data.local_pawn = systems::g_local.pawn();
		// In a production environment, these should be resolved from offsets system
		current.data.m_fFlags = 0x3CC;
		current.data.m_pButtons = 0x40;

		// Update the remote shared memory buffer
		std::uintptr_t remote_shm_ptr = 0;
		if ( g::memory.read( this->m_remote_shellcode_base + 0x80, &remote_shm_ptr, 8 ) ) {
			::WriteProcessMemory( g::memory.handle(), reinterpret_cast<void*>( remote_shm_ptr ), &current, sizeof(shm::shared_data), nullptr );
		}
	}

} // namespace systems
