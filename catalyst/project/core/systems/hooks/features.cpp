#include <stdafx.hpp>
#include "hooks.hpp"
#include "shm.hpp"

namespace systems {

	void hooks::update_features( )
	{
		if ( !this->m_shared_data ) return;

		shm::shared_data current_features{};
		current_features.features.bhop_enabled = settings::misc::bhop;
		current_features.features.silent_aim = settings::combat::aimbot::enabled;

		std::uintptr_t remote_shm_ptr = 0;
		if ( g::memory.read( this->m_remote_shellcode_base + 0x80, &remote_shm_ptr, 8 ) ) {
			::WriteProcessMemory( g::memory.handle(), reinterpret_cast<void*>( remote_shm_ptr ), &current_features.features, sizeof(current_features.features), nullptr );
		}
	}

} // namespace systems
