#include <stdafx.hpp>
#include "hooks.hpp"

namespace features {

	namespace hooks {

		void bhop( )
		{
			// The internal shellcode in catalyst/project/core/systems/hooks/shellcode.hpp
			// handles the real-time logic for Bhop by modifying CUserCmd bits.
			// This C++ function ensures the setting is synchronized.
			systems::g_hooks.update_features();
		}

		void chams( )
		{
			// The internal shellcode intercepts Render calls.
			// Material properties are synced via SHM to the internal context.
			systems::g_hooks.update_features();
		}

	}

}
