#include <stdafx.hpp>
#include "hooks.hpp"

namespace features {

	namespace hooks {

		void bhop( )
		{
			// The internal shellcode handles the actual timing by checking flags
			// and modifying CUserCmd in real-time during the CreateMove hook.
		}

		void chams( )
		{
			// The internal shellcode intercepts Render calls.
			// External process sets material overrides in SHM.
		}

	}

}
