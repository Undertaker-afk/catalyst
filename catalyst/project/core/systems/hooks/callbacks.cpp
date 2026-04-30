#include <stdafx.hpp>
#include "hooks.hpp"
#include <core/features/features.hpp>

namespace systems {

	void hooks::on_createmove( void* rcx, void* rdx )
	{
		// This will be called (ideally) from the internal context or
		// via data captured by the hook.

		// For external catalyst, we might just use the hook to sync timing
		// or read the CUserCmd that we intercepted.

		if ( settings::misc::bhop )
		{
			// Bhop logic using intercepted CUserCmd
		}
	}

} // namespace systems
