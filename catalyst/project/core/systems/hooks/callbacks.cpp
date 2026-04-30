#include <stdafx.hpp>
#include "hooks.hpp"
#include <core/features/features.hpp>

namespace systems {

	// This file now acts as the bridge for logic triggered by internal hooks
	// In a hybrid external/internal, we process data from SHM.

	void hooks::on_createmove( void* rcx, void* rdx )
	{
		// Internal logic (in shellcode) modifies CUserCmd for Bhop
		// External process can read/write SHM to influence this.
	}

} // namespace systems
