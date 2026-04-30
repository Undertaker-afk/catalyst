#include <stdafx.hpp>
#include "hooks.hpp"
#include <core/features/features.hpp>

namespace systems {

	void hooks::on_createmove( void* rcx, void* rdx )
	{
		// The internal shellcode in catalyst/project/core/systems/hooks/shellcode.hpp
		// handles the modification of CUserCmd for features like Bhop and Silent Aim.
		// This callback can be used to perform additional external processing if required.
		this->update_features();
	}

} // namespace systems
