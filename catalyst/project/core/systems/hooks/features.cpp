#include <stdafx.hpp>
#include "hooks.hpp"
#include "shm.hpp"

namespace systems {

	void hooks::update_features( )
	{
		if ( !this->m_shared_data ) return;

		this->m_shared_data->features.bhop_enabled = settings::misc::bhop;
		// Update more features here
	}

} // namespace systems
