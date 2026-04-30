#include <stdafx.hpp>
#include "hooks.hpp"
#include "shm.hpp"
#include "syscalls.hpp"

namespace systems {

	bool hooks::enable( const std::string& name )
	{
		auto it = std::find_if( this->m_hooks.begin(), this->m_hooks.end(), [ & ]( const auto& h ) { return h.name == name; } );
		if ( it == this->m_hooks.end() ) return false;
		if ( it->enabled ) return true;

		const auto index = std::distance( this->m_hooks.begin(), it );
		if ( index >= 15 ) return false;

		// Write address to shellcode slot
		::WriteProcessMemory( g::memory.handle(), reinterpret_cast<void*>( this->m_remote_shellcode_base + 0x08 + (index * 8) ), &it->target_address, 8, nullptr );

		// Set PAGE_GUARD
		DWORD old;
		::VirtualProtectEx( g::memory.handle(), reinterpret_cast<void*>( it->target_address ), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old );

		it->enabled = true;
		return true;
	}

} // namespace systems
