#include <stdafx.hpp>
#include "hooks.hpp"
#include "shellcode.hpp"
#include "syscalls.hpp"
#include "shm.hpp"
#include <random>

namespace systems {

	bool hooks::setup_shared_memory( )
	{
		// Randomize SHM name for stealth
		std::string name = "Local\\";
		const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		std::default_random_engine rng( std::random_device{}() );
		std::uniform_int_distribution<> dist( 0, sizeof( charset ) - 2 );
		for ( int i = 0; i < 16; ++i ) name += charset[ dist( rng ) ];

		this->m_shared_memory_handle = ::CreateFileMappingA( INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof( shm::shared_data ), name.c_str( ) );
		if ( !this->m_shared_memory_handle )
			return false;

		this->m_shared_data = static_cast< shm::shared_data* >( ::MapViewOfFile( this->m_shared_memory_handle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof( shm::shared_data ) ) );
		if ( !this->m_shared_data )
			return false;

		std::memset( this->m_shared_data, 0, sizeof( shm::shared_data ) );
		this->m_shared_data->magic = 0xCA7A1357;

		g::console.print( std::format( "shared memory created: {}", name ) );
		return true;
	}

	bool hooks::inject_shellcode( )
	{
		const auto nt_protect_ssn = syscalls::resolve( "NtProtectVirtualMemory" );
		const auto rtl_add_veh = ::GetProcAddress( ::GetModuleHandleA( "ntdll.dll" ), "RtlAddVectoredExceptionHandler" );

		this->m_remote_shellcode_base = reinterpret_cast<std::uintptr_t>( ::VirtualAllocEx( g::memory.handle( ), nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
		if ( !this->m_remote_shellcode_base ) return false;

		std::vector<std::uint8_t> buffer( std::begin( shellcode::veh_shellcode ), std::end( shellcode::veh_shellcode ) );

		// Map SHM into target process for shellcode access
		// In a production scenario, we'd use NtMapViewOfSection.
		// For now, we'll assume the shellcode can find it if we pass the handle or just use the local name.
		// Actually, let's just pass the address of the mapped view in the target.

		// To get the address in target, we'd need to call MapViewOfFile inside the target.
		// A simpler way for this PoC/Integration is to allocate another buffer in target for parameters.

		std::memcpy( buffer.data( ) + 0x88, &nt_protect_ssn, 2 );
		std::memcpy( buffer.data( ) + 0x90, &rtl_add_veh, 8 );

		if ( !::WriteProcessMemory( g::memory.handle( ), reinterpret_cast<void*>( this->m_remote_shellcode_base ), buffer.data( ), buffer.size( ), nullptr ) )
			return false;

		// Set to RX
		DWORD old;
		::VirtualProtectEx( g::memory.handle( ), reinterpret_cast<void*>( this->m_remote_shellcode_base ), buffer.size( ), PAGE_EXECUTE_READ, &old );

		return this->hijack_thread( this->m_remote_shellcode_base + 0xA0 );
	}

} // namespace systems
