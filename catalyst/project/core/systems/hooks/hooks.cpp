#include <stdafx.hpp>
#include "hooks.hpp"
#include "shellcode.hpp"
#include "syscalls.hpp"
#include "shm.hpp"
#include <random>

namespace systems {

	namespace detail {
		static constexpr std::uint32_t offset_shared_mem = 0x80;
		static constexpr std::uint32_t offset_ssn = 0x88;
		static constexpr std::uint32_t offset_rtl_add_veh = 0x90;
		static constexpr std::uint32_t offset_saved_rip = 0x98;
		static constexpr std::uint32_t offset_entry = 0xA0;
	}

	bool hooks::initialize( )
	{
		if ( this->m_initialized )
			return true;

		if ( !this->setup_shared_memory( ) )
		{
			g::console.print( "failed to setup shared memory for hooks." );
			return false;
		}

		if ( !this->inject_shellcode( ) )
		{
			g::console.print( "failed to inject hook shellcode." );
			return false;
		}

		this->add( "CreateMove", "client.dll", {0x48,0x8B,0xC4,0x4C,0x89,0x40,0x00,0x48,0x89,0x48,0x00,0x55,0x53,0x41,0x54}, "xxxxx?xx?xxx" );
		this->add( "Render", "scenesystem.dll", {0x48,0x8B,0xC4,0x53,0x57,0x41,0x54}, "xxxxxxx" );

		this->m_initialized = true;
		g::console.print( "hooks system initialized." );
		return true;
	}

	void hooks::shutdown( )
	{
		if ( !this->m_initialized )
			return;

		for ( auto& hook : this->m_hooks )
		{
			if ( hook.enabled )
				this->disable( hook.name );
		}

		if ( this->m_shared_data )
			::UnmapViewOfFile( this->m_shared_data );

		if ( this->m_shared_memory_handle )
			::CloseHandle( this->m_shared_memory_handle );

		this->m_initialized = false;
	}

	bool hooks::add( const std::string& name, const std::string& module_name, const std::vector<std::uint8_t>& pattern, const std::string& mask )
	{
		const auto module_base = g::memory.get_module( module_name );
		if ( !module_base ) return false;

		std::string pattern_str;
		for ( size_t i = 0; i < pattern.size(); ++i ) {
			if ( mask[i] == '?' ) pattern_str += "?? ";
			else pattern_str += std::format( "{:02X} ", pattern[i] );
		}

		const auto target = g::memory.find_pattern( module_base, pattern_str );
		if ( !target ) return false;

		this->m_hooks.push_back( { name, module_name, pattern, mask, target, false } );
		this->enable( name );
		return true;
	}

	bool hooks::disable( const std::string& name )
	{
		auto it = std::find_if( this->m_hooks.begin(), this->m_hooks.end(), [ & ]( const auto& h ) { return h.name == name; } );
		if ( it == this->m_hooks.end() || !it->enabled ) return false;

		DWORD old_prot;
		::VirtualProtectEx( g::memory.handle(), reinterpret_cast<void*>( it->target_address ), 1, PAGE_EXECUTE_READ, &old_prot );

		it->enabled = false;
		return true;
	}

	bool hooks::enable( const std::string& name )
	{
		auto it = std::find_if( this->m_hooks.begin(), this->m_hooks.end(), [ & ]( const auto& h ) { return h.name == name; } );
		if ( it == this->m_hooks.end() || it->enabled ) return false;

		const auto index = std::distance( this->m_hooks.begin(), it );
		if ( index >= shm::k_max_hooks ) return false;

		::WriteProcessMemory( g::memory.handle(), reinterpret_cast<void*>( this->m_remote_shellcode_base + 0x08 + (index * 8) ), &it->target_address, 8, nullptr );

		DWORD old;
		::VirtualProtectEx( g::memory.handle(), reinterpret_cast<void*>( it->target_address ), 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old );

		it->enabled = true;
		return true;
	}

	bool hooks::setup_shared_memory( )
	{
		std::string name = "Local\\";
		const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		std::default_random_engine rng( std::random_device{}() );
		std::uniform_int_distribution<> dist( 0, sizeof( charset ) - 2 );
		for ( int i = 0; i < 16; ++i ) name += charset[ dist( rng ) ];

		LARGE_INTEGER section_size = { .QuadPart = sizeof( shm::shared_data ) };
		this->m_shared_memory_handle = ::CreateFileMappingA( INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, section_size.HighPart, section_size.LowPart, name.c_str( ) );
		if ( !this->m_shared_memory_handle )
			return false;

		const auto raw_view = ::MapViewOfFile( this->m_shared_memory_handle, FILE_MAP_ALL_ACCESS, 0, 0, sizeof( shm::shared_data ) );
		if ( !raw_view )
		{
			::CloseHandle( this->m_shared_memory_handle );
			this->m_shared_memory_handle = nullptr;
			return false;
		}

		auto* data = static_cast<shm::shared_data*>(raw_view);
		data->magic = 0xCA7A1357;
		data->shellcode_ready.store(false);
		for (int i = 0; i < shm::k_max_hooks; ++i) {
			data->hooks[i].active.store(false);
			data->hooks[i].address = 0;
		}
		data->features.bhop_enabled = false;
		data->features.silent_aim = false;

		this->m_shared_data = data;
		return true;
	}

	bool hooks::hijack_thread( std::uintptr_t entry_point )
	{
		const auto snap = ::CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
		if ( snap == INVALID_HANDLE_VALUE ) return false;

		THREADENTRY32 te{ .dwSize = sizeof( THREADENTRY32 ) };
		DWORD target_tid = 0;
		const auto pid = ::GetProcessId( g::memory.handle( ) );

		if ( ::Thread32First( snap, &te ) )
		{
			do {
				if ( te.th32OwnerProcessID == pid ) {
					target_tid = te.th32ThreadID;
					break;
				}
			} while ( ::Thread32Next( snap, &te ) );
		}
		::CloseHandle( snap );

		if ( !target_tid ) return false;

		const auto thread = ::OpenThread( THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, target_tid );
		if ( !thread ) return false;

		::SuspendThread( thread );

		CONTEXT ctx{ .ContextFlags = CONTEXT_CONTROL };
		if ( ::GetThreadContext( thread, &ctx ) )
		{
			const auto old_rip = ctx.Rip;
			::WriteProcessMemory( g::memory.handle(), reinterpret_cast<void*>( this->m_remote_shellcode_base + detail::offset_saved_rip ), &old_rip, 8, nullptr );

			ctx.Rip = entry_point;
			::SetThreadContext( thread, &ctx );
		}

		::ResumeThread( thread );
		::CloseHandle( thread );
		return true;
	}

	bool hooks::inject_shellcode( )
	{
		const auto ntdll = g::memory.get_module( "ntdll.dll" );
		if ( !ntdll ) return false;

		const auto dos = g::memory.read<IMAGE_DOS_HEADER>( ntdll );
		const auto nt = g::memory.read<IMAGE_NT_HEADERS>( ntdll + dos.e_lfanew );
		const auto exp_dir_rva = nt.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
		const auto exp = g::memory.read<IMAGE_EXPORT_DIRECTORY>( ntdll + exp_dir_rva );
		const auto names = ntdll + exp.AddressOfNames;
		const auto ordinals = ntdll + exp.AddressOfNameOrdinals;
		const auto functions = ntdll + exp.AddressOfFunctions;

		std::uintptr_t rtl_add_veh = 0;
		for ( std::uint32_t i = 0; i < exp.NumberOfNames; ++i ) {
			if ( g::memory.read_string( ntdll + g::memory.read<std::uint32_t>( names + i * 4 ) ) == "RtlAddVectoredExceptionHandler" ) {
				rtl_add_veh = ntdll + g::memory.read<std::uint32_t>( functions + g::memory.read<std::uint16_t>( ordinals + i * 2 ) * 4 );
				break;
			}
		}

		if ( !rtl_add_veh ) return false;

		const auto nt_protect_ssn = syscalls::resolve( "NtProtectVirtualMemory" );

		this->m_remote_shellcode_base = reinterpret_cast<std::uintptr_t>( ::VirtualAllocEx( g::memory.handle( ), nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
		if ( !this->m_remote_shellcode_base ) return false;

		HANDLE remote_handle;
		if ( !::DuplicateHandle( ::GetCurrentProcess( ), this->m_shared_memory_handle, g::memory.handle( ), &remote_handle, 0, FALSE, DUPLICATE_SAME_ACCESS ) )
			return false;

		const auto remote_shm_addr = reinterpret_cast<std::uintptr_t>( ::VirtualAllocEx( g::memory.handle( ), nullptr, sizeof( shm::shared_data ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );
		if ( !remote_shm_addr ) return false;

		std::vector<std::uint8_t> buffer( std::begin( shellcode::veh_shellcode ), std::end( shellcode::veh_shellcode ) );

		std::memcpy( buffer.data( ) + detail::offset_shared_mem, &remote_shm_addr, 8 );
		std::memcpy( buffer.data( ) + detail::offset_ssn, &nt_protect_ssn, 2 );
		std::memcpy( buffer.data( ) + detail::offset_rtl_add_veh, &rtl_add_veh, 8 );

		if ( !::WriteProcessMemory( g::memory.handle( ), reinterpret_cast<void*>( this->m_remote_shellcode_base ), buffer.data( ), buffer.size( ), nullptr ) )
			return false;

		DWORD old;
		::VirtualProtectEx( g::memory.handle( ), reinterpret_cast<void*>( this->m_remote_shellcode_base ), buffer.size( ), PAGE_EXECUTE_READ, &old );

		return this->hijack_thread( this->m_remote_shellcode_base + detail::offset_entry );
	}

} // namespace systems
