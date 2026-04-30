#include <stdafx.hpp>
#include "syscalls.hpp"
#include <mutex>

namespace systems {

	std::uint16_t syscalls::resolve( std::string_view name )
	{
		const auto hash = fnv1a::hash( name.data() );

		static std::unordered_map<std::uint64_t, std::uint16_t> cache;
		static std::mutex cache_mutex;

		{
			std::lock_guard lock( cache_mutex );
			if ( cache.contains( hash ) )
				return cache[ hash ];
		}

		const auto ntdll = g::memory.get_module( "ntdll.dll" );
		if ( !ntdll ) return 0;

		const auto dos = g::memory.read<IMAGE_DOS_HEADER>( ntdll );
		const auto nt = g::memory.read<IMAGE_NT_HEADERS>( ntdll + dos.e_lfanew );
		const auto exp_dir_rva = nt.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
		const auto exp = g::memory.read<IMAGE_EXPORT_DIRECTORY>( ntdll + exp_dir_rva );

		const auto names = ntdll + exp.AddressOfNames;
		const auto ordinals = ntdll + exp.AddressOfNameOrdinals;
		const auto functions = ntdll + exp.AddressOfFunctions;

		for ( std::uint32_t i = 0; i < exp.NumberOfNames; ++i )
		{
			const auto name_rva = g::memory.read<std::uint32_t>( names + i * 4 );
			const auto name_str = g::memory.read_string( ntdll + name_rva );

			if ( fnv1a::hash( name_str.c_str() ) == hash )
			{
				const auto ordinal = g::memory.read<std::uint16_t>( ordinals + i * 2 );
				const auto func_rva = g::memory.read<std::uint32_t>( functions + ordinal * 4 );
				const auto stub = ntdll + func_rva;

				for ( std::uint32_t j = 0; j < 32; ++j )
				{
					if ( g::memory.read<std::uint8_t>( stub + j ) == 0xB8 )
					{
						const auto ssn = g::memory.read<std::uint16_t>( stub + j + 1 );

						std::lock_guard lock( cache_mutex );
						cache[ hash ] = ssn;
						return ssn;
					}
				}
			}
		}

		return 0;
	}

} // namespace systems
