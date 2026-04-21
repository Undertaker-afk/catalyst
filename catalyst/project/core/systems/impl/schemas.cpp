#include <stdafx.hpp>

namespace systems {

	std::int32_t schemas::lookup( const char* class_name, std::uint32_t field_hash )
	{
		const auto class_info = this->find_class_binding( class_name );
		if ( !class_info )
		{
			return 0;
		}

		const auto field_count = g::memory.read<std::int16_t>( class_info + 0x24 );
		const auto fields_ptr = g::memory.read<std::uintptr_t>( class_info + 0x30 );

		if ( field_count <= 0 || !fields_ptr )
		{
			return 0;
		}

		for ( std::int16_t i = 0; i < field_count; ++i )
		{
			const auto field_addr = fields_ptr + static_cast< std::size_t >( i ) * 0x20;
			const auto name_ptr = g::memory.read<std::uintptr_t>( field_addr );

			if ( !name_ptr )
			{
				continue;
			}

			char name[ 256 ]{};
			g::memory.read( name_ptr, name, sizeof( name ) );

			if ( fnv1a::runtime_hash( name ) == field_hash )
			{
				return g::memory.read< std::int32_t >( field_addr + 0x10 );
			}
		}

		return 0;
	}

	std::uintptr_t schemas::find_class_binding( const char* class_name )
	{
		if ( !this->m_client_scope )
		{
			const auto schema_system = g::memory.find_vtable_instance( g::modules.schemasystem, "CSchemaSystem" );
			if ( !schema_system )
			{
				return 0;
			}

			const auto scope_count = g::memory.read<std::int32_t>( schema_system + 0x190 );
			const auto scope_data = g::memory.read<std::uintptr_t>( schema_system + 0x198 );

			if ( !scope_count || scope_count > 64 || !scope_data )
			{
				return 0;
			}

			for ( std::int32_t i = 0; i < scope_count; ++i )
			{
				const auto scope_ptr = g::memory.read<std::uintptr_t>( scope_data + i * sizeof( std::uintptr_t ) );
				if ( !scope_ptr )
				{
					continue;
				}

				char scope_name[ 32 ]{};
				g::memory.read( scope_ptr + 0x8, scope_name, sizeof( scope_name ) );

				if ( std::strcmp( scope_name, "client.dll" ) == 0 )
				{
					this->m_client_scope = scope_ptr;
					break;
				}
			}

			if ( !this->m_client_scope )
			{
				return 0;
			}
		}

		const auto name_hash = this->murmur2( class_name );
		const auto idx = this->bucket_index( name_hash );

		const auto bucket_addr = this->m_client_scope + 0x5c0 + static_cast< std::size_t >( idx ) * 24;
		const auto first = g::memory.read<std::uintptr_t>( bucket_addr );
		auto element = first;

		while ( element )
		{
			const auto key = g::memory.read<std::uint32_t>( element );
			if ( key == name_hash )
			{
				const auto data = g::memory.read<std::uintptr_t>( element + 16 );
				if ( data )
				{
					return data;
				}
			}

			element = g::memory.read<std::uintptr_t>( element + 8 );
		}

		const auto first_uncommitted = g::memory.read<std::uintptr_t>( bucket_addr + 16 );
		element = first_uncommitted;

		while ( element && element != first )
		{
			const auto key = g::memory.read<std::uint32_t>( element );
			if ( key == name_hash )
			{
				const auto data = g::memory.read<std::uintptr_t>( element + 16 );
				if ( data )
				{
					return data;
				}
			}

			element = g::memory.read<std::uintptr_t>( element + 8 );
		}

		return 0;
	}

	std::uint32_t schemas::murmur2( const char* str )
	{
		std::uint32_t len{ 0 };
		const auto data = reinterpret_cast< const std::uint8_t* >( str );

		while ( data[ len ] )
		{
			++len;
		}

		auto h = len ^ 0xBAADFEED;
		auto remaining = len;
		const auto* p = data;

		while ( remaining >= 4 )
		{
			auto k = *reinterpret_cast< const std::uint32_t* >( p );
			k *= 0x5BD1E995;
			k ^= k >> 24;
			k *= 0x5BD1E995;

			h *= 0x5BD1E995;
			h ^= k;

			p += 4;
			remaining -= 4;
		}

		switch ( remaining )
		{
		case 3: h ^= p[ 2 ] << 16; [[fallthrough]];
		case 2: h ^= p[ 1 ] << 8; [[fallthrough]];
		case 1: h ^= p[ 0 ];
			h *= 0x5BD1E995;
			break;
		}

		h ^= h >> 13;
		h *= 0x5BD1E995;
		h ^= h >> 15;

		return h;
	}

	std::uint8_t schemas::bucket_index( std::uint32_t hash )
	{
		auto v4 = ( 4097 * hash + 2127912214 ) ^ ( ( 4097 * hash + 2127912214 ) >> 19 ) ^ 0xC761C23C;
		auto v5 = ( 33 * v4 + 374761393 ) << 9;

		auto a = 9 * ( v5 ^ ( 33 * v4 - 369570787 ) ) - 42973499;
		auto b = ( a >> 16 ) ^ a ^ 0xB55A4F09;

		auto byte0 = static_cast< std::uint8_t >( ( a >> 16 ) ^ ( 9 * ( v5 ^ ( 33 * v4 + 29 ) ) - 59 ) );
		auto byte1 = static_cast< std::uint8_t >( b >> 16 );
		auto byte2 = static_cast< std::uint8_t >( ( static_cast< std::uint16_t >( ( a >> 16 ) ^ ( 9 * ( v5 ^ ( 33 * v4 - 13283 ) ) + 18117 ) ^ 0x4F09 ^ ( b >> 16 ) ) ) >> 8 );

		return byte0 ^ 9 ^ byte1 ^ byte2;
	}

} // namespace systems