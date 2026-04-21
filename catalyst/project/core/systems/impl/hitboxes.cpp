#include <stdafx.hpp>

namespace systems {

	hitboxes::set hitboxes::query( std::uintptr_t game_scene_node ) const
	{
		set result{};

		const auto model_handle = g::memory.read<std::uintptr_t>( game_scene_node + 0x210 );
		if ( !model_handle )
		{
			return result;
		}

		const auto cmodel = g::memory.read<std::uintptr_t>( model_handle );
		if ( !cmodel )
		{
			return result;
		}

		const auto render_meshes = g::memory.read<std::uintptr_t>( g::memory.read<std::uintptr_t>( cmodel + 0x78 ) );
		if ( !render_meshes )
		{
			return result;
		}

		const auto hitbox_data = g::memory.read<std::uintptr_t>( render_meshes + 0x150 );
		if ( !hitbox_data )
		{
			return result;
		}

		const auto count = g::memory.read<int>( hitbox_data + 0x28 );
		if ( count <= 0 || count > 20 )
		{
			return result;
		}

		const auto array_ptr = g::memory.read<std::uintptr_t>( hitbox_data + 0x30 );
		if ( !array_ptr )
		{
			return result;
		}

		constexpr auto k_hitbox_stride{ 0x70 };

		std::array<std::byte, 20 * k_hitbox_stride> buffer{};
		if ( !g::memory.read( array_ptr, buffer.data( ), static_cast< std::size_t >( count ) * k_hitbox_stride ) )
		{
			return result;
		}

		for ( int i = 0; i < count; ++i )
		{
			if ( i < 0 || i >= static_cast< int >( std::size( this->k_bone_map ) ) )
			{
				continue;
			}

			const auto bone = this->k_bone_map[ i ];
			if ( bone == -1 )
			{
				continue;
			}

			const auto offset = i * k_hitbox_stride;
			const auto radius = *reinterpret_cast< const float* >( buffer.data( ) + offset + 0x30 );

			if ( radius < 0.0f || radius > 100.0f )
			{
				continue;
			}

			auto& hb = result.entries[ result.count++ ];
			hb.index = i;
			hb.bone = bone;
			hb.mins = *reinterpret_cast< const math::vector3* >( buffer.data( ) + offset + 0x18 );
			hb.maxs = *reinterpret_cast< const math::vector3* >( buffer.data( ) + offset + 0x24 );
			hb.radius = radius;
		}

		return result;
	}

	int hitboxes::hitgroup_from_hitbox( int hitbox ) const
	{
		switch ( hitbox )
		{
		case 0:
		case 1:  return 1;
		case 2:
		case 3:  return 3;
		case 4:
		case 5:  return 2;
		case 6:  return 3;
		case 7:
		case 9:
		case 11: return 4;
		case 8:
		case 10:
		case 12: return 5;
		case 13:
		case 15:
		case 17: return 6;
		case 14:
		case 16:
		case 18: return 7;
		default: return 2;
		}
	}

} // namespace systems