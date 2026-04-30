#include <stdafx.hpp>
#include <fstream>
#include <filesystem>

void menu::draw_config( )
{
	const auto [avail_w, avail_h] = zui::get_content_region_avail( );
	const auto col_w = ( avail_w - 8.0f ) * 0.5f;

	if ( zui::begin_group_box( "management", col_w ) )
	{
		static std::string cfg_name = "default";
		zui::text_input( "name##cfg", cfg_name );

		if ( zui::button( "save##cfg", col_w - 20.0f, 24.0f ) )
		{
			std::ofstream out( cfg_name + ".bin", std::ios::binary );
			if ( out.is_open( ) )
			{
				out.write( reinterpret_cast< const char* >( &settings::g_combat ), sizeof( settings::combat ) );
				out.write( reinterpret_cast< const char* >( &settings::g_esp ), sizeof( settings::esp ) );
				out.write( reinterpret_cast< const char* >( &settings::g_misc ), sizeof( settings::misc ) );
				out.close( );
				g::console.print( "config saved." );
			}
		}

		if ( zui::button( "load##cfg", col_w - 20.0f, 24.0f ) )
		{
			std::ifstream in( cfg_name + ".bin", std::ios::binary );
			if ( in.is_open( ) )
			{
				in.read( reinterpret_cast< char* >( &settings::g_combat ), sizeof( settings::combat ) );
				in.read( reinterpret_cast< char* >( &settings::g_esp ), sizeof( settings::esp ) );
				in.read( reinterpret_cast< char* >( &settings::g_misc ), sizeof( settings::misc ) );
				in.close( );
				g::console.print( "config loaded." );
			}
		}

		zui::end_group_box( );
	}

	zui::same_line( );

	if ( zui::begin_group_box( "files", col_w ) )
	{
		for ( const auto& entry : std::filesystem::directory_iterator( "." ) )
		{
			if ( entry.path( ).extension( ) == ".bin" )
			{
				const auto name = entry.path( ).stem( ).string( );
				zui::text( name );
			}
		}
		zui::end_group_box( );
	}
}
