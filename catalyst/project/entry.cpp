#include <stdafx.hpp>

#include <timeapi.h>
#pragma comment( lib, "winmm.lib" )

int main( )
{
	timeBeginPeriod( 1 );

	{
		if ( !g::console.initialize( " :> " ) )
		{
			return 1;
		}

		if ( !g::input.initialize( ) )
		{
			return 1;
		}

		if ( !g::memory.initialize( L"cs2.exe" ) )
		{
			return 1;
		}

		if ( !systems::g_hooks.initialize( ) )
		{
			return 1;
		}
	}

	{
		if ( !g::modules.initialize( ) )
		{
			return 1;
		}

		if ( !g::offsets.initialize( ) )
		{
			return 1;
		}
	}

	{
		std::thread( threads::game ).detach( );
		std::thread( threads::combat ).detach( );

		if ( !g::render.initialize( ) )
		{
			return 1;
		}
	}

	return 0;
}