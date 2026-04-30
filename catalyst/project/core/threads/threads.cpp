#include <stdafx.hpp>

namespace threads {

	void game( )
	{
		std::string last_map{};

		std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );

		while ( true )
		{
			systems::g_local.update( );

			if ( systems::g_local.valid( ) )
			{
				systems::g_entities.refresh( );
				systems::g_collector.run( );

				const auto global_vars = g::memory.read<std::uintptr_t>( g::offsets.global_vars );
				if ( global_vars )
				{
					const auto map_ptr = g::memory.read<std::uintptr_t>( global_vars + 0x188 );
					const auto current_map = map_ptr ? g::memory.read_string( map_ptr ) : std::string{};

					if ( !current_map.empty( ) && current_map != "<empty>" && current_map != last_map ) 
					{
						g::console.print( "map change: {} -> {}", last_map.empty( ) ? "none" : last_map, current_map );
						last_map = current_map;
						systems::g_bvh.clear( );
						g::console.print( "parsing bvh for {}...", current_map );
						systems::g_bvh.parse( );
						g::console.success( "bvh parsed." );
					}
				}
			}
			else
			{
				if ( !last_map.empty( ) )
				{
					last_map = {};
					systems::g_bvh.clear( );
				}
			}

			std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
		}
	}

	void combat( )
	{
		constexpr auto target_tps{ 128 };
		constexpr auto tick_interval = std::chrono::nanoseconds( 1'000'000'000 / target_tps );
		auto next_tick = std::chrono::steady_clock::now( );

		while ( true )
		{
			if ( systems::g_local.valid( ) && systems::g_bvh.valid( ) )
			{
				features::combat::g_shared.tick( );
				features::combat::g_legit.tick( );
			}

			next_tick += tick_interval;

			const auto now = std::chrono::steady_clock::now( );
			if ( next_tick < now )
			{
				next_tick = now;
				continue;
			}

			std::this_thread::sleep_until( next_tick - std::chrono::milliseconds( 1 ) );

			while ( std::chrono::steady_clock::now( ) < next_tick )
			{
				_mm_pause( );
			}
		}
	}

	void hooks( )
	{
		// Wait for game to initialize subsystems first
		std::this_thread::sleep_for( std::chrono::milliseconds( 2000 ) );

		auto& mgr = hooks::HookManager::Instance( );

		if ( !mgr.Initialize( g::memory.handle( ) ) )
		{
			g::console.print( "hook manager init failed" );
			return;
		}

		g::console.success( "hook manager initialized" );

		// Register all detour feature handlers
		hooks::RegisterAllDetourHandlers( );

		// Install hooks for core features
		const auto install_hook = [ & ]( uint8_t hook_id, bool detour, const char* name ) {
			auto* pattern = hooks::patterns::FindPatternByHookID( hook_id );
			if ( !pattern ) return;

			auto callback = []( uint8_t id, const hooks::HookContext& ctx ) {
				hooks::DetourEngine::Instance( ).ProcessEvent( id, ctx );
			};

			if ( mgr.InstallHook( hook_id, detour, callback ) )
			{
				g::console.success( "hook installed: {}", name );
			}
			else
			{
				g::console.print( "hook failed: {}", name );
			}
		};

		// Install CreateMove (always needed for bhop/antiaim/silent aim/doubletap)
		install_hook( hooks::HOOK_CREATEMOVE, true, "CreateMove" );

		// Install FrameStageNotify (needed for chams/world modulation/no flash)
		install_hook( hooks::HOOK_FRAMESTAGENOTIFY, true, "FrameStageNotify" );

		// Install OverrideView (FOV/third person)
		install_hook( hooks::HOOK_OVERRIDEVIEW, true, "OverrideView" );

		// Install world modulation hooks
		install_hook( hooks::HOOK_DRAWSMOKEVERTEX, true, "DrawSmokeVertex" );
		install_hook( hooks::HOOK_FLASHOVERLAY, true, "FlashOverlay" );
		install_hook( hooks::HOOK_DRAWSCOPEOVERLAY, true, "DrawScopeOverlay" );

		// Install viewmodel hook
		install_hook( hooks::HOOK_CALCVIEWMODEL, true, "CalcViewModel" );

		// Install DrawLegs (third person leg rendering)
		install_hook( hooks::HOOK_DRAWLEGS, true, "DrawLegs" );

		// Main polling loop — polls for hook events and dispatches
		while ( true )
		{
			mgr.ProcessEvents( );

			// Sync detour settings -> detour_settings (in detour.hpp)
			const auto& s = settings::g_hooks;
			hooks::detour_settings::bhop         = { s.bhop.enabled, s.bhop.hit_chance, s.bhop.min_hops, s.bhop.max_hops };
			hooks::detour_settings::antiaim      = { s.antiaim.enabled, s.antiaim.pitch, s.antiaim.yaw_offset, s.antiaim.yaw_jitter, s.antiaim.desync, s.antiaim.desync_amt };
			hooks::detour_settings::silent_aim   = { s.silent_aim.enabled, s.silent_aim.fov, s.silent_aim.autowall, s.silent_aim.min_damage };
			hooks::detour_settings::double_tap   = { s.double_tap.enabled, s.double_tap.shift_ticks };
			hooks::detour_settings::chams        = { s.chams.enabled, s.chams.visible_only, s.chams.wireframe, s.chams.flat, s.chams.visible_color.r / 255.0f, s.chams.visible_color.g / 255.0f, s.chams.visible_color.b / 255.0f, s.chams.visible_color.a / 255.0f, s.chams.occluded_color.r / 255.0f, s.chams.occluded_color.g / 255.0f, s.chams.occluded_color.b / 255.0f, s.chams.occluded_color.a / 255.0f };
			hooks::detour_settings::world_mod    = { s.world_mod.no_smoke, s.world_mod.no_flash, s.world_mod.no_scope, s.world_mod.night_mode, s.world_mod.ambient_r / 255.0f, s.world_mod.ambient_g / 255.0f, s.world_mod.ambient_b / 255.0f };
			hooks::detour_settings::view         = { s.view.fov_override, s.view.fov, s.view.third_person, s.view.tp_distance };
			hooks::detour_settings::viewmodel    = { s.viewmodel.override_fov, s.viewmodel.fov, s.viewmodel.offset_x, s.viewmodel.offset_y, s.viewmodel.offset_z };

			// Update detour active states based on settings
			mgr.SetDetourActive( hooks::HOOK_CREATEMOVE,
				s.bhop.enabled || s.antiaim.enabled || s.silent_aim.enabled || s.double_tap.enabled );
			mgr.SetDetourActive( hooks::HOOK_FRAMESTAGENOTIFY,
				s.chams.enabled || s.world_mod.no_flash || s.world_mod.night_mode );
			mgr.SetDetourActive( hooks::HOOK_OVERRIDEVIEW,
				s.view.fov_override || s.view.third_person );
			mgr.SetDetourActive( hooks::HOOK_DRAWSMOKEVERTEX, s.world_mod.no_smoke );
			mgr.SetDetourActive( hooks::HOOK_FLASHOVERLAY, s.world_mod.no_flash );
			mgr.SetDetourActive( hooks::HOOK_DRAWSCOPEOVERLAY, s.world_mod.no_scope );
			mgr.SetDetourActive( hooks::HOOK_CALCVIEWMODEL,
				s.viewmodel.override_fov || s.viewmodel.offset_x != 0.0f || s.viewmodel.offset_y != 0.0f || s.viewmodel.offset_z != 0.0f );
			mgr.SetDetourActive( hooks::HOOK_DRAWLEGS, s.view.third_person );

			std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
		}
	}

} // namespace threads