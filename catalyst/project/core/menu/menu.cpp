#include <stdafx.hpp>

void menu::draw( )
{
	if ( GetAsyncKeyState( VK_INSERT ) & 1 )
	{
		this->m_open = !this->m_open;
	}

	if ( !this->m_open )
	{
		return;
	}

	zui::begin( );

	if ( zui::begin_window( "catalyst##main", this->m_x, this->m_y, this->m_w, this->m_h, true, 580.0f, 440.0f ) )
	{
		const auto [avail_w, avail_h] = zui::get_content_region_avail( );

		if ( zui::begin_nested_window( "##inner", avail_w, avail_h ) )
		{
			constexpr auto header_h{ 28.0f };
			constexpr auto padding{ 6.0f };

			zui::set_cursor_pos( padding, padding );
			this->draw_header( avail_w - padding * 2.0f, header_h );

			zui::set_cursor_pos( padding, padding + header_h + padding );
			this->draw_content( avail_w - padding * 2.0f, avail_h - header_h - padding * 3.0f );

			if ( const auto win = zui::detail::get_current_window( ) )
			{
				this->draw_accent_lines( win->bounds );
			}

			zui::end_nested_window( );
		}

		zui::end_window( );
	}

	zui::end( );
}

void menu::draw_header( float width, float height )
{
	if ( !zui::begin_nested_window( "##header", width, height ) )
	{
		return;
	}

	const auto current = zui::detail::get_current_window( );
	if ( !current )
	{
		zui::end_nested_window( );
		return;
	}

	const auto& style = zui::get_style( );
	const auto dt = zdraw::get_delta_time( );
	const auto bx = current->bounds.x;
	const auto by = current->bounds.y;
	const auto bw = current->bounds.w;
	const auto bh = current->bounds.h;

	zdraw::get_draw_list( ).add_rect_filled( bx, by, bw, bh, zdraw::rgba{ 14, 14, 14, 255 } );
	zdraw::get_draw_list( ).add_rect( bx, by, bw, bh, zdraw::rgba{ 38, 38, 38, 255 } );

	{
		constexpr auto title{ "catalyst" };
		auto [tw, th] = zdraw::measure_text( title );
		zdraw::get_draw_list( ).add_text( bx + 10.0f, by + ( bh - th ) * 0.5f, title, nullptr, style.accent );
	}

	static constexpr std::pair<const char*, tab> tabs[ ]
	{
		{ "combat", tab::combat },
		{ "esp",    tab::esp    },
		{ "misc",   tab::misc   },
		{ "config", tab::config },
	};

	constexpr auto tab_count = static_cast< int >( std::size( tabs ) );
	constexpr auto tab_spacing{ 16.0f };

	struct tab_anim { float v{ 0.0f }; };
	static std::array<tab_anim, tab_count> anims{};

	auto cursor_x = bx + bw - 10.0f;

	for ( int i = tab_count - 1; i >= 0; --i )
	{
		const auto& t = tabs[ i ];
		const auto is_sel = ( this->m_tab == t.second );
		auto [tw, th] = zdraw::measure_text( t.first );

		cursor_x -= tw;

		const auto tab_rect = zui::rect{ cursor_x, by, tw, bh };
		const auto hovered = zui::detail::mouse_hovered( tab_rect ) && !zui::detail::overlay_blocking_input( );

		if ( hovered && zui::detail::mouse_clicked( ) )
		{
			this->m_tab = t.second;
		}

		auto& anim = anims[ i ];
		anim.v += ( ( is_sel ? 1.0f : 0.0f ) - anim.v ) * std::min( 10.0f * dt, 1.0f );

		const auto text_y = by + ( bh - th ) * 0.5f;
		const auto col = is_sel ? zui::lighten( style.accent, 1.0f + 0.1f * anim.v ) : zui::lerp( zdraw::rgba{ 110, 110, 110, 255 }, style.text, hovered ? 1.0f : 0.0f );

		zdraw::get_draw_list( ).add_text( cursor_x, text_y, t.first, nullptr, col );

		cursor_x -= tab_spacing;
	}

	zui::end_nested_window( );
}

void menu::draw_content( float width, float height )
{
	zui::push_style_var( zui::style_var::window_padding_x, 10.0f );
	zui::push_style_var( zui::style_var::window_padding_y, 10.0f );

	if ( !zui::begin_nested_window( "##content", width, height ) )
	{
		zui::pop_style_var( 2 );
		return;
	}

	if ( const auto win = zui::detail::get_current_window( ) )
	{
		this->draw_accent_lines( win->bounds );
	}

	switch ( this->m_tab )
	{
	case tab::combat: this->draw_combat( ); break;
	case tab::esp:    this->draw_esp( );    break;
	case tab::misc:   this->draw_misc( );   break;
	case tab::config: this->draw_config( ); break;
	default: break;
	}

	zui::pop_style_var( 2 );
	zui::end_nested_window( );
}

void menu::draw_accent_lines( const zui::rect& bounds, float fade_ratio )
{
	const auto ix = bounds.x + 1.0f;
	const auto iw = bounds.w - 2.0f;
	const auto top_y = bounds.y + 1.0f;
	const auto bot_y = bounds.y + bounds.h - 2.0f;
	const auto accent = zui::get_accent_color( );
	const auto trans = zdraw::rgba{ accent.r, accent.g, accent.b, 0 };
	const auto fade_w = iw * fade_ratio;
	const auto solid_w = iw - fade_w * 2.0f;

	for ( const auto ly : { top_y, bot_y } )
	{
		zdraw::get_draw_list( ).add_rect_filled_multi_color( ix, ly, fade_w, 1.0f, trans, accent, accent, trans );
		zdraw::get_draw_list( ).add_rect_filled( ix + fade_w, ly, solid_w, 1.0f, accent );
		zdraw::get_draw_list( ).add_rect_filled_multi_color( ix + fade_w + solid_w, ly, fade_w, 1.0f, accent, trans, trans, accent );
	}
}

void menu::draw_combat( )
{
	const auto [avail_w, avail_h] = zui::get_content_region_avail( );
	const auto col_w = ( avail_w - 8.0f ) * 0.5f;
	const auto& style = zui::get_style( );

	{
		const auto win = zui::detail::get_current_window( );
		if ( win )
		{
			constexpr auto group_spacing{ 12.0f };
			constexpr auto bar_h{ 22.0f };
			auto gx = win->bounds.x + style.window_padding_x;
			const auto gy = win->bounds.y + win->cursor_y;

			for ( int i = 0; i < 7; ++i )
			{
				auto [tw, th] = zdraw::measure_text( k_weapon_groups[ i ] );
				const auto gr = zui::rect{ gx, gy, tw, bar_h };
				const auto hov = zui::detail::mouse_hovered( gr ) && !zui::detail::overlay_blocking_input( );

				if ( hov && zui::detail::mouse_clicked( ) )
				{
					this->m_weapon_group = i;
				}

				const auto sel = ( this->m_weapon_group == i );
				const auto col = sel ? zui::get_accent_color( ) : zui::lerp( zdraw::rgba{ 100, 100, 100, 255 }, style.text, hov ? 1.0f : 0.0f );

				zdraw::get_draw_list( ).add_text( gx, gy + ( bar_h - th ) * 0.5f, k_weapon_groups[ i ], nullptr, col );

				if ( sel )
				{
					const auto accent = zui::get_accent_color( );
					const auto trans = zdraw::rgba{ accent.r, accent.g, accent.b, 0 };
					const auto fade = tw * 0.3f;
					zdraw::get_draw_list( ).add_rect_filled_multi_color( gx, gy + bar_h - 2.0f, fade, 1.0f, trans, accent, accent, trans );
					zdraw::get_draw_list( ).add_rect_filled( gx + fade, gy + bar_h - 2.0f, tw - fade * 2.0f, 1.0f, accent );
					zdraw::get_draw_list( ).add_rect_filled_multi_color( gx + tw - fade, gy + bar_h - 2.0f, fade, 1.0f, accent, trans, trans, accent );
				}

				gx += tw + group_spacing;
			}

			win->cursor_y += bar_h + style.item_spacing_y;
			win->line_height = 0.0f;
		}
	}

	auto& cfg = settings::g_combat.groups[ this->m_weapon_group ];

	if ( this->m_weapon_group > 0 )
	{
		zui::checkbox( "override global settings", cfg.override_global );
		zui::separator( );
	}

	if ( zui::begin_group_box( "aimbot", col_w ) )
	{
		zui::checkbox( "enabled##ab", cfg.aimbot.enabled );
		zui::keybind( "key##ab", cfg.aimbot.key );

		zui::slider_int( "fov##ab", cfg.aimbot.fov, 1, 45 );
		zui::slider_int( "smoothing##ab", cfg.aimbot.smoothing, 0, 50 );
		zui::checkbox( "head only##ab", cfg.aimbot.head_only );
		zui::checkbox( "visible only##ab", cfg.aimbot.visible_only );

		if ( cfg.aimbot.visible_only )
		{
			zui::checkbox( "autowall##ab", cfg.aimbot.autowall );

			if ( zui::begin_popup( "##ab_aw_popup", 200.0f ) )
			{
				zui::slider_float( "min damage##ab", cfg.aimbot.min_damage, 1.0f, 100.0f, "%.0f" );
				zui::end_popup( );
			}
		}

		zui::checkbox( "predictive##ab", cfg.aimbot.predictive );
		zui::separator( );
		zui::checkbox( "draw fov##ab", cfg.aimbot.draw_fov );

		if ( zui::begin_popup( "##ab_tb_popup", 200.0f ) )
		{
			zui::color_picker( "color##ab", cfg.aimbot.fov_color );
			zui::end_popup( );
		}

		zui::end_group_box( );
	}

	zui::same_line( );

	if ( zui::begin_group_box( "triggerbot", col_w ) )
	{
		zui::checkbox( "enabled##tb", cfg.triggerbot.enabled );
		zui::keybind( "key##tb", cfg.triggerbot.key );
		zui::slider_float( "hitchance##tb", cfg.triggerbot.hitchance, 0.0f, 100.0f, "%.0f%%" );
		zui::slider_int( "delay (ms)##tb", cfg.triggerbot.delay, 0, 500 );
		zui::checkbox( "autowall##tb", cfg.triggerbot.autowall );

		if ( zui::begin_popup( "##tb_aw_popup", 200.0f ) )
		{
			zui::slider_float( "min damage##tb", cfg.triggerbot.min_damage, 1.0f, 100.0f, "%.0f" );
			zui::end_popup( );
		}

		zui::checkbox( "autostop##tb", cfg.triggerbot.autostop );

		if ( zui::begin_popup( "##tb_as_popup", 200.0f ) )
		{
			zui::checkbox( "early autostop##tb", cfg.triggerbot.early_autostop );
			zui::end_popup( );
		}

		zui::checkbox( "predictive##tb", cfg.triggerbot.predictive );
		zui::end_group_box( );
	}

	if ( zui::begin_group_box( "other", col_w ) )
	{
		zui::checkbox( "penetration crosshair##ot", cfg.other.penetration_crosshair );

		if ( zui::begin_popup( "##ot_colors_popup", 200.0f ) )
		{
			zui::color_picker( "can penetrate##ot", cfg.other.penetration_color_yes );
			zui::color_picker( "cannot penetrate##ot", cfg.other.penetration_color_no );
			zui::end_popup( );
		}

		zui::end_group_box( );
	}
}

void menu::draw_esp( )
{
	const auto [avail_w, avail_h] = zui::get_content_region_avail( );
	const auto col_w = ( avail_w - 8.0f ) * 0.5f;
	auto& p = settings::g_esp.m_player;

	if ( zui::begin_group_box( "players", col_w ) )
	{
		zui::checkbox( "enabled##pl", p.enabled );

		zui::checkbox( "box##bx", p.m_box.enabled );
		if ( zui::begin_popup( "##bx_popup", 200.0f ) )
		{
			constexpr const char* box_styles[ ]{ "full", "cornered" };
			auto bs = static_cast< int >( p.m_box.style );

			if ( zui::combo( "style##bx", bs, box_styles, 2 ) )
			{
				p.m_box.style = static_cast< settings::esp::player::box::style_type >( bs );
			}

			zui::checkbox( "fill##bx", p.m_box.fill );
			zui::checkbox( "outline##bx", p.m_box.outline );

			if ( p.m_box.style == settings::esp::player::box::style_type::cornered )
			{
				zui::slider_float( "corner len##bx", p.m_box.corner_length, 4.0f, 30.0f, "%.0f" );
			}

			zui::color_picker( "visible##bx", p.m_box.visible_color );
			zui::color_picker( "occluded##bx", p.m_box.occluded_color );
			zui::end_popup( );
		}

		zui::checkbox( "skeleton##sk", p.m_skeleton.enabled );
		if ( zui::begin_popup( "##sk_popup", 200.0f ) )
		{
			zui::slider_float( "thickness##sk", p.m_skeleton.thickness, 0.5f, 4.0f, "%.1f" );
			zui::color_picker( "visible##sk", p.m_skeleton.visible_color );
			zui::color_picker( "occluded##sk", p.m_skeleton.occluded_color );
			zui::end_popup( );
		}

		zui::checkbox( "health bar##hb", p.m_health_bar.enabled );
		if ( zui::begin_popup( "##hb_popup", 200.0f ) )
		{
			constexpr const char* hb_positions[ ]{ "left", "top", "bottom" };
			auto hbp = static_cast< int >( p.m_health_bar.position );

			if ( zui::combo( "position##hb", hbp, hb_positions, 3 ) )
			{
				p.m_health_bar.position = static_cast< settings::esp::player::health_bar::position_type >( hbp );
			}

			zui::checkbox( "outline##hb", p.m_health_bar.outline );
			zui::checkbox( "gradient##hb", p.m_health_bar.gradient );
			zui::checkbox( "show value##hb", p.m_health_bar.show_value );
			zui::color_picker( "full##hb", p.m_health_bar.full_color );
			zui::color_picker( "low##hb", p.m_health_bar.low_color );
			zui::color_picker( "background##hb", p.m_health_bar.background_color );
			zui::color_picker( "outline color##hb", p.m_health_bar.outline_color );
			zui::color_picker( "text color##hb", p.m_health_bar.text_color );
			zui::end_popup( );
		}

		zui::checkbox( "ammo bar##amb", p.m_ammo_bar.enabled );
		if ( zui::begin_popup( "##amb_popup", 200.0f ) )
		{
			constexpr const char* amb_positions[ ]{ "left", "top", "bottom" };
			auto abp = static_cast< int >( p.m_ammo_bar.position );

			if ( zui::combo( "position##amb", abp, amb_positions, 3 ) )
			{
				p.m_ammo_bar.position = static_cast< settings::esp::player::ammo_bar::position_type >( abp );
			}

			zui::checkbox( "outline##amb", p.m_ammo_bar.outline );
			zui::checkbox( "gradient##amb", p.m_ammo_bar.gradient );
			zui::checkbox( "show value##amb", p.m_ammo_bar.show_value );
			zui::color_picker( "full##amb", p.m_ammo_bar.full_color );
			zui::color_picker( "low##amb", p.m_ammo_bar.low_color );
			zui::color_picker( "background##amb", p.m_ammo_bar.background_color );
			zui::color_picker( "outline color##amb", p.m_ammo_bar.outline_color );
			zui::color_picker( "text color##amb", p.m_ammo_bar.text_color );
			zui::end_popup( );
		}

		zui::checkbox( "name##nm", p.m_name.enabled );
		if ( zui::begin_popup( "##nm_popup", 200.0f ) )
		{
			zui::color_picker( "color##nm", p.m_name.color );
			zui::end_popup( );
		}

		zui::checkbox( "weapon##wp", p.m_weapon.enabled );
		if ( zui::begin_popup( "##wp_popup", 200.0f ) )
		{
			constexpr const char* disp_types[ ]{ "text", "icon", "text + icon" };
			auto dt = static_cast< int >( p.m_weapon.display );

			if ( zui::combo( "display##wp", dt, disp_types, 3 ) )
			{
				p.m_weapon.display = static_cast< settings::esp::player::weapon::display_type >( dt );
			}

			zui::color_picker( "text color##wp", p.m_weapon.text_color );
			zui::color_picker( "icon color##wp", p.m_weapon.icon_color );
			zui::end_popup( );
		}

		zui::checkbox( "hitboxes##hx", p.m_hitboxes.enabled );
		if ( zui::begin_popup( "##hx_popup", 200.0f ) )
		{
			zui::checkbox( "fill##hx", p.m_hitboxes.fill );
			zui::checkbox( "outline##hx", p.m_hitboxes.outline );
			zui::color_picker( "visible##hx", p.m_hitboxes.visible_color );
			zui::color_picker( "occluded##hx", p.m_hitboxes.occluded_color );
			zui::end_popup( );
		}

		zui::checkbox( "info flags##if", p.m_info_flags.enabled );
		if ( zui::begin_popup( "##if_popup", 200.0f ) )
		{
			constexpr const char* flag_names[ ]{ "money", "armor", "kit", "scoped", "defusing", "flashed", "distance" };
			constexpr settings::esp::player::info_flags::flag flag_values[ ]{ settings::esp::player::info_flags::money, settings::esp::player::info_flags::armor, settings::esp::player::info_flags::kit, settings::esp::player::info_flags::scoped, settings::esp::player::info_flags::defusing, settings::esp::player::info_flags::flashed, settings::esp::player::info_flags::distance, };

			for ( int i = 0; i < 7; ++i )
			{
				auto active = p.m_info_flags.has( flag_values[ i ] );
				if ( zui::checkbox( flag_names[ i ], active ) )
				{
					if ( active )
					{
						p.m_info_flags.flags |= flag_values[ i ];
					}
					else
					{
						p.m_info_flags.flags &= ~flag_values[ i ];
					}
				}
			}

			zui::separator( );
			zui::color_picker( "money##if", p.m_info_flags.money_color );
			zui::color_picker( "armor##if", p.m_info_flags.armor_color );
			zui::color_picker( "kit##if", p.m_info_flags.kit_color );
			zui::color_picker( "scoped##if", p.m_info_flags.scoped_color );
			zui::color_picker( "defusing##if", p.m_info_flags.defusing_color );
			zui::color_picker( "flashed##if", p.m_info_flags.flashed_color );
			zui::color_picker( "distance##if", p.m_info_flags.distance_color );
			zui::end_popup( );
		}

		zui::end_group_box( );
	}

	zui::same_line( );

	if ( zui::begin_group_box( "items", col_w ) )
	{
		auto& it = settings::g_esp.m_item;
		zui::checkbox( "enabled##it", it.enabled );
		zui::slider_float( "max dist##it", it.max_distance, 5.0f, 150.0f, "%.0fm" );

		zui::checkbox( "icon##it", it.m_icon.enabled );
		if ( zui::begin_popup( "##it_icon_popup", 180.0f ) )
		{
			zui::color_picker( "color##it_icon", it.m_icon.color );
			zui::end_popup( );
		}

		zui::checkbox( "name##it", it.m_name.enabled );
		if ( zui::begin_popup( "##it_name_popup", 180.0f ) )
		{
			zui::color_picker( "color##it_name", it.m_name.color );
			zui::end_popup( );
		}

		zui::checkbox( "ammo##it", it.m_ammo.enabled );
		if ( zui::begin_popup( "##it_ammo_popup", 180.0f ) )
		{
			zui::color_picker( "color##it_ammo", it.m_ammo.color );
			zui::color_picker( "empty##it_ammo", it.m_ammo.empty_color );
			zui::end_popup( );
		}

		zui::separator( );

		auto& f = it.m_filters;
		constexpr const char* filter_items[ ]{ "rifles", "smgs", "shotguns", "snipers", "pistols", "heavy", "grenades", "utility" };
		static bool filter_selected[ 8 ]{ true, true, true, true, true, true, true, true };

		zui::multicombo( "filters##f", filter_selected, filter_items, 8 );

		f.rifles = filter_selected[ 0 ];
		f.smgs = filter_selected[ 1 ];
		f.shotguns = filter_selected[ 2 ];
		f.snipers = filter_selected[ 3 ];
		f.pistols = filter_selected[ 4 ];
		f.heavy = filter_selected[ 5 ];
		f.grenades = filter_selected[ 6 ];
		f.utility = filter_selected[ 7 ];
		zui::end_group_box( );
	}

	if ( zui::begin_group_box( "projectiles", col_w ) )
	{
		auto& pr = settings::g_esp.m_projectile;
		zui::checkbox( "enabled##pr", pr.enabled );
		zui::checkbox( "icon##pr", pr.show_icon );
		zui::checkbox( "name##pr", pr.show_name );
		zui::checkbox( "timer bar##pr", pr.show_timer_bar );
		zui::checkbox( "inferno bounds##pr", pr.show_inferno_bounds );

		if ( zui::begin_popup( "##pr_colors_popup", 200.0f ) )
		{
			zui::color_picker( "default##pr", pr.default_color );
			zui::color_picker( "he##pr", pr.color_he );
			zui::color_picker( "flash##pr", pr.color_flash );
			zui::color_picker( "smoke##pr", pr.color_smoke );
			zui::color_picker( "molotov##pr", pr.color_molotov );
			zui::color_picker( "decoy##pr", pr.color_decoy );
			zui::separator( );
			zui::color_picker( "timer high##pr", pr.timer_high_color );
			zui::color_picker( "timer low##pr", pr.timer_low_color );
			zui::color_picker( "bar background##pr", pr.bar_background );
			zui::end_popup( );
		}

		zui::end_group_box( );
	}
}

void menu::draw_misc( )
{
	const auto [avail_w, avail_h] = zui::get_content_region_avail( );
	const auto col_w = ( avail_w - 8.0f ) * 0.5f;

	if ( zui::begin_group_box( "main", col_w ) )
	{
		zui::checkbox( "bunnyhop##bh", settings::g_misc.bhop );
		zui::checkbox( "grenade prediction##gr", settings::g_misc.m_grenades.enabled );

		if ( zui::begin_popup( "##gr_popup", 200.0f ) )
		{
			zui::checkbox( "local only##gr", settings::g_misc.m_grenades.local_only );
			zui::color_picker( "color##gr", settings::g_misc.m_grenades.color );
			zui::end_popup( );
		}

		zui::checkbox( "limit fps##fps", settings::g_misc.limit_fps );

		if ( zui::begin_popup( "##fps_popup", 200.0f ) )
		{
			zui::slider_int( "fps limit##fps", settings::g_misc.fps_limit, 30, 1000 );
			zui::end_popup( );
		}

		zui::end_group_box( );
	}

	zui::same_line( );

	if ( zui::begin_group_box( "config", col_w ) )
	{
		zui::end_group_box( );
	}
}