#pragma once

namespace settings {

	struct combat
	{
		struct aimbot
		{
			bool enabled{ true };
			int key{ VK_XBUTTON2 };

			int fov{ 5 };
			int smoothing{ 5 };

			bool autowall{ true };
			float min_damage{ 90.0f };

			bool head_only{ true };
			bool visible_only{ true };

			bool draw_fov{ true };
			zdraw::rgba fov_color{ 225, 225, 225, 125 };

			bool predictive{ true };
		};

		struct triggerbot
		{
			bool enabled{ true };
			int key{ VK_XBUTTON2 };

			float hitchance{ 75.0f };
			int delay{ 10 };

			bool autowall{ true };
			float min_damage{ 90.0f };

			bool autostop{ false };
			bool early_autostop{ false };

			bool predictive{ true };
		};

		struct other
		{
			bool penetration_crosshair{ true };

			zdraw::rgba penetration_color_yes{ 50, 255, 50, 125 };
			zdraw::rgba penetration_color_no{ 255, 50, 50, 125 };
		};

		struct group_config
		{
			bool override_global{ false };
			aimbot aimbot{};
			triggerbot triggerbot{};
			other other{};
		};

		static constexpr std::uint32_t k_group_count{ 7 }; // +1 for global

		std::array<group_config, k_group_count> groups{};

		group_config& get( std::uint32_t weapon_type )
		{
			const auto idx = weapon_type - cstypes::pistol + 1;
			auto& group = this->groups[ idx < k_group_count ? idx : 3 ];
			return group.override_global ? group : this->groups[ 0 ];
		}

		const group_config& get( std::uint32_t weapon_type ) const
		{
			const auto idx = weapon_type - cstypes::pistol;
			return this->groups[ idx < k_group_count ? idx : 2 ];
		}
	};

	struct esp
	{
		struct player
		{
			bool enabled{ true };

			struct box
			{
				enum class style_type : std::uint8_t { full, cornered };

				bool enabled{ true };
				style_type style{ style_type::cornered };
				bool fill{ true };
				bool outline{ true };
				float corner_length{ 10.0f };

				zdraw::rgba visible_color{ 140, 150, 235, 255 };
				zdraw::rgba occluded_color{ 110, 115, 170, 180 };
			} m_box{};

			struct skeleton
			{
				bool enabled{ true };
				float thickness{ 1.0f };

				zdraw::rgba visible_color{ 170, 175, 220, 255 };
				zdraw::rgba occluded_color{ 130, 135, 180, 180 };
			} m_skeleton{};

			struct hitboxes
			{
				bool enabled{ false };

				zdraw::rgba visible_color{ 150, 160, 240, 10 };
				zdraw::rgba occluded_color{ 115, 120, 185, 10 };

				bool fill{ true };
				bool outline{ true };
			} m_hitboxes{};

			struct health_bar
			{
				enum class position_type : std::uint8_t { left, top, bottom };

				bool enabled{ true };
				position_type position{ position_type::left };
				bool outline{ true };
				bool gradient{ true };
				bool show_value{ true };

				zdraw::rgba full_color{ 140, 150, 235, 255 };
				zdraw::rgba low_color{ 75, 80, 180, 255 };
				zdraw::rgba background_color{ 15, 16, 22, 150 };
				zdraw::rgba outline_color{ 15, 16, 22, 255 };
				zdraw::rgba text_color{ 195, 200, 215, 255 };
			} m_health_bar{};

			struct ammo_bar
			{
				enum class position_type : std::uint8_t { left, top, bottom };

				bool enabled{ true };
				position_type position{ position_type::bottom };
				bool outline{ true };
				bool gradient{ true };
				bool show_value{ false };

				zdraw::rgba full_color{ 140, 150, 235, 255 };
				zdraw::rgba low_color{ 75, 80, 180, 255 };
				zdraw::rgba background_color{ 15, 16, 22, 150 };
				zdraw::rgba outline_color{ 15, 16, 22, 255 };
				zdraw::rgba text_color{ 195, 200, 215, 255 };
			} m_ammo_bar{};

			struct info_flags
			{
				enum flag : std::uint8_t
				{
					none = 0,
					money = 1 << 0,
					armor = 1 << 1,
					kit = 1 << 2,
					scoped = 1 << 3,
					defusing = 1 << 4,
					flashed = 1 << 5,
					ping = 1 << 6,
					distance = 1 << 7
				};

				bool enabled{ true };
				std::uint8_t flags{ flag::money | flag::armor | flag::kit | flag::scoped | flag::defusing | flag::flashed | flag::ping };

				zdraw::rgba money_color{ 120, 230, 160, 255 };
				zdraw::rgba armor_color{ 195, 200, 215, 255 };
				zdraw::rgba kit_color{ 140, 150, 235, 255 };
				zdraw::rgba scoped_color{ 195, 200, 215, 255 };
				zdraw::rgba defusing_color{ 140, 150, 235, 255 };
				zdraw::rgba flashed_color{ 255, 210, 120, 255 };
				zdraw::rgba distance_color{ 90, 95, 130, 255 };

				[[nodiscard]] bool has( flag f ) const { return this->flags & f; }
			} m_info_flags{};

			struct name
			{
				bool enabled{ true };
				zdraw::rgba color{ 195, 200, 215, 230 };
			} m_name{};

			struct weapon
			{
				enum class display_type : std::uint8_t { text, icon, text_and_icon };

				bool enabled{ true };
				display_type display{ display_type::icon };

				zdraw::rgba text_color{ 195, 200, 215, 210 };
				zdraw::rgba icon_color{ 195, 200, 215, 230 };
			} m_weapon{};
		} m_player{};

		struct item
		{
			bool enabled{ true };
			float max_distance{ 40.0f };

			struct icon
			{
				bool enabled{ true };
				zdraw::rgba color{ 195, 200, 215, 200 };
			} m_icon{};

			struct name
			{
				bool enabled{ false };
				zdraw::rgba color{ 195, 200, 215, 180 };
			} m_name{};

			struct ammo
			{
				bool enabled{ true };
				zdraw::rgba color{ 140, 150, 235, 200 };
				zdraw::rgba empty_color{ 180, 80, 80, 200 };
			} m_ammo{};

			struct filters
			{
				bool rifles{ true };
				bool smgs{ true };
				bool shotguns{ true };
				bool snipers{ true };
				bool pistols{ true };
				bool heavy{ true };
				bool grenades{ true };
				bool utility{ true };
			} m_filters{};
		} m_item{};

		struct projectile
		{
			bool enabled{ true };

			bool show_icon{ true };
			bool show_name{ true };
			bool show_timer_bar{ true };
			bool show_inferno_bounds{ true };

			zdraw::rgba default_color{ 195, 200, 215, 200 };
			zdraw::rgba color_he{ 220, 150, 150, 220 };
			zdraw::rgba color_flash{ 230, 220, 150, 220 };
			zdraw::rgba color_smoke{ 160, 200, 180, 220 };
			zdraw::rgba color_molotov{ 220, 170, 130, 220 };
			zdraw::rgba color_decoy{ 170, 175, 200, 200 };

			zdraw::rgba timer_high_color{ 140, 150, 235, 255 };
			zdraw::rgba timer_low_color{ 220, 100, 100, 255 };
			zdraw::rgba bar_background{ 15, 16, 22, 150 };
		} m_projectile{};
	};

	struct misc
	{
		struct grenades
		{
			bool enabled{ true };
			bool local_only{ true };
			zdraw::rgba color{ 170, 175, 220, 200 };
		} m_grenades{};

		bool bhop{ true };

		bool limit_fps{ true };
		int fps_limit{ 240 };
	};

	inline combat g_combat{};
	inline esp g_esp{};
	inline misc g_misc{};

} // namespace settings