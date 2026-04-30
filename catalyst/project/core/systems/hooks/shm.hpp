#pragma once
#include <cstdint>
#include <atomic>

namespace systems {

	namespace shm {

		static constexpr std::size_t k_max_hooks = 15;

		struct hook_entry
		{
			std::atomic<bool> active;
			std::uintptr_t address;
		};

		// POD-only structure for safe serialization and SHM access
		struct feature_data
		{
			bool bhop_enabled;         // 0x00
			bool silent_aim;           // 0x01
			bool anti_aim;             // 0x02
			bool double_tap;           // 0x03
			bool chams_enabled;        // 0x04
			bool world_modulation;     // 0x05
			uint8_t pad[2];
			float view_angles[3];      // 0x08
			float chams_color[4];      // 0x14
			float world_color[4];      // 0x24
		};

		struct game_data
		{
			std::uintptr_t local_pawn; // 0x00
			std::uint32_t m_fFlags;    // 0x08
			std::uint32_t m_pButtons;  // 0x0C
		};

		struct shared_data
		{
			feature_data features;     // 0x00
			game_data data;           // 0x34 (approx)

			std::uint32_t magic;
			std::atomic<bool> shellcode_ready;
			hook_entry hooks[ k_max_hooks ];
		};

	}

}
