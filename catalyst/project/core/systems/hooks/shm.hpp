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

		struct shared_data
		{
			struct {
				bool bhop_enabled;
				bool silent_aim;
				bool anti_aim;
				bool double_tap;
				float view_angles[ 3 ];
				bool chams_enabled;
				float chams_color[ 4 ];
			} features;

			struct {
				std::uintptr_t local_pawn;
			} data;

			std::uint32_t magic;
			std::atomic<bool> shellcode_ready;
			hook_entry hooks[ k_max_hooks ];
		};

	}

}
