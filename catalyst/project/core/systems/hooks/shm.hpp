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
			// Features at the beginning for easy assembly access
			struct {
				bool bhop_enabled;
				bool silent_aim;
				float view_angles[ 3 ];
			} features;

			std::uint32_t magic;
			std::atomic<bool> shellcode_ready;
			hook_entry hooks[ k_max_hooks ];
		};

	}

}
