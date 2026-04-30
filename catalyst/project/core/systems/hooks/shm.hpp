#pragma once
#include <cstdint>
#include <atomic>

namespace systems {

	namespace shm {

		struct hook_entry
		{
			std::atomic<bool> active;
			std::uintptr_t address;
			std::uint8_t data[ 256 ]; // For parameters
		};

		struct shared_data
		{
			std::atomic<std::uint32_t> magic;
			std::atomic<bool> shellcode_ready;
			hook_entry hooks[ 15 ];

			// Feature specific data
			struct {
				bool bhop_enabled;
				bool silent_aim;
				float view_angles[ 3 ];
			} features;
		};

	}

}
