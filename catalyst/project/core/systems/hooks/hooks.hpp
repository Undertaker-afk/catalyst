#pragma once
#include "shm.hpp"

namespace systems {

	class hooks
	{
	public:
		struct hook_data
		{
			std::string name{};
			std::string module{};
			std::vector<std::uint8_t> pattern{};
			std::string mask{};
			std::uintptr_t target_address{};
			bool enabled{ false };
		};

		bool initialize( );
		void shutdown( );

		bool add( const std::string& name, const std::string& module_name, const std::vector<std::uint8_t>& pattern, const std::string& mask );
		bool enable( const std::string& name );
		bool disable( const std::string& name );

		void update_features( );

	private:
		bool setup_shared_memory( );
		bool inject_shellcode( );
		bool hijack_thread( std::uintptr_t entry_point );

		std::vector<hook_data> m_hooks{};
		void* m_shared_memory_handle{};
		shm::shared_data* m_shared_data{};
		std::uintptr_t m_remote_shellcode_base{};
		bool m_initialized{ false };
	};

} // namespace systems
