#pragma once

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

	private:
		struct shared_data
		{
			std::atomic<std::uint32_t> write_index;
			std::atomic<std::uint32_t> read_index;
			// Expand this for more features
			std::uint8_t buffer[ 0x1000 ];
		};

		bool setup_shared_memory( );
		bool inject_shellcode( );
		bool hijack_thread( std::uintptr_t entry_point );

		std::vector<hook_data> m_hooks{};
		void* m_shared_memory_handle{};
		shared_data* m_shared_data{};
		std::uintptr_t m_remote_shellcode_base{};
		bool m_initialized{ false };
	};

	inline hooks g_hooks{};

} // namespace systems
