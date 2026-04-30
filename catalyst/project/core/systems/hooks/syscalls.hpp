#pragma once
#include <cstdint>
#include <string_view>

namespace systems {

	class syscalls
	{
	public:
		static std::uint16_t resolve( std::string_view name );
	};

} // namespace systems
