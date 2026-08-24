#pragma once

#include <cstdint>

namespace Relocation
{
	inline constexpr std::int32_t FORMAT_ANNIVERSARY_EDITION{ 2 };

	struct Version
	{
		std::int32_t major;
		std::int32_t minor;
		std::int32_t revision;
		std::int32_t build;
	};
	static_assert(sizeof(Version) == 0x10);

	struct Element
	{
		std::uint64_t identifier;
		std::uint64_t offset;
	};
	static_assert(sizeof(Element) == 0x10);

	struct Header
	{
		std::int32_t format;
		Version      productVersion;
		std::int32_t fileNameLength;
		char         fileName[0x20];
		std::int32_t pointerSize;
		std::int32_t addressCount;
	};
	static_assert(sizeof(Header) == 0x40);
}
