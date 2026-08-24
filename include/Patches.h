#pragma once

#include <cstdint>
#include <span>

namespace Patches
{
	// 1.7.99 added a base class to PlayerCharacter, shifting members above the
	// insertion by 8. Of the 27 classes that changed size, it is the only one any
	// of these plugins reads.
	struct Displacement
	{
		std::uint32_t rva;             // start of the instruction
		std::uint8_t  displacementAt;  // where the disp32 sits inside it
		std::uint32_t corrected;
	};

	inline constexpr Displacement SCRAMBLED_BUGS[]{
		// Fixes::WeaponCharge::UpdateEquippedEnchantmentCharge
		{ 0x0060ED, 3, 0xBEB },  // movzx eax, byte ptr [rcx + 0xBE3]
		{ 0x0060FF, 2, 0xBEB },  // mov byte ptr [rcx + 0xBE3], al  <- the write
		// Patches::DifficultyMultipliers::AdjustHealthDamageToDifficulty
		{ 0x00690E, 2, 0xB08 },  // mov ecx, dword ptr [rsi + 0xB00]
	};

	// The CodeView GUID identifying one build, laid out as the record stores it.
	// A plugin version would not do: both of the newer plugins report version 1,
	// which a rebuild would likely keep, and the RVAs below would then describe a
	// binary we no longer have. tools/build_identity.py prints these.
	struct Guid
	{
		std::uint32_t data1;
		std::uint16_t data2;
		std::uint16_t data3;
		std::uint8_t  data4[8];
	};
	static_assert(sizeof(Guid) == 16);

	// KernalsEgg's plugins link the same Relocation::AddressLibrary, so the same
	// two functions are replaced in each and only the RVAs differ. Every number
	// here came from the PDB shipped beside the DLL.
	struct Module
	{
		const wchar_t*                file;
		const char*                   name;
		Guid                          build;
		std::uint32_t                 headerRead;          // Header::Read
		std::uint32_t                 addressLibraryRead;  // AddressLibrary::Read
		std::span<const Displacement> displacements;
	};

	inline constexpr Module MODULES[]{
		// 72FF555D-9E17-4A7B-9A64-50DC1030A5E4
		{ L"ScrambledBugs.dll", "Scrambled Bugs",
		  { 0x72FF555D, 0x9E17, 0x4A7B, { 0x9A, 0x64, 0x50, 0xDC, 0x10, 0x30, 0xA5, 0xE4 } },
		  0x0404A0, 0x041750, SCRAMBLED_BUGS },
		// 76879527-999C-4CA2-BF31-0643B8A4F22A
		{ L"ScriptEffectArchetypeCrashFix.dll", "Script Effect Archetype Crash Fix",
		  { 0x76879527, 0x999C, 0x4CA2, { 0xBF, 0x31, 0x06, 0x43, 0xB8, 0xA4, 0xF2, 0x2A } },
		  0x0220B0, 0x023460, {} },
		// 1EF99E87-85DB-47B3-8D02-CC447AD34F61
		{ L"VendorRespawnFix.dll", "Vendor Respawn Fix",
		  { 0x1EF99E87, 0x85DB, 0x47B3, { 0x8D, 0x02, 0xCC, 0x44, 0x7A, 0xD3, 0x4F, 0x61 } },
		  0x023190, 0x024540, {} },
	};
}
