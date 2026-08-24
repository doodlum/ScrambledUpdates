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

	// KernalsEgg's plugins link the same Relocation::AddressLibrary, so the same
	// two functions are replaced in each and only the RVAs differ. Every number
	// here came from the PDB shipped beside the DLL.
	struct Module
	{
		const wchar_t*                file;
		const char*                   name;
		std::uint32_t                 pluginVersion;
		std::uint32_t                 headerRead;          // Header::Read
		std::uint32_t                 addressLibraryRead;  // AddressLibrary::Read
		std::span<const Displacement> displacements;
	};

	inline constexpr Module MODULES[]{
		{ L"ScrambledBugs.dll", "Scrambled Bugs",
		  21, 0x0404A0, 0x041750, SCRAMBLED_BUGS },
		{ L"ScriptEffectArchetypeCrashFix.dll", "Script Effect Archetype Crash Fix",
		  1, 0x0220B0, 0x023460, {} },
		{ L"VendorRespawnFix.dll", "Vendor Respawn Fix",
		  1, 0x023190, 0x024540, {} },
	};
}
