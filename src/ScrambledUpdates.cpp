#include "Patches.h"
#include "Relocation.h"

#include <RE/M/Misc.h>
#include <REL/Module.h>
#include <REL/Offset2ID.h>
#include <REL/Relocation.h>
#include <SKSE/API.h>
#include <SKSE/Interfaces.h>
#include <SKSE/Version.h>

#include <spdlog/sinks/basic_file_sink.h>

namespace
{
	std::optional<REL::Offset2ID> g_table;

	bool LoadAddressLibrary()
	{
		g_table.emplace();
		logger::info("address library: {} offsets", g_table->size());
		return g_table->size() != 0;
	}

	// Replaces Relocation::AddressLibrary::Header::Read
	void __fastcall HookHeaderRead(
		Relocation::Header*        self,
		void*                      /*stream*/,
		const Relocation::Version* productVersion)
	{
		self->format         = Relocation::FORMAT_ANNIVERSARY_EDITION;
		self->productVersion = *productVersion;
		self->fileNameLength = 0;
		self->pointerSize    = sizeof(void*);

		// Entries that exist, not the file's identifier range, so the mapping
		// sized from this has no slack to fill.
		self->addressCount = static_cast<std::int32_t>(g_table->size());
	}

	// Replaces Relocation::AddressLibrary::Read
	void __fastcall HookRead(
		Relocation::Element*      destination,
		void*                     /*stream*/,
		const Relocation::Header* /*header*/)
	{
		std::size_t written{ 0 };
		for (const auto& entry : *g_table)
		{
			destination[written++] = { entry.id, entry.offset };
		}

		logger::info("loaded {} addresses", written);
	}

	enum class Status : std::uint8_t
	{
		Waiting,
		Patched,
		Failed,
	};

	Status g_status[std::size(Patches::MODULES)]{};

	const Patches::Guid* BuildGuid(const std::uint8_t* base)
	{
		const auto* pe = base + *reinterpret_cast<const std::uint32_t*>(base + 0x3C);
		const auto* directory = reinterpret_cast<const std::uint32_t*>(pe + 24 + 112 + 6 * 8);

		for (std::uint32_t at = 0; at + 28 <= directory[1]; at += 28)
		{
			const auto* entry = base + directory[0] + at;
			if (*reinterpret_cast<const std::uint32_t*>(entry + 12) != 2)
			{
				continue;
			}

			const auto* record = base + *reinterpret_cast<const std::uint32_t*>(entry + 20);
			if (std::memcmp(record, "RSDS", 4) == 0)
			{
				return reinterpret_cast<const Patches::Guid*>(record + 4);
			}
		}
		return nullptr;
	}

	void AbsoluteJump(std::uint8_t* target, void* destination)
	{
		std::uint8_t jump[]{ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp [rip+0]
			                 0, 0, 0, 0, 0, 0, 0, 0 };
		const auto address = reinterpret_cast<std::uintptr_t>(destination);
		std::memcpy(jump + 6, &address, sizeof(address));

		REL::safe_write(reinterpret_cast<std::uintptr_t>(target), jump, sizeof(jump));
	}

	bool Patch(const Patches::Module& target, REX::W32::HMODULE module)
	{
		auto* base = reinterpret_cast<std::uint8_t*>(module);

		const auto* build = BuildGuid(base);
		if (!build || std::memcmp(build, &target.build, sizeof(*build)) != 0)
		{
			logger::error("{} is not the build these patches describe", target.name);
			return false;
		}

		for (const auto& site : target.displacements)
		{
			REL::safe_write(
				reinterpret_cast<std::uintptr_t>(base + site.rva + site.displacementAt),
				site.corrected);
		}

		AbsoluteJump(base + target.headerRead, &HookHeaderRead);
		AbsoluteJump(base + target.addressLibraryRead, &HookRead);

		logger::info("patched {} at {}: {} displacements",
		             target.name, static_cast<const void*>(base),
		             target.displacements.size());
		return true;
	}

	void Apply()
	{
		for (std::size_t i = 0; i < std::size(Patches::MODULES); ++i)
		{
			if (g_status[i] != Status::Waiting)
			{
				continue;
			}

			const auto& target = Patches::MODULES[i];
			auto        module = REX::W32::GetModuleHandleW(target.file);
			if (!module)
			{
				continue;
			}

			g_status[i] = Patch(target, module) ? Status::Patched : Status::Failed;
		}
	}

	constexpr std::uint32_t DLL_NOTIFICATION_REASON_LOADED{ 1 };

	using DllNotificationCallback = void(__stdcall*)(std::uint32_t, const void*, void*);
	using RegisterNotification =
		std::int32_t(__stdcall*)(std::uint32_t, DllNotificationCallback, void*, void**);

	void __stdcall OnDllLoaded(std::uint32_t reason, const void* /*data*/, void* /*context*/)
	{
		if (reason == DLL_NOTIFICATION_REASON_LOADED)
		{
			Apply();
		}
	}

	void WatchForPlugins()
	{
		auto add = reinterpret_cast<RegisterNotification>(REX::W32::GetProcAddress(
			REX::W32::GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification"));

		void* dummy{ nullptr };
		if (add(0, &OnDllLoaded, nullptr, &dummy) != 0)
		{
			logger::error("could not watch for the plugins to patch");
		}
	}

	void InitializeLog()
	{
		auto path = logger::log_directory();
		if (!path) {
			stl::report_and_fail("Failed to find standard logging directory"sv);
		}

		*path /= "ScrambledUpdates.log"sv;
		auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true);

		auto log = std::make_shared<spdlog::logger>("global log"s, std::move(sink));

		log->set_level(spdlog::level::info);
		log->flush_on(spdlog::level::info);

		spdlog::set_default_logger(std::move(log));
		spdlog::set_pattern("[%H:%M:%S] [%l] %v"s);
	}

	bool NeedsPatching()
	{
		return REL::Module::get().version() >= SKSE::RUNTIME_SSE_1_7_99;
	}

	void OnMessage(SKSE::MessagingInterface::Message* message)
	{
		if (message->type != SKSE::MessagingInterface::kDataLoaded)
		{
			return;
		}

		std::string failed;
		bool        patched{ false };

		for (std::size_t i = 0; i < std::size(Patches::MODULES); ++i)
		{
			if (g_status[i] == Status::Patched)
			{
				patched = true;
			}
			else if (g_status[i] == Status::Failed)
			{
				failed += failed.empty() ? "" : ", ";
				failed += Patches::MODULES[i].name;
			}
		}

		std::string warning;
		if (!failed.empty())
		{
			warning = std::format("Installed but not patched, so their fixes are "
			                      "not working: {}. See ScrambledUpdates.log",
			                      failed);
		}
		else if (!patched)
		{
			warning = "None of the plugins ScrambledUpdates patches are installed, "
			          "so it is inactive";
		}
		else
		{
			return;
		}

		logger::error("{}", warning);
		RE::DebugMessageBox(warning.c_str());
	}
}

SKSEPluginInfo(
	.Version = REL::Version{ 1, 1, 1, 0 },
	.Name = "ScrambledUpdates"sv,
	.Author = "doodlum"sv,
	.StructCompatibility = SKSE::StructCompatibility::Independent,
	.RuntimeCompatibility = SKSE::PluginDeclaration::RuntimeCompatibility(
		SKSE::VersionIndependence::AddressLibrary))

SKSEPluginLoad(const SKSE::LoadInterface* skse)
{
	if (NeedsPatching())
	{
		SKSE::Init(skse, false);
		SKSE::GetMessagingInterface()->RegisterListener(OnMessage);
	}
	return true;
}

extern "C" __declspec(dllexport) bool SKSEPlugin_Preload(const SKSE::LoadInterface* /*skse*/)
{
	if (!NeedsPatching())
	{
		return true;
	}

	InitializeLog();

	if (!LoadAddressLibrary())
	{
		return true;
	}

	// None of them export SKSEPlugin_Preload, so none is loaded at this point
	WatchForPlugins();

	return true;
}
