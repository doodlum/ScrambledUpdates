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

	constexpr std::uint32_t VERSION_DATA_EX{ 0x304 };
	constexpr std::uint8_t  EX_ADDRESS_LIBRARY_V5{ 1 << 1 };

	const Patches::Guid* FileBuildGuid(const std::vector<char>& file)
	{
		const auto* base = reinterpret_cast<const std::uint8_t*>(file.data());
		const auto  u32  = [&](std::size_t o) {
			return *reinterpret_cast<const std::uint32_t*>(base + o);
		};
		const auto u16 = [&](std::size_t o) {
			return *reinterpret_cast<const std::uint16_t*>(base + o);
		};

		const std::size_t pe       = u32(0x3C);
		const std::size_t optional = pe + 24;
		const std::size_t table    = optional + u16(pe + 20);
		const auto        count    = u16(pe + 6);

		const auto toOffset = [&](std::uint32_t rva) -> std::size_t {
			for (std::uint16_t i = 0; i < count; ++i)
			{
				const auto entry = table + i * 40u;
				const auto va    = u32(entry + 12);
				const auto size  = std::max(u32(entry + 8), u32(entry + 16));
				if (rva >= va && rva < va + size)
				{
					return u32(entry + 20) + (rva - va);
				}
			}
			return 0;
		};

		const auto directory = toOffset(u32(optional + 112 + 6 * 8));
		const auto bytes     = u32(optional + 116 + 6 * 8);

		for (std::uint32_t at = 0; directory && at + 28 <= bytes; at += 28)
		{
			const auto entry = directory + at;
			if (u32(entry + 12) != 2)
			{
				continue;
			}

			const auto record = u32(entry + 24);
			if (record + 20 <= file.size() && std::memcmp(base + record, "RSDS", 4) == 0)
			{
				return reinterpret_cast<const Patches::Guid*>(base + record + 4);
			}
		}
		return nullptr;
	}

	constexpr std::uint32_t VERSION_DATA_INDEPENDENCE{ 0x308 };
	constexpr std::uint8_t  INDEPENDENT_ADDRESS_LIBRARY{ 1 << 0 };
	constexpr std::uint32_t STAMP_FLOOR{ 0x1F008600 };
	constexpr std::uint32_t STAMP_RANGE{ 0x493328FF };

	std::filesystem::path PluginPath(const Patches::Module& target)
	{
		return std::filesystem::path{ L"Data/SKSE/Plugins" } / target.file;
	}

	// SKSE 2.3.1's own condition, evaluated from the same place it reads: the file.
	bool SkseWillRefuse(const Patches::Module& target)
	{
		const auto path = PluginPath(target);

		std::vector<char> file;
		{
			std::ifstream in{ path, std::ios::binary };
			if (!in)
			{
				return false;
			}
			file.assign(std::istreambuf_iterator<char>{ in }, {});
		}

		if (file.size() <= target.versionData + VERSION_DATA_INDEPENDENCE + 4)
		{
			return false;
		}

		const auto* base = reinterpret_cast<const std::uint8_t*>(file.data());
		const auto  u32  = [&](std::size_t o) {
			return *reinterpret_cast<const std::uint32_t*>(base + o);
		};

		if (!(u32(target.versionData + VERSION_DATA_INDEPENDENCE) &
		      INDEPENDENT_ADDRESS_LIBRARY) ||
		    u32(target.versionData + VERSION_DATA_EX) & EX_ADDRESS_LIBRARY_V5 ||
		    u32(u32(0x3C) + 8) - STAMP_FLOOR > STAMP_RANGE)
		{
			return false;
		}

		const auto* build = FileBuildGuid(file);
		if (!build || std::memcmp(build, &target.build, sizeof(*build)) != 0)
		{
			logger::error("{} on disk is not the build these patches describe",
			              target.name);
			return false;
		}
		return true;
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

	// Declaring AddressLibraryV5 is what stops SKSE 2.3.1 refusing the plugin, and
	// it is truthful once we are installed, because we replace its format 5 reader.
	// SKSE decides from the file while it scans, long before any plugin runs, so
	// this can only take effect on the next launch.
	bool DeclareAddressLibraryV5(const Patches::Module& target)
	{
		const auto path = PluginPath(target);
		const auto at   = target.versionData + VERSION_DATA_EX;

		{
			std::fstream file{ path, std::ios::binary | std::ios::in | std::ios::out };
			std::uint8_t flags{};
			if (!file || !file.seekg(at).read(reinterpret_cast<char*>(&flags), 1))
			{
				logger::error("cannot read {}", target.name);
				return false;
			}

			flags |= EX_ADDRESS_LIBRARY_V5;
			if (!file.seekp(at).write(reinterpret_cast<const char*>(&flags), 1))
			{
				logger::error("cannot write {}", target.name);
				return false;
			}
		}

		// Read it back through a fresh handle. A write that was redirected or undone
		// - by file virtualisation, or by a mod manager rebuilding its overlay -
		// would otherwise restart the game for nothing, on every launch, forever.
		std::ifstream check{ path, std::ios::binary };
		std::uint8_t  written{};
		if (!check.seekg(at).read(reinterpret_cast<char*>(&written), 1) ||
		    !(written & EX_ADDRESS_LIBRARY_V5))
		{
			logger::error("{} did not keep the change", target.name);
			return false;
		}

		logger::info("declared AddressLibraryV5 for {}", target.name);
		return true;
	}

	constexpr const wchar_t* RESTARTED{ L"ScrambledUpdatesRestarted" };

	// Relaunching means going back through SKSE's loader, not the game exe, so the
	// next process gets its plugins as well as its hooks.
	bool Relaunch()
	{
		// From the running exe rather than the working directory, because getting
		// this wrong means quitting without coming back.
		std::wstring game(REX::W32::MAX_PATH, L'\0');
		game.resize(REX::W32::GetModuleFileNameW(nullptr, game.data(),
		                                         static_cast<std::uint32_t>(game.size())));

		const auto loader = std::filesystem::path{ game }.parent_path() / L"skse64_loader.exe";
		if (game.empty() || !std::filesystem::exists(loader))
		{
			logger::error("no skse64_loader.exe beside the game");
			return false;
		}

		REX::W32::STARTUPINFOW       startup{ .size = sizeof(startup) };
		REX::W32::PROCESS_INFORMATION process{};

		// Inherited by the process we are about to start, so it can tell that it is
		// the second attempt.
		REX::W32::SetEnvironmentVariableW(RESTARTED, L"1");

		if (!REX::W32::CreateProcessW(loader.c_str(), nullptr, nullptr, nullptr, false,
		                              0, nullptr, loader.parent_path().c_str(),
		                              &startup, &process))
		{
			logger::error("could not start {}", loader.string());
			return false;
		}

		REX::W32::CloseHandle(process.thread);
		REX::W32::CloseHandle(process.process);
		return true;
	}

	[[noreturn]] void Quit()
	{
		REX::W32::TerminateProcess(REX::W32::GetCurrentProcess(), 0);
		std::unreachable();
	}

	// SKSE has already refused these plugins for this run and nothing a plugin does
	// now can change that, so the only way to get them loaded is a fresh process.
	// Preload is early enough that this costs a moment of startup and nothing else.
	void EnableRefusedPlugins()
	{
		bool enabled{ false };
		for (const auto& target : Patches::MODULES)
		{
			if (SkseWillRefuse(target) && DeclareAddressLibraryV5(target))
			{
				enabled = true;
			}
		}

		if (!enabled)
		{
			return;
		}

		// The flag is on disk and verified, so a second refusal means something
		// outside this process is undoing it. Carry on unpatched rather than
		// restarting into the same wall for the rest of time.
		if (REX::W32::GetEnvironmentVariableW(RESTARTED, nullptr, 0) != 0)
		{
			logger::error("still refused after restarting once - giving up");
			return;
		}

		logger::info("restarting so SKSE will load them");

		Relaunch();
		Quit();
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

	// Replaces the process, and does not return, if anything had to be enabled.
	EnableRefusedPlugins();

	if (!LoadAddressLibrary())
	{
		return true;
	}

	// None of them export SKSEPlugin_Preload, so none is loaded at this point
	WatchForPlugins();

	return true;
}
