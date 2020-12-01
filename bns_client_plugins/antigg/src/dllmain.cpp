#include <iostream>
#include <string>
#include <filesystem>

#include <fnv1a.h>
#include <pe/module.h>
#include <pe/section.h>
#include <pluginsdk.h>
#include <plugindbg.h>
#include <versioninfo.h>
#include <ns/pattern.h>

const DetoursData* g_DetoursData;

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);

        if (const auto module = pe::get_module()) {
            auto sections = module->sections();

            auto sectionIt = std::find_if(sections->begin(), sections->end(), [](pe::section& section) {
                return section.executable();
            });

            if (sectionIt == sections->end())
                return FALSE;

            // Don't load if it's not private server client.exe
            const wchar_t* FileVersion;
            if (GetModuleVersionInfo(module, L"\\StringFileInfo\\*\\FileVersion", &(LPCVOID&)FileVersion) >= 0)
                if (wcscmp(L"0, 0, 210, 6668", FileVersion) != 0)
                    return FALSE;

            std::wstring_view base_name = module->base_name();
            if (fnv1a::make_hash(base_name.data(), towlower) != L"client.exe"_fnv1al)
                return FALSE;

            return TRUE;
        }
    }

    return FALSE;
}

bool FillBytes(LPVOID address, size_t size, int value)
{
    DWORD oldProtection;

    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtection))
        return false;

    memset(address, value, size);

    VirtualProtect(address, size, oldProtection, &oldProtection);
    return true;
}

void PatchGameGuard() {
    static bool patched = false;

    if (patched)
        return;

    pe::module* module = pe::get_module();

    if (!module)
        return;

    auto sections = module->sections();

    auto codeSection = std::find_if(sections->begin(), sections->end(), [](pe::section& section) {
        return section.executable();
    });

    if (codeSection == sections->end())
        return;

    // Find method match
    constexpr auto pattern = COMPILE_PATTERN("83 C4 04 85 C0 74 13 C6 40 ?? 00 C7 00 ?? ?? ?? ?? C7 40 ?? 00 00 00 00 EB 02 33 C0 85 C0 A3 ?? ?? ?? ?? 74 09");
    auto offset = ns::find_pattern(pattern, *codeSection);

    if (offset == ns::no_match)
        return;

    offset -= offset % 4;

    // Find method begin
    uint32_t* codeSegmentBegin = (uint32_t*)codeSection->data();
    uint32_t* methodBeginScan = (uint32_t*)(codeSection->data() + offset);

    while ((*methodBeginScan & 0x00FFFFFF) != 0x0068FF6A)
    {
        methodBeginScan--;

        if (methodBeginScan <= codeSegmentBegin)
            return;
    }

    char* methodBegin = (char*)methodBeginScan;

    constexpr size_t antigg_method_base = 0x005D54A0;
    constexpr size_t loadgg_offset = 0x005D54F7 - antigg_method_base;
    constexpr size_t loadaegisty_offset = 0x005D5548 - antigg_method_base;

    dbg_wprintf(L"Found anti-cheat loading at: 0x%p\n", methodBegin);
    dbg_wprintf(L"LoadGG call at: 0x%p\n", methodBegin + loadgg_offset);
    dbg_wprintf(L"LoadAegisty call at: 0x%p\n", methodBegin + loadaegisty_offset);

    if (FillBytes((LPVOID)(methodBegin + loadgg_offset), 5, 0x90)
        && FillBytes((LPVOID)(methodBegin + loadaegisty_offset), 5, 0x90))
    {
        dbg_wprintf(L"Successfully patched\n");
        patched = true;
    }
    else
    {
        dbg_wprintf(L"Failed to patch call bytes\n");
    }

}

void __cdecl DllLoadedNotification(const struct DllNotificationData* Data, void* Context)
{
    switch (fnv1a::make_hash(Data->Name, towlower))
    {
    case L"netutils.dll"_fnv1al:
    case L"netapi32.dll"_fnv1al:
    case L"ws2_32.dll"_fnv1al:
    case L"psapi.dll"_fnv1al:
        dbg_wprintf(L"Scanning on %s load\n", Data->Name);
        PatchGameGuard();
        break;
    }
}

void __cdecl InitNotification(const struct InitNotificationData* Data, void* Context)
{
    initialize_dbg_console();
    g_DetoursData = Data->Detours;
}

#ifndef __DATEW__
#define __DATEW__ _CRT_WIDE(__DATE__)
#endif

extern "C"
__declspec(dllexport)
void __cdecl GetPluginInfo2(PluginInfo2* plgi)
{
    plgi->Name = L"antigg";
    plgi->Version = __DATEW__;
    plgi->Description = L"Bypasses GameGuard";
    plgi->InitNotification = &InitNotification;
    plgi->DllLoadedNotification = &DllLoadedNotification;
}
