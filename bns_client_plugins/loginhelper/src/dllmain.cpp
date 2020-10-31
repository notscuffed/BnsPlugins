#include <phnt_windows.h>
#include <phnt.h>

#include <iostream>
#include <algorithm>

#include <fnv1a.h>
#include <pe/module.h>
#include <xorstr.hpp>
#include <pluginsdk.h>
#include <plugindbg.h>
#include <versioninfo.h>

#include "game_versions/privateserver_x86.h"
#include "state.h"

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);

        if (const auto module = pe::get_module()) {
            std::wstring_view base_name = module->base_name();
            if (fnv1a::make_hash(base_name.data(), towlower) != L"client.exe"_fnv1al)
                return FALSE;

            return TRUE;
        }
    }

    return FALSE;
}

void Patch()
{
    static bool patched = false;

    if (patched)
        return;

    const auto module = pe::get_module(L"client.exe");

    if (!module)
    {
        dbg_printf("Module not found\n");
        return;
    }

    auto sections = module->sections();

    const auto code_segment = std::find_if(sections->begin(), sections->end(), [](pe::section& section) {
        return section.executable();
        });

    if (code_segment == sections->end()) {
        dbg_printf("Code segment not found\n");
        return;
    }

    auto data = std::span<char>((char*)code_segment->data(), code_segment->size());
    
    auto username = wil::TryGetEnvironmentVariableW(L"BNS_PROFILE_USERNAME");
    auto password = wil::TryGetEnvironmentVariableW(L"BNS_PROFILE_PASSWORD");

    auto has_login_details = username.is_valid() && password.is_valid();

    dbg_printf("Has login details: %s\n", has_login_details ? "yes" : "no");

    if (has_login_details)
    {
        // Hooks are supposed to make copy of username & password

        if (!ps_x86::hook(data, username.get(), password.get(), nullptr))
            return;
    }

    patched = true;
}

void __cdecl DllLoadedNotification(const struct DllNotificationData* Data, void* Context)
{
    switch (fnv1a::make_hash(Data->Name, towlower))
    {
    case L"netutils.dll"_fnv1al:
    case L"netapi32.dll"_fnv1al:
    case L"psapi.dll"_fnv1al:
        dbg_wprintf(L"Scanning on %s load\n", Data->Name);
        Patch();
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
void __cdecl GetPluginInfo2(PluginInfo2 * plgi)
{
    static std::once_flag once_flag;
    static auto name = xorstr(L"loginhelper");
    static auto version = xorstr(__DATEW__);
    static auto description = xorstr(L"Allows automatic login+pin and makes pin input easier");

    std::call_once(once_flag, [](auto& name, auto& version, auto& description) {
        name.crypt();
        version.crypt();
        description.crypt();
        }, name, version, description);

    plgi->Name = name.get();
    plgi->Version = version.get();
    plgi->Description = description.get();
    plgi->InitNotification = &InitNotification;
    plgi->DllLoadedNotification = &DllLoadedNotification;
}
