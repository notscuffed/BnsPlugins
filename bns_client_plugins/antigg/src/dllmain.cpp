#include <fnv1a.h>
#include <pe/module.h>
#include <pluginsdk.h>
#include <versioninfo.h>

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);

        const auto module = pe::get_module();

        // Don't load if it's not private server client.exe
        const wchar_t* FileVersion;
        if (GetModuleVersionInfo(module, L"\\StringFileInfo\\*\\FileVersion", &(LPCVOID&)FileVersion) >= 0)
            if (wcscmp(L"0, 0, 210, 6668", FileVersion) != 0)
                return FALSE;

        if (fnv1a::make_hash(module->base_name().data(), towlower) != L"client.exe"_fnv1al)
            return FALSE;
    }

    return TRUE;
}

void __cdecl DllLoadedNotification(const struct DllNotificationData* Data, void* Context)
{
    switch (fnv1a::make_hash(Data->Name, towlower))
    {
    case L"netutils.dll"_fnv1al:
    case L"netapi32.dll"_fnv1al:
    case L"ws2_32.dll"_fnv1al:
    case L"psapi.dll"_fnv1al:

        __try
        {
            if (   *(uint64_t*)0x5D54F7 == 0x75'C0'84'00'6C'2A'54'E8
                && *(uint64_t*)0x5D5548 == 0x8B'01'B0'00'6C'30'63'E8)
            {
                memset((void*)0x5D54F7, 0x90, 5); // Load game guard
                memset((void*)0x5D5548, 0x90, 5); // Load aegisty
            }
        }
        __except (1)
        {
            // Unlikely to happen, but just in case
        }

        break;
    }
}

#ifndef __DATEW__
#define __DATEW__ _CRT_WIDE(__DATE__)
#endif

extern "C"
__declspec(dllexport)
void __cdecl GetPluginInfo2(PluginInfo2 * plgi)
{
    plgi->Name = L"antigg";
    plgi->Version = __DATEW__;
    plgi->Description = L"Bypasses GameGuard";
    plgi->DllLoadedNotification = &DllLoadedNotification;
}
