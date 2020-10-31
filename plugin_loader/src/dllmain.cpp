#include <phnt_windows.h>
#include <phnt.h>
#include <delayimp.h>

#include <filesystem>
#include <vector>

#include <detours.h>
#include <ntmm.hpp>
#include <ntrtl.hpp>
#include <pe/debug.h>
#include <pe/exports.h>
#include <pe/module.h>
#include <wil/stl.h>
#include <wil/win32_helpers.h>

#include "FastWildCompare.h"
#include "pluginsdk.h"

LONG WINAPI DetourAttach2(HMODULE hModule, PCSTR pProcName, PVOID* pPointer, PVOID pDetour)
{
    if (!hModule) return ERROR_INVALID_PARAMETER;
    if (!pPointer) return ERROR_INVALID_PARAMETER;

    if (*pPointer = GetProcAddress(hModule, pProcName))
        return DetourAttachEx(pPointer, pDetour, nullptr, nullptr, nullptr);

    return ERROR_PROC_NOT_FOUND;
}

static const DetoursData g_DetoursData = {
    &DetourTransactionBegin,
    &DetourTransactionAbort,
    &DetourTransactionCommit,
    &DetourUpdateThread,
    &DetourAttach,
    &DetourAttach2,
    &DetourDetach
};

static std::vector<PluginInfo2> g_Plugins;

PVOID g_pvDllNotificationCookie;

VOID CALLBACK DllNotification(ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
    switch (NotificationReason) {
    case LDR_DLL_NOTIFICATION_REASON_LOADED: {
        const auto Data = DllNotificationData{
            NotificationData->Loaded.Flags,
            NotificationData->Loaded.FullDllName->Buffer,
            (SIZE_T)NotificationData->Loaded.FullDllName->Length >> 1u,
            NotificationData->Loaded.BaseDllName->Buffer,
            (SIZE_T)NotificationData->Loaded.BaseDllName->Length >> 1u,
            (HINSTANCE)NotificationData->Loaded.DllBase,
            NotificationData->Loaded.SizeOfImage,
            &g_DetoursData
        };

        for (const auto& plgi : g_Plugins)
            if (plgi.DllLoadedNotification)
                plgi.DllLoadedNotification(&Data, plgi.Context);

        break;
    }

    case LDR_DLL_NOTIFICATION_REASON_UNLOADED: {
        const auto Data = DllNotificationData{
          NotificationData->Unloaded.Flags,
          NotificationData->Unloaded.FullDllName->Buffer,
          (SIZE_T)NotificationData->Unloaded.FullDllName->Length >> 1u,
          NotificationData->Unloaded.BaseDllName->Buffer,
          (SIZE_T)NotificationData->Unloaded.BaseDllName->Length >> 1u,
          (HINSTANCE)NotificationData->Unloaded.DllBase,
          NotificationData->Unloaded.SizeOfImage,
          &g_DetoursData
        };

        for (const auto& plgi : g_Plugins)
            if (plgi.DllUnloadedNotification)
                plgi.DllUnloadedNotification(&Data, plgi.Context);

        break;
    }
    }
}

VOID NTAPI ApcLoadPlugins(ULONG_PTR Parameter)
{
    const auto folder = std::filesystem::path(pe::get_module()->full_name()).remove_filename().append(L"plugins");

    auto ec = std::error_code();
    for (const auto& it : std::filesystem::directory_iterator(folder, ec)) {
        if (!it.is_regular_file())
            continue;

        if (FastWildCompare(L"*.dll", it.path().filename())) {
            auto module = static_cast<pe::module*>(LoadLibraryExW(it.path().c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH));
            if (!module)
                continue;

            if (const auto GetPluginInfo2 = reinterpret_cast<GetPluginInfo2Fn>(GetProcAddress(module, "GetPluginInfo2"))) {
                PluginInfo2 pluginInfo2{};
                GetPluginInfo2(&pluginInfo2);
                g_Plugins.push_back(pluginInfo2);
                if (pluginInfo2.InitNotification) {
                    const auto Data = InitNotificationData{ &g_DetoursData };
                    pluginInfo2.InitNotification(&Data, pluginInfo2.Context);
                }
            }
            else if (const auto GetPluginInfo = reinterpret_cast<GetPluginInfoFn>(GetProcAddress(module, "GetPluginInfo"))) {
                PluginInfo pluginInfo{};
                GetPluginInfo(&pluginInfo);
                if (pluginInfo.Init)
                    pluginInfo.Init();
            }
            else {
                FreeLibrary(module);
                continue;
            }

            const auto debug = module->debug();
            if (!debug || debug->type() != IMAGE_DEBUG_TYPE_CODEVIEW) {
                module->hide_from_module_lists();
                const auto ntheader = module->nt_header();
                const nt::mm::protect_memory p{ module, ntheader->OptionalHeader.SizeOfHeaders, PAGE_READWRITE };
                SecureZeroMemory(module, ntheader->OptionalHeader.SizeOfHeaders);
            }
        }
    }

    if (const auto module = pe::get_module(L"ntdll.dll")) {
        if (const auto pLdrRegisterDllNotification = reinterpret_cast<decltype(&LdrRegisterDllNotification)>(
            GetProcAddress(module, "LdrRegisterDllNotification"))) {
            pLdrRegisterDllNotification(0, &DllNotification, nullptr, &g_pvDllNotificationCookie);
        }
    }
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInstance);
        QueueUserAPC(&ApcLoadPlugins, NtCurrentThread(), 0);
    }
    return TRUE;
}

ExternC const PfnDliHook __pfnDliNotifyHook2 = [](unsigned dliNotify, PDelayLoadInfo pdli) -> FARPROC{
    if (dliNotify != dliNotePreLoadLibrary)
        return nullptr;

    if (!_stricmp(pdli->szDll, pe::instance_module->exports()->name())) {
        NtTestAlert();
        if (std::wstring result; SUCCEEDED(wil::GetSystemDirectoryW(result))) {
            const auto path = std::filesystem::path(result).append(pdli->szDll);
            return (FARPROC)LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        }
    }

    return nullptr;
};