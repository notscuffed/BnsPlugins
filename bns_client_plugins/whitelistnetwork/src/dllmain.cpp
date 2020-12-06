#include <iostream>
#include <string>
#include <filesystem>
#include <sstream>

#include <fnv1a.h>
#include <pe/module.h>
#include <pe/section.h>
#include <plugindbg.h>
#include <pluginsdk.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <wininet.h>

const DetoursData* g_DetoursData;
std::vector<sockaddr_in> g_Whitelisted;

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hInstance);

    return TRUE;
}

decltype(&HttpOpenRequestA) g_pfnHttpOpenRequestA;
extern "C" HINTERNET __stdcall HttpOpenRequestA_hook(
    _In_ HINTERNET hConnect,
    _In_opt_ LPCSTR lpszVerb,
    _In_opt_ LPCSTR lpszObjectName,
    _In_opt_ LPCSTR lpszVersion,
    _In_opt_ LPCSTR lpszReferrer,
    _In_opt_z_ LPCSTR FAR * lplpszAcceptTypes,
    _In_ DWORD dwFlags,
    _In_opt_ DWORD_PTR dwContext
) {
    dbg_puts("Blocked HttpOpenRequestA");
    return nullptr;
}

decltype(&HttpOpenRequestW) g_pfnHttpOpenRequestW;
extern "C" HINTERNET __stdcall HttpOpenRequestW_hook(
    _In_ HINTERNET hConnect,
    _In_opt_ LPCSTR lpszVerb,
    _In_opt_ LPCSTR lpszObjectName,
    _In_opt_ LPCSTR lpszVersion,
    _In_opt_ LPCSTR lpszReferrer,
    _In_opt_z_ LPCSTR FAR * lplpszAcceptTypes,
    _In_ DWORD dwFlags,
    _In_opt_ DWORD_PTR dwContext
) {
    dbg_puts("Blocked HttpOpenRequestW");
    return nullptr;
}

decltype(&WSAConnect) g_pfnWSAConnect;
int WSAAPI WSAConnect_hook(
    SOCKET s,
    sockaddr* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS)
{
    if (name->sa_family != AF_INET && name->sa_family != AF_UNIX)
    {
        dbg_printf("Blocked connect to sa family other than AF_INET/AF_UNIX: %i\n", name->sa_family);
        WSASetLastError(WSA_INVALID_PARAMETER);
        return SOCKET_ERROR;
    }

    auto ip4name = reinterpret_cast<sockaddr_in*>(name);

#ifdef DBG_CONSOLE
    char buffer[64]{};
    inet_ntop(AF_INET, &ip4name->sin_addr, buffer, sizeof(buffer));
#endif

    if (std::find_if(g_Whitelisted.begin(), g_Whitelisted.end(), [ip4name](sockaddr_in& si) {
        return si.sin_addr.S_un.S_addr == ip4name->sin_addr.S_un.S_addr;
    }) == g_Whitelisted.end())
    {
        dbg_printf("Blocked WSAConnect to non whitelisted ip: %s\n", buffer);
        WSASetLastError(WSA_INVALID_PARAMETER);
        return SOCKET_ERROR;
    }

    dbg_printf("Allowing WSAConnect to whitelisted ip: %s\n", buffer);

    return g_pfnWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

decltype(&connect) g_pfnConnect;
int WSAAPI connect_hook(
    SOCKET s,
    sockaddr* name,
    int namelen)
{
    if (name->sa_family != AF_INET && name->sa_family != AF_UNIX)
    {
        dbg_printf("Blocked connect to sa family other than AF_INET/AF_UNIX: %i\n", name->sa_family);
        WSASetLastError(WSA_INVALID_PARAMETER);
        return SOCKET_ERROR;
    }

    auto ip4name = reinterpret_cast<sockaddr_in*>(name);

#ifdef DBG_CONSOLE
    char buffer[64]{};
    inet_ntop(AF_INET, &ip4name->sin_addr, buffer, sizeof(buffer));
#endif

    if (std::find_if(g_Whitelisted.begin(), g_Whitelisted.end(), [ip4name](sockaddr_in& si) {
        return si.sin_addr.S_un.S_addr == ip4name->sin_addr.S_un.S_addr;
        }) == g_Whitelisted.end())
    {
        dbg_printf("Blocked connect to non whitelisted ip: %s\n", buffer);
        WSASetLastError(WSA_INVALID_PARAMETER);
        return SOCKET_ERROR;
    }

    dbg_printf("Allowing connect to whitelisted ip: %s\n", buffer);

    return g_pfnConnect(s, name, namelen);
}

void PatchWS2_32(pe::module* module)
{
    dbg_puts("Patching ws2_32.dll");

    g_DetoursData->TransactionBegin();
    g_DetoursData->UpdateThread(NtCurrentThread());

    g_DetoursData->Attach2(module, "WSAConnect", &(PVOID&)g_pfnWSAConnect, &WSAConnect_hook);
    g_DetoursData->Attach2(module, "connect", &(PVOID&)g_pfnConnect, &connect_hook);

    if (g_DetoursData->TransactionCommit() != NO_ERROR)
    {
        dbg_puts("Failed to commit detours on ws2_32.dll");
        return;
    }
}

void PatchWininet(pe::module* module)
{
    dbg_puts("Patching wininet.dll");

    g_DetoursData->TransactionBegin();
    g_DetoursData->UpdateThread(NtCurrentThread());

    g_DetoursData->Attach2(module, "HttpOpenRequestA", &(PVOID&)g_pfnHttpOpenRequestA, &HttpOpenRequestA_hook);
    g_DetoursData->Attach2(module, "HttpOpenRequestW", &(PVOID&)g_pfnHttpOpenRequestW, &HttpOpenRequestW_hook);

    if (g_DetoursData->TransactionCommit() != NO_ERROR)
    {
        dbg_puts("Failed to commit detours on wininet.dll");
        return;
    }
}

void __cdecl DllLoadedNotification(const struct DllNotificationData* Data, void* Context)
{
    switch (fnv1a::make_hash(Data->Name, towlower))
    {
    case L"ws2_32.dll"_fnv1al:
        PatchWS2_32(reinterpret_cast<pe::module*>(Data->BaseOfImage));
        break;
    case L"wininet.dll"_fnv1al:
        PatchWininet(reinterpret_cast<pe::module*>(Data->BaseOfImage));
        break;
    }
}

void __cdecl InitNotification(const struct InitNotificationData* Data, void* Context)
{
    initialize_dbg_console();
    g_DetoursData = Data->Detours;

    if (const auto module = pe::get_module()) {
        std::wstring_view base_name = module->base_name();
        dbg_wprintf(L"Module name: %s\n", base_name.data());
    }

    auto whitelist_mem = wil::TryGetEnvironmentVariableW(L"BNS_IPWHITELIST");
    if (whitelist_mem.is_valid())
    {
        char buffer[64]{};
        wcstombs(buffer, whitelist_mem.get(), sizeof(buffer));

        std::istringstream ss{ buffer };
        std::string ip;
        sockaddr_in si;

        while (std::getline(ss, ip, ','))
        {
            if (ip.empty())
                continue;

            if (!inet_pton(AF_INET, ip.c_str(), &si.sin_addr))
                continue;

            dbg_printf("Adding whitelisted ip: %s\n", ip.c_str());
            g_Whitelisted.push_back(si);
        }
    }

    if (g_Whitelisted.size() == 0)
        dbg_printf("No whitelisted addresses added\n");

    if (auto module = pe::get_module(L"ws2_32.dll"))
        PatchWS2_32(module);
}

#ifndef __DATEW__
#define __DATEW__ _CRT_WIDE(__DATE__)
#endif

extern "C"
__declspec(dllexport)
void __cdecl GetPluginInfo2(PluginInfo2* plgi)
{
    plgi->Name = L"whitelistnetwork";
    plgi->Version = __DATEW__;
    plgi->Description = L"Blocks non white listed ip connections";
    plgi->InitNotification = &InitNotification;
    plgi->DllLoadedNotification = &DllLoadedNotification;
}
