#include <phnt_windows.h>
#include <phnt.h>

#include <mutex>

#include <plugindbg.h>
#include <xorstr.hpp>

#include "privateserver_x86.h"
#include "state.h"
#include "pattern_helper.h"

namespace ps_x86
{
    DEFINE_PATTERN(pattern_lobby_helper);
    DEFINE_PATTERN(pattern_login);

    bool(__stdcall* pfnLogin)(const wchar_t* username, const wchar_t* password);

    std::wstring ps_username;
    std::wstring ps_password;

    void execute_login()
    {
        bool result = pfnLogin(ps_username.c_str(), ps_password.c_str());
        dbg_printf("Login result: %s\n", result ? "success" : "fail");
    }

    bool(__fastcall* pfnLobbyHelper)(void* self, const wchar_t* unk0, const wchar_t* unk1);
    bool __fastcall lobby_helper(void* self, const wchar_t* unk0, const wchar_t* unk1)
    {   
        static bool is_logged_in = false;

        dbg_printf("LobbyHelper begin\n");

        if (!is_logged_in)
        {
            dbg_printf("Creating ExecuteLogin thread\n");
            is_logged_in = true;
            HANDLE thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)execute_login, nullptr, 0, nullptr);

            if (thread)
                CloseHandle(thread);
            else
                dbg_printf("Failed to create ExecuteLogin thread\n");
        }

        dbg_printf("Calling original LobbyHelper\n");
        
        auto result = pfnLobbyHelper(self, unk0, unk1);

        return result;
    }

    bool hook(std::span<char> data, const wchar_t* username, const wchar_t* password, const wchar_t* pin)
    {
        static std::once_flag once_flag;

        if (!username || !*username || !password || !*password)
            return false;

        ps_username = username;
        ps_password = password;

        // Initialize patterns & find
        std::call_once(once_flag, []() {
            INIT_PATTERN(pattern_lobby_helper, 0, "56 57 8B F1 FF 15 ?? ?? ?? ?? 8B C8 85 C9 0F 84 ?? ?? ?? ?? 8B 7C 24 0C 85 FF");
            INIT_PATTERN(pattern_login, 0, "8B 15 ?? ?? ?? ?? B9 08 00 00 00 39 0D ?? ?? ?? ?? 73 05 BA ?? ?? ?? ?? 39 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 73 05");
        });

        FIND_OR_RETURN(addr_lobby_helper, pattern_lobby_helper);
        FIND_OR_RETURN(addr_login, pattern_login);

        // Hook
        g_DetoursData->TransactionBegin();
        g_DetoursData->UpdateThread(NtCurrentThread());

        pfnLobbyHelper = (decltype(pfnLobbyHelper))addr_lobby_helper;
        g_DetoursData->Attach(&(PVOID&)pfnLobbyHelper, lobby_helper);

        pfnLogin = (decltype(pfnLogin))addr_login;

        if (g_DetoursData->TransactionCommit() != NO_ERROR)
        {
            dbg_printf("Failed to commit detours\n");
            return false;
        }

        return true;
    }
}
