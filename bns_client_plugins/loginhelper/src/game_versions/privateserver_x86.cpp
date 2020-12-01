#include <phnt_windows.h>
#include <phnt.h>

#include <mutex>

#include <plugindbg.h>
#include <ns/pattern.h>

#include "privateserver_x86.h"
#include "state.h"

namespace ps_x86
{
    constexpr auto LobbyHelperPattern = COMPILE_PATTERN("56 57 8B F1 FF 15 ?? ?? ?? ?? 8B C8 85 C9 0F 84 ?? ?? ?? ?? 8B 7C 24 0C 85 FF");
    constexpr auto LoginPattern = COMPILE_PATTERN("8B 15 ?? ?? ?? ?? B9 08 00 00 00 39 0D ?? ?? ?? ?? 73 05 BA ?? ?? ?? ?? 39 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 73 05");

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

        dbg_puts("LobbyHelper begin");

        if (!is_logged_in)
        {
            dbg_puts("Creating ExecuteLogin thread");
            is_logged_in = true;
            HANDLE thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)execute_login, nullptr, 0, nullptr);

            if (thread)
                CloseHandle(thread);
            else
                dbg_puts("Failed to create ExecuteLogin thread");
        }

        dbg_puts("Calling original LobbyHelper");
        
        auto result = pfnLobbyHelper(self, unk0, unk1);

        return result;
    }

    bool hook(std::span<unsigned char> data, const wchar_t* username, const wchar_t* password, const wchar_t* pin)
    {
        static std::once_flag once_flag;

        if (!username || !*username || !password || !*password)
            return false;

        ps_username = username;
        ps_password = password;

        // Initialize patterns & find
        auto lobby_helper_offset = ns::find_pattern(LobbyHelperPattern, data);
        if (lobby_helper_offset == ns::no_match)
        {
            dbg_puts("Failed to find lobby helper pattern");
            return false;
        }

        auto login_offset = ns::find_pattern(LoginPattern, data);
        if (login_offset == ns::no_match)
        {
            dbg_puts("Failed to find login pattern");
            return false;
        }

        // Hook
        g_DetoursData->TransactionBegin();
        g_DetoursData->UpdateThread(NtCurrentThread());

        pfnLobbyHelper = (decltype(pfnLobbyHelper))(data.data() + lobby_helper_offset);
        g_DetoursData->Attach(&(PVOID&)pfnLobbyHelper, lobby_helper);

        pfnLogin = (decltype(pfnLogin))(data.data() + login_offset);

        if (g_DetoursData->TransactionCommit() != NO_ERROR)
        {
            dbg_printf("Failed to commit detours\n");
            return false;
        }

        return true;
    }
}
