#include <iostream>
#include <string>
#include <filesystem>

#include <pe/module.h>
#include <pluginsdk.h>

const DetoursData* g_DetoursData;

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hInstance);

    return TRUE;
}

template<class T>
void patch_rva(pe::module* module, uint32_t rva, T value)
{
    DWORD oldProtection;

    void* address = module->rva_to<void>(rva);

    if (!VirtualProtect(address, sizeof(value), PAGE_EXECUTE_READWRITE, &oldProtection)) {
        MessageBoxA(nullptr, "Failed to virtual protect", "Fail", 0);
        return;
    }

    memcpy(address, (void*)&value, sizeof(value));

    VirtualProtect(address, sizeof(value), oldProtection, &oldProtection);
}

template<class T>
void patch_rva(pe::module* module, uint32_t rva, T* value, uint32_t size)
{
    DWORD oldProtection;

    void* address = module->rva_to<void>(rva);

    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        MessageBoxA(nullptr, "Failed to virtual protect", "Fail", 0);
        return;
    }

    memcpy(address, (void*)value, size);

    VirtualProtect(address, size, oldProtection, &oldProtection);
}

void patch_jump(pe::module* module, uintptr_t jump_rva, uintptr_t destination_rva)
{
    patch_rva(module, (uint32_t)jump_rva + 2, (uint32_t)(destination_rva - jump_rva - 6));
}

void make_jump(pe::module* module, uintptr_t jump_rva, uintptr_t destination_rva)
{
    unsigned char buffer[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};

    uint32_t offset = (uint32_t)(destination_rva - jump_rva - sizeof(buffer));
    memcpy(&buffer[1], &offset, sizeof(offset));
    
    patch_rva(module, (uint32_t)jump_rva, buffer, sizeof(buffer));
}

void nop(pe::module* module, uint32_t rva, int size)
{
    DWORD oldProtection;

    void* address = module->rva_to<void>(rva);

    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtection)) {
        MessageBoxA(nullptr, "Failed to virtual protect", "Fail", 0);
        return;
    }

    memset(address, 0x90, size);

    VirtualProtect(address, size, oldProtection, &oldProtection);
}

#define TO_RVA(x) x - 0x7FF79E5A0000

void Patch()
{
    static bool patched = false;

    if (patched)
        return;

    if (const auto module = pe::get_module())
    {
        // Patch log: [npc-spawn], cannot spawn npc; already spawned, zone:0x%I64x, spawn-key:0x%I64x
        nop(module, TO_RVA(0x7FF79E8F57C6), 5);
        nop(module, TO_RVA(0x7FF79E8F5FA2), 5);
        nop(module, TO_RVA(0x7FF79E8F5BB8), 5);

        // Patch log: [npc], Npc::OnKilled, npcId:0x%I64x, npcPtr:%p, npcAlias:%s
        nop(module, TO_RVA(0x7FF79E8B55A3), 5);

        // Patch log: [skill] initilize data, invalid targetFilterData, caster %I64X, data id %d.
        nop(module, TO_RVA(0x7FF79E91FBB2), 5);

        // Patch log: [brain], npc:%s, ignored event:%s, current pending event:%s
        nop(module, TO_RVA(0x7FF79E8A3244), 5);

        // Patch log: [script], reaction:'%s', line:%d, opponent is not an object, opponent:%I64x
        // in sub_7FF79E8FE1D0
        nop(module, TO_RVA(0x7FF79E8FE380), 5);

        // in sub_7FF79E8FE030
        nop(module, TO_RVA(0x7FF79E8FE1AF), 5);

        // Patch log: [brain], movearound to same position(random value is same position), npc-alias:%s, npc:%I64X, curPos:%d;%d;%d, dstPos:%d;%d;%d
        nop(module, TO_RVA(0x7FF79E8A1806), 5);

        // Patch log: [zone], construct cube, geozone:%d, zoneType2:%d, cubeXSize:%d, cubeYSize:%d, cubeCount:%d
        nop(module, TO_RVA(0x7FF79E640D48), 5);

        // Patch log: [serialize object list], grow, this:%p, old count:%d, new count:%d
        nop(module, TO_RVA(0x7FF79EAAC530), 5);

        // [channel], disabled channel, zone:%I64x, geozone:%d, channel:%d
        nop(module, TO_RVA(0x7FF79E7508C0), 5);
        nop(module, TO_RVA(0x7FF79E75094F), 5);

        // [Campfire], initialize, Campfire : (%I64X), dataId : %d, zone : (%I64X)
        nop(module, TO_RVA(0x7FF79E5DD8D4), 5);

        // [pc], pc start skill casting, pcId:0x%I64X, name:%s, skillId:%d, skillLevel:%d, currentTime:%I64d, limitTime:%I64d, diffTime:%I64d
        nop(module, TO_RVA(0x7FF79E9267F0), 5);

        // [skill], casting skill, casterId:0x%I64X, targetId:0x%I64X, skillId:%d, skillLevel:%d, time:%I64d
        nop(module, TO_RVA(0x7FF79E926879), 5);

        // [duel-bot], duel-bot start skill casting, duel-bot-id:0x%I64x, name:%s, skillId:%d, skillLevel:%d, currentTime:%I64d, limitTime:%I64d, diffTime:%I64d
        nop(module, TO_RVA(0x7FF79E926697), 5);

        // [pc], pc changed stance, pc : %s, old stance : %d, new stance : %d
        nop(module, TO_RVA(0x7FF79E76A06D), 5);
        
        // reaction-set failed, name:%s, line:%d
        nop(module, TO_RVA(0x7FF79E902E1A), 5);

        // [skill] initilize data, invalid targetFilterData, caster %I64X, data id %d.
        nop(module, TO_RVA(0x7FF79E91FBB2), 5);
        nop(module, TO_RVA(0x7FF79E92058B), 5);

        // [%s],position is not land, caster:%I64x, spawn_alias:%s, npcpos [%d,%d,%d], cx,cy [%d,%d], cell-type:%d
        nop(module, TO_RVA(0x7FF79E8BF6A6), 5);
        nop(module, TO_RVA(0x7FF79E8BD4C9), 5);

        // [npc-spawn], cannot spawn npc; invalid spawn record, zone:0x%I64x, spawn-data-key:0x%I64x
        nop(module, TO_RVA(0x7FF79E8F548A), 5);
        nop(module, TO_RVA(0x7FF79E8F5886), 5);

        // [script], invalid subscription for npc., object:%I64x, subscription:'%s', subscription-index:%d
        nop(module, TO_RVA(0x7FF79E903E81), 5);

        // [script], invalid subscription for npc party. subscription:'%s', subscription-index:%d
        nop(module, TO_RVA(0x7FF79E9038D2), 5);

        // filter failed; get subject2 failed, type:%s, line:%d
        nop(module, TO_RVA(0x7FF79E902D65), 5);
        nop(module, TO_RVA(0x7FF79E9E25B0), 5);

        // [skill], checkTargetFilter, caster %I64X, CheckAttackException is true, target(%I64X)
        nop(module, TO_RVA(0x7FF79E92D3D5), 5);

        // [skill], SkillAction::invokeCastEffect; failed to invoke effect, casterId:0x%I64X, skillId:%d, variationId:%d, effectId:%d
        nop(module, TO_RVA(0x7FF79E92DDEA), 5);

        // [skill], SkillAction::invokeCastEffect; failed to invoke effect, casterId:0x%I64X, targetId:0x%I64X, skillId:%d, variationId:%d, effectId:%d
        nop(module, TO_RVA(0x7FF79E92E0D1), 5);

        // [filter], target is not an object., filter:'%s', target:%I64x
        nop(module, TO_RVA(0x7FF79E77183F), 5);

    }

    patched = true;
}

void __cdecl DllLoadedNotification(const struct DllNotificationData* Data, void* Context)
{
    Patch();
}

void __cdecl InitNotification(const struct InitNotificationData* Data, void* Context)
{
    g_DetoursData = Data->Detours;
}

#ifndef __DATEW__
#define __DATEW__ _CRT_WIDE(__DATE__)
#endif

extern "C" __declspec(dllexport)
void __cdecl GetPluginInfo2(PluginInfo2* plgi)
{
    plgi->Name = L"serverpatch";
    plgi->Version = __DATEW__;
    plgi->Description = L"Patches some GameDaemon01 bullshit";
    plgi->InitNotification = &InitNotification;
    plgi->DllLoadedNotification = &DllLoadedNotification;
}
