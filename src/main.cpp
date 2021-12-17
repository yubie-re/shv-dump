#include "inc.hpp"
#include "scan.hpp"
#include "MinHook.h"

bool g_dumped = false;
DWORD (*o_get_module_name)(HMODULE mod, LPSTR filename, DWORD size);
DWORD get_module_name_hk(HMODULE mod, LPSTR filename, DWORD size)
{
    if (mod == 0 || g_dumped)
        return o_get_module_name(mod, filename, size);
    auto first_map = (int64_t *)scanner::rip(scanner::scan("4C 8D 15 ? ? ? ? 33 D2 49 8B CA 44 8B CA", "First Map", mod), 3);
    auto update_count = *(int*)((uintptr_t)(scanner::scan("48 81 C1 ? ? ? ? 49 63 C1 48 3D", "Update Count", mod)) + 3) / sizeof(int64_t);
    auto total_natives = *(int*)((uintptr_t)(scanner::scan("48 3D ? ? ? ? 72 E6", "Total Natives", mod)) + 2);

    std::unordered_map<int64_t, int64_t> crossmap;
    std::unordered_map<int64_t, int64_t> crossupdate; // so we can backtrack update to update (it is stored basically as crosstables for each update)

    for (int i = 0; i < update_count - 1; i++)
    {
        auto map = first_map + i;
        for(size_t native_index = 0; native_index < total_natives; native_index++, map += (update_count))
        {
            auto new_hash = *(int64_t *)(first_map + update_count * native_index + (i + 1));
            auto old_hash = *map;
            if(new_hash == 0)
                continue;
            if (crossupdate.contains(old_hash) && !crossupdate.contains(new_hash))
            {
                crossmap[crossupdate[old_hash]] = new_hash;
                crossupdate[new_hash] = crossupdate[old_hash];
            }
            else
            {
                if (old_hash == 0)
                    old_hash = new_hash;
                crossmap[old_hash] = new_hash;
                crossupdate[new_hash] = old_hash;
            }
        }
    }

    g_dumped = true;
    
    for(auto& [o, n] : crossmap)
    {
        printf("{ 0x%016llX, 0x%016llX },\n", o, n);
    }
    std::cout << "Dumped " << crossmap.size() << " Natives." << std::endl;
    return o_get_module_name(mod, filename, size);
}

int main()
{
    MH_Initialize();
    MH_CreateHook(GetModuleFileNameA, get_module_name_hk, (void **)&o_get_module_name);
    MH_EnableHook(GetModuleFileNameA);
    // Unfortunately they do most things in DllMain so we'll need to catch it before it unloads/exits. I accomplished this by hooking GetModuleFileNameA since that is the first thing they call.
    // Then we can do any memory reading we need to in that hook.
    LoadLibraryA("ScriptHookV.dll");
    while (!g_dumped)
        std::this_thread::sleep_for(5s);
    MH_Uninitialize();
    return 0;
}