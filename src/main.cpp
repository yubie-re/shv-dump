#include "inc.hpp"
#include "scan.hpp"
#include "MinHook.h"

bool g_dumped = false;
int64_t* g_native_table = 0;
int g_update_count = 0;
int g_max_natives = 0;

/*
The table structure looks something like this
int64_t native_table[NATIVES_COUNT][UPDATE_COUNT]
Not really any clean way as we need to scan for the sizes at runtime but we can work with it.
*/

DWORD (*o_get_module_name)(HMODULE mod, LPSTR filename, DWORD size);
DWORD get_module_name_hk(HMODULE mod, LPSTR filename, DWORD size)
{
    if (mod == 0 || g_dumped)
        return o_get_module_name(mod, filename, size);
    g_native_table = (int64_t *)scanner::rip(scanner::scan("4C 8D 15 ? ? ? ? 33 D2 49 8B CA 44 8B CA", "First Map", mod), 3);
    g_update_count = *(int*)((uintptr_t)(scanner::scan("48 81 C1 ? ? ? ? 49 63 C1 48 3D", "Update Count", mod)) + 3) / sizeof(int64_t);
    g_max_natives = *(int*)((uintptr_t)(scanner::scan("48 3D ? ? ? ? 72 E6", "Total Natives", mod)) + 2);
    std::vector<std::pair<int64_t, int64_t>> crossmap;
    for(size_t native_index = 0; native_index < g_max_natives; native_index++)
    {
        int64_t* native_update_array = &g_native_table[native_index * g_update_count];
        int64_t initial_hash = 0;
        for(int i = 0; i < g_update_count; i++)
        {
            if(native_update_array[i] != 0)
            {
                initial_hash = native_update_array[i];
                break;
            }
        }
        if(native_update_array[g_update_count - 1] != 0)
        {
            crossmap.push_back(std::make_pair(initial_hash, native_update_array[g_update_count - 1]));
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