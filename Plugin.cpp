
#define WIN32_LEAN_AND_MEAN
#include <MinHook.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <Windows.h>
#include <intrin.h>

typedef BOOL(WINAPI* FlushFileBuffersFn)(HANDLE file);
FlushFileBuffersFn FlushFileBuffersTrampoline;
HMODULE Kernel32;
FlushFileBuffersFn FlushFileBuffersPtr;

BOOL WINAPI FlushFileBuffersHook(HANDLE file)
{
    HMODULE module = NULL;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)_ReturnAddress(), &module))
    {
        msg("BinDiffNoFlush: GetModuleHandleEx failed! %d\n", GetLastError());
        return FALSE;
    }

    char name[MAX_PATH];
    if (!GetModuleFileName(module, name, MAX_PATH))
    {
        msg("BinDiffNoFlush: GetModuleFileName failed! %d\n", GetLastError());
        return FALSE;
    }

    if (strstr(name, "zynamics_bindiff"))
    {
        // For bindiff plugin pretend we flushed
        return TRUE;
    }

    return FlushFileBuffersTrampoline(file);
}

int IDAP_init()
{
    Kernel32 = LoadLibrary("kernel32.dll");
    if (!Kernel32)
    {
        msg("BinDiffNoFlush: Not loaded. Reason: LoadLibrary(\"kernel32.dll\") failed.\n");
        return PLUGIN_SKIP;
    }

    FlushFileBuffersPtr = (FlushFileBuffersFn)GetProcAddress(Kernel32, "FlushFileBuffers");
    if (!FlushFileBuffersPtr)
    {
        msg("BinDiffNoFlush: Not loaded. Reason: GetProcAddress(Kernel32, \"FlushFileBuffers\") failed.\n");
        return PLUGIN_SKIP;
    }

    if (MH_Initialize() != MH_OK)
    {
        msg("BinDiffNoFlush: Not loaded. Reason: MH_Initialize() != MH_OK failed.\n");
        return PLUGIN_SKIP;
    }

    if (MH_CreateHook(FlushFileBuffersPtr, &FlushFileBuffersHook, reinterpret_cast<LPVOID*>(&FlushFileBuffersTrampoline)) != MH_OK)
    {
        msg("BinDiffNoFlush: Not loaded. Reason: MH_CreateHook(FlushFileBuffersPtr, &FlushFileBuffersHook, reinterpret_cast<LPVOID*>(&FlushFileBuffersTrampoline)) != MH_OK failed.\n");
        return PLUGIN_SKIP;
    }

    if (MH_EnableHook(FlushFileBuffersPtr) != MH_OK)
    {
        msg("BinDiffNoFlush: Not loaded. Reason: MH_EnableHook(FlushFileBuffersPtr) != MH_OK failed.\n");
        return PLUGIN_SKIP;
    }

    return PLUGIN_KEEP;
}

void IDAP_term()
{
    if (FlushFileBuffersPtr)
    {
        MH_DisableHook(FlushFileBuffersPtr);
        MH_RemoveHook(FlushFileBuffersPtr);
    }

    MH_Uninitialize();

    if (Kernel32)
        FreeLibrary(Kernel32);
}

void IDAP_run(int) { }

char const IDAP_name[] = "BinDiffNoFlush";

plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,  // IDA version plug-in is written for
    PLUGIN_HIDE,            // Flags
    IDAP_init,              // Initialisation function
    IDAP_term,              // Clean-up function
    IDAP_run,               // Main plug-in body
    "",                     // Comment - unused
    "",                     // As above - unused
    IDAP_name,              // Plug-in name shown in
                            //    Edit->Plugins    menu
    ""                      // Hot key to run the plug-in
};
