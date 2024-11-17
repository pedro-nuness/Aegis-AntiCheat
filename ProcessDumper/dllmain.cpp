#include "imports.h"
#include "globals.h"
#include "utils/security.h"

#include "internal/hooks.hpp"
HINSTANCE DllHandle;

#define WIN32_LEAN_AND_MEAN

DWORD WINAPI InitExec() {
    //std::cout xorstr_("[-] MainThread Started\n");
    if (MH_Initialize() != MH_OK) {
        return 0;
    }
    //std::cout xorstr_("[HOOKLIB] Initialized\n");


    /* Security Based Hooks */
    if (MH_CreateHookApi(L"kernel32.dll", xorstr_("GetThreadContext"), &hookedGetThreadContext, reinterpret_cast<void**>(&pGetThreadContext)) != MH_OK) {
        //MessageBoxA(NULL, xorstr_("Failed To Hook GetThreadContext"), "", MB_OK);
    }
    else {
        //std::cout xorstr_("[security-enabled] GetThreadContext->dr. for HW Breakpoints\n");
    }

    if (MH_CreateHookApi(L"ntdll.dll", xorstr_("NtRaiseHardError"), &hookedNtRaiseHardError, reinterpret_cast<void**>(&pNtRaiseHardError)) != MH_OK) {
        //MessageBoxA(NULL, xorstr_("Failed To Hook NtRaisedHardError"), "", MB_OK);
    }
    else {
        //std::cout xorstr_("[security-enabled] GetThreadContext->dr. for HW Breakpoints\n");
    }

    /* RPM / WPM Hooks */
    if (MH_CreateHookApi(L"kernel32.dll", xorstr_("WriteProcessMemory"), &hookedWriteProcessMemory, reinterpret_cast<void**>(&pWriteProcessMemory)) != MH_OK) {
        // MessageBoxA(NULL, xorstr_("Failed To Hook WriteProcessMemory"), "", MB_OK);
    }
    else {
        //std::cout xorstr_("[enabled] WriteProcessMemory Dumper\n");
    }

    /* RPM / SWDP Hooks */
    if ( MH_CreateHookApi( L"user32.dll" , xorstr_( "SetWindowDisplayAffinity" ) , &hookedSetWindowDisplayAffinity , reinterpret_cast< void ** >( &pWriteProcessMemory ) ) != MH_OK ) {
        // MessageBoxA( NULL , xorstr_( "Failed To Hook WriteProcessMemory" ) , "" , MB_OK );
    }
    else {
        //std::cout xorstr_("[enabled] WriteProcessMemory Dumper\n");
    }

    if (MH_CreateHookApi(L"kernel32.dll", xorstr_("ReadProcessMemory"), &hookedReadProcessMemory, reinterpret_cast<void**>(&pReadProcessMemory)) != MH_OK) {
        MessageBoxA(NULL, xorstr_("Failed To Hook ReadProcessMemory"), "", MB_OK);
    }
    else {
        //std::cout xorstr_("[enabled] ReadProcessMemory Dumper\n");
    }  

    
    MH_EnableHook(MH_ALL_HOOKS);
    while (true) {
        Sleep(50);
        if (GetAsyncKeyState(VK_END) & 1) {
            break;
        }
    }

    return 0;
}

BOOL EnumWindowsCallback( HWND hwnd , LPARAM lParam ) {
    DWORD windowProcessID;
    GetWindowThreadProcessId( hwnd , &windowProcessID );
    if ( windowProcessID == static_cast< DWORD >( lParam ) ) {
        auto * windows = reinterpret_cast< std::vector<HWND>* >( lParam );
        windows->push_back( hwnd );
    }
    return TRUE;
}

std::vector<HWND> GetProcessWindows( DWORD processID ) {
    std::vector<HWND> windows;
    EnumWindows( EnumWindowsCallback , reinterpret_cast< LPARAM >( &windows ) );
    return windows;
}

DWORD WINAPI main( PVOID base ) {
    DWORD startTime = GetTickCount64( );
    auto windows = GetProcessWindows( GetCurrentProcessId( ) );

    while ( GetTickCount64( ) - startTime < 20000 ) {
        for ( auto window : windows ) {
            SetWindowDisplayAffinity( window , WDA_NONE );
        }
    }

    return EXIT_SUCCESS;
}


int __stdcall DllMain(const HMODULE hModule, const std::uintptr_t reason, const void* reserved) {
    if (reason == 1) {
        /* Alocate Console */
        if (globals::AllocateConsole == true) {
            AllocConsole();
            FILE* fp;
            freopen_s(&fp, "CONOUT$", "w", stdout);
        }

        DisableThreadLibraryCalls(hModule);
        //std::cout xorstr_("[-] AllocConsole - freopen_s | SET\n");
        DllHandle = hModule;

        hyde::CreateThread( main , DllHandle );
        hyde::CreateThread(InitExec, DllHandle);
        //std::cout xorstr_("[-] Started Main Thread...\n");
     
        return true;
    }
    return true;
}

