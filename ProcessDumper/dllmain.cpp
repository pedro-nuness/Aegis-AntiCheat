#include "imports.h"
#include "globals.h"
#include "utils/security.h"

#include "internal/hooks.hpp"
HINSTANCE DllHandle;

#define WIN32_LEAN_AND_MEAN

bool StopThreads = false;
bool InitializedHooks = false;



void DeallocHooks( ) {
	MH_DisableHook( MH_ALL_HOOKS );
	MH_Uninitialize( );
	StopThreads = true;
}

BOOL EnumWindowsCallback( HWND hwnd , LPARAM lParam ) {
	DWORD windowProcessID;
	GetWindowThreadProcessId( hwnd , &windowProcessID );
	if ( windowProcessID == GetCurrentProcessId( ) ) {
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

DWORD WINAPI InitExec( PVOID base ) {

	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

	if ( MH_Initialize( ) != MH_OK ) {
		return 0;
	}

	if ( MH_CreateHookApi( L"kernel32.dll" , xorstr_( "GetThreadContext" ) , &hookedGetThreadContext , reinterpret_cast< void ** >( &pGetThreadContext ) ) != MH_OK ) {

	}
	else {

	}

	if ( MH_CreateHookApi( L"ntdll.dll" , xorstr_( "NtRaiseHardError" ) , &hookedNtRaiseHardError , reinterpret_cast< void ** >( &pNtRaiseHardError ) ) != MH_OK ) {

	}
	else {
	}

	/* RPM / WPM Hooks */
	if ( MH_CreateHookApi( L"kernel32.dll" , xorstr_( "WriteProcessMemory" ) , &hookedWriteProcessMemory , reinterpret_cast< void ** >( &pWriteProcessMemory ) ) != MH_OK ) {

	}
	else {

	}

	/* RPM / SWDP Hooks */
	if ( MH_CreateHookApi( L"user32.dll" , xorstr_( "SetWindowDisplayAffinity" ) , &hookedSetWindowDisplayAffinity , reinterpret_cast< void ** >( &OriginalSetWindowDisplayAffinity ) ) != MH_OK ) {
	}
	else {

	}

	if ( MH_CreateHookApi( L"kernel32.dll" , xorstr_( "ReadProcessMemory" ) , &hookedReadProcessMemory , reinterpret_cast< void ** >( &pReadProcessMemory ) ) != MH_OK ) {
	}
	else {
	}

	MH_EnableHook( MH_ALL_HOOKS );

	auto windows = GetProcessWindows( GetCurrentProcessId( ) );
	for ( auto window : windows ) {
		SetWindowDisplayAffinity( window , WDA_NONE );
	}

	while ( true ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
		if ( StopThreads ) {
			std::this_thread::sleep_for( std::chrono::seconds( 15 ) );
			DeallocHooks( );
			break;
		}
	}

	return 0;
}


int __stdcall DllMain( const HMODULE hModule , const std::uintptr_t reason , const void * reserved ) {
	if ( reason == 1 ) {
		/* Alocate Console */
		if ( globals::AllocateConsole == true ) {
			AllocConsole( );
			FILE * fp;
			freopen_s( &fp , "CONOUT$" , "w" , stdout );
		}

		DisableThreadLibraryCalls( hModule );

		//DllHandle = hModule;

		CreateThread( nullptr , 0 , InitExec , hModule , 0 , nullptr );

		//hyde::CreateThread( InitExec , DllHandle );
		/*hyde::CreateThread( InitExec , DllHandle ); */
		//std::cout xorstr_("[-] Started Main Thread...\n");

		return true;
	}
	return true;
}

