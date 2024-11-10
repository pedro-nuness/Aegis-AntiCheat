#include <iostream>
#include <Windows.h>
#include <ShlObj.h>
#include <ShlObj_core.h>
#include <thread>

DWORD WINAPI main( PVOID base )
{
	AllocConsole( );

	if ( !freopen( ( "CONOUT$" ) , ( "w" ) , stdout ) )
	{
		FreeConsole( );
		return EXIT_SUCCESS;
	}

	std::cout << ( "[+] DLL Sucessfully attached at " ) << base << ( "\n" );

	while ( true ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	FreeConsole( );
	return EXIT_SUCCESS;
}

BOOL WINAPI DllMain( HMODULE hModule , DWORD dwReason , LPVOID lpReserved )
{
	switch ( dwReason ) {
	case DLL_PROCESS_ATTACH:
		CreateThread( nullptr , 0 , main , hModule , 0 , nullptr );
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}