// AntiCheatProtector.cpp : Este arquivo contém a função 'main'. A execução do programa começa e termina ali.
//


#include <Windows.h>
#include <iostream>
#include <thread>


#include "Systems/Memory/memory.h"
#include "Systems/Globals/Globals.h"
#include "Systems/Utils/utils.h"
#include "Systems/Utils/xorstr.h"
#include "Systems/LogSystem/Log.h"
#include "Systems/Security/security.h"

#include "Modules/Communication/Communication.h"
#include "Modules/Detections/Detections.h"
#include "Modules/ThreadMonitor/MonitorThread.h"


DWORD WINAPI main( PVOID base )
{
#ifdef  _DEBUG
	AllocConsole( );

	if ( !freopen( ( "CONOUT$" ) , ( "w" ) , stdout ) )
	{
		FreeConsole( );
		return EXIT_SUCCESS;
	}


#endif //  _DEBUG

	AllocConsole( );

	if ( !freopen( ( "CONOUT$" ) , ( "w" ) , stdout ) )
	{
		FreeConsole( );
		return EXIT_SUCCESS;
	}


	Utils::Get( ).WarnMessage( GREEN , xorstr_( "AEGIS" ) , xorstr_( "Sucessfully attached :)" ) , WHITE );

	/*if ( Mem::Get( ).RestrictProcessAccess( ) ) {
		Utils::Get( ).WarnMessage( GREEN , xorstr_( "-" ) , xorstr_( "Memory protected sucessfully" ) , GREEN );
	}
	else {
		Utils::Get( ).WarnMessage( RED , xorstr_( "!" ) , xorstr_( "Failed to protect memory!" ) , RED );
		LogSystem::Get( ).Log( xorstr_( "[0] Failed to protect process!" ) );
	}*/

	Communication CommunicationEvents;
	Detections DetectionsEvents;

	CommunicationEvents.start( );



	while ( !Globals::Get( ).VerifiedSession )
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );


	std::vector<std::pair<ThreadMonitor * , int>> threads = {
	std::make_pair( &CommunicationEvents, COMMUNICATION ) ,
	std::make_pair( &DetectionsEvents, DETECTIONS )
	};

	DetectionsEvents.start( );

	MonitorThread monitor( threads );

	monitor.start( );

	while ( true ) {
		std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
	}

	FreeConsole( );

#ifdef _DEBUG
	FreeConsole( );
#endif
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