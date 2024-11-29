// AntiCheatProtector.cpp : Este arquivo contém a função 'main'. A execução do programa começa e termina ali.
//


#include <Windows.h>
#include <iostream>
#include <thread>


#include "Systems/Memory/memory.h"
#include "Globals/Globals.h"
#include "Systems/Utils/utils.h"
#include "Systems/Utils/xorstr.h"
#include "Systems/LogSystem/Log.h"
#include "Systems/Security/security.h"
#include "Systems/Preventions/Preventions.h"

#include "Modules/Communication/Communication.h"
#include "Modules/Detections/Detections.h"
#include "Modules/ThreadGuard/ThreadGuard.h"


DWORD WINAPI main( PVOID base )
{
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX );
	

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


	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Sucessfully attached :)" ) , WHITE );

	/*if ( Mem::Get( ).RestrictProcessAccess( ) ) {
		LogSystem::Get( ).ConsoleLog( GREEN , xorstr_( "-" ) , xorstr_( "Memory protected sucessfully" ) , GREEN );
	}
	else {
		LogSystem::Get( ).ConsoleLog( RED , xorstr_( "!" ) , xorstr_( "Failed to protect memory!" ) , RED );
		LogSystem::Get( ).Log( xorstr_( "[0] Failed to protect process!" ) );
	}*/

	Communication CommunicationEvents;
	Detections DetectionsEvents;

	CommunicationEvents.start( );
	std::vector<std::pair<ThreadHolder * , int>> threads = {
		std::make_pair( &CommunicationEvents, COMMUNICATION ) ,
		std::make_pair( &DetectionsEvents, DETECTIONS )
	};

	Globals::Get( ).CommunicationObjectPointer = &CommunicationEvents;

	DetectionsEvents.start( );
	ThreadGuard monitor( threads );
	monitor.start( );

	Preventions::Get( ).Deploy( );

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