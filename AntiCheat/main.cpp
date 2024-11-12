#include <iostream>
#include <Windows.h>
#include <string>
#include <thread>
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <cassert>

#include "Modules/Triggers/Triggers.h"
#include "Modules/Communication/Communication.h"
#include "Modules/ThreadGuard/ThreadGuard.h"
#include "Modules/Detections/Detections.h"
#include "Modules/AntiDebugger/AntiDebugger.h"

#include "Systems/LogSystem/Log.h"
#include "Systems/Preventions/Preventions.h"
#include "Systems/Utils/utils.h"
#include "Systems/Utils/xorstr.h"
#include "Systems/Memory/memory.h"
#include "Systems/Monitoring/Monitoring.h"
#include "Systems/FileChecking/FileChecking.h"

#include "Globals/Globals.h"



int main( int argc , char * argv[ ] ) {
	system( "pause" );
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX );
	Preventions::Get( ).Deploy( );
	
	Detections DetectionEvent;
	//Deploy DLL Attach verification

	Globals::Get( ).SelfID = ::_getpid( );

	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

#ifdef _DEBUG
	
#else
#endif // !DEBUG


	//if ( argc < 3 ) {
	//	LogSystem::Get( ).Log( xorstr_( "[401] Initialization failed" ) );
	//	return 0;
	//}

	//if ( !Utils::Get( ).isNumber( argv[ 1 ] ) || !Utils::Get( ).isNumber( argv[ 2 ] ) ) {
	//	LogSystem::Get( ).Log( xorstr_( "[401] Invalid Input" ) );
	//	return 0;
	//}

	//Globals::Get( ).OriginalProcess = stoi( ( std::string ) argv[ 1 ] );
	//Globals::Get( ).ProtectProcess = stoi( ( std::string ) argv[ 2 ] );


	Globals::Get( ).OriginalProcess = Mem::Get( ).GetProcessID( "explorer.exe" );
	Globals::Get( ).ProtectProcess = Mem::Get( ).GetProcessID( "notepad.exe" );

	FileChecking::Get( ).ValidateFiles( );

	Communication CommunicationEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	CommunicationEvent.start( );

	while ( !Globals::Get( ).VerifiedSession ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	Triggers TriggerEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	DetectionEvent.SetupPid( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	AntiDebugger AntiDbg;

	std::vector<std::pair<ThreadHolder * , int>> threads = {		
		std::make_pair( &DetectionEvent, DETECTIONS ),
		std::make_pair( &AntiDbg, ANTIDEBUGGER ),
		std::make_pair( &TriggerEvent, TRIGGERS ) ,
		std::make_pair( &CommunicationEvent, COMMUNICATION )
	};

	DetectionEvent.start( );
	TriggerEvent.start( );
	AntiDbg.start( );


	ThreadGuard monitor( threads );
	Globals::Get( ).GuardMonitorPointer = &monitor;
	monitor.start( );

	std::this_thread::sleep_for( std::chrono::seconds( 5 ) );

	while ( true ) {
		Utils::Get( ).WarnMessage( _MAIN , xorstr_( "ping" ) , GRAY );

		if ( !monitor.isRunning( ) ) {
			Utils::Get( ).WarnMessage( _MAIN , xorstr_( "thread monitor is not running" ) , RED );
		}
		else if ( monitor.ThreadObject->IsShutdownSignalled( ) ) {
			Utils::Get( ).WarnMessage( _MAIN , xorstr_( "thread monitor signalled shutdown, shutting down modules!" ) , YELLOW );
		}
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}

	return 1;
}