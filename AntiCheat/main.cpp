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
#include "Modules/Listener/Listener.h"

#include "Systems/LogSystem/Log.h"
#include "Systems/Preventions/Preventions.h"
#include "Systems/Utils/utils.h"
#include "Systems/Utils/xorstr.h"
#include "Systems/Memory/memory.h"
#include "Systems/Monitoring/Monitoring.h"
#include "Systems/FileChecking/FileChecking.h"
#include "Systems/Hardware/hardware.h"

#include "Client/client.h"

#include "Globals/Globals.h"

Detections DetectionEvent;

void Startup( ) {
	Communication CommunicationEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	Triggers TriggerEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	AntiDebugger AntiDbg;
	Listener ListenEvent;

	DetectionEvent.SetupPid( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );

	CommunicationEvent.start( );
	DetectionEvent.start( );
	TriggerEvent.start( );
	AntiDbg.start( );
	ListenEvent.start( );

	DetectionEvent.InitializeThreads( );

	std::vector<std::pair<ThreadHolder * , int>> threads = {
		std::make_pair( &DetectionEvent, DETECTIONS ),
		std::make_pair( &AntiDbg, ANTIDEBUGGER ),
		std::make_pair( &TriggerEvent, TRIGGERS ) ,
		std::make_pair( &CommunicationEvent, COMMUNICATION ),
		std::make_pair( &ListenEvent,  LISTENER )
	};

	ThreadGuard monitor( threads );
	Globals::Get( ).GuardMonitorPointer = &monitor;
	Globals::Get( ).DetectionsPointer = &DetectionEvent;
	Globals::Get( ).TriggersPointer = &TriggerEvent;
	Globals::Get( ).AntiDebuggerPointer = &AntiDbg;
	monitor.start( );

	while ( !Globals::Get( ).VerifiedSession ) {
		//as fast as possible cuh
		std::this_thread::sleep_for( std::chrono::nanoseconds( 1 ) );
	}

	std::this_thread::sleep_for( std::chrono::seconds( 5 ) );

	while ( true ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "ping" ) , GRAY );

		if ( !monitor.isRunning( ) ) {
			LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "thread monitor is not running" ) , RED );
		}
		else if ( monitor.ThreadObject->IsShutdownSignalled( ) ) {
			LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "thread monitor signalled shutdown, shutting down main module!" ) , YELLOW );
			break;
		}
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}
}





int main( int argc , char * argv[ ] ) {
	//Ignore load library missing msgbox

	// LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Hello world!" ) , GREEN );
	hardware::Get( ).GenerateCache( );
	Preventions::Get( ).Deploy( );
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX );


	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

#if true
	//FreeConsole( );
	//::ShowWindow( ::GetConsoleWindow( ) , SW_HIDE );
	if ( argc < 3 ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Initialization failed" ) );
		return 0;
	}

	if ( !Utils::Get( ).isNumber( argv[ 1 ] ) || !Utils::Get( ).isNumber( argv[ 2 ] ) ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Invalid Input" ) );
		return 0;
	}

	Globals::Get( ).OriginalProcess = stoi( ( std::string ) argv[ 1 ] );
	Globals::Get( ).ProtectProcess = stoi( ( std::string ) argv[ 2 ] );

	if ( !Communication::InitializeClient( ) ) {
		LogSystem::Get( ).Log( xorstr_( "Can't init client" ) );
	}
	else {
		if ( !client::Get( ).SendPingToServer( ) ) {
			goto idle;
		}

		//Start client module
		TerminateProcess( Mem::Get( ).GetProcessHandle( Globals::Get( ).OriginalProcess ) , 1 );

#else
	Globals::Get( ).OriginalProcess = Mem::Get( ).GetProcessID( "explorer.exe" );
	Globals::Get( ).ProtectProcess = Mem::Get( ).GetProcessID( "notepad.exe" );

	if ( !Communication::InitializeClient( ) ) {
		LogSystem::Get( ).Log( xorstr_( "Can't init client" ) );
	}
	else {
		::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );
#endif // !DEBUG

		Globals::Get( ).SelfID = ::_getpid( );
		FileChecking::Get( ).ValidateFiles( );

		Startup( );
	}
	
	
idle:
	int MaxIdle = 3;
	for ( int i = 0; i <= MaxIdle; i++ ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "idle" ) , GRAY );
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) ); 
	}

	return 1;
}