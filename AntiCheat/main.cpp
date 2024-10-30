#include <iostream>
#include <Windows.h>
#include <string>
#include <thread>
#include <windows.h>
#include <winternl.h>
#include <iostream>

#include "Modules/Triggers/Triggers.h"
#include "Modules/Communication/Communication.h"
#include "Modules/ThreadMonitor/MonitorThread.h"
#include "Modules/Detections/Detections.h"

#include "Systems/LogSystem/Log.h"
#include "Systems/Utils/utils.h"
#include "Systems/Utils/xorstr.h"
#include "Systems/Memory/memory.h"
#include "Systems/Monitoring/Monitoring.h"
#include "Systems/FileChecking/FileChecking.h"

#include "Globals/Globals.h"

int main( int argc , char * argv[ ] ) {
	if ( !Mem::Get( ).RestrictProcessAccess( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[9] Failed to protect process" ) );
	}
	Globals::Get( ).SelfID = ::_getpid( );

#ifdef _DEBUG
	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );
#else
	::ShowWindow( ::GetConsoleWindow( ) , SW_HIDE );
#endif // !DEBUG

	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

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


	/*Globals::Get( ).OriginalProcess = Mem::Get( ).GetProcessID( "explorer.exe" );
	Globals::Get( ).ProtectProcess = Mem::Get( ).GetProcessID( "notepad.exe" );*/

	FileChecking::Get( ).ValidateFiles( );

	Triggers TriggerEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	Detections DetectionEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	Communication CommunicationEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );

	CommunicationEvent.start( );

	while ( !Globals::Get( ).VerifiedSession ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	std::vector<std::pair<ThreadMonitor * , int>> threads = {
		std::make_pair( &TriggerEvent, TRIGGERS ) ,
		std::make_pair( &DetectionEvent, DETECTIONS ),
		std::make_pair( &CommunicationEvent, COMMUNICATION ) };

	DetectionEvent.start( );
	TriggerEvent.start( );

	MonitorThread monitor( threads );
	monitor.start( );

	std::this_thread::sleep_for( std::chrono::seconds( 5 ) );

	while ( true ) {
		Utils::Get( ).WarnMessage( LIGHT_WHITE , xorstr_( "PING" ) , xorstr_( "main" ) , GRAY );

		if ( !monitor.isRunning( ) ) {
			Utils::Get( ).WarnMessage( BLUE , xorstr_( "main" ) , xorstr_( "thread monitor is not running" ) , RED );
			monitor.reset( );
		}
		else
			monitor.requestupdate( );

		std::this_thread::sleep_for( std::chrono::minutes( 1 ) );
	}
}