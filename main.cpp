#include <iostream>
#include <Windows.h>
#include <string>
#include <thread>

#include "Modules/Triggers/Triggers.h"
#include "Modules/Communication/Communication.h"
#include "Modules/ThreadMonitor/MonitorThread.h"
#include "Modules/Detections/Detections.h"

#include "Systems/LogSystem/Log.h"
#include "Systems/Utils/utils.h"
#include "Systems/Utils/crypt_str.h"
#include "Systems/Memory/memory.h"
#include "Systems/Monitoring/Monitoring.h"

#include "Globals/Globals.h"




int main( int argc , char * argv[ ] ) {
	system( "Title Aegis" );

#ifdef _DEBUG
	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

	Triggers TriggerEvent( 0 , 0 );
	Detections DetectionEvent( 0 , 0 );
	Communication CommunicationEvent( 0 , 0 );

	CommunicationEvent.start( );

	while ( !Globals::Get( ).VerifiedSession ) {
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
	}

	std::vector<std::pair<ThreadMonitor *, int>> threads = { std::make_pair( &TriggerEvent, TRIGGERS ) , 
		std::make_pair( &DetectionEvent, DETECTIONS ),
		std::make_pair( &CommunicationEvent, COMMUNICATION ) };

	DetectionEvent.start( );
	TriggerEvent.start( );
	
	MonitorThread monitor( threads );
	monitor.start( );

#else
	::ShowWindow( ::GetConsoleWindow( ) , SW_HIDE );

	if ( argc < 3 ) {
		LogSystem::Get( ).Log( crypt_str( "[401] Initialization failed" ) );
		return 0;
	}

	if ( !Utils::Get( ).isNumber( argv[ 1 ] ) || !Utils::Get( ).isNumber( argv[ 2 ] ) ) {
		LogSystem::Get( ).Log( crypt_str( "[401] Invalid Input" ) );
		return 0;
	}

	Globals::Get( ).OriginalProcess = stoi( ( std::string ) argv[ 1 ] );
	Globals::Get( ).ProtectProcess = stoi( ( std::string ) argv[ 2 ] );

	Triggers TriggerEvent( Globals::Get().OriginalProcess , Globals::Get( ).ProtectProcess );
	Detections DetectionEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	Communication CommunicationEvent( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );

	std::vector<ThreadMonitor *> threads = { &TriggerEvent, &DetectionEvent, &CommunicationEvent };

	DetectionEvent.start( );
	TriggerEvent.start( );
	CommunicationEvent.start( );

	MonitorThread monitor( threads );
	monitor.start( );

#endif // !DEBUG

	std::this_thread::sleep_for( std::chrono::seconds( 5 ) );

	while ( true ) {
		std::cout << crypt_str("[main] Ping!\n");

		if ( !monitor.isRunning( ) ) {
			std::cout << crypt_str( "[main] thread monitor is not running\n" );
			monitor.reset( );
		}
		else
			monitor.requestupdate( );

		std::this_thread::sleep_for( std::chrono::minutes( 1 ) );
	}
}