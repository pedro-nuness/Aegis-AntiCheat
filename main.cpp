#include <iostream>
#include <Windows.h>
#include <string>
#include <thread>

#include "Triggers/Triggers.h"
#include "Communication/Communication.h"
#include "LogSystem/Log.h"
#include "Globals/Globals.h"
#include "Utils/utils.h"
#include "Utils/crypt_str.h"
#include "Memory/memory.h"
#include "Detections/Detections.h"
#include "Monitoring/Monitoring.h"



int main( int argc , char * argv[ ] ) {
	system( "Title Aegis" );

#ifdef _DEBUG
	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

	Triggers EventTriggers( 0 , 0 );
	Detections DetectionEvents( 0 , 0 );
	

	DetectionEvents.Init( );

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

	Communication LauncherCommunication( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	LauncherCommunication.StartCommunicationThread( );

	Triggers EventTriggers( Globals::Get().OriginalProcess , Globals::Get( ).ProtectProcess );
	Detections DetectionEvents( Globals::Get( ).OriginalProcess , Globals::Get( ).ProtectProcess );
	DetectionEvents.Init( );

#endif // !DEBUG

	Monitoring MonitoringEvent;
	std::thread( &Monitoring::Init , &MonitoringEvent ).detach();


	while ( true ) {
		std::vector<Trigger> EventResult = EventTriggers.StartTriggers( );

		for ( Trigger Event : EventResult ) {
			std::cout << "[WARNING]: " << Event.Area << ", " << Event.Trigger << ", " << Event.ExpectedTrigger << "\n";
		}

		Sleep( 500 );
	}
}