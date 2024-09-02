#include <iostream>
#include <Windows.h>
#include <string>
#include <thread>

#include "../Globals/Globals.h"
#include "../Triggers/Triggers.h"
#include "../Utils/crypt_str.h"
#include "../LogSystem/Log.h"
#include "../Communication/Communication.h"
#include "../Utils/utils.h"
#include "../Memory/memory.h"

Triggers EventTriggers;

int main( int argc , char * argv[ ] ) {
	system( "Title Aegis" );
	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

	/*if ( argc < 3 ) {
		LogSystem::Get( ).Log( crypt_str( "[401] Initialization failed" ) );
		return 0;
	}

	if ( !Utils::Get( ).isNumber( argv[ 1 ] ) || !Utils::Get( ).isNumber( argv[ 2 ] ) ) {
		LogSystem::Get( ).Log( crypt_str( "[401] Invalid Input" ) );
		return 0;
	}

	Globals::Get( ).OriginalProcess = stoi((std::string)argv[ 1 ]);
	Globals::Get( ).ProtectProcess = stoi((std::string)argv[ 2 ]);

	Communication LauncherCommunication( Globals::Get( ).OriginalProcess , Globals::Get().ProtectProcess );
	LauncherCommunication.StartCommunicationThread( );*/
	

	std::cout << "OriginalProcess: " << Globals::Get( ).OriginalProcess << std::endl;
	std::cout << "ProtectProcess: " << Globals::Get( ).ProtectProcess << std::endl;

	while ( true ) {
		std::vector<Trigger> EventResult = EventTriggers.StartTriggers( );

		for ( Trigger Event : EventResult ) {
			std::cout << "Event: " << "DETECTED " << Event.Area << ", " << ", " << Event.Trigger << ", " << Event.ExpectedTrigger << "\n";
		}

		Sleep( 10 );
	}
}