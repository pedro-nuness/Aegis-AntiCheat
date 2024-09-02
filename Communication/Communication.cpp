#include <iostream>

#include "Communication.h"



#include "../Globals/Globals.h"
#include "../Memory/memory.h"
#include "../LogSystem/Log.h"
#include "../Utils/crypt_str.h"
#include "../Utils/utils.h"

void Communication::StartCommunicationThread( ) {

	this->MonitoringThread.Handle = CreateThread( NULL , 0 , &Communication::Monitoring , this , 0 , NULL );
	if ( this->MonitoringThread.Handle == NULL ) {
		LogSystem::Get( ).Log( crypt_str( "[808] Can't create thread!" ) );
		exit( 0 );
	}
	this->MonitoringThread.CURRENT_STATUS = COMMUNICATION_STATUS::THREAD_RUNNING;




}

DWORD WINAPI Communication::Monitoring( LPVOID param ){
	Communication * pThis = static_cast< Communication * >( param );

	if ( !Mem::Get( ).IsPIDRunning( pThis->ProcessPID ) ) {
		LogSystem::Get( ).Log( crypt_str( "[402] Can't find communication device!\n" ));
		exit( 0 );
	}

	if ( !Mem::Get( ).IsPIDRunning( pThis->GamePID ) ) {
		LogSystem::Get( ).Log( crypt_str( "[403] Can't find game!\n" ) );
		exit( 0 );
	}

	pThis->AuthenticMemoryHash =
		Utils::Get( ).DownloadString( crypt_str( "https://raw.githubusercontent.com/icarogame/hashlauncher/main/hash.txt" ) );

	std::string CurrentHash = Mem::Get( ).GetFileHash(Mem::Get().GetProcessName( pThis->ProcessPID )) + "\n";

	if ( CurrentHash != pThis->AuthenticMemoryHash ) {
		LogSystem::Get( ).Log( crypt_str( "[403] Can't validate session!\n" ) + pThis->AuthenticMemoryHash + CurrentHash );
		exit( 0 );
	}

	while ( true ) {
		if ( !Mem::Get( ).IsPIDRunning( pThis->ProcessPID ) ) {
			TerminateProcess( Mem::Get( ).GetProcessHandle( pThis->GamePID ), 0 );
			exit( 0 );
		}
		if ( !Mem::Get( ).IsPIDRunning( pThis->GamePID ) ) {
			exit( 0 );
		}

		CurrentHash = Mem::Get( ).GetFileHash( Mem::Get( ).GetProcessName( pThis->ProcessPID ) ) + "\n";
		if ( CurrentHash != pThis->AuthenticMemoryHash ) {
			exit( 0 );
		}
		Sleep( 1000 );
	}
}