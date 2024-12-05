#include <iostream>
#include <Windows.h>
#include <string>
#include <thread>
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <cassert>
#include <tlhelp32.h>

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

// Function to get the parent process ID
DWORD GetParentProcessId( DWORD processId ) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	if ( hSnapshot == INVALID_HANDLE_VALUE ) {
		return 0;
	}

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof( PROCESSENTRY32 );

	if ( Process32First( hSnapshot , &processEntry ) ) {
		do {
			if ( processEntry.th32ProcessID == processId ) {
				DWORD parentPid = processEntry.th32ParentProcessID;
				CloseHandle( hSnapshot );
				return parentPid;
			}
		} while ( Process32Next( hSnapshot , &processEntry ) );
	}

	CloseHandle( hSnapshot );
	return 0;
}


int main( int argc , char * argv[ ] ) {
	//Ignore load library missing msgbox

	// LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Hello world!" ) , GREEN );
	hardware::Get( ).GenerateCache( );
	Preventions::Get( ).Deploy( );
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX );

	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

	Globals::Get( ).SelfID = ::_getpid( );
	FileChecking::Get( ).ValidateFiles( );
#if true
	DWORD ParentProcessId = GetParentProcessId( GetCurrentProcessId( ) );

	if ( !ParentProcessId || ParentProcessId == GetCurrentProcessId() ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Initialization failed no parent"), false );
		return 0;
	}

	//FreeConsole( );
	//::ShowWindow( ::GetConsoleWindow( ) , SW_HIDE );
	if ( argc < 3 ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Initialization failed" ) , false );
		return 0;
	}

	if ( !Utils::Get( ).isNumber( argv[ 1 ] ) || !Utils::Get( ).isNumber( argv[ 2 ] ) ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Invalid Input" ) , false );
		return 0;
	}
	Globals::Get( ).OriginalProcess = stoi( ( std::string ) argv[ 1 ] );
	Globals::Get( ).ProtectProcess = stoi( ( std::string ) argv[ 2 ] );

	/*std::string OriginalProcessPath = Mem::Get( ).GetProcessExecutablePath( Globals::Get( ).OriginalProcess );

	if ( OriginalProcessPath.empty( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Can't get original process path!" ) );
		return 0;
	}
	system( "pause" );
	std::string OriginalProcessHash = Mem::Get( ).GetFileHash( OriginalProcessPath );
	if ( OriginalProcessHash.empty( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Can't get original process hash!" ) );
		return 0;
	}
	Globals::Get( ).OriginalProcessHash = OriginalProcessHash;
	{
		std::cout << "trying to download!\n";
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

		std::vector<char> OriginalLauncherMemory;
		if ( !Utils::Get( ).DownloadToBuffer( xorstr_( "https://download1076.mediafire.com/c9yznmvqavegRUmomfayh0JMiTBzWAsOUn44K-_gOI8HbrQeZe-4rV8QtMpVxWwOneIdBGltMzL4t_PmETpe8ygwzhuXwc8UJBA2CK1gEVvj4md6SGLjLhnfTSWRBla-sfAkt4ZtYGXDRHiJwn1Y66571g8xw7Pl2jYGYAvMRxnuGQ/oqngyfw6l8fd1s1/LauncherApocalypse_1.0.0.exe" ) , OriginalLauncherMemory ) ) {
			LogSystem::Get( ).Log( xorstr_( "[401] Failed to require file!" ) );
			return 0;
		}

		std::cout << "downloaded!\n";
		std::this_thread::sleep_for( std::chrono::seconds( 1 ) );

		std::string AuthenticLauncherHash = Mem::Get( ).GenerateVecCharHash( OriginalLauncherMemory );
		if ( AuthenticLauncherHash.empty( ) ) {
			LogSystem::Get( ).Log( xorstr_( "[401] Failed to get required file hash!" ) );
			return 0;
		}

		if ( AuthenticLauncherHash != OriginalProcessHash ) {
			LogSystem::Get( ).Log( xorstr_( "[401] Failed initialize!" ) );
			return 0;
		}

	}*/

	if ( !Communication::InitializeClient( ) ) {
		LogSystem::Get( ).Log( xorstr_( "Can't init client" ) , false );
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