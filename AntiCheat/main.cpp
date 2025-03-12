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
	Communication CommunicationEvent( _globals.OriginalProcess , _globals.ProtectProcess );
	Triggers TriggerEvent( _globals.OriginalProcess , _globals.ProtectProcess );
	AntiDebugger AntiDbg;
	Listener ListenEvent;

	DetectionEvent.SetupPid( _globals.OriginalProcess , _globals.ProtectProcess );

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
	_globals.GuardMonitorPointer = &monitor;

	_globals.TriggersPointer = &TriggerEvent;
	_globals.AntiDebuggerPointer = &AntiDbg;
	monitor.start( );

	while ( !_globals.VerifiedSession ) {
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
			return;
		}
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}
}

DWORD GetParentProcessID( DWORD processID ) {
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof( PROCESSENTRY32 );

	// Create a snapshot of all processes
	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );
	if ( snapshot == INVALID_HANDLE_VALUE ) {
		return 0;
	}

	// Iterate through the processes to find the one with the matching process ID
	if ( Process32First( snapshot , &pe ) ) {
		do {
			if ( pe.th32ProcessID == processID ) {
				CloseHandle( snapshot );
				return pe.th32ParentProcessID;
			}
		} while ( Process32Next( snapshot , &pe ) );
	}

	CloseHandle( snapshot );
	return 0;
}

bool IsProcessParent( DWORD processID , DWORD targetParentPID ) {
	DWORD parentPID = GetParentProcessID( processID );
	return parentPID == targetParentPID;
}

#include <nlohmann/json.hpp>
#include "Systems/LogSystem/File/File.h"
using nlohmann::json;


int main( int argc , char * argv[ ] ) {

	_globals.GameName = xorstr_( "DayZ_x64.exe" );
	FreeConsole( );
	//Init anti-cheat
	{
		//Request MB and Disk ID
		if ( !hardware::Get( ).GenerateInitialCache( ) ) {
			LogSystem::Get( ).Log( xorstr_( "[401] Failed to generate initial hardware cache" ) , false );
			return 0;
		}

		//Initialize in case preventions module has to add a external detection
		_globals.DetectionsPointer = &DetectionEvent;

		//Deploy Preventions
		int PreventionsResult = Preventions::Get( ).Deploy( );
		if ( PreventionsResult != 903 ) {
			LogSystem::Get( ).Log( xorstr_( "[401] Failed to deploy prevention " ) + std::to_string( PreventionsResult ) , false );
			return 0;
		}
		//Ignore errors caused in process
		SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX );

		DWORD myProcessID = GetCurrentProcessId( ); // Get the current process ID
		DWORD ParentProcessId = GetParentProcessID( myProcessID ); // Get the parent process ID

		if ( !ParentProcessId ) {
			LogSystem::Get( ).Log( xorstr_( "[401] Initialization failed no parent" ) , false );
			return 0;
		}
		_globals.OriginalProcess = ParentProcessId;

		DWORD GameProcessID = Mem::Get( ).GetProcessID( _globals.GameName.c_str( ) );
		if ( !GameProcessID ) {
			LogSystem::Get( ).Log( xorstr_( "[401] Game not found" ) , false );
			return 0;
		}
		_globals.ProtectProcess = GameProcessID;

		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Parent: " ) + Mem::Get( ).GetProcessName( ParentProcessId ) , GRAY );



		if ( !hardware::Get( ).EndCacheGeneration( ) ) {
			LogSystem::Get( ).Log( xorstr_( "[401] Failed to end hardware cache" ) , false );
			return 0;
		}

		std::string VersionID;
		if ( !hardware::Get( ).GetVersionUID( &VersionID ) )
		{
			LogSystem::Get( ).Log( xorstr_( "[401] Failed to get version ID" ) , false );
			return 0;
		}
		LogSystem::Get( ).ConsoleLog( _HWID , xorstr_( "VersionID: " ) + VersionID , YELLOW );

	}

	// ::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

	_globals.SelfID = ::_getpid( );

#if true




	//std::cout << "Parent hash:  " << ParentHash << "\n";
	//[system( "pause" ); ]

	//FreeConsole( );
	//::ShowWindow( ::GetConsoleWindow( ) , SW_HIDE );

	if ( !FileChecking::Get( ).ValidateFiles( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Can't validate files" ) , false );
		return 0;
	}

	if ( !_client.SendPingToServer( ) ) {
		LogSystem::Get( ).Log( xorstr_( "[401] Can't connect to server" ) , false );
	}


	//Start client module
	TerminateProcess( Mem::Get( ).GetProcessHandle( _globals.OriginalProcess ) , 1 );

#endif 


	Startup( );



idle:
	int MaxIdle = 3;
	for ( int i = 0; i <= MaxIdle; i++ ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "idle" ) , GRAY );
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}

	return 1;
}