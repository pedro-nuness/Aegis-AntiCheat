#include <iostream>
#include <Windows.h>
#include <string>
#include <thread>
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <cassert>
#include <tlhelp32.h>
#include <filesystem>
#include <nlohmann/json.hpp>

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
#include "Systems/LogSystem/File/File.h"

#include "Client/client.h"
#include "Globals/Globals.h"

using nlohmann::json;

namespace fs = std::filesystem;


#define IDR_DUMPERDLL 104
#define IDR_LIBCRYPTO 105
#define IDR_LIBSSL 106

void * LoadInternalResource( DWORD * buffer, int resourceID, LPSTR type ) {
	if ( _globals.dllModule == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN, std::to_string( resourceID ) + xorstr_( ": Error gettind dll module" ) , RED );
		return nullptr;
	}

	HRSRC hResInfo = FindResourceA( _globals.dllModule , MAKEINTRESOURCE( resourceID ) , type );
	if ( hResInfo == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error locating resources" ) , RED );
		return nullptr;
	}

	DWORD resourceSize = SizeofResource( _globals.dllModule , hResInfo );
	if ( resourceSize == 0 ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error gettind resource size" ) , RED );
		return nullptr;
	}

	HGLOBAL hResData = LoadResource( _globals.dllModule , hResInfo );
	if ( hResData == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error loading resource" ) , RED );
		return nullptr;
	}

	void * pResData = LockResource( hResData );
	if ( pResData == NULL ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , std::to_string( resourceID ) + xorstr_( ": Error locking resource" ) , RED );
		return nullptr;
	}

	*buffer = resourceSize;

	return pResData;
}

bool LoadLibraryWithMemory(char* data, DWORD size, std::string name = "" ) {
	std::string filename = ( name.empty( ) ? Utils::Get( ).GetRandomWord( 32 ) + xorstr_( ".dll" ) : name);

	// Salvar a DLL extraída em um arquivo temporário
	std::ofstream outFile( filename , std::ios::binary );
	if ( outFile ) {
		outFile.write( data, size);
		outFile.close( );

		// Carregar a DLL usando LoadLibrary
		HMODULE hModule = LoadLibrary( filename.c_str() );

		if ( !fs::remove( filename.c_str( ) ) ) {
			LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Couldnt delete library" ) , RED );
		}

		if ( hModule ) {
			return true;
		}

	
	}
	else {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Couldnt save library" ) , RED );
		return false;
	}

	return false;
}


bool LoadAntiCheatResources( ) {
	{
		DWORD dumperSize = 0;
		void * dumperDll = LoadInternalResource( &dumperSize , IDR_DUMPERDLL , RT_RCDATA );
		if ( dumperDll == nullptr ) {
			return false;
		}
		_globals.encryptedDumper = std::vector<uint8_t>( ( uint8_t * ) dumperDll , ( uint8_t * ) dumperDll + dumperSize );
	}

	std::string teste = Utils::Get().GenerateStringHash( "teste" );

	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Resources loaded succesfully" ) , GREEN );

	return true;
}

void Startup( ) {
	Communication CommunicationEvent( _globals.OriginalProcess , _globals.ProtectProcess );
	Triggers TriggerEvent( _globals.OriginalProcess , _globals.ProtectProcess );
	AntiDebugger AntiDbg;
	Listener ListenEvent;

	Detections * detection = ( Detections * ) _globals.DetectionsPointer;

	detection->SetupPid( _globals.OriginalProcess , _globals.ProtectProcess );


	//threads holder
	std::vector<std::pair<ThreadHolder * , int>> threads = {
		std::make_pair( detection, DETECTIONS ),
		std::make_pair( &AntiDbg, ANTIDEBUGGER ),
		std::make_pair( &TriggerEvent, TRIGGERS ) ,
		std::make_pair( &CommunicationEvent, COMMUNICATION ),
		std::make_pair( &ListenEvent,  LISTENER )
	};


	//Thread holder state
	for ( int i = 0; i < threads.size( ); i++ ) {
		_globals.threadsReady.emplace_back( false );
	}

	CommunicationEvent.start( );
	detection->start( );
	TriggerEvent.start( );
	AntiDbg.start( );
	ListenEvent.start( );

	detection->InitializeThreads( );

	ThreadGuard monitor( threads );
	_globals.GuardMonitorPointer = &monitor;

	_globals.TriggersPointer = &TriggerEvent;
	_globals.AntiDebuggerPointer = &AntiDbg;
	monitor.start( );

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

ULONGLONG FileTimeToULL( const FILETIME & ft ) {
	ULARGE_INTEGER li;
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;
	return li.QuadPart;
}

double GetProcessUptimeSeconds( ) {
	FILETIME createTime , exitTime , kernelTime , userTime;

	if ( GetProcessTimes( GetCurrentProcess( ) , &createTime , &exitTime , &kernelTime , &userTime ) ) {
		FILETIME now;
		GetSystemTimeAsFileTime( &now );

		ULONGLONG now64 = FileTimeToULL( now );
		ULONGLONG create64 = FileTimeToULL( createTime );

		// Cada unidade do FILETIME representa 100 nanossegundos
		return ( now64 - create64 ) / 10000000.0; // converte para segundos
	}

	return -1.0;
}

bool IsRunningAsAdmin( ) {
	BOOL isAdmin = FALSE;
	PSID adminGroup = nullptr;

	// Cria um SID para o grupo Administradores
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	if ( AllocateAndInitializeSid(
		&ntAuthority , 2 ,
		SECURITY_BUILTIN_DOMAIN_RID ,
		DOMAIN_ALIAS_RID_ADMINS ,
		0 , 0 , 0 , 0 , 0 , 0 ,
		&adminGroup ) ) {
		CheckTokenMembership( nullptr , adminGroup , &isAdmin );
		FreeSid( adminGroup );
	}

	return isAdmin == TRUE;
}


bool OpenConsole( ) {

	AllocConsole( );
	if ( freopen( "CONOUT$" , "w" , stdout ) == nullptr ) {
		return false;
	}
	::ShowWindow( ::GetConsoleWindow( ) , SW_SHOW );

	return true;
}


DWORD WINAPI main( LPVOID lpParam ) {
	double StartupTime = GetProcessUptimeSeconds( );

	if ( StartupTime > 2 ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to start process" ) , false );
		return 1;
	}

	//Ignore errors caused in process
	SetErrorMode( SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX );

	if ( !IsRunningAsAdmin( ) ) {
		LogSystem::Get( ).MessageBoxError( xorstr_( "Process is not on admin mode!" ) , xorstr_( "Process is not on admin mode!" ) , false );
		return 1;
	}

	if ( !fs::exists( xorstr_( "ACLogs" ) ) )
		fs::create_directory( xorstr_( "ACLogs" ) );

	OpenConsole( );

	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Process startup Time:" ) + std::to_string( StartupTime ) , WHITE );

	if ( !Preventions::Get( ).DeployFirstBarrier( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to deploy first barrier" ) , false );
		return 1;
	}

	if ( !LoadAntiCheatResources( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to load resources" ) , false );
		return 1;
	}

	if ( !FileChecking::Get( ).ValidateFiles( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Can't validate files" ) , false );
		return 1;
	}

	Utils::Get( ).waitModule( xorstr_( "ntdll" ) );

	Detections DetectionEvent;

	_globals.GameName = xorstr_( "DayZ_x64.exe" );
	_globals.DetectionsPointer = &DetectionEvent;
	_globals.SelfID = ::_getpid( );
	DWORD ParentProcessId = GetParentProcessID( _globals.SelfID ); // Get the parent process ID
	if ( !ParentProcessId ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Initialization failed no parent" ) , false );
		return 1;
	}
	_globals.OriginalProcess = ParentProcessId;
	LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "Parent: " ) + Mem::Get( ).GetProcessName( ParentProcessId ) , GRAY );

	//Request MB and Disk ID
	if ( !hardware::Get( ).GenerateInitialCache( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to generate initial hardware cache" ) , false );
		return 1;
	}

	if ( !hardware::Get( ).EndCacheGeneration( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to end hardware cache" ) , false );
		return 1;
	}

	//Utils::Get( ).waitModule( xorstr_( "BEClient" ) );

	if ( !Preventions::Get( ).DeployLastBarrier( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Failed to deploy last barrier" ) , false );
		return 1;
	}

	if ( !_client.SendPingToServer( ) ) {
		LogSystem::Get( ).Error( xorstr_( "[401] Can't connect to server" ) , false );
	}

	Startup( );
idle:
	int MaxIdle = 3;
	for ( int i = 0; i <= MaxIdle; i++ ) {
		LogSystem::Get( ).ConsoleLog( _MAIN , xorstr_( "idle" ) , GRAY );
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
	}

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule ,
	DWORD  ul_reason_for_call ,
	LPVOID lpReserved )
{
	_globals.dllModule = hModule;

	switch ( ul_reason_for_call )
	{
	case DLL_PROCESS_ATTACH:
		// Cria a thread quando a DLL é carregada
		CreateThread( NULL , 0 , main , NULL , 0 , NULL );
		break;
	case DLL_PROCESS_DETACH:
		// Finalização, se necessário
		break;
	}
	return TRUE;
}