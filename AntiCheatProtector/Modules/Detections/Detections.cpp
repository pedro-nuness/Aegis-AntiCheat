#include "Detections.h"

#include <iostream>
#include <Windows.h>
#include <vector>
#include <thread>
#include <tlhelp32.h>
#include <psapi.h>
#include <unordered_map>
#include <dbghelp.h>
#include <tlhelp32.h>

#pragma comment(lib, "dbghelp.lib")

#include "../../Systems/Utils/utils.h"
#include "../../Systems/Memory/memory.h"
#include "../../Systems/Utils/xorstr.h"
#include "../../Systems/Injection/Injection.h"
#include "../../Systems/LogSystem/Log.h"
#include "../../Systems/AntiTamper/Authentication.h"


Detections::Detections( ) {}

Detections::~Detections( ) {}



bool Detections::isRunning( ) const {
	if ( this->ThreadObject->IsThreadSuspended( this->ThreadObject->GetHandle( ) ) ) {
		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}

	if ( !this->ThreadObject->IsThreadRunning( this->ThreadObject->GetHandle( ) ) && !this->ThreadObject->IsShutdownSignalled( ) ) {

		LogSystem::Get( ).Log( xorstr_( "Failed to run thread" ) );
	}
}



// Remover injeção de um processo (opcional)
void Detections::RemoveInjection( DWORD processId ) {}

// Verifica processos injetados
void Detections::CheckInjectedProcesses( ) {
	for ( auto it = InjectedProcesses.begin( ); it != InjectedProcesses.end( );) {
		if ( !Mem::Get( ).IsPIDRunning( it->first ) ) {
			it = InjectedProcesses.erase( it );
		}
		else
			it++;
	}
}

bool DoesProcessHaveOpenHandleTous( DWORD pid , std::vector <_SYSTEM_HANDLE> handles )
{
	if ( pid == 0 || pid == 4 ) //system idle process + system pids
		return false;

	for ( const auto & handle : handles )
	{
		if ( handle.ProcessId == pid && handle.ReferencingUs )
		{
			return true;
		}
	}

	return false;
}




// Verifica handles suspeitos
void Detections::CheckHandles( ) {
	std::vector<_SYSTEM_HANDLE> handles = Mem::Handle::Get( ).DetectOpenHandlesToProcess( );

	for ( auto & handle : handles )
	{
		if ( DoesProcessHaveOpenHandleTous( handle.ProcessId , handles ) )
		{
			std::string ProcessPath = Mem::Get( ).GetProcessExecutablePath( handle.ProcessId );

			//if ( !Authentication::Get( ).HasSignature( ProcessPath ) ) {
			//LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );
			//}

			/*
			* System processes
			Process C:\Windows\System32\svchost.exe has open handle to us!
			Process C:\Windows\System32\conhost.exe has open handle to us!
			  Process D:\Program Files (x86)\Steam\steam.exe
			  C:\\Windows\\System32\\audiodg.exe
			  C:\\Windows\\System32\\lsass.exe
			*/

			if ( !strcmp( ProcessPath.c_str() , xorstr_( "C:\\Windows\\System32\\audiodg.exe" ) ) ) {
				continue;
			}

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\svchost.exe" ) ) ) {
				continue;
			}

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\lsass.exe" ) ) ) {
				continue;
			}

			if ( !strcmp( ProcessPath.c_str( ) , xorstr_( "C:\\Windows\\System32\\conhost.exe" ) ) )
				continue;

			HANDLE processHandle = OpenProcess( PROCESS_DUP_HANDLE , FALSE , handle.ProcessId );

			if ( processHandle )
			{
				HANDLE duplicatedHandle = INVALID_HANDLE_VALUE;

				if ( DuplicateHandle( processHandle , ( HANDLE ) handle.Handle , GetCurrentProcess( ) , &duplicatedHandle , 0 , FALSE , DUPLICATE_SAME_ACCESS ) )
				{
					if ( Mem::Handle::Get( ).CheckDangerousPermissions( duplicatedHandle ) ) {
						LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );

						//if ( InjectProcess( handle.ProcessId ) ) {

						//}
					}
					else
						LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , YELLOW );
				

					if ( duplicatedHandle != INVALID_HANDLE_VALUE )
						CloseHandle( duplicatedHandle );
				}

				CloseHandle( processHandle );
			}
			

			// AddDetection( OPENHANDLE_TO_US , DetectionStruct( ProcessPath , SUSPECT  );

			//LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Process " ) + Mem::Get( ).GetProcessExecutablePath( handle.ProcessId ) + xorstr_( " has open handle to us!" ) , RED );
			//Logger::logfw( "UltimateAnticheat.log" , Detection , L"Process %s has open process handle to our process." , procName.c_str( ) );
			//foundHandle = TRUE;
			//continue;
		}
	}
}

// Método de injeção
bool Detections::InjectProcess( DWORD processId ) {
	char exePath[ MAX_PATH ];
	GetModuleFileNameA( NULL , exePath , MAX_PATH );
	std::string exePathStr( exePath );

	auto find = this->InjectedProcesses.find( processId );
	if ( find != this->InjectedProcesses.end( ) ) {
		return false;
	}

	std::string filename = xorstr_( "windows.dll" );
	if ( Utils::Get( ).ExistsFile( filename ) ) {
		this->InjectedProcesses[ processId ] = true;

		if ( Injector::Get( ).Inject( filename , processId ) == 1 )
			return true;
	}
	else {
		LogSystem::Get( ).ConsoleLog( _DETECTION , xorstr_( "Failed to find buffer" ) , LIGHT_GREEN );
	}

	return false;
}

// Função do thread principal do anti-cheat
void Detections::threadFunction( ) {
	bool m_running = true;

	while ( m_running ) {
		CheckInjectedProcesses( );
		CheckHandles( );
		std::this_thread::sleep_for( std::chrono::seconds( 10 ) );
	}
}
